# cache/manager.py
import redis
import json
import pickle
import zlib
from typing import Any, Optional, Union, Dict, List
from datetime import timedelta
import logging
from functools import wraps
import hashlib

logger = logging.getLogger(__name__)

class RedisCacheManager:
    """Redis-based cache manager for Path Predict"""
    
    def __init__(self, 
                 host: str = "localhost", 
                 port: int = 6379,
                 password: str = None,
                 db: int = 0,
                 default_ttl: int = 3600):  # 1 hour default
        
        self.redis_client = redis.Redis(
            host=host,
            port=port,
            password=password,
            db=db,
            decode_responses=False  # We'll handle encoding/decoding
        )
        
        self.default_ttl = default_ttl
        
        # Test connection
        try:
            self.redis_client.ping()
            logger.info(f"Redis cache connected to {host}:{port}")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def get(self, 
           key: str, 
           decompress: bool = True) -> Optional[Any]:
        """Get value from cache"""
        
        try:
            value = self.redis_client.get(key)
            if value is None:
                return None
            
            if decompress:
                try:
                    # Try to decompress first
                    decompressed = zlib.decompress(value)
                    return pickle.loads(decompressed)
                except:
                    # If decompression fails, try to load as pickle directly
                    return pickle.loads(value)
            else:
                return value
                
        except Exception as e:
            logger.error(f"Error getting cache key {key}: {e}")
            return None
    
    def set(self, 
           key: str, 
           value: Any, 
           ttl: Optional[int] = None,
           compress: bool = True) -> bool:
        """Set value in cache"""
        
        try:
            if compress:
                # Pickle and compress value
                pickled = pickle.dumps(value)
                compressed = zlib.compress(pickled, level=3)
                to_store = compressed
            else:
                to_store = pickle.dumps(value)
            
            ttl = ttl or self.default_ttl
            
            if ttl > 0:
                self.redis_client.setex(key, ttl, to_store)
            else:
                self.redis_client.set(key, to_store)
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            return self.redis_client.delete(key) > 0
        except Exception as e:
            logger.error(f"Error deleting cache key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            return self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Error checking cache key {key}: {e}")
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                return self.redis_client.delete(*keys)
            return 0
        except Exception as e:
            logger.error(f"Error clearing cache pattern {pattern}: {e}")
            return 0
    
    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter value"""
        try:
            return self.redis_client.incrby(key, amount)
        except Exception as e:
            logger.error(f"Error incrementing cache key {key}: {e}")
            return None
    
    def get_or_set(self, 
                  key: str, 
                  callback: callable,
                  ttl: Optional[int] = None,
                  force_refresh: bool = False) -> Any:
        """Get value from cache or set it using callback"""
        
        if not force_refresh:
            cached = self.get(key)
            if cached is not None:
                return cached
        
        # Generate new value
        new_value = callback()
        
        # Store in cache
        self.set(key, new_value, ttl)
        
        return new_value
    
    def cache_decorator(self, 
                       ttl: int = 3600,
                       key_prefix: str = "cache",
                       vary_on: List[str] = None):
        """Decorator for caching function results"""
        
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_cache_key(
                    func, args, kwargs, key_prefix, vary_on
                )
                
                # Try to get from cache
                cached_result = self.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for {cache_key}")
                    return cached_result
                
                # Cache miss, execute function
                logger.debug(f"Cache miss for {cache_key}")
                result = func(*args, **kwargs)
                
                # Store in cache
                self.set(cache_key, result, ttl)
                
                return result
            
            return wrapper
        
        return decorator
    
    def _generate_cache_key(self, 
                          func, 
                          args, 
                          kwargs, 
                          key_prefix: str,
                          vary_on: Optional[List[str]]) -> str:
        """Generate cache key from function and arguments"""
        
        # Start with prefix and function name
        parts = [key_prefix, func.__module__, func.__name__]
        
        # Add args if vary_on is None or empty (means vary on all)
        if vary_on is None or len(vary_on) == 0:
            parts.append(str(args))
            parts.append(str(sorted(kwargs.items())))
        else:
            # Only vary on specified kwargs
            vary_kwargs = {k: kwargs.get(k) for k in vary_on if k in kwargs}
            parts.append(str(sorted(vary_kwargs.items())))
        
        # Create hash of the key parts
        key_string = ":".join(parts)
        return f"pathpredict:{hashlib.md5(key_string.encode()).hexdigest()}"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            info = self.redis_client.info()
            
            return {
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', '0B'),
                'total_connections_received': info.get('total_connections_received', 0),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0),
                'hit_rate': (
                    info.get('keyspace_hits', 0) / 
                    max(info.get('keyspace_hits', 0) + info.get('keyspace_misses', 1), 1)
                ),
                'db_size': info.get('db0', {}).get('keys', 0) if 'db0' in info else 0
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
    
    def clear_all(self) -> bool:
        """Clear all cache entries"""
        try:
            self.redis_client.flushdb()
            logger.info("Cache cleared")
            return True
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False

# Cache key patterns for Path Predict
class CacheKeys:
    """Standard cache key patterns"""
    
    @staticmethod
    def attack_paths(account_id: str, path_type: str = None) -> str:
        key = f"attack_paths:{account_id}"
        if path_type:
            key += f":{path_type}"
        return key
    
    @staticmethod
    def graph_stats(account_id: str) -> str:
        return f"graph_stats:{account_id}"
    
    @staticmethod
    def node_details(node_id: str) -> str:
        return f"node:{node_id}"
    
    @staticmethod
    def query_result(query_hash: str) -> str:
        return f"query:{query_hash}"
    
    @staticmethod
    def prediction_result(prediction_id: str) -> str:
        return f"prediction:{prediction_id}"
    
    @staticmethod
    def terraform_analysis(plan_hash: str) -> str:
        return f"terraform:{plan_hash}"

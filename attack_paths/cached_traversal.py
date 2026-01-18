# attack_paths/cached_traversal.py
from typing import List, Dict, Any, Optional
import logging
import hashlib
import json
from .traversal import AttackPathTraversal
from cache.manager import RedisCacheManager, CacheKeys

logger = logging.getLogger(__name__)

class CachedAttackPathTraversal(AttackPathTraversal):
    """Attack path traversal with Redis caching"""
    
    def __init__(self, cache_manager: RedisCacheManager):
        super().__init__()
        self.cache = cache_manager
        self.cache_ttl = 300  # 5 minutes cache TTL
    
    def detect_privilege_escalation(self, 
                                   limit: int = 25, 
                                   use_cache: bool = True) -> List[Dict[str, Any]]:
        """Detect privilege escalation paths with caching"""
        
        cache_key = self._generate_detection_key(
            "privilege_escalation", 
            {"limit": limit}
        )
        
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for privilege escalation detection")
                return cached
        
        # Cache miss or disabled, compute paths
        paths = super().detect_privilege_escalation(limit)
        
        # Store in cache
        self.cache.set(cache_key, paths, self.cache_ttl)
        
        return paths
    
    def detect_all_paths(self, use_cache: bool = True) -> Dict[str, List[Dict[str, Any]]]:
        """Run all detection queries with caching"""
        
        cache_key = self._generate_detection_key("all_paths", {})
        
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for all paths detection")
                return cached
        
        # Cache miss or disabled, compute paths
        paths = super().detect_all_paths()
        
        # Store in cache
        self.cache.set(cache_key, paths, self.cache_ttl)
        
        return paths
    
    def find_paths_between(self, 
                          source_id: str, 
                          target_id: str, 
                          max_hops: int = 5,
                          use_cache: bool = True) -> List[Dict[str, Any]]:
        """Find all paths between two nodes with caching"""
        
        cache_key = self._generate_detection_key(
            "paths_between",
            {"source": source_id, "target": target_id, "max_hops": max_hops}
        )
        
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                logger.debug(f"Cache hit for paths between {source_id} and {target_id}")
                return cached
        
        # Cache miss or disabled, compute paths
        paths = super().find_paths_between(source_id, target_id, max_hops)
        
        # Store in cache
        self.cache.set(cache_key, paths, self.cache_ttl)
        
        return paths
    
    def _generate_detection_key(self, 
                               detection_type: str, 
                               params: Dict[str, Any]) -> str:
        """Generate cache key for detection results"""
        
        # Create deterministic string from params
        params_str = json.dumps(params, sort_keys=True)
        
        # Generate hash
        key_hash = hashlib.md5(
            f"{detection_type}:{params_str}".encode()
        ).hexdigest()
        
        return f"detection:{detection_type}:{key_hash}"
    
    def invalidate_cache(self, 
                        detection_type: Optional[str] = None,
                        account_id: Optional[str] = None) -> int:
        """Invalidate cache entries"""
        
        if detection_type:
            # Invalidate specific detection type
            pattern = f"detection:{detection_type}:*"
        elif account_id:
            # Invalidate all cache for account
            pattern = f"*:{account_id}:*"
        else:
            # Invalidate all detection cache
            pattern = "detection:*"
        
        cleared = self.cache.clear_pattern(pattern)
        logger.info(f"Cleared {cleared} cache entries for pattern: {pattern}")
        
        return cleared
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for attack path detection"""
        
        stats = self.cache.get_stats()
        
        # Count our cache entries
        detection_keys = self.cache.redis_client.keys("detection:*")
        stats['detection_cache_entries'] = len(detection_keys)
        
        return stats

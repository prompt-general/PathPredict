# auth/middleware.py
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Optional, Callable
from functools import wraps
import logging
from .rbac import RBACManager, Permission, User

logger = logging.getLogger(__name__)

security = HTTPBearer()

class RBACMiddleware:
    """FastAPI middleware for RBAC"""
    
    def __init__(self, rbac_manager: RBACManager):
        self.rbac = rbac_manager
    
    async def get_current_user(
        self, 
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> Optional[User]:
        """Get current user from token"""
        
        token = credentials.credentials
        user = self.rbac.verify_token(token)
        
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token"
            )
        
        return user
    
    def require_permission(self, permission: Permission):
        """Decorator to require specific permission"""
        
        def permission_decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract user from kwargs
                request = kwargs.get('request')
                current_user = kwargs.get('current_user')
                
                if not current_user:
                    # Try to get from request state
                    if request and hasattr(request.state, 'user'):
                        current_user = request.state.user
                
                if not current_user:
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )
                
                # Check permission
                if not self.rbac.has_permission(current_user, permission):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Permission denied: {permission.value}"
                    )
                
                return await func(*args, **kwargs)
            
            return wrapper
        
        return permission_decorator
    
    def require_any_permission(self, permissions: List[Permission]):
        """Decorator to require any of given permissions"""
        
        def permission_decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                current_user = kwargs.get('current_user')
                
                if not current_user:
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )
                
                # Check if user has any of the required permissions
                user_permissions = self.rbac.get_user_permissions(current_user)
                
                if not any(p in user_permissions for p in permissions):
                    permission_names = [p.value for p in permissions]
                    raise HTTPException(
                        status_code=403,
                        detail=f"Requires any of: {', '.join(permission_names)}"
                    )
                
                return await func(*args, **kwargs)
            
            return wrapper
        
        return permission_decorator
    
    def require_role(self, role: str):
        """Decorator to require specific role"""
        
        def role_decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                current_user = kwargs.get('current_user')
                
                if not current_user:
                    raise HTTPException(
                        status_code=401,
                        detail="Authentication required"
                    )
                
                if role not in current_user.roles:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Role required: {role}"
                    )
                
                return await func(*args, **kwargs)
            
            return wrapper
        
        return role_decorator

# Example usage in FastAPI routes
"""
from auth.middleware import RBACMiddleware, require_permission, Permission

app = FastAPI()
rbac_middleware = RBACMiddleware(rbac_manager)

@app.get("/attack-paths")
@require_permission(Permission.VIEW_ATTACK_PATHS)
async def get_attack_paths(
    current_user: User = Depends(rbac_middleware.get_current_user)
):
    # Your endpoint logic here
    pass
"""

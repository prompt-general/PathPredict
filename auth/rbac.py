# auth/rbac.py
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid
import bcrypt
import jwt
import logging
from functools import wraps

logger = logging.getLogger(__name__)

class Permission(Enum):
    """Permissions for RBAC"""
    # Read permissions
    VIEW_GRAPH = "view_graph"
    VIEW_ATTACK_PATHS = "view_attack_paths"
    VIEW_EVENTS = "view_events"
    VIEW_CONFIG = "view_config"
    
    # Write permissions
    CREATE_ALERT = "create_alert"
    UPDATE_GRAPH = "update_graph"
    UPDATE_CONFIG = "update_config"
    
    # Admin permissions
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    MANAGE_INTEGRATIONS = "manage_integrations"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    
    # Special permissions
    EXECUTE_QUERIES = "execute_queries"
    SIMULATE_ATTACKS = "simulate_attacks"
    REMEDIATE = "remediate"

class Role(Enum):
    """Predefined roles"""
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"
    AUDITOR = "auditor"

@dataclass
class User:
    """User model for RBAC"""
    user_id: str
    username: str
    email: str
    hashed_password: str
    roles: List[str]
    is_active: bool = True
    created_at: datetime = None
    last_login: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}

@dataclass
class RoleDefinition:
    """Role definition with permissions"""
    name: str
    description: str
    permissions: Set[Permission]
    is_system: bool = False

class RBACManager:
    """Role-Based Access Control Manager"""
    
    def __init__(self, secret_key: str, token_expiry_hours: int = 24):
        self.secret_key = secret_key
        self.token_expiry_hours = token_expiry_hours
        
        # Initialize system roles
        self.roles = self._initialize_system_roles()
        
        # In-memory storage (in production, use database)
        self.users = {}
        self.sessions = {}
        self.audit_log = []
        
        logger.info("RBAC Manager initialized")
    
    def _initialize_system_roles(self) -> Dict[str, RoleDefinition]:
        """Initialize system roles with permissions"""
        
        roles = {
            Role.VIEWER.value: RoleDefinition(
                name=Role.VIEWER.value,
                description="Can view graphs and attack paths",
                permissions={
                    Permission.VIEW_GRAPH,
                    Permission.VIEW_ATTACK_PATHS,
                    Permission.VIEW_EVENTS
                },
                is_system=True
            ),
            
            Role.ANALYST.value: RoleDefinition(
                name=Role.ANALYST.value,
                description="Can analyze and query attack paths",
                permissions={
                    Permission.VIEW_GRAPH,
                    Permission.VIEW_ATTACK_PATHS,
                    Permission.VIEW_EVENTS,
                    Permission.EXECUTE_QUERIES,
                    Permission.SIMULATE_ATTACKS,
                    Permission.CREATE_ALERT
                },
                is_system=True
            ),
            
            Role.RESPONDER.value: RoleDefinition(
                name=Role.RESPONDER.value,
                description="Can respond to and remediate attacks",
                permissions={
                    Permission.VIEW_GRAPH,
                    Permission.VIEW_ATTACK_PATHS,
                    Permission.VIEW_EVENTS,
                    Permission.EXECUTE_QUERIES,
                    Permission.SIMULATE_ATTACKS,
                    Permission.CREATE_ALERT,
                    Permission.REMEDIATE,
                    Permission.UPDATE_GRAPH
                },
                is_system=True
            ),
            
            Role.ADMIN.value: RoleDefinition(
                name=Role.ADMIN.value,
                description="Full system access",
                permissions=set(Permission),  # All permissions
                is_system=True
            ),
            
            Role.AUDITOR.value: RoleDefinition(
                name=Role.AUDITOR.value,
                description="Can view audit logs and configurations",
                permissions={
                    Permission.VIEW_AUDIT_LOGS,
                    Permission.VIEW_CONFIG,
                    Permission.VIEW_GRAPH,
                    Permission.VIEW_ATTACK_PATHS
                },
                is_system=True
            )
        }
        
        return roles
    
    def create_user(self, 
                   username: str, 
                   email: str, 
                   password: str,
                   roles: List[str] = None,
                   metadata: Dict[str, Any] = None) -> User:
        """Create a new user"""
        
        # Check if user already exists
        if any(u.username == username for u in self.users.values()):
            raise ValueError(f"User {username} already exists")
        
        if any(u.email == email for u in self.users.values()):
            raise ValueError(f"Email {email} already exists")
        
        # Validate roles
        if roles is None:
            roles = [Role.VIEWER.value]
        
        for role in roles:
            if role not in self.roles:
                raise ValueError(f"Invalid role: {role}")
        
        # Hash password
        hashed_password = self._hash_password(password)
        
        # Create user
        user_id = str(uuid.uuid4())
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            hashed_password=hashed_password,
            roles=roles,
            metadata=metadata or {}
        )
        
        self.users[user_id] = user
        
        # Audit log
        self._log_audit(
            action="USER_CREATED",
            user_id=user_id,
            details={"username": username, "roles": roles}
        )
        
        logger.info(f"User created: {username}")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return token"""
        
        # Find user
        user = None
        for u in self.users.values():
            if u.username == username and u.is_active:
                user = u
                break
        
        if not user:
            logger.warning(f"Authentication failed: User {username} not found")
            return None
        
        # Verify password
        if not self._verify_password(password, user.hashed_password):
            logger.warning(f"Authentication failed: Invalid password for {username}")
            return None
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Generate token
        token = self._generate_token(user)
        
        # Store session
        self.sessions[token] = {
            'user_id': user.user_id,
            'created_at': datetime.utcnow(),
            'last_access': datetime.utcnow()
        }
        
        # Audit log
        self._log_audit(
            action="USER_LOGIN",
            user_id=user.user_id,
            details={"username": username}
        )
        
        logger.info(f"User authenticated: {username}")
        return token
    
    def verify_token(self, token: str) -> Optional[User]:
        """Verify JWT token and return user"""
        
        try:
            # Verify JWT
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=["HS256"]
            )
            
            user_id = payload.get('user_id')
            if not user_id:
                return None
            
            # Check session
            session = self.sessions.get(token)
            if not session:
                return None
            
            # Update session access time
            session['last_access'] = datetime.utcnow()
            
            # Get user
            user = self.users.get(user_id)
            if not user or not user.is_active:
                return None
            
            return user
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def has_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has specific permission"""
        
        if not user or not user.is_active:
            return False
        
        # Collect all permissions from user's roles
        user_permissions = set()
        for role_name in user.roles:
            role = self.roles.get(role_name)
            if role:
                user_permissions.update(role.permissions)
        
        return permission in user_permissions
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """Get all permissions for a user"""
        
        if not user or not user.is_active:
            return set()
        
        permissions = set()
        for role_name in user.roles:
            role = self.roles.get(role_name)
            if role:
                permissions.update(role.permissions)
        
        return permissions
    
    def create_custom_role(self, 
                          name: str, 
                          description: str,
                          permissions: List[Permission]) -> RoleDefinition:
        """Create a custom role"""
        
        if name in self.roles:
            raise ValueError(f"Role {name} already exists")
        
        role = RoleDefinition(
            name=name,
            description=description,
            permissions=set(permissions),
            is_system=False
        )
        
        self.roles[name] = role
        
        # Audit log
        self._log_audit(
            action="ROLE_CREATED",
            user_id="system",
            details={"role": name, "permissions": [p.value for p in permissions]}
        )
        
        logger.info(f"Custom role created: {name}")
        return role
    
    def update_user_roles(self, 
                         user_id: str, 
                         roles: List[str],
                         updated_by: str) -> bool:
        """Update user roles"""
        
        user = self.users.get(user_id)
        if not user:
            return False
        
        # Validate roles
        for role in roles:
            if role not in self.roles:
                raise ValueError(f"Invalid role: {role}")
        
        old_roles = user.roles.copy()
        user.roles = roles
        
        # Audit log
        self._log_audit(
            action="USER_ROLES_UPDATED",
            user_id=updated_by,
            details={
                "target_user_id": user_id,
                "old_roles": old_roles,
                "new_roles": roles
            }
        )
        
        logger.info(f"User roles updated for {user.username}")
        return True
    
    def get_audit_logs(self, 
                      user_id: Optional[str] = None,
                      action: Optional[str] = None,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs with filters"""
        
        filtered = self.audit_log
        
        if user_id:
            filtered = [log for log in filtered if log['user_id'] == user_id]
        
        if action:
            filtered = [log for log in filtered if log['action'] == action]
        
        if start_time:
            filtered = [log for log in filtered if log['timestamp'] >= start_time]
        
        if end_time:
            filtered = [log for log in filtered if log['timestamp'] <= end_time]
        
        return sorted(filtered, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def _verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    
    def _generate_token(self, user: User) -> str:
        """Generate JWT token for user"""
        
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'roles': user.roles,
            'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
    
    def _log_audit(self, 
                  action: str, 
                  user_id: str, 
                  details: Dict[str, Any]):
        """Log audit event"""
        
        log_entry = {
            'log_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow(),
            'action': action,
            'user_id': user_id,
            'details': details,
            'ip_address': '127.0.0.1'  # In production, get from request
        }
        
        self.audit_log.append(log_entry)
        
        # Keep audit log size manageable
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]

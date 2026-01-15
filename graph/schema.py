from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


class NodeType(Enum):
    IDENTITY = "Identity"
    RESOURCE = "Resource"
    POLICY = "Policy"
    METADATA = "Metadata"
    ACCOUNT = "Account"
    ATTACK_PATH = "AttackPath"


class IdentitySubtype(Enum):
    USER = "User"
    ROLE = "Role"
    SERVICE_ACCOUNT = "ServiceAccount"
    GROUP = "Group"


class ResourceSubtype(Enum):
    COMPUTE = "Compute"
    STORAGE = "Storage"
    DATABASE = "Database"
    NETWORK = "Network"


class RelationshipType(Enum):
    CAN_ASSUME = "CAN_ASSUME"
    CAN_ACCESS = "CAN_ACCESS"
    CONTAINS = "CONTAINS"
    TRUSTS = "TRUSTS"
    VIOLATES = "VIOLATES"
    MEMBER_OF = "MEMBER_OF"
    ATTACHED_TO = "ATTACHED_TO"


@dataclass
class UnifiedNode:
    """Unified node representation across all clouds"""
    node_id: str  # Format: cloud::service::type::id (e.g., aws::iam::role/AdminRole)
    node_type: NodeType
    subtype: str
    properties: Dict[str, Any]
    cloud_provider: str
    account_id: str
    region: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    graph_version: str = "v1"


@dataclass
class UnifiedRelationship:
    """Unified relationship representation"""
    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: Dict[str, Any]
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None


class GraphSchema:
    """Graph schema definition and validation"""
    
    # Schema constraints and indexes
    CONSTRAINTS = [
        {"label": "Identity", "property": "node_id"},
        {"label": "Resource", "property": "node_id"},
        {"label": "Policy", "property": "node_id"},
        {"label": "Account", "property": "node_id"},
    ]
    
    INDEXES = [
        {"label": "Identity", "property": "cloud_provider"},
        {"label": "Resource", "property": "cloud_provider"},
        {"label": "Identity", "property": "subtype"},
        {"label": "Resource", "property": "subtype"},
        {"label": "Identity", "property": "valid_from"},
        {"label": "Identity", "property": "valid_to"},
        {"label": "AttackPath", "property": "score"},
    ]
    
    @staticmethod
    def generate_node_id(cloud: str, service: str, resource_type: str, resource_id: str) -> str:
        """Generate unified node ID across all clouds"""
        return f"{cloud}::{service}::{resource_type}::{resource_id}"
    
    @staticmethod
    def parse_node_id(node_id: str) -> Dict[str, str]:
        """Parse unified node ID into components"""
        parts = node_id.split("::")
        return {
            "cloud": parts[0],
            "service": parts[1],
            "type": parts[2],
            "id": "::".join(parts[3:]) if len(parts) > 3 else ""
        }

# ingestion/azure/azure_ad_ingestor.py
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure.identity import ClientSecretCredential
from azure.graphrbac import GraphRbacManagementClient
from graph.schema import (
    UnifiedNode, UnifiedRelationship,
    NodeType, IdentitySubtype, RelationshipType, GraphSchema
)
from graph.writer import TimeVersionedWriter

logger = logging.getLogger(__name__)


class AzureADIngestor:
    """Ingest Azure Active Directory data"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        self.graph_client = GraphRbacManagementClient(
            self.credential,
            tenant_id
        )
        self.writer = TimeVersionedWriter()
    
    def ingest_users(self) -> List[str]:
        """Ingest Azure AD users"""
        logger.info("Ingesting Azure AD users")
        node_ids = []
        
        try:
            users = self.graph_client.users.list()
            
            for user in users:
                user_id = user.object_id
                user_name = user.user_principal_name
                
                # Create user node
                node_id = GraphSchema.generate_node_id(
                    cloud="azure",
                    service="ad",
                    resource_type="user",
                    resource_id=user_id
                )
                
                user_node = UnifiedNode(
                    node_id=node_id,
                    node_type=NodeType.IDENTITY,
                    subtype=IdentitySubtype.USER.value,
                    properties={
                        "user_principal_name": user_name,
                        "display_name": user.display_name,
                        "account_enabled": user.account_enabled,
                        "user_type": user.user_type,
                        "risk_score": self._calculate_user_risk(user)
                    },
                    cloud_provider="azure",
                    account_id=self.tenant_id,
                    region="global"
                )
                
                self.writer.write_node(user_node)
                node_ids.append(node_id)
            
            logger.info(f"Ingested {len(node_ids)} Azure AD users")
            return node_ids
            
        except Exception as e:
            logger.error(f"Error ingesting Azure AD users: {e}")
            return []
    
    def ingest_groups(self) -> List[str]:
        """Ingest Azure AD groups"""
        logger.info("Ingesting Azure AD groups")
        node_ids = []
        
        try:
            groups = self.graph_client.groups.list()
            
            for group in groups:
                group_id = group.object_id
                group_name = group.display_name
                
                # Create group node
                node_id = GraphSchema.generate_node_id(
                    cloud="azure",
                    service="ad",
                    resource_type="group",
                    resource_id=group_id
                )
                
                group_node = UnifiedNode(
                    node_id=node_id,
                    node_type=NodeType.IDENTITY,
                    subtype=IdentitySubtype.GROUP.value,
                    properties={
                        "display_name": group_name,
                        "description": group.description,
                        "security_enabled": group.security_enabled,
                        "mail_enabled": group.mail_enabled,
                        "risk_score": 0.3  # Base risk
                    },
                    cloud_provider="azure",
                    account_id=self.tenant_id,
                    region="global"
                )
                
                self.writer.write_node(group_node)
                node_ids.append(node_id)
                
                # Get group members
                self._ingest_group_members(group_id, node_id)
            
            logger.info(f"Ingested {len(node_ids)} Azure AD groups")
            return node_ids
            
        except Exception as e:
            logger.error(f"Error ingesting Azure AD groups: {e}")
            return []
    
    def ingest_service_principals(self) -> List[str]:
        """Ingest Azure AD service principals"""
        logger.info("Ingesting Azure AD service principals")
        node_ids = []
        
        try:
            service_principals = self.graph_client.service_principals.list()
            
            for sp in service_principals:
                sp_id = sp.object_id
                sp_name = sp.display_name
                
                # Create service principal node
                node_id = GraphSchema.generate_node_id(
                    cloud="azure",
                    service="ad",
                    resource_type="serviceprincipal",
                    resource_id=sp_id
                )
                
                sp_node = UnifiedNode(
                    node_id=node_id,
                    node_type=NodeType.IDENTITY,
                    subtype=IdentitySubtype.SERVICE_ACCOUNT.value,
                    properties={
                        "display_name": sp_name,
                        "app_display_name": sp.app_display_name,
                        "app_id": sp.app_id,
                        "risk_score": self._calculate_sp_risk(sp)
                    },
                    cloud_provider="azure",
                    account_id=self.tenant_id,
                    region="global"
                )
                
                self.writer.write_node(sp_node)
                node_ids.append(node_id)
            
            logger.info(f"Ingested {len(node_ids)} Azure AD service principals")
            return node_ids
            
        except Exception as e:
            logger.error(f"Error ingesting Azure AD service principals: {e}")
            return []
    
    def _ingest_group_members(self, group_id: str, group_node_id: str):
        """Ingest group memberships"""
        try:
            members = self.graph_client.groups.get_group_members(group_id)
            
            for member in members:
                member_id = member.object_id
                
                # Generate member node ID based on type
                if hasattr(member, 'user_principal_name'):
                    member_node_id = GraphSchema.generate_node_id(
                        cloud="azure",
                        service="ad",
                        resource_type="user",
                        resource_id=member_id
                    )
                elif hasattr(member, 'display_name') and hasattr(member, 'mail_enabled'):
                    member_node_id = GraphSchema.generate_node_id(
                        cloud="azure",
                        service="ad",
                        resource_type="group",
                        resource_id=member_id
                    )
                elif hasattr(member, 'app_display_name'):
                    member_node_id = GraphSchema.generate_node_id(
                        cloud="azure",
                        service="ad",
                        resource_type="serviceprincipal",
                        resource_id=member_id
                    )
                else:
                    continue
                
                # Create MEMBER_OF relationship
                rel = UnifiedRelationship(
                    source_id=member_node_id,
                    target_id=group_node_id,
                    relationship_type=RelationshipType.MEMBER_OF,
                    properties={
                        "membership_type": "direct",
                        "source": "azure_ad"
                    }
                )
                
                self.writer.write_relationship(rel)
                
        except Exception as e:
            logger.error(f"Error ingesting group members for {group_id}: {e}")
    
    def _calculate_user_risk(self, user) -> float:
        """Calculate risk score for a user"""
        risk = 0.3
        
        # Check for admin roles or high privileges
        if user.user_principal_name and 'admin' in user.user_principal_name.lower():
            risk += 0.3
        
        # Check if account is disabled
        if not user.account_enabled:
            risk -= 0.2
        
        # Check for external users
        if user.user_type and user.user_type.lower() == 'guest':
            risk += 0.2
        
        return max(0.1, min(1.0, risk))
    
    def _calculate_sp_risk(self, service_principal) -> float:
        """Calculate risk score for a service principal"""
        risk = 0.5  # Service principals are higher risk by default
        
        # Check for high privilege names
        if service_principal.display_name:
            name_lower = service_principal.display_name.lower()
            if any(term in name_lower for term in ['admin', 'owner', 'contributor', 'write']):
                risk += 0.3
        
        return max(0.1, min(1.0, risk))
    
    def ingest_all(self) -> Dict[str, List[str]]:
        """Ingest all Azure AD data"""
        return {
            "users": self.ingest_users(),
            "groups": self.ingest_groups(),
            "service_principals": self.ingest_service_principals()
        }

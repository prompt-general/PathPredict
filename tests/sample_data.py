"""
Create sample data for testing attack path detection
"""
from graph.writer import TimeVersionedWriter
from graph.schema import (
    UnifiedNode, UnifiedRelationship,
    NodeType, IdentitySubtype, ResourceSubtype,
    RelationshipType, GraphSchema
)
from datetime import datetime, timedelta
import random

def create_sample_attack_graph():
    """Create a realistic sample attack graph for testing"""
    writer = TimeVersionedWriter()
    
    # Create sample accounts
    accounts = [
        {"id": "aws::account::123456789012", "name": "Production", "cloud": "aws"},
        {"id": "aws::account::210987654321", "name": "Development", "cloud": "aws"},
        {"id": "azure::subscription::sub-001", "name": "Azure Prod", "cloud": "azure"},
    ]
    
    for acc in accounts:
        account_node = UnifiedNode(
            node_id=acc["id"],
            node_type=NodeType.METADATA,
            subtype="Account",
            properties={
                "name": acc["name"],
                "environment": "prod" if "Prod" in acc["name"] else "dev",
                "criticality": 0.8 if "Prod" in acc["name"] else 0.3
            },
            cloud_provider=acc["cloud"],
            account_id=acc["id"].split("::")[-1],
            region="global"
        )
        writer.write_node(account_node)
    
    # Create sample identities with varying risk levels
    identities = [
        # High-risk external user
        {
            "id": "aws::iam::user/ExternalContractor",
            "type": IdentitySubtype.USER,
            "props": {
                "external": True,
                "risk_score": 0.7,
                "mfa_enabled": False,
                "last_login": (datetime.utcnow() - timedelta(days=1)).isoformat()
            }
        },
        # Admin role (high privilege)
        {
            "id": "aws::iam::role/AdminRole",
            "type": IdentitySubtype.ROLE,
            "props": {
                "external": False,
                "risk_score": 0.9,
                "admin": True,
                "trust_policy": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}'
            }
        },
        # Service account with database access
        {
            "id": "aws::iam::role/DatabaseAccessRole",
            "type": IdentitySubtype.ROLE,
            "props": {
                "external": False,
                "risk_score": 0.6,
                "permissions": ["rds:*", "dynamodb:*"]
            }
        },
        # Azure service principal
        {
            "id": "azure::ad::serviceprincipal/AppService",
            "type": IdentitySubtype.SERVICE_ACCOUNT,
            "props": {
                "external": False,
                "risk_score": 0.5,
                "app_id": "app-001"
            }
        },
    ]
    
    for identity in identities:
        identity_node = UnifiedNode(
            node_id=identity["id"],
            node_type=NodeType.IDENTITY,
            subtype=identity["type"].value,
            properties=identity["props"],
            cloud_provider=identity["id"].split("::")[0],
            account_id="123456789012" if "aws" in identity["id"] else "sub-001",
            region="global"
        )
        writer.write_node(identity_node)
    
    # Create sample resources
    resources = [
        # Critical production database
        {
            "id": "aws::rds::instance/prod-database-1",
            "type": ResourceSubtype.DATABASE,
            "props": {
                "criticality": 0.9,
                "public_access": False,
                "encryption": True,
                "environment": "production",
                "contains_pii": True
            }
        },
        # Publicly exposed S3 bucket
        {
            "id": "aws::s3::bucket/public-data-bucket",
            "type": ResourceSubtype.STORAGE,
            "props": {
                "criticality": 0.7,
                "public_access": True,
                "internet_facing": True,
                "encryption": False,
                "environment": "development"
            }
        },
        # EC2 instance in public subnet
        {
            "id": "aws::ec2::instance/i-1234567890abcdef0",
            "type": ResourceSubtype.COMPUTE,
            "props": {
                "criticality": 0.6,
                "public_ip": "54.123.45.67",
                "internet_facing": True,
                "instance_type": "t3.large",
                "environment": "production"
            }
        },
        # Azure storage account
        {
            "id": "azure::storage::account/prodstorage",
            "type": ResourceSubtype.STORAGE,
            "props": {
                "criticality": 0.8,
                "public_access": False,
                "encryption": True,
                "environment": "production"
            }
        },
    ]
    
    for resource in resources:
        resource_node = UnifiedNode(
            node_id=resource["id"],
            node_type=NodeType.RESOURCE,
            subtype=resource["type"].value,
            properties=resource["props"],
            cloud_provider=resource["id"].split("::")[0],
            account_id="123456789012" if "aws" in resource["id"] else "sub-001",
            region="us-east-1" if "aws" in resource["id"] else "eastus"
        )
        writer.write_node(resource_node)
    
    # Create attack path relationships
    relationships = [
        # External contractor can assume admin role (privilege escalation)
        ("aws::iam::user/ExternalContractor", "aws::iam::role/AdminRole", 
         RelationshipType.CAN_ASSUME, {"condition": "none"}),
        
        # Admin role can access production database
        ("aws::iam::role/AdminRole", "aws::rds::instance/prod-database-1",
         RelationshipType.CAN_ACCESS, {"permission": "full"}),
        
        # Admin role can access public S3 bucket
        ("aws::iam::role/AdminRole", "aws::s3::bucket/public-data-bucket",
         RelationshipType.CAN_ACCESS, {"permission": "write"}),
        
        # Database role can access database
        ("aws::iam::role/DatabaseAccessRole", "aws::rds::instance/prod-database-1",
         RelationshipType.CAN_ACCESS, {"permission": "read"}),
        
        # EC2 instance contains sensitive data (implicit)
        ("aws::ec2::instance/i-1234567890abcdef0", "aws::rds::instance/prod-database-1",
         RelationshipType.CONTAINS, {"access": "network"}),
        
        # Cross-cloud trust (simulated)
        ("aws::iam::role/AdminRole", "azure::ad::serviceprincipal/AppService",
         RelationshipType.TRUSTS, {"federation": "enabled"}),
    ]
    
    for source_id, target_id, rel_type, props in relationships:
        rel = UnifiedRelationship(
            source_id=source_id,
            target_id=target_id,
            relationship_type=rel_type,
            properties=props
        )
        writer.write_relationship(rel)
    
    print("✅ Created sample attack graph with:")
    print(f"   - {len(accounts)} accounts")
    print(f"   - {len(identities)} identities")
    print(f"   - {len(resources)} resources")
    print(f"   - {len(relationships)} relationships")
    print("\nExample attack paths created:")
    print("1. ExternalContractor → AdminRole → prod-database-1")
    print("2. AdminRole → public-data-bucket (public exposure)")
    print("3. Cross-cloud: AdminRole ↔ Azure AppService")

if __name__ == "__main__":
    create_sample_attack_graph()

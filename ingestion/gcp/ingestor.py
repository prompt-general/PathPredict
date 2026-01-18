# ingestion/gcp/ingestor.py
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from google.cloud import resource_manager, iam, compute, storage, sqladmin
from google.oauth2 import service_account
from graph.schema import (
    UnifiedNode, UnifiedRelationship,
    NodeType, IdentitySubtype, ResourceSubtype,
    RelationshipType, GraphSchema
)
from graph.writer import TimeVersionedWriter

class GCPIngestor:
    """Ingest GCP resources into the attack graph"""
    
    def __init__(self, credentials_path: Optional[str] = None, project_id: Optional[str] = None):
        if credentials_path:
            self.credentials = service_account.Credentials.from_service_account_file(credentials_path)
        else:
            # Use default credentials (e.g., environment variable GOOGLE_APPLICATION_CREDENTIALS)
            self.credentials = None
        
        self.project_id = project_id
        self.writer = TimeVersionedWriter()
        
        # Initialize clients
        self.resource_client = resource_manager.Client(credentials=self.credentials)
        self.iam_client = iam.IAMClient(credentials=self.credentials)
        self.compute_client = compute.InstancesClient(credentials=self.credentials)
        self.storage_client = storage.Client(credentials=self.credentials)
        self.sql_client = sqladmin.SqlAdminServiceClient(credentials=self.credentials)
    
    def ingest_all(self, project_id: Optional[str] = None):
        """Ingest all GCP resources from a project"""
        project_id = project_id or self.project_id
        if not project_id:
            raise ValueError("Project ID must be provided")
        
        print(f"Ingesting GCP project: {project_id}")
        
        # Ingest project (as Account node)
        self.ingest_project(project_id)
        
        # Ingest IAM resources
        self.ingest_iam_policy(project_id)
        self.ingest_service_accounts(project_id)
        
        # Ingest compute resources
        self.ingest_compute_instances(project_id)
        
        # Ingest storage resources
        self.ingest_storage_buckets(project_id)
        
        # Ingest database resources
        self.ingest_sql_instances(project_id)
        
        # Ingest networking resources (VPC, firewall rules)
        self.ingest_firewall_rules(project_id)
    
    def ingest_project(self, project_id: str):
        """Ingest GCP project as an Account node"""
        project = self.resource_client.fetch_project(project_id)
        
        node_id = GraphSchema.generate_node_id(
            cloud="gcp",
            service="resourcemanager",
            resource_type="project",
            resource_id=project_id
        )
        
        node = UnifiedNode(
            node_id=node_id,
            node_type=NodeType.ACCOUNT,
            subtype="Project",
            properties={
                "project_id": project_id,
                "name": project.name,
                "project_number": project.number,
                "create_time": project.create_time.isoformat() if project.create_time else None,
                "labels": project.labels,
                "status": project.status.name
            },
            cloud_provider="gcp",
            account_id=project_id,
            region="global"
        )
        
        self.writer.write_node(node)
        return node_id
    
    def ingest_iam_policy(self, project_id: str):
        """Ingest IAM policy for the project"""
        # Get IAM policy
        policy = self.resource_client.get_iam_policy(project_id)
        
        # Create policy node
        policy_id = GraphSchema.generate_node_id(
            cloud="gcp",
            service="iam",
            resource_type="policy",
            resource_id=f"{project_id}/policy"
        )
        
        policy_node = UnifiedNode(
            node_id=policy_id,
            node_type=NodeType.POLICY,
            subtype="IAMPolicy",
            properties={
                "bindings": [
                    {
                        "role": binding.role,
                        "members": list(binding.members)
                    }
                    for binding in policy.bindings
                ],
                "version": policy.version
            },
            cloud_provider="gcp",
            account_id=project_id,
            region="global"
        )
        
        self.writer.write_node(policy_node)
        
        # Link policy to project
        project_node_id = GraphSchema.generate_node_id(
            cloud="gcp",
            service="resourcemanager",
            resource_type="project",
            resource_id=project_id
        )
        
        rel = UnifiedRelationship(
            source_id=project_node_id,
            target_id=policy_id,
            relationship_type=RelationshipType.ATTACHED_TO,
            properties={"attachment_type": "project_iam_policy"}
        )
        self.writer.write_relationship(rel)
        
        return policy_id
    
    def ingest_service_accounts(self, project_id: str):
        """Ingest service accounts and their IAM roles"""
        # List service accounts
        parent = f"projects/{project_id}"
        accounts = self.iam_client.list_service_accounts(parent=parent)
        
        for account in accounts:
            # Create service account node
            account_id = GraphSchema.generate_node_id(
                cloud="gcp",
                service="iam",
                resource_type="serviceaccount",
                resource_id=account.email
            )
            
            account_node = UnifiedNode(
                node_id=account_id,
                node_type=NodeType.IDENTITY,
                subtype=IdentitySubtype.SERVICE_ACCOUNT.value,
                properties={
                    "email": account.email,
                    "display_name": account.display_name,
                    "description": account.description,
                    "disabled": account.disabled,
                    "oauth2_client_id": account.oauth2_client_id
                },
                cloud_provider="gcp",
                account_id=project_id,
                region="global"
            )
            
            self.writer.write_node(account_node)
    
    def ingest_compute_instances(self, project_id: str):
        """Ingest Compute Engine instances"""
        # List all zones and instances
        zones = ["us-central1-a", "us-east1-b", "europe-west1-b"]  # Example, should fetch dynamically
        
        for zone in zones:
            instances = self.compute_client.list(project=project_id, zone=zone)
            
            for instance in instances:
                instance_id = GraphSchema.generate_node_id(
                    cloud="gcp",
                    service="compute",
                    resource_type="instance",
                    resource_id=instance.id
                )
                
                # Check if instance has external IP
                external_ips = []
                for interface in instance.network_interfaces:
                    for config in interface.access_configs:
                        if config.nat_i_p:
                            external_ips.append(config.nat_i_p)
                
                instance_node = UnifiedNode(
                    node_id=instance_id,
                    node_type=NodeType.RESOURCE,
                    subtype=ResourceSubtype.COMPUTE.value,
                    properties={
                        "name": instance.name,
                        "zone": zone,
                        "machine_type": instance.machine_type.split('/')[-1],
                        "status": instance.status,
                        "external_ips": external_ips,
                        "internet_facing": len(external_ips) > 0,
                        "labels": instance.labels,
                        "service_accounts": [
                            sa.email for sa in instance.service_accounts
                        ] if instance.service_accounts else []
                    },
                    cloud_provider="gcp",
                    account_id=project_id,
                    region=zone[:-2]  # Remove zone letter to get region
                )
                
                self.writer.write_node(instance_node)
                
                # Link service accounts to instance
                if instance.service_accounts:
                    for sa in instance.service_accounts:
                        sa_node_id = GraphSchema.generate_node_id(
                            cloud="gcp",
                            service="iam",
                            resource_type="serviceaccount",
                            resource_id=sa.email
                        )
                        
                        rel = UnifiedRelationship(
                            source_id=sa_node_id,
                            target_id=instance_id,
                            relationship_type=RelationshipType.CAN_ACCESS,
                            properties={"access_type": "instance_service_account"}
                        )
                        self.writer.write_relationship(rel)
    
    def ingest_storage_buckets(self, project_id: str):
        """Ingest Cloud Storage buckets"""
        buckets = self.storage_client.list_buckets(project=project_id)
        
        for bucket in buckets:
            bucket_id = GraphSchema.generate_node_id(
                cloud="gcp",
                service="storage",
                resource_type="bucket",
                resource_id=bucket.name
            )
            
            # Check bucket IAM policy for public access
            policy = bucket.get_iam_policy()
            is_public = False
            for binding in policy.bindings:
                if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                    is_public = True
                    break
            
            bucket_node = UnifiedNode(
                node_id=bucket_id,
                node_type=NodeType.RESOURCE,
                subtype=ResourceSubtype.STORAGE.value,
                properties={
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "public": is_public,
                    "labels": bucket.labels,
                    "versioning_enabled": bucket.versioning_enabled,
                    "encryption": bucket.default_kms_key_name is not None
                },
                cloud_provider="gcp",
                account_id=project_id,
                region=bucket.location
            )
            
            self.writer.write_node(bucket_node)
    
    def ingest_sql_instances(self, project_id: str):
        """Ingest Cloud SQL instances"""
        instances = self.sql_client.list(project=project_id)
        
        for instance in instances.items:
            instance_id = GraphSchema.generate_node_id(
                cloud="gcp",
                service="sql",
                resource_type="instance",
                resource_id=instance.name
            )
            
            # Check if instance has public IP
            public_ip = None
            for ip in instance.ip_addresses:
                if ip.type == "PRIMARY":
                    public_ip = ip.ip_address
                    break
            
            instance_node = UnifiedNode(
                node_id=instance_id,
                node_type=NodeType.RESOURCE,
                subtype=ResourceSubtype.DATABASE.value,
                properties={
                    "name": instance.name,
                    "database_version": instance.database_version,
                    "region": instance.region,
                    "public_ip": public_ip,
                    "internet_facing": public_ip is not None,
                    "settings": {
                        "tier": instance.settings.tier,
                        "backup_enabled": instance.settings.backup_configuration.enabled,
                        "ip_configuration": {
                            "authorized_networks": [
                                net.value for net in instance.settings.ip_configuration.authorized_networks
                            ]
                        }
                    }
                },
                cloud_provider="gcp",
                account_id=project_id,
                region=instance.region
            )
            
            self.writer.write_node(instance_node)
    
    def ingest_firewall_rules(self, project_id: str):
        """Ingest VPC firewall rules"""
        # Note: We need to use the compute client for firewall rules
        firewall_client = compute.FirewallsClient(credentials=self.credentials)
        firewalls = firewall_client.list(project=project_id)
        
        for firewall in firewalls:
            firewall_id = GraphSchema.generate_node_id(
                cloud="gcp",
                service="compute",
                resource_type="firewall",
                resource_id=firewall.name
            )
            
            # Check if rule allows public access
            source_ranges = firewall.source_ranges
            is_public = "0.0.0.0/0" in source_ranges
            
            firewall_node = UnifiedNode(
                node_id=firewall_id,
                node_type=NodeType.POLICY,
                subtype="FirewallRule",
                properties={
                    "name": firewall.name,
                    "network": firewall.network,
                    "priority": firewall.priority,
                    "direction": firewall.direction,
                    "allowed": [
                        {
                            "protocol": rule.ip_protocol,
                            "ports": rule.ports
                        }
                        for rule in firewall.allowed
                    ],
                    "source_ranges": source_ranges,
                    "target_tags": firewall.target_tags,
                    "public": is_public
                },
                cloud_provider="gcp",
                account_id=project_id,
                region="global"  # Firewall rules are global in GCP
            )
            
            self.writer.write_node(firewall_node)

import boto3
from datetime import datetime
from typing import List, Dict, Any
from graph.schema import (
    UnifiedNode, UnifiedRelationship, 
    NodeType, IdentitySubtype, ResourceSubtype,
    RelationshipType, GraphSchema
)
from graph.writer import TimeVersionedWriter


class AWSIngestor:
    """Basic AWS IAM and EC2 ingestor"""
    
    def __init__(self, aws_profile: str = "default", account_id: str = None):
        self.session = boto3.Session(profile_name=aws_profile)
        self.account_id = account_id or self._get_account_id()
        self.writer = TimeVersionedWriter()
    
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        sts = self.session.client('sts')
        return sts.get_caller_identity()["Account"]
    
    def ingest_iam_roles(self) -> List[str]:
        """Ingest IAM roles and their policies"""
        iam = self.session.client('iam')
        node_ids = []
        
        # Get all IAM roles
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                # Create role node
                role_id = GraphSchema.generate_node_id(
                    cloud="aws",
                    service="iam",
                    resource_type="role",
                    resource_id=role['RoleName']
                )
                
                role_node = UnifiedNode(
                    node_id=role_id,
                    node_type=NodeType.IDENTITY,
                    subtype=IdentitySubtype.ROLE.value,
                    properties={
                        "arn": role['Arn'],
                        "name": role['RoleName'],
                        "create_date": role['CreateDate'].isoformat(),
                        "description": role.get('Description', ''),
                        "max_session_duration": role.get('MaxSessionDuration', 3600)
                    },
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global"  # IAM is global
                )
                
                self.writer.write_node(role_node)
                node_ids.append(role_id)
                
                # Inline policies
                self._ingest_role_policies(role['RoleName'], role_id)
        
        return node_ids
    
    def _ingest_role_policies(self, role_name: str, role_node_id: str):
        """Ingest inline policies for a role"""
        iam = self.session.client('iam')
        
        # List inline policies
        try:
            policies = iam.list_role_policies(RoleName=role_name)
            
            for policy_name in policies['PolicyNames']:
                # Get policy document
                policy_doc = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                
                # Create policy node
                policy_id = GraphSchema.generate_node_id(
                    cloud="aws",
                    service="iam",
                    resource_type="policy",
                    resource_id=f"{role_name}/{policy_name}"
                )
                
                policy_node = UnifiedNode(
                    node_id=policy_id,
                    node_type=NodeType.POLICY,
                    subtype="InlinePolicy",
                    properties={
                        "name": policy_name,
                        "document": str(policy_doc['PolicyDocument']),
                        "role_name": role_name
                    },
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region="global"
                )
                
                self.writer.write_node(policy_node)
                
                # Create ATTACHED_TO relationship
                rel = UnifiedRelationship(
                    source_id=role_node_id,
                    target_id=policy_id,
                    relationship_type=RelationshipType.ATTACHED_TO,
                    properties={"attachment_type": "inline"}
                )
                self.writer.write_relationship(rel)
        except Exception as e:
            print(f"Error ingesting policies for role {role_name}: {e}")
    
    def ingest_ec2_instances(self, region: str = "us-east-1") -> List[str]:
        """Ingest EC2 instances"""
        ec2 = self.session.client('ec2', region_name=region)
        node_ids = []
        
        response = ec2.describe_instances()
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                
                # Create instance node
                node_id = GraphSchema.generate_node_id(
                    cloud="aws",
                    service="ec2",
                    resource_type="instance",
                    resource_id=instance_id
                )
                
                instance_node = UnifiedNode(
                    node_id=node_id,
                    node_type=NodeType.RESOURCE,
                    subtype=ResourceSubtype.COMPUTE.value,
                    properties={
                        "instance_id": instance_id,
                        "instance_type": instance.get('InstanceType', 'unknown'),
                        "state": instance['State']['Name'],
                        "launch_time": instance['LaunchTime'].isoformat(),
                        "tags": {tag['Key']: tag['Value'] 
                                for tag in instance.get('Tags', []) 
                                if 'Key' in tag and 'Value' in tag}
                    },
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=region
                )
                
                self.writer.write_node(instance_node)
                node_ids.append(node_id)
        
        return node_ids

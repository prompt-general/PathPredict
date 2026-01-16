# events/processors/event_processor.py
from typing import Dict, List, Any, Optional
import logging
import json
from datetime import datetime
from graph.writer import TimeVersionedWriter
from graph.schema import (
    UnifiedNode, UnifiedRelationship,
    NodeType, IdentitySubtype, ResourceSubtype,
    RelationshipType, GraphSchema
)
from attack_paths.traversal import AttackPathTraversal
from attack_paths.scoring import RiskScoringEngine

logger = logging.getLogger(__name__)


class EventProcessor:
    """Processes security events and updates attack graph"""
    
    def __init__(self):
        self.writer = TimeVersionedWriter()
        self.path_traversal = AttackPathTraversal()
        self.scoring = RiskScoringEngine()
        self.threat_indicators = self._load_threat_indicators()
    
    def process_aws_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process an AWS event and update graph"""
        logger.info(f"Processing AWS event: {event.get('event_name')}")
        
        event_name = event.get('event_name')
        request_params = event.get('request_parameters', {})
        response_elements = event.get('response_elements', {})
        
        # Process based on event type
        if event_name == 'CreateRole':
            return self._process_iam_role_created(request_params, response_elements)
        elif event_name == 'AttachRolePolicy':
            return self._process_iam_policy_attached(request_params, response_elements)
        elif event_name == 'UpdateAssumeRolePolicy':
            return self._process_iam_trust_updated(request_params, response_elements)
        elif event_name == 'RunInstances':
            return self._process_ec2_instance_launched(request_params, response_elements)
        elif event_name == 'AuthorizeSecurityGroupIngress':
            return self._process_security_group_modified(request_params, response_elements)
        elif event_name == 'AssumeRole':
            return self._process_sts_assume_role(request_params, response_elements)
        else:
            logger.warning(f"Unhandled event type: {event_name}")
            return {"status": "unhandled", "event": event_name}
    
    def _process_iam_role_created(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process IAM role creation"""
        role_name = request_params.get('roleName')
        assume_role_policy = request_params.get('assumeRolePolicyDocument', {})
        role_arn = response_elements.get('role', {}).get('arn')
        
        # Create role node
        role_id = GraphSchema.generate_node_id(
            cloud="aws",
            service="iam",
            resource_type="role",
            resource_id=role_name
        )
        
        role_node = UnifiedNode(
            node_id=role_id,
            node_type=NodeType.IDENTITY,
            subtype=IdentitySubtype.ROLE.value,
            properties={
                "arn": role_arn,
                "name": role_name,
                "assume_role_policy": json.dumps(assume_role_policy),
                "create_time": datetime.utcnow().isoformat(),
                "risk_score": self._calculate_role_risk(assume_role_policy)
            },
            cloud_provider="aws",
            account_id=self._extract_account_id(role_arn),
            region="global"
        )
        
        self.writer.write_node(role_node)
        
        # Check for high-risk trust policies
        if self._is_high_risk_trust(assume_role_policy):
            return {
                "status": "created_high_risk",
                "role_name": role_name,
                "risk_level": "HIGH",
                "message": "New IAM role with high-risk trust policy detected"
            }
        
        return {
            "status": "created",
            "role_name": role_name,
            "risk_level": "LOW"
        }
    
    def _process_iam_policy_attached(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process IAM policy attachment"""
        role_name = request_params.get('roleName')
        policy_arn = request_params.get('policyArn')
        
        # Create policy node if it doesn't exist
        policy_id = GraphSchema.generate_node_id(
            cloud="aws",
            service="iam",
            resource_type="policy",
            resource_id=policy_arn.split('/')[-1] if '/' in policy_arn else policy_arn
        )
        
        policy_node = UnifiedNode(
            node_id=policy_id,
            node_type=NodeType.POLICY,
            subtype="ManagedPolicy",
            properties={
                "arn": policy_arn,
                "attached_to": role_name,
                "attachment_time": datetime.utcnow().isoformat()
            },
            cloud_provider="aws",
            account_id=self._extract_account_id(policy_arn),
            region="global"
        )
        
        self.writer.write_node(policy_node)
        
        # Create relationship
        role_id = GraphSchema.generate_node_id(
            cloud="aws",
            service="iam",
            resource_type="role",
            resource_id=role_name
        )
        
        rel = UnifiedRelationship(
            source_id=role_id,
            target_id=policy_id,
            relationship_type=RelationshipType.ATTACHED_TO,
            properties={
                "attachment_type": "managed",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        self.writer.write_relationship(rel)
        
        # Check if policy is high-risk
        if self._is_high_risk_policy(policy_arn):
            return {
                "status": "attached_high_risk",
                "role_name": role_name,
                "policy_arn": policy_arn,
                "risk_level": "HIGH",
                "message": "High-risk policy attached to role"
            }
        
        return {
            "status": "attached",
            "role_name": role_name,
            "policy_arn": policy_arn,
            "risk_level": "MEDIUM"
        }
    
    def _process_iam_trust_updated(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process IAM trust policy update"""
        role_name = request_params.get('roleName')
        policy_document = request_params.get('policyDocument', {})
        
        # Update role properties
        role_id = GraphSchema.generate_node_id(
            cloud="aws",
            service="iam",
            resource_type="role",
            resource_id=role_name
        )
        
        # We need to fetch existing role and update
        # For now, just log the change
        risk_change = self._calculate_trust_change_risk(policy_document)
        
        return {
            "status": "trust_updated",
            "role_name": role_name,
            "risk_change": risk_change,
            "message": f"Trust policy updated, risk change: {risk_change}"
        }
    
    def _process_ec2_instance_launched(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process EC2 instance launch"""
        instances = response_elements.get('instancesSet', {}).get('items', [])
        
        results = []
        for instance in instances:
            instance_id = instance.get('instanceId')
            
            # Check if instance is public
            public_ip = instance.get('ipAddress')
            subnet_id = instance.get('subnetId', '')
            
            is_public = bool(public_ip) or 'public' in subnet_id.lower()
            
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
                    "instance_type": instance.get('instanceType', 'unknown'),
                    "public_ip": public_ip,
                    "internet_facing": is_public,
                    "launch_time": datetime.utcnow().isoformat(),
                    "risk_score": 0.7 if is_public else 0.3
                },
                cloud_provider="aws",
                account_id="",  # Would extract from instance ARN
                region=request_params.get('region', 'us-east-1')
            )
            
            self.writer.write_node(instance_node)
            
            if is_public:
                results.append({
                    "instance_id": instance_id,
                    "risk_level": "HIGH",
                    "message": "Public EC2 instance launched"
                })
            else:
                results.append({
                    "instance_id": instance_id,
                    "risk_level": "LOW"
                })
        
        return {
            "status": "instances_launched",
            "count": len(instances),
            "results": results
        }
    
    def _process_security_group_modified(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process security group modification"""
        group_id = request_params.get('groupId')
        ip_permissions = request_params.get('ipPermissions', {}).get('items', [])
        
        # Check for public access rules
        public_access_rules = []
        for perm in ip_permissions:
            ip_ranges = perm.get('ipRanges', {}).get('items', [])
            for ip_range in ip_ranges:
                cidr = ip_range.get('cidrIp', '')
                if cidr == '0.0.0.0/0':
                    public_access_rules.append({
                        "port": perm.get('fromPort', 'any'),
                        "protocol": perm.get('ipProtocol', 'any')
                    })
        
        if public_access_rules:
            return {
                "status": "public_access_added",
                "security_group_id": group_id,
                "public_rules": public_access_rules,
                "risk_level": "HIGH",
                "message": f"Public access rules added to security group {group_id}"
            }
        
        return {
            "status": "modified",
            "security_group_id": group_id,
            "risk_level": "LOW"
        }
    
    def _process_sts_assume_role(self, request_params: Dict, response_elements: Dict) -> Dict[str, Any]:
        """Process STS AssumeRole call (actual privilege escalation)"""
        role_arn = request_params.get('roleArn')
        role_session_name = request_params.get('roleSessionName')
        
        # This is an actual attack indicator
        return {
            "status": "assume_role_called",
            "role_arn": role_arn,
            "session_name": role_session_name,
            "risk_level": "MEDIUM",
            "message": f"AssumeRole called for {role_arn}",
            "alert": True
        }
    
    def _calculate_role_risk(self, assume_role_policy: Dict) -> float:
        """Calculate risk score for IAM role based on trust policy"""
        if not assume_role_policy:
            return 0.3
        
        statements = assume_role_policy.get('Statement', [])
        risk = 0.3
        
        for stmt in statements:
            principal = stmt.get('Principal', {})
            
            # Check for wildcard principals
            if principal == '*':
                risk = 0.9
            elif isinstance(principal, dict):
                # Check for external accounts
                if 'AWS' in principal:
                    aws_principals = principal['AWS']
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    
                    for aws_principal in aws_principals:
                        if aws_principal.endswith(':root'):
                            risk = max(risk, 0.8)
                        elif 'arn:aws:iam::' in aws_principal and ':user/' in aws_principal:
                            risk = max(risk, 0.6)
            
            # Check for admin actions
            action = stmt.get('Action', '')
            if action == 'sts:AssumeRole' and 'Condition' not in stmt:
                risk = max(risk, 0.7)
        
        return risk
    
    def _is_high_risk_trust(self, assume_role_policy: Dict) -> bool:
        """Check if trust policy is high risk"""
        return self._calculate_role_risk(assume_role_policy) > 0.7
    
    def _is_high_risk_policy(self, policy_arn: str) -> bool:
        """Check if policy is high risk"""
        high_risk_policies = [
            'AdministratorAccess',
            'PowerUserAccess',
            'IAMFullAccess',
            'AmazonS3FullAccess',
            'AmazonRDSFullAccess'
        ]
        
        for risky_policy in high_risk_policies:
            if risky_policy in policy_arn:
                return True
        
        return False
    
    def _calculate_trust_change_risk(self, new_policy: Dict) -> str:
        """Calculate risk change from trust policy update"""
        old_risk = 0.5  # Would fetch from existing role
        new_risk = self._calculate_role_risk(new_policy)
        
        if new_risk > old_risk + 0.2:
            return "INCREASED"
        elif new_risk < old_risk - 0.2:
            return "DECREASED"
        else:
            return "STABLE"
    
    def _extract_account_id(self, arn: str) -> str:
        """Extract account ID from ARN"""
        if not arn:
            return "unknown"
        
        parts = arn.split(':')
        if len(parts) >= 5:
            return parts[4]
        return "unknown"
    
    def _load_threat_indicators(self) -> Dict[str, Any]:
        """Load threat indicators for event correlation"""
        return {
            "privilege_escalation_patterns": [
                "CreateRole -> AttachRolePolicy -> AssumeRole",
                "UpdateAssumeRolePolicy -> AssumeRole",
                "EC2 launch with instance profile"
            ],
            "public_exposure_patterns": [
                "AuthorizeSecurityGroupIngress with 0.0.0.0/0",
                "CreateBucket with public access",
                "PutBucketPolicy with public access"
            ],
            "data_exfiltration_patterns": [
                "S3 policy modification",
                "RDS snapshot export",
                "Lambda function with external invocation"
            ]
        }
    
    def detect_attack_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect attack patterns from sequence of events"""
        attacks = []
        
        # Simple pattern matching
        event_sequence = [e.get('event_name') for e in events]
        event_sequence_str = ' -> '.join(event_sequence)
        
        for pattern_name, patterns in self.threat_indicators.items():
            for pattern in patterns:
                pattern_events = pattern.split(' -> ')
                
                # Check if pattern matches event sequence
                if self._sequence_matches(pattern_events, event_sequence):
                    attacks.append({
                        "pattern": pattern_name,
                        "matched_pattern": pattern,
                        "event_sequence": event_sequence_str,
                        "risk_level": "HIGH",
                        "description": f"Detected {pattern_name} pattern"
                    })
        
        return attacks
    
    def _sequence_matches(self, pattern: List[str], sequence: List[str]) -> bool:
        """Check if event sequence matches attack pattern"""
        if len(sequence) < len(pattern):
            return False
        
        for i in range(len(sequence) - len(pattern) + 1):
            if sequence[i:i+len(pattern)] == pattern:
                return True
        
        return False

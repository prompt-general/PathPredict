# cicd/terraform_analyzer.py
import json
import hcl2
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass
from graph.schema import GraphSchema
from attack_paths.scoring import RiskScoringEngine

logger = logging.getLogger(__name__)


@dataclass
class TerraformResource:
    """Terraform resource definition"""
    resource_type: str
    resource_name: str
    attributes: Dict[str, Any]
    provider: str
    location: str


class TerraformPlanAnalyzer:
    """Analyzes Terraform plans for potential attack paths"""
    
    def __init__(self):
        self.scoring = RiskScoringEngine()
        self.risk_patterns = self._load_risk_patterns()
    
    def analyze_plan(self, plan_json: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Terraform plan for security risks"""
        logger.info("Analyzing Terraform plan for attack paths")
        
        # Extract resource changes
        resource_changes = self._extract_resource_changes(plan_json)
        
        # Analyze each resource
        findings = []
        high_risk_resources = []
        
        for change in resource_changes:
            analysis = self._analyze_resource_change(change)
            
            if analysis['risk_level'] in ['HIGH', 'CRITICAL']:
                high_risk_resources.append({
                    'resource': change['address'],
                    'risk_level': analysis['risk_level'],
                    'issues': analysis['issues']
                })
            
            findings.append(analysis)
        
        # Check for attack path creation
        potential_paths = self._find_potential_attack_paths(resource_changes)
        
        return {
            'summary': {
                'total_changes': len(resource_changes),
                'high_risk_changes': len([f for f in findings if f['risk_level'] in ['HIGH', 'CRITICAL']]),
                'potential_attack_paths': len(potential_paths)
            },
            'findings': findings,
            'high_risk_resources': high_risk_resources,
            'potential_attack_paths': potential_paths,
            'recommendations': self._generate_recommendations(findings)
        }
    
    def analyze_hcl(self, hcl_content: str) -> Dict[str, Any]:
        """Analyze HCL/Terraform code directly"""
        try:
            # Parse HCL
            parsed = hcl2.loads(hcl_content)
            
            # Extract resources
            resources = self._extract_resources_from_hcl(parsed)
            
            # Analyze resources
            findings = []
            for resource in resources:
                analysis = self._analyze_terraform_resource(resource)
                findings.append(analysis)
            
            return {
                'resources_analyzed': len(resources),
                'findings': findings,
                'high_risk_count': len([f for f in findings if f['risk_level'] in ['HIGH', 'CRITICAL']])
            }
            
        except Exception as e:
            logger.error(f"Error parsing HCL: {e}")
            return {
                'error': str(e),
                'resources_analyzed': 0,
                'findings': []
            }
    
    def _extract_resource_changes(self, plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract resource changes from Terraform plan"""
        changes = []
        
        # Navigate to resource changes
        resource_changes = plan_json.get('resource_changes', [])
        
        for rc in resource_changes:
            change = rc.get('change', {})
            actions = change.get('actions', [])
            
            # Only consider create/update
            if 'create' in actions or 'update' in actions:
                changes.append({
                    'address': rc.get('address', ''),
                    'type': rc.get('type', ''),
                    'name': rc.get('name', ''),
                    'provider': rc.get('provider_name', ''),
                    'actions': actions,
                    'before': change.get('before', {}),
                    'after': change.get('after', {}),
                    'is_sensitive': self._contains_sensitive_data(change)
                })
        
        return changes
    
    def _analyze_resource_change(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single resource change for risks"""
        resource_type = change['type']
        address = change['address']
        after_config = change['after']
        
        issues = []
        risk_level = 'LOW'
        
        # AWS-specific checks
        if resource_type.startswith('aws_'):
            issues.extend(self._analyze_aws_resource(resource_type, after_config))
        
        # Azure-specific checks
        elif resource_type.startswith('azurerm_'):
            issues.extend(self._analyze_azure_resource(resource_type, after_config))
        
        # GCP-specific checks
        elif resource_type.startswith('google_'):
            issues.extend(self._analyze_gcp_resource(resource_type, after_config))
        
        # General checks
        issues.extend(self._analyze_general_risks(resource_type, after_config))
        
        # Determine risk level
        if any(issue['severity'] == 'CRITICAL' for issue in issues):
            risk_level = 'CRITICAL'
        elif any(issue['severity'] == 'HIGH' for issue in issues):
            risk_level = 'HIGH'
        elif any(issue['severity'] == 'MEDIUM' for issue in issues):
            risk_level = 'MEDIUM'
        
        return {
            'resource': address,
            'resource_type': resource_type,
            'risk_level': risk_level,
            'issues': issues,
            'recommendations': self._generate_resource_recommendations(resource_type, issues)
        }
    
    def _analyze_aws_resource(self, resource_type: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze AWS resource for risks"""
        issues = []
        
        # IAM Role
        if resource_type == 'aws_iam_role':
            if config.get('assume_role_policy'):
                policy = config['assume_role_policy']
                if self._has_wildcard_principal(policy):
                    issues.append({
                        'id': 'IAM-001',
                        'title': 'Wildcard principal in trust policy',
                        'description': 'IAM role allows any principal to assume it',
                        'severity': 'CRITICAL',
                        'mitre': 'T1078.004'
                    })
            
            if config.get('name', '').lower() in ['admin', 'administrator', 'poweruser']:
                issues.append({
                    'id': 'IAM-002',
                    'title': 'High-privilege role name',
                    'description': 'Role name suggests excessive permissions',
                    'severity': 'HIGH',
                    'mitre': 'T1078.004'
                })
        
        # IAM Policy
        elif resource_type == 'aws_iam_policy':
            policy_doc = config.get('policy', '')
            if self._has_admin_permissions(policy_doc):
                issues.append({
                    'id': 'IAM-003',
                    'title': 'Administrative permissions in policy',
                    'description': 'Policy grants administrator-level permissions',
                    'severity': 'CRITICAL',
                    'mitre': 'T1078.004'
                })
        
        # EC2 Instance
        elif resource_type == 'aws_instance':
            if config.get('associate_public_ip_address') is True:
                issues.append({
                    'id': 'EC2-001',
                    'title': 'Public IP address assigned',
                    'description': 'EC2 instance is publicly accessible',
                    'severity': 'HIGH',
                    'mitre': 'T1190'
                })
            
            if not config.get('disable_api_termination', False):
                issues.append({
                    'id': 'EC2-002',
                    'title': 'Termination protection disabled',
                    'description': 'Instance can be terminated without protection',
                    'severity': 'MEDIUM',
                    'mitre': 'T1485'
                })
        
        # S3 Bucket
        elif resource_type == 'aws_s3_bucket':
            if config.get('acl') in ['public-read', 'public-read-write']:
                issues.append({
                    'id': 'S3-001',
                    'title': 'Public bucket ACL',
                    'description': 'S3 bucket is publicly accessible',
                    'severity': 'CRITICAL',
                    'mitre': 'T1530'
                })
            
            if not config.get('versioning', {}).get('enabled', False):
                issues.append({
                    'id': 'S3-002',
                    'title': 'Versioning disabled',
                    'description': 'Data loss risk if objects are deleted',
                    'severity': 'MEDIUM',
                    'mitre': 'T1485'
                })
        
        # Security Group
        elif resource_type == 'aws_security_group':
            ingress_rules = config.get('ingress', [])
            for rule in ingress_rules:
                cidr_blocks = rule.get('cidr_blocks', [])
                if '0.0.0.0/0' in cidr_blocks:
                    issues.append({
                        'id': 'SG-001',
                        'title': 'Open to the world',
                        'description': 'Security group allows traffic from any IP',
                        'severity': 'CRITICAL',
                        'mitre': 'T1190'
                    })
        
        return issues
    
    def _analyze_azure_resource(self, resource_type: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze Azure resource for risks"""
        issues = []
        
        # Azure Virtual Machine
        if resource_type == 'azurerm_virtual_machine':
            if config.get('public_ip_address_id'):
                issues.append({
                    'id': 'AZVM-001',
                    'title': 'Public IP assigned',
                    'description': 'Virtual machine is publicly accessible',
                    'severity': 'HIGH',
                    'mitre': 'T1190'
                })
        
        # Azure Storage Account
        elif resource_type == 'azurerm_storage_account':
            if config.get('allow_blob_public_access') is True:
                issues.append({
                    'id': 'AZSA-001',
                    'title': 'Public blob access enabled',
                    'description': 'Storage account allows public blob access',
                    'severity': 'CRITICAL',
                    'mitre': 'T1530'
                })
        
        return issues
    
    def _analyze_gcp_resource(self, resource_type: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze GCP resource for risks"""
        issues = []
        
        # GCP Compute Instance
        if resource_type == 'google_compute_instance':
            network_interfaces = config.get('network_interface', [])
            for ni in network_interfaces:
                if ni.get('access_config'):
                    issues.append({
                        'id': 'GCPVM-001',
                        'title': 'External IP assigned',
                        'description': 'Compute instance has external IP address',
                        'severity': 'HIGH',
                        'mitre': 'T1190'
                    })
        
        # GCP Storage Bucket
        elif resource_type == 'google_storage_bucket':
            if config.get('public_access_prevention') != 'enforced':
                issues.append({
                    'id': 'GCPSB-001',
                    'title': 'Public access not prevented',
                    'description': 'Storage bucket may allow public access',
                    'severity': 'CRITICAL',
                    'mitre': 'T1530'
                })
        
        return issues
    
    def _analyze_general_risks(self, resource_type: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze general risks across all resources"""
        issues = []
        
        # Check for hardcoded secrets
        config_str = json.dumps(config).lower()
        secret_patterns = ['password', 'secret', 'key', 'token', 'credential']
        
        for pattern in secret_patterns:
            if pattern in config_str:
                issues.append({
                    'id': 'GEN-001',
                    'title': f'Potential secret in configuration: {pattern}',
                    'description': f'Configuration may contain hardcoded {pattern}',
                    'severity': 'HIGH',
                    'mitre': 'T1552'
                })
        
        return issues
    
    def _find_potential_attack_paths(self, changes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find potential attack paths created by these changes"""
        potential_paths = []
        
        # Group changes by resource type
        iam_changes = [c for c in changes if 'iam' in c['type']]
        compute_changes = [c for c in changes if any(x in c['type'] for x in ['instance', 'vm'])]
        storage_changes = [c for c in changes if any(x in c['type'] for x in ['s3', 'storage', 'bucket'])]
        
        # Look for privilege escalation patterns
        for iam_change in iam_changes:
            for compute_change in compute_changes:
                # Check if IAM role can access compute resource
                potential_paths.append({
                    'type': 'privilege_escalation',
                    'source': iam_change['address'],
                    'target': compute_change['address'],
                    'confidence': 0.6,
                    'description': f'IAM role {iam_change["name"]} may access compute resource {compute_change["name"]}'
                })
        
        # Look for data exfiltration patterns
        for compute_change in compute_changes:
            for storage_change in storage_changes:
                potential_paths.append({
                    'type': 'data_exfiltration',
                    'source': compute_change['address'],
                    'target': storage_change['address'],
                    'confidence': 0.5,
                    'description': f'Compute resource {compute_change["name"]} may access storage {storage_change["name"]}'
                })
        
        return potential_paths
    
    def _has_wildcard_principal(self, policy: str) -> bool:
        """Check if policy has wildcard principal"""
        if not policy:
            return False
        
        if isinstance(policy, dict):
            policy = json.dumps(policy)
        
        return '"Principal":"*"' in policy or "'Principal':'*'" in policy
    
    def _has_admin_permissions(self, policy_doc: str) -> bool:
        """Check if policy has admin permissions"""
        if not policy_doc:
            return False
        
        if isinstance(policy_doc, dict):
            policy_doc = json.dumps(policy_doc)
        
        admin_patterns = [
            '"Effect":"Allow"',
            '"Action":"*"',
            '"Resource":"*"'
        ]
        
        # Check for admin policy
        if all(pattern in policy_doc for pattern in admin_patterns):
            return True
        
        # Check for specific admin actions
        admin_actions = [
            'iam:*',
            '*:*',
            'admin',
            'Administrator'
        ]
        
        for action in admin_actions:
            if action in policy_doc:
                return True
        
        return False
    
    def _contains_sensitive_data(self, change: Dict[str, Any]) -> bool:
        """Check if change contains sensitive data"""
        sensitive_keywords = ['password', 'secret', 'key', 'token', 'credential']
        
        change_str = json.dumps(change).lower()
        return any(keyword in change_str for keyword in sensitive_keywords)
    
    def _extract_resources_from_hcl(self, parsed_hcl: Dict[str, Any]) -> List[TerraformResource]:
        """Extract resources from parsed HCL"""
        resources = []
        
        # Navigate resource blocks
        resource_blocks = parsed_hcl.get('resource', [])
        
        for block in resource_blocks:
            for resource_type, resource_defs in block.items():
                if isinstance(resource_defs, dict):
                    resource_defs = [resource_defs]
                
                for rd in resource_defs:
                    for resource_name, config in rd.items():
                        resources.append(TerraformResource(
                            resource_type=resource_type,
                            resource_name=resource_name,
                            attributes=config or {},
                            provider=self._determine_provider(resource_type),
                            location='terraform'
                        ))
        
        return resources
    
    def _determine_provider(self, resource_type: str) -> str:
        """Determine cloud provider from resource type"""
        if resource_type.startswith('aws_'):
            return 'aws'
        elif resource_type.startswith('azurerm_'):
            return 'azure'
        elif resource_type.startswith('google_'):
            return 'gcp'
        else:
            return 'unknown'
    
    def _analyze_terraform_resource(self, resource: TerraformResource) -> Dict[str, Any]:
        """Analyze a Terraform resource from HCL"""
        # Similar to _analyze_resource_change but for HCL resources
        issues = []
        
        if resource.provider == 'aws':
            issues.extend(self._analyze_aws_resource(resource.resource_type, resource.attributes))
        elif resource.provider == 'azure':
            issues.extend(self._analyze_azure_resource(resource.resource_type, resource.attributes))
        elif resource.provider == 'gcp':
            issues.extend(self._analyze_gcp_resource(resource.resource_type, resource.attributes))
        
        # Determine risk level
        if any(issue['severity'] == 'CRITICAL' for issue in issues):
            risk_level = 'CRITICAL'
        elif any(issue['severity'] == 'HIGH' for issue in issues):
            risk_level = 'HIGH'
        elif any(issue['severity'] == 'MEDIUM' for issue in issues):
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'resource': f'{resource.resource_type}.{resource.resource_name}',
            'provider': resource.provider,
            'risk_level': risk_level,
            'issues': issues,
            'location': resource.location
        }
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations"""
        recommendations = []
        
        for finding in findings:
            if finding['risk_level'] in ['HIGH', 'CRITICAL']:
                for issue in finding['issues']:
                    if issue['severity'] in ['HIGH', 'CRITICAL']:
                        recommendations.append({
                            'resource': finding['resource'],
                            'issue': issue['title'],
                            'severity': issue['severity'],
                            'recommendation': self._get_remediation_for_issue(issue['id']),
                            'priority': 'HIGH' if issue['severity'] == 'CRITICAL' else 'MEDIUM'
                        })
        
        # Sort by priority
        recommendations.sort(key=lambda x: 0 if x['priority'] == 'HIGH' else 1)
        
        return recommendations
    
    def _generate_resource_recommendations(self, resource_type: str, issues: List[Dict[str, Any]]) -> List[str]:
        """Generate specific recommendations for a resource"""
        recommendations = []
        
        for issue in issues:
            if issue['severity'] in ['HIGH', 'CRITICAL']:
                rec = self._get_remediation_for_issue(issue['id'])
                if rec:
                    recommendations.append(rec)
        
        return list(set(recommendations))  # Remove duplicates
    
    def _get_remediation_for_issue(self, issue_id: str) -> str:
        """Get remediation guidance for a specific issue"""
        remediation_map = {
            'IAM-001': 'Restrict assume role policy to specific principals or roles',
            'IAM-002': 'Use least privilege roles and avoid admin naming patterns',
            'IAM-003': 'Review and restrict policy permissions to minimum required',
            'EC2-001': 'Use private IPs and access via VPN or bastion host',
            'EC2-002': 'Enable termination protection for critical instances',
            'S3-001': 'Set bucket ACL to private and use bucket policies for granular access',
            'S3-002': 'Enable versioning to protect against accidental deletion',
            'SG-001': 'Restrict security group rules to specific IP ranges',
            'AZVM-001': 'Use private IPs and Azure Private Link for connectivity',
            'AZSA-001': 'Disallow public blob access and use SAS tokens',
            'GCPVM-001': 'Use private IPs and Cloud NAT for outbound connectivity',
            'GCPSB-001': 'Enforce public access prevention on storage buckets',
            'GEN-001': 'Use secret management system (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)'
        }
        
        return remediation_map.get(issue_id, 'Review and apply security best practices')
    
    def _load_risk_patterns(self) -> Dict[str, Any]:
        """Load risk patterns for analysis"""
        return {
            'privilege_escalation': [
                'iam_role + assume_role_policy',
                'instance_profile + iam_role',
                'service_account + permissions'
            ],
            'public_exposure': [
                'public_ip = true',
                'cidr_blocks = ["0.0.0.0/0"]',
                'acl = "public-read"'
            ],
            'data_exfiltration': [
                'storage + public_access',
                'database + public_access',
                'cross_account_access'
            ]
        }

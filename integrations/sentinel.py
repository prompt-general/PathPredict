# integrations/sentinel.py
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)

class AzureSentinelIntegration:
    """Integration with Microsoft Sentinel"""
    
    def __init__(self,
                 data_collection_endpoint: str,
                 data_collection_rule_id: str,
                 stream_name: str = "PathPredictAttackPaths",
                 credential: Optional[DefaultAzureCredential] = None):
        
        self.data_collection_endpoint = data_collection_endpoint
        self.data_collection_rule_id = data_collection_rule_id
        self.stream_name = stream_name
        
        self.credential = credential or DefaultAzureCredential()
        self.client = LogsIngestionClient(
            endpoint=data_collection_endpoint,
            credential=self.credential,
            logging_enable=True
        )
        
        logger.info("Azure Sentinel integration initialized")
    
    def send_attack_path(self, attack_path: Dict[str, Any]) -> bool:
        """Send attack path to Azure Sentinel"""
        
        formatted_log = self._format_for_sentinel(attack_path)
        
        try:
            # Upload logs to Sentinel
            self.client.upload(
                rule_id=self.data_collection_rule_id,
                stream_name=self.stream_name,
                logs=[formatted_log]
            )
            
            logger.info(f"Sent attack path to Sentinel: {attack_path.get('path_id')}")
            return True
            
        except HttpResponseError as e:
            logger.error(f"Sentinel upload failed: {e}")
            return False
    
    def send_batch(self, attack_paths: List[Dict[str, Any]]) -> bool:
        """Send batch of attack paths to Sentinel"""
        
        if not attack_paths:
            return True
        
        formatted_logs = [self._format_for_sentinel(path) for path in attack_paths]
        
        try:
            self.client.upload(
                rule_id=self.data_collection_rule_id,
                stream_name=self.stream_name,
                logs=formatted_logs
            )
            
            logger.info(f"Sent {len(attack_paths)} attack paths to Sentinel")
            return True
            
        except HttpResponseError as e:
            logger.error(f"Sentinel batch upload failed: {e}")
            return False
    
    def _format_for_sentinel(self, attack_path: Dict[str, Any]) -> Dict[str, Any]:
        """Format attack path for Sentinel ingestion"""
        
        risk_assessment = attack_path.get('risk_assessment', {})
        
        return {
            "TimeGenerated": datetime.utcnow().isoformat() + "Z",
            
            # Core fields
            "PathID": attack_path.get('path_id'),
            "PathType": attack_path.get('type'),
            "Source": attack_path.get('source'),
            "Target": attack_path.get('target'),
            "HopCount": attack_path.get('hop_count'),
            
            # Risk assessment
            "RiskScore": risk_assessment.get('raw_score'),
            "RiskLevel": risk_assessment.get('risk_level'),
            "Confidence": risk_assessment.get('confidence'),
            "RemediationPriority": risk_assessment.get('remediation_priority'),
            
            # Security context
            "MITRETechniques": risk_assessment.get('mitre_techniques', []),
            "CloudProviders": attack_path.get('providers', []),
            "CrossCloud": len(attack_path.get('providers', [])) > 1,
            
            # Resource context
            "Criticality": attack_path.get('criticality', 0),
            "PublicExposure": attack_path.get('public_access', False),
            "InternetFacing": attack_path.get('internet_facing', False),
            
            # Detection info
            "DetectionTime": attack_path.get('timestamp', datetime.utcnow().isoformat()),
            "DetectedBy": "PathPredict",
            "AlertSeverity": self._map_to_sentinel_severity(risk_assessment.get('risk_level')),
            
            # Extended properties
            "ExtendedProperties": {
                "NodeCount": len(attack_path.get('nodes', [])),
                "RelationshipTypes": attack_path.get('relationships', []),
                "BusinessImpact": attack_path.get('business_impact', 'unknown'),
                "Environment": attack_path.get('environment', 'unknown')
            }
        }
    
    def _map_to_sentinel_severity(self, risk_level: str) -> str:
        """Map Path Predict risk levels to Sentinel severity"""
        mapping = {
            'CRITICAL': 'High',
            'HIGH': 'Medium',
            'MEDIUM': 'Low',
            'LOW': 'Informational'
        }
        return mapping.get(risk_level, 'Informational')
    
    def create_sentinel_analytics_rules(self) -> List[Dict[str, Any]]:
        """Create Sentinel analytics rules for attack paths"""
        
        rules = [
            {
                "name": "PathPredict_Critical_Attack_Path_Detected",
                "query": """
                PathPredictAttackPaths_CL
                | where RiskLevel == "CRITICAL"
                | project TimeGenerated, PathID, Source, Target, RiskScore, MITRETechniques
                """,
                "severity": "High",
                "tactics": ["PrivilegeEscalation", "LateralMovement", "Exfiltration"],
                "description": "Critical attack path detected by Path Predict"
            },
            {
                "name": "PathPredict_Cross_Cloud_Privilege_Escalation",
                "query": """
                PathPredictAttackPaths_CL
                | where PathType == "privilege_escalation" and CrossCloud == true
                | project TimeGenerated, PathID, CloudProviders, RiskScore, Source, Target
                """,
                "severity": "Medium",
                "tactics": ["PrivilegeEscalation"],
                "description": "Cross-cloud privilege escalation detected"
            },
            {
                "name": "PathPredict_Public_Resource_Exposure",
                "query": """
                PathPredictAttackPaths_CL
                | where PublicExposure == true and RiskScore >= 70
                | project TimeGenerated, PathID, Target, RiskScore, CloudProviders
                """,
                "severity": "Medium",
                "tactics": ["InitialAccess"],
                "description": "High-risk public resource exposure detected"
            }
        ]
        
        return rules

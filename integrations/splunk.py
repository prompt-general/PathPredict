# integrations/splunk.py
import json
import time
import requests
import hmac
import hashlib
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SplunkIntegration:
    """Integration with Splunk for attack path alerting"""
    
    def __init__(self, 
                 host: str, 
                 port: int = 8088,
                 token: str = None,
                 index: str = "main",
                 source_type: str = "path_predict:attack_path",
                 use_ssl: bool = True):
        
        self.host = host
        self.port = port
        self.token = token
        self.index = index
        self.source_type = source_type
        
        protocol = "https" if use_ssl else "http"
        self.url = f"{protocol}://{host}:{port}/services/collector"
        
        self.headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json"
        }
        
        # Verify connection
        if not self._test_connection():
            raise ConnectionError(f"Cannot connect to Splunk at {self.url}")
    
    def _test_connection(self) -> bool:
        """Test Splunk connection"""
        try:
            test_payload = {
                "event": {"test": "connection"},
                "index": self.index,
                "sourcetype": self.source_type
            }
            
            response = requests.post(
                self.url, 
                headers=self.headers, 
                json=test_payload,
                verify=False,  # Disable SSL verification for testing
                timeout=5
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk connection test failed: {e}")
            return False
    
    def send_attack_path(self, attack_path: Dict[str, Any]) -> bool:
        """Send an attack path alert to Splunk"""
        
        # Format event for Splunk
        splunk_event = {
            "event": self._format_for_splunk(attack_path),
            "index": self.index,
            "sourcetype": self.source_type,
            "source": "path_predict",
            "host": "path-predict-server",
            "time": datetime.utcnow().timestamp()
        }
        
        try:
            response = requests.post(
                self.url, 
                headers=self.headers, 
                json=splunk_event,
                verify=False,  # In production, use proper SSL certs
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Sent attack path to Splunk: {attack_path.get('path_id')}")
                return True
            else:
                logger.error(f"Splunk API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send to Splunk: {e}")
            return False
    
    def send_batch(self, attack_paths: List[Dict[str, Any]]) -> bool:
        """Send multiple attack paths in batch"""
        
        if not attack_paths:
            return True
        
        batch_payload = []
        
        for attack_path in attack_paths:
            batch_payload.append({
                "event": self._format_for_splunk(attack_path),
                "index": self.index,
                "sourcetype": self.source_type,
                "source": "path_predict",
                "host": "path-predict-server"
            })
        
        try:
            response = requests.post(
                self.url, 
                headers=self.headers, 
                json=batch_payload,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info(f"Sent {len(attack_paths)} attack paths to Splunk")
                return True
            else:
                logger.error(f"Splunk batch API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send batch to Splunk: {e}")
            return False
    
    def _format_for_splunk(self, attack_path: Dict[str, Any]) -> Dict[str, Any]:
        """Format attack path for Splunk consumption"""
        
        risk_assessment = attack_path.get('risk_assessment', {})
        
        return {
            "path_id": attack_path.get('path_id'),
            "type": attack_path.get('type'),
            "source": attack_path.get('source'),
            "target": attack_path.get('target'),
            "hop_count": attack_path.get('hop_count'),
            
            "risk_score": risk_assessment.get('raw_score'),
            "risk_level": risk_assessment.get('risk_level'),
            "confidence": risk_assessment.get('confidence'),
            
            "mitre_techniques": risk_assessment.get('mitre_techniques', []),
            "providers": attack_path.get('providers', []),
            
            "criticality": attack_path.get('criticality', 0),
            "public_exposure": attack_path.get('public_access', False),
            "cross_cloud": len(attack_path.get('providers', [])) > 1,
            
            "detection_time": attack_path.get('timestamp', datetime.utcnow().isoformat()),
            "severity": "CRITICAL" if risk_assessment.get('risk_level') == "CRITICAL" else 
                       "HIGH" if risk_assessment.get('risk_level') == "HIGH" else 
                       "MEDIUM" if risk_assessment.get('risk_level') == "MEDIUM" else "LOW",
            
            "recommendations": self._generate_splunk_recommendations(attack_path),
            
            # Raw data for Splunk searches
            "_raw": json.dumps(attack_path)
        }
    
    def _generate_splunk_recommendations(self, attack_path: Dict[str, Any]) -> List[str]:
        """Generate recommendations for Splunk alerts"""
        recommendations = []
        
        risk_level = attack_path.get('risk_assessment', {}).get('risk_level', 'LOW')
        
        if risk_level in ['HIGH', 'CRITICAL']:
            recommendations.append("Immediate investigation required")
            
            if attack_path.get('public_access'):
                recommendations.append("Remove public access from affected resources")
            
            if attack_path.get('type') == 'privilege_escalation':
                recommendations.append("Review and restrict IAM permissions")
            
            if len(attack_path.get('providers', [])) > 1:
                recommendations.append("Review cross-cloud trust relationships")
        
        return recommendations
    
    def create_splunk_dashboard(self, dashboard_name: str = "path_predict"):
        """Create Splunk dashboard for Path Predict"""
        
        # This would create a Splunk dashboard via REST API
        # For now, return the SPL queries
        
        queries = {
            "high_risk_paths": f"""
            index={self.index} sourcetype={self.source_type} severity="CRITICAL" OR severity="HIGH"
            | stats count by risk_level, type
            | sort -count
            """,
            
            "trend_over_time": f"""
            index={self.index} sourcetype={self.source_type}
            | timechart span=1d count by severity
            """,
            
            "top_attack_patterns": f"""
            index={self.index} sourcetype={self.source_type}
            | stats count by type, mitre_techniques
            | sort -count
            | head 10
            """,
            
            "cloud_provider_distribution": f"""
            index={self.index} sourcetype={self.source_type}
            | mvexpand providers
            | stats count by providers
            | sort -count
            """
        }
        
        return queries

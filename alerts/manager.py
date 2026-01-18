# alerts/manager.py
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime
from integrations.splunk import SplunkIntegration
from integrations.slack import SlackIntegration

logger = logging.getLogger(__name__)

class AlertManager:
    """Manage and route alerts to different integrations"""
    
    def __init__(self):
        self.integrations = []
        self.alert_history = []
    
    def add_splunk_integration(self, host: str, port: int, token: str, index: str):
        """Add Splunk integration"""
        splunk = SplunkIntegration(host, port, token, index)
        self.integrations.append(('splunk', splunk))
        logger.info("Splunk integration added")
    
    def add_slack_integration(self, webhook_url: str, channel: str = "#security-alerts"):
        """Add Slack integration"""
        slack = SlackIntegration(webhook_url, channel)
        self.integrations.append(('slack', slack))
        logger.info("Slack integration added")
    
    def send_attack_path_alerts(self, attack_paths: List[Dict[str, Any]], 
                               min_severity: str = "MEDIUM"):
        """Send attack path alerts through all integrations"""
        severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        filtered_paths = [
            path for path in attack_paths
            if severity_order.index(path.get('risk_assessment', {}).get('risk_level', 'LOW')) >= 
               severity_order.index(min_severity)
        ]
        
        if not filtered_paths:
            logger.info("No attack paths meet the minimum severity threshold")
            return
        
        logger.info(f"Sending {len(filtered_paths)} attack path alerts")
        
        for path in filtered_paths:
            for name, integration in self.integrations:
                try:
                    if name == 'splunk':
                        integration.send_attack_path(path)
                    elif name == 'slack':
                        integration.send_attack_path_alert(path)
                except Exception as e:
                    logger.error(f"Error sending alert via {name}: {e}")
            
            # Record in history
            self.alert_history.append({
                'timestamp': datetime.utcnow().isoformat(),
                'path_id': path.get('path_id'),
                'severity': path.get('risk_assessment', {}).get('risk_level'),
                'sent_to': [name for name, _ in self.integrations]
            })
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alert history"""
        return self.alert_history[-limit:]

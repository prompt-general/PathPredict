# alerts/channels/teams.py
import json
import requests
import logging
from typing import Dict, Any
from datetime import datetime
from ..manager import Alert, AlertSeverity

logger = logging.getLogger(__name__)

class TeamsChannel:
    """Microsoft Teams alert channel"""
    
    def __init__(self, 
                 webhook_url: str,
                 min_severity: AlertSeverity = AlertSeverity.MEDIUM):
        
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        
        if not self._test_connection():
            raise ConnectionError("Cannot connect to Teams webhook")
    
    async def send(self, alert: Alert) -> bool:
        """Send alert to Microsoft Teams"""
        
        # Create Teams message card
        card = self._create_teams_card(alert)
        
        try:
            response = requests.post(
                self.webhook_url,
                json=card,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Teams alert sent: {alert.alert_id}")
                return True
            else:
                logger.error(f"Teams API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Teams alert: {e}")
            return False
    
    def _create_teams_card(self, alert: Alert) -> Dict[str, Any]:
        """Create Microsoft Teams Adaptive Card from alert"""
        
        # Theme color based on severity
        color_map = {
            AlertSeverity.CRITICAL: "FF0000",  # Red
            AlertSeverity.HIGH: "FFA500",      # Orange
            AlertSeverity.MEDIUM: "FFFF00",    # Yellow
            AlertSeverity.LOW: "00FF00",       # Green
            AlertSeverity.INFO: "808080"       # Gray
        }
        
        theme_color = color_map.get(alert.severity, "808080")
        
        # Create card
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": alert.title,
            "sections": [
                {
                    "activityTitle": alert.title,
                    "activitySubtitle": f"Severity: {alert.severity.value}",
                    "activityImage": "https://path-predict.internal/icon.png",
                    "facts": [
                        {
                            "name": "Description",
                            "value": alert.description
                        },
                        {
                            "name": "Source",
                            "value": f"`{alert.source}`"
                        },
                        {
                            "name": "Target",
                            "value": f"`{alert.target}`"
                        }
                    ],
                    "markdown": True
                }
            ]
        }
        
        # Add risk score if available
        if alert.risk_score:
            card["sections"][0]["facts"].append({
                "name": "Risk Score",
                "value": f"{alert.risk_score:.1f}/100"
            })
        
        # Add MITRE techniques if available
        if alert.mitre_techniques:
            card["sections"][0]["facts"].append({
                "name": "MITRE Techniques",
                "value": ", ".join(alert.mitre_techniques[:3])
            })
        
        # Add timestamp
        card["sections"][0]["facts"].append({
            "name": "Detection Time",
            "value": alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')
        })
        
        # Add potential action section
        if alert.path_id:
            card["potentialAction"] = [
                {
                    "@type": "OpenUri",
                    "name": "View Details",
                    "targets": [
                        {
                            "os": "default",
                            "uri": f"https://path-predict.internal/paths/{alert.path_id}"
                        }
                    ]
                }
            ]
        
        return card
    
    def _test_connection(self) -> bool:
        """Test Teams webhook connection"""
        try:
            test_card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "Connection Test",
                "sections": [{
                    "activityTitle": "Path Predict Teams Integration",
                    "activitySubtitle": "Connection test successful",
                    "markdown": True
                }]
            }
            
            response = requests.post(
                self.webhook_url,
                json=test_card,
                timeout=5
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Teams connection test failed: {e}")
            return False

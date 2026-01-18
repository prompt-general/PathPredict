# alerts/channels/slack.py
import json
import requests
import logging
from typing import Dict, Any
from datetime import datetime
from ..manager import Alert, AlertSeverity

logger = logging.getLogger(__name__)

class SlackChannel:
    """Slack alert channel"""
    
    def __init__(self, 
                 webhook_url: str,
                 channel: str = "#security-alerts",
                 username: str = "Path Predict",
                 icon_emoji: str = "🔍",
                 min_severity: AlertSeverity = AlertSeverity.MEDIUM):
        
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.min_severity = min_severity
        
        # Test connection
        if not self._test_connection():
            raise ConnectionError("Cannot connect to Slack webhook")
    
    async def send(self, alert: Alert) -> bool:
        """Send alert to Slack"""
        
        # Create Slack message
        message = self._create_slack_message(alert)
        
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.debug(f"Slack alert sent: {alert.alert_id}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def _create_slack_message(self, alert: Alert) -> Dict[str, Any]:
        """Create Slack message from alert"""
        
        # Color based on severity
        color_map = {
            AlertSeverity.CRITICAL: "#FF0000",  # Red
            AlertSeverity.HIGH: "#FFA500",      # Orange
            AlertSeverity.MEDIUM: "#FFFF00",    # Yellow
            AlertSeverity.LOW: "#00FF00",       # Green
            AlertSeverity.INFO: "#808080"       # Gray
        }
        
        color = color_map.get(alert.severity, "#808080")
        
        # Create blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {alert.title}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.description
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert.severity.value}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{alert.risk_score:.1f}" if alert.risk_score else "*Risk Score:*\nN/A"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n`{alert.source[:50]}{'...' if len(alert.source) > 50 else ''}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n`{alert.target[:50]}{'...' if len(alert.target) > 50 else ''}`"
                    }
                ]
            }
        ]
        
        # Add MITRE techniques if available
        if alert.mitre_techniques:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*MITRE Techniques:*\n{', '.join(alert.mitre_techniques[:3])}"
                }
            })
        
        # Add remediation priority
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Remediation Priority:* {alert.remediation_priority}/5 (1 = highest)"
            }
        })
        
        # Add timestamp and actions
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Detected: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })
        
        # Add action buttons if path_id is available
        if alert.path_id:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "View Details"
                        },
                        "url": f"https://path-predict.internal/paths/{alert.path_id}",
                        "style": "primary"
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Acknowledge"
                        },
                        "action_id": "acknowledge_alert",
                        "value": alert.alert_id
                    }
                ]
            })
        
        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "blocks": blocks,
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }
    
    def _test_connection(self) -> bool:
        """Test Slack webhook connection"""
        try:
            test_message = {
                "text": "Path Predict Slack integration test",
                "channel": self.channel
            }
            
            response = requests.post(
                self.webhook_url,
                json=test_message,
                timeout=5
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack connection test failed: {e}")
            return False

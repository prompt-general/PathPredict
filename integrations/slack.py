# integrations/slack.py
import json
import requests
from typing import Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SlackIntegration:
    """Send attack path alerts to Slack"""
    
    def __init__(self, webhook_url: str, channel: str = "#security-alerts"):
        self.webhook_url = webhook_url
        self.channel = channel
    
    def send_attack_path_alert(self, attack_path: Dict[str, Any]):
        """Send an attack path alert to Slack"""
        risk_level = attack_path.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        score = attack_path.get('risk_assessment', {}).get('raw_score', 0)
        
        # Color code based on risk
        color = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FFA500',
            'MEDIUM': '#FFFF00',
            'LOW': '#00FF00'
        }.get(risk_level, '#808080')
        
        # Create Slack message
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Attack Path Detected: {risk_level} Risk"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Path ID:*\n{attack_path.get('path_id', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Score:*\n{score:.1f}/100"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Type:*\n{attack_path.get('type', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Hops:*\n{attack_path.get('hop_count', 'N/A')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Source:* `{attack_path.get('source', 'N/A')}`\n*Target:* `{attack_path.get('target', 'N/A')}`"
                }
            }
        ]
        
        # Add MITRE techniques if available
        mitre_techs = attack_path.get('risk_assessment', {}).get('mitre_techniques', [])
        if mitre_techs:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*MITRE Techniques:*\n{', '.join(mitre_techs[:3])}"
                }
            })
        
        # Add remediation priority
        priority = attack_path.get('risk_assessment', {}).get('remediation_priority', 5)
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Remediation Priority:* {priority}/5 (1 = highest)"
            }
        })
        
        # Add timestamp
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Detected at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            ]
        })
        
        payload = {
            "channel": self.channel,
            "username": "Path Predict",
            "icon_emoji": "🔍",
            "blocks": blocks
        }
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info(f"Sent Slack alert for path: {attack_path.get('path_id')}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

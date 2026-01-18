# config.py
import yaml
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class SplunkConfig:
    host: str
    port: int
    token: str
    index: str

@dataclass
class SlackConfig:
    webhook_url: str
    channel: str

@dataclass
class GCPConfig:
    credentials_path: Optional[str]
    projects: List[str]

class ConfigManager:
    """Manage Path Predict configuration"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not os.path.exists(self.config_path):
            return self.default_config()
        
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'integrations': {
                'splunk': {
                    'enabled': False,
                    'host': 'localhost',
                    'port': 8088,
                    'token': '',
                    'index': 'main'
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': '',
                    'channel': '#security-alerts'
                }
            },
            'gcp': {
                'credentials_path': None,
                'projects': []
            },
            'alerting': {
                'min_severity': 'HIGH'
            }
        }
    
    def get_splunk_config(self) -> Optional[SplunkConfig]:
        """Get Splunk configuration"""
        splunk_cfg = self.config.get('integrations', {}).get('splunk', {})
        if splunk_cfg.get('enabled'):
            return SplunkConfig(
                host=splunk_cfg.get('host'),
                port=splunk_cfg.get('port'),
                token=splunk_cfg.get('token'),
                index=splunk_cfg.get('index')
            )
        return None
    
    def get_slack_config(self) -> Optional[SlackConfig]:
        """Get Slack configuration"""
        slack_cfg = self.config.get('integrations', {}).get('slack', {})
        if slack_cfg.get('enabled'):
            return SlackConfig(
                webhook_url=slack_cfg.get('webhook_url'),
                channel=slack_cfg.get('channel', '#security-alerts')
            )
        return None
    
    def get_gcp_config(self) -> GCPConfig:
        """Get GCP configuration"""
        gcp_cfg = self.config.get('gcp', {})
        return GCPConfig(
            credentials_path=gcp_cfg.get('credentials_path'),
            projects=gcp_cfg.get('projects', [])
        )
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)

# Update api/main.py or create new module for initialization
from config import ConfigManager
from alerts.manager import AlertManager

def setup_integrations():
    """Setup integrations from configuration"""
    config = ConfigManager()
    alert_manager = AlertManager()
    
    # Setup Splunk
    splunk_cfg = config.get_splunk_config()
    if splunk_cfg:
        alert_manager.add_splunk_integration(
            host=splunk_cfg.host,
            port=splunk_cfg.port,
            token=splunk_cfg.token,
            index=splunk_cfg.index
        )
    
    # Setup Slack
    slack_cfg = config.get_slack_config()
    if slack_cfg:
        alert_manager.add_slack_integration(
            webhook_url=slack_cfg.webhook_url,
            channel=slack_cfg.channel
        )
    
    return alert_manager

# Use in attack path detection
alert_manager = setup_integrations()

# In your attack path detection endpoint:
paths = traversal.detect_and_alert(alert_manager, min_severity="HIGH")

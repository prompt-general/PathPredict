# integrations/splunk.py
import json
import time
import requests
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class SplunkIntegration:
    """Send attack path alerts to Splunk"""
    
    def __init__(self, host: str, port: int, token: str, index: str):
        self.host = host
        self.port = port
        self.token = token
        self.index = index
        self.url = f"https://{host}:{port}/services/collector"
        
        self.headers = {
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json"
        }
    
    def send_attack_path(self, attack_path: Dict[str, Any]):
        """Send an attack path alert to Splunk"""
        event = {
            "event": attack_path,
            "index": self.index,
            "sourcetype": "path_predict:attack_path",
            "source": "path_predict"
        }
        
        response = requests.post(self.url, headers=self.headers, 
                                data=json.dumps(event), verify=False)
        
        if response.status_code == 200:
            logger.info(f"Sent attack path to Splunk: {attack_path.get('path_id')}")
            return True
        else:
            logger.error(f"Failed to send to Splunk: {response.status_code} - {response.text}")
            return False
    
    def send_batch(self, attack_paths: List[Dict[str, Any]]):
        """Send multiple attack paths in batch"""
        for path in attack_paths:
            self.send_attack_path(path)
            time.sleep(0.1)  # Avoid rate limiting

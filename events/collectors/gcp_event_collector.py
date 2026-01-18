# events/collectors/gcp_event_collector.py
from google.cloud import logging_v2
from google.cloud.logging_v2.services.logging_service_v2 import LoggingServiceV2Client
from google.cloud.logging_v2.types import LogEntry
from typing import List, Dict, Any, Optional, Generator
import json
import logging
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)

class GCPAuditLogType(Enum):
    """GCP Audit Log types for attack path detection"""
    IAM_POLICY_CHANGE = "google.iam.admin.v1.SetIamPolicy"
    SERVICE_ACCOUNT_CREATE = "google.iam.admin.v1.CreateServiceAccount"
    SERVICE_ACCOUNT_KEY_CREATE = "google.iam.admin.v1.CreateServiceAccountKey"
    COMPUTE_INSTANCE_CREATE = "google.cloud.compute.v1.Instances.Insert"
    COMPUTE_INSTANCE_DELETE = "google.cloud.compute.v1.Instances.Delete"
    STORAGE_BUCKET_CREATE = "google.cloud.storage.v1.Buckets.Insert"
    STORAGE_BUCKET_IAM_CHANGE = "google.cloud.storage.v1.Buckets.SetIamPolicy"
    SQL_INSTANCE_CREATE = "google.cloud.sql.v1.Instances.Insert"
    VPC_FIREWALL_CREATE = "google.cloud.compute.v1.Firewalls.Insert"

class GCPEventCollector:
    """Collect real-time events from GCP Audit Logs"""
    
    def __init__(self, project_id: str, credentials_path: Optional[str] = None):
        self.project_id = project_id
        
        if credentials_path:
            from google.oauth2 import service_account
            self.credentials = service_account.Credentials.from_service_account_file(
                credentials_path
            )
        else:
            self.credentials = None
        
        self.logging_client = LoggingServiceV2Client(credentials=self.credentials)
        self.processed_entry_ids = set()
    
    def stream_audit_logs(self, lookback_minutes: int = 60) -> Generator[Dict[str, Any], None, None]:
        """Stream audit logs from Cloud Logging"""
        logger.info(f"Starting GCP audit log stream for project {self.project_id}")
        
        # Create filter for security-relevant logs
        filter_str = f"""
        resource.type=("cloud_run_revision" OR "gce_instance" OR "gcs_bucket" OR "bigquery_dataset" OR "cloud_sql_database")
        AND (protoPayload.methodName:("SetIamPolicy" OR "CreateServiceAccount" OR "CreateServiceAccountKey" OR "Insert" OR "Delete"))
        AND timestamp > "{datetime.utcnow() - timedelta(minutes=lookback_minutes):%Y-%m-%dT%H:%M:%SZ}"
        """
        
        while True:
            try:
                # List log entries
                entries = self.logging_client.list_log_entries(
                    resource_names=[f"projects/{self.project_id}"],
                    filter_=filter_str,
                    order_by="timestamp desc",
                    page_size=100
                )
                
                for entry in entries:
                    if self._should_process(entry):
                        normalized = self._normalize_log_entry(entry)
                        yield normalized
                
                # Wait before next poll
                import time
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Error streaming GCP logs: {e}")
                import time
                time.sleep(60)
    
    def _should_process(self, entry: LogEntry) -> bool:
        """Determine if log entry should be processed"""
        entry_id = entry.insert_id
        
        if not entry_id:
            return False
        
        if entry_id in self.processed_entry_ids:
            return False
        
        # Only process specific methods
        method_name = entry.proto_payload.method_name if entry.proto_payload else None
        if not method_name:
            return False
        
        valid_methods = [
            "SetIamPolicy",
            "CreateServiceAccount",
            "CreateServiceAccountKey",
            "Instances.Insert",
            "Buckets.Insert",
            "Buckets.SetIamPolicy",
            "Firewalls.Insert",
            "Firewalls.Update"
        ]
        
        if not any(method in method_name for method in valid_methods):
            return False
        
        self.processed_entry_ids.add(entry_id)
        return True
    
    def _normalize_log_entry(self, entry: LogEntry) -> Dict[str, Any]:
        """Normalize GCP log entry to standard format"""
        proto_payload = entry.proto_payload
        
        return {
            "event_id": entry.insert_id,
            "event_type": proto_payload.method_name if proto_payload else "unknown",
            "event_time": entry.timestamp.isoformat() if entry.timestamp else datetime.utcnow().isoformat(),
            "resource_name": entry.resource_name,
            "principal_email": proto_payload.authentication_info.principal_email if proto_payload and proto_payload.authentication_info else "unknown",
            "request_metadata": {
                "caller_ip": proto_payload.request_metadata.caller_ip if proto_payload and proto_payload.request_metadata else None,
                "caller_supplied_user_agent": proto_payload.request_metadata.caller_supplied_user_agent if proto_payload and proto_payload.request_metadata else None
            },
            "request": proto_payload.request if proto_payload else {},
            "response": proto_payload.response if proto_payload else {},
            "resource": {
                "type": entry.resource.type,
                "labels": dict(entry.resource.labels)
            } if entry.resource else {},
            "severity": entry.severity.name,
            "raw_entry": json.loads(LogEntry.to_json(entry))
        }
    
    def setup_log_sink(self, sink_name: str, destination: str):
        """Set up Cloud Logging sink for real-time events"""
        logger.info(f"Setting up GCP log sink: {sink_name}")
        
        from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
        from google.cloud.logging_v2.types import LogSink
        
        config_client = ConfigServiceV2Client(credentials=self.credentials)
        
        # Create sink filter for security events
        sink_filter = """
        (protoPayload.serviceName="iam.googleapis.com" OR 
         protoPayload.serviceName="compute.googleapis.com" OR 
         protoPayload.serviceName="storage.googleapis.com" OR 
         protoPayload.serviceName="sqladmin.googleapis.com")
        AND (protoPayload.methodName:("SetIamPolicy" OR "CreateServiceAccount" OR 
             "CreateServiceAccountKey" OR "Insert" OR "Delete" OR "Update"))
        """
        
        sink = LogSink(
            name=sink_name,
            destination=destination,  # Could be Pub/Sub, BigQuery, or Cloud Storage
            filter=sink_filter,
            description="Path Predict security event sink"
        )
        
        try:
            config_client.create_sink(
                parent=f"projects/{self.project_id}",
                sink=sink
            )
            logger.info(f"Log sink {sink_name} created successfully")
        except Exception as e:
            logger.error(f"Error creating log sink: {e}")

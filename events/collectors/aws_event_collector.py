# events/collectors/aws_event_collector.py
import boto3
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AWSEventType(Enum):
    """Critical AWS event types for attack path detection"""
    IAM_ROLE_CREATED = "CreateRole"
    IAM_POLICY_ATTACHED = "AttachRolePolicy"
    IAM_TRUST_UPDATED = "UpdateAssumeRolePolicy"
    EC2_INSTANCE_LAUNCHED = "RunInstances"
    EC2_SECURITY_GROUP_MODIFIED = "AuthorizeSecurityGroupIngress"
    S3_BUCKET_CREATED = "CreateBucket"
    S3_POLICY_MODIFIED = "PutBucketPolicy"
    RDS_INSTANCE_CREATED = "CreateDBInstance"
    LAMBDA_FUNCTION_CREATED = "CreateFunction"
    STS_ASSUME_ROLE = "AssumeRole"


@dataclass
class AWSEvent:
    """Normalized AWS event"""
    event_id: str
    event_type: AWSEventType
    event_time: datetime
    source_arn: str
    principal: Dict[str, Any]
    request_parameters: Dict[str, Any]
    response_elements: Dict[str, Any]
    resources: List[Dict[str, Any]]
    raw_event: Dict[str, Any]


class AWSCloudTrailCollector:
    """Collects real-time events from AWS CloudTrail/EventBridge"""
    
    def __init__(self, aws_profile: str = "default"):
        self.session = boto3.Session(profile_name=aws_profile)
        self.cloudtrail = self.session.client('cloudtrail')
        self.eventbridge = self.session.client('events')
        self.processed_event_ids = set()
    
    async def stream_events(self, lookback_minutes: int = 60):
        """Stream events from CloudTrail (polling mode)"""
        logger.info(f"Starting CloudTrail event stream (last {lookback_minutes} minutes)")
        
        while True:
            try:
                events = self._get_recent_events(lookback_minutes)
                
                for event in events:
                    if self._should_process(event):
                        normalized = self._normalize_event(event)
                        yield normalized
                
                # Wait before next poll
                await asyncio.sleep(30)  # Poll every 30 seconds
                
            except Exception as e:
                logger.error(f"Error streaming events: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    def _get_recent_events(self, lookback_minutes: int) -> List[Dict[str, Any]]:
        """Get recent events from CloudTrail"""
        start_time = datetime.utcnow() - timedelta(minutes=lookback_minutes)
        
        response = self.cloudtrail.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventSource', 'AttributeValue': 'iam.amazonaws.com'},
                {'AttributeKey': 'EventSource', 'AttributeValue': 'ec2.amazonaws.com'},
                {'AttributeKey': 'EventSource', 'AttributeValue': 's3.amazonaws.com'},
                {'AttributeKey': 'EventSource', 'AttributeValue': 'rds.amazonaws.com'},
                {'AttributeKey': 'EventSource', 'AttributeValue': 'lambda.amazonaws.com'},
                {'AttributeKey': 'EventSource', 'AttributeValue': 'sts.amazonaws.com'},
            ],
            StartTime=start_time,
            EndTime=datetime.utcnow(),
            MaxResults=100
        )
        
        return response.get('Events', [])
    
    def _should_process(self, event: Dict[str, Any]) -> bool:
        """Determine if event should be processed"""
        event_id = event.get('EventId')
        event_name = event.get('EventName')
        
        # Skip already processed events
        if event_id in self.processed_event_ids:
            return False
        
        # Skip read-only events
        read_only_patterns = ['Describe', 'Get', 'List', 'Lookup']
        if any(pattern in event_name for pattern in read_only_patterns):
            return False
        
        # Only process specific event types
        valid_types = [e.value for e in AWSEventType]
        if event_name not in valid_types:
            return False
        
        self.processed_event_ids.add(event_id)
        return True
    
    def _normalize_event(self, event: Dict[str, Any]) -> AWSEvent:
        """Normalize CloudTrail event to our format"""
        event_name = event.get('EventName')
        
        # Parse event time
        event_time_str = event.get('EventTime')
        if isinstance(event_time_str, datetime):
            event_time = event_time_str
        else:
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        
        # Parse cloudtrail event
        cloudtrail_event = json.loads(event.get('CloudTrailEvent', '{}'))
        
        return AWSEvent(
            event_id=event.get('EventId'),
            event_type=AWSEventType(event_name),
            event_time=event_time,
            source_arn=cloudtrail_event.get('sourceIPAddress', 'unknown'),
            principal=cloudtrail_event.get('userIdentity', {}),
            request_parameters=cloudtrail_event.get('requestParameters', {}),
            response_elements=cloudtrail_event.get('responseElements', {}),
            resources=cloudtrail_event.get('resources', []),
            raw_event=cloudtrail_event
        )
    
    def setup_eventbridge_rule(self, rule_name: str, target_arn: str):
        """Set up EventBridge rule for real-time events"""
        logger.info(f"Setting up EventBridge rule: {rule_name}")
        
        # Create rule pattern for critical events
        rule_pattern = {
            "source": ["aws.iam", "aws.ec2", "aws.s3", "aws.rds", "aws.lambda", "aws.sts"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": [
                    "iam.amazonaws.com",
                    "ec2.amazonaws.com", 
                    "s3.amazonaws.com",
                    "rds.amazonaws.com",
                    "lambda.amazonaws.com",
                    "sts.amazonaws.com"
                ],
                "eventName": [e.value for e in AWSEventType]
            }
        }
        
        # Put rule
        self.eventbridge.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(rule_pattern),
            State='ENABLED',
            Description='Path Predict critical security events'
        )
        
        # Add target (e.g., Lambda function, SNS, or HTTP endpoint)
        self.eventbridge.put_targets(
            Rule=rule_name,
            Targets=[{
                'Id': 'path-predict-target',
                'Arn': target_arn,
                'InputTransformer': {
                    'InputPathsMap': {
                        'eventId': '$.id',
                        'eventTime': '$.time',
                        'eventName': '$.detail.eventName',
                        'eventSource': '$.detail.eventSource',
                        'requestParams': '$.detail.requestParameters',
                        'responseElements': '$.detail.responseElements'
                    },
                    'InputTemplate': json.dumps({
                        'event_id': '<eventId>',
                        'event_time': '<eventTime>',
                        'event_name': '<eventName>',
                        'event_source': '<eventSource>',
                        'request_parameters': <requestParams>,
                        'response_elements': <responseElements>
                    })
                }
            }]
        )
        
        logger.info(f"EventBridge rule {rule_name} configured")

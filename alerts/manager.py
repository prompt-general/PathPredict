# alerts/manager.py
from typing import Dict, List, Any, Optional
import logging
import asyncio
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import json

logger = logging.getLogger(__name__)

class AlertChannel(Enum):
    SLACK = "slack"
    TEAMS = "teams"
    EMAIL = "email"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"

class AlertSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    source: str
    target: str
    path_id: Optional[str] = None
    risk_score: Optional[float] = None
    mitre_techniques: List[str] = None
    remediation_priority: int = 5
    timestamp: datetime = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.metadata is None:
            self.metadata = {}

class AlertManager:
    """Central alert manager for multi-channel notifications"""
    
    def __init__(self):
        self.channels = {}
        self.alert_history = []
        self.rate_limit_cache = {}
        
    def add_channel(self, channel_type: AlertChannel, config: Dict[str, Any]):
        """Add an alert channel"""
        if channel_type == AlertChannel.SLACK:
            from alerts.channels.slack import SlackChannel
            self.channels[channel_type] = SlackChannel(**config)
        elif channel_type == AlertChannel.TEAMS:
            from alerts.channels.teams import TeamsChannel
            self.channels[channel_type] = TeamsChannel(**config)
        elif channel_type == AlertChannel.EMAIL:
            from alerts.channels.email import EmailChannel
            self.channels[channel_type] = EmailChannel(**config)
        elif channel_type == AlertChannel.WEBHOOK:
            from alerts.channels.webhook import WebhookChannel
            self.channels[channel_type] = WebhookChannel(**config)
        elif channel_type == AlertChannel.PAGERDUTY:
            from alerts.channels.pagerduty import PagerDutyChannel
            self.channels[channel_type] = PagerDutyChannel(**config)
        else:
            raise ValueError(f"Unsupported channel type: {channel_type}")
        
        logger.info(f"Added alert channel: {channel_type.value}")
    
    async def send_alert(self, alert: Alert, channels: List[AlertChannel] = None):
        """Send alert through specified channels"""
        
        # Apply rate limiting
        if not self._check_rate_limit(alert):
            logger.info(f"Alert rate limited: {alert.alert_id}")
            return False
        
        # If no channels specified, use all configured channels
        if channels is None:
            channels = list(self.channels.keys())
        
        # Filter by severity if channel has minimum severity
        filtered_channels = []
        for channel_type in channels:
            channel = self.channels.get(channel_type)
            if channel and self._meets_severity_threshold(alert, channel):
                filtered_channels.append(channel_type)
        
        # Send alerts asynchronously
        tasks = []
        for channel_type in filtered_channels:
            channel = self.channels[channel_type]
            task = asyncio.create_task(
                self._send_single_alert(channel, alert, channel_type)
            )
            tasks.append(task)
        
        # Wait for all sends to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Log results
            success_count = sum(1 for r in results if r is True)
            if success_count > 0:
                logger.info(f"Alert {alert.alert_id} sent to {success_count} channels")
            
            # Store in history
            self.alert_history.append({
                'alert_id': alert.alert_id,
                'timestamp': alert.timestamp,
                'channels': [c.value for c in filtered_channels],
                'success_count': success_count
            })
            
            # Keep history limited
            if len(self.alert_history) > 1000:
                self.alert_history = self.alert_history[-1000:]
            
            return success_count > 0
        
        return False
    
    async def _send_single_alert(self, channel, alert: Alert, channel_type: AlertChannel):
        """Send alert through a single channel"""
        try:
            success = await channel.send(alert)
            if success:
                logger.debug(f"Alert {alert.alert_id} sent via {channel_type.value}")
                return True
            else:
                logger.error(f"Failed to send alert via {channel_type.value}")
                return False
        except Exception as e:
            logger.error(f"Error sending alert via {channel_type.value}: {e}")
            return False
    
    def create_alert_from_attack_path(self, attack_path: Dict[str, Any]) -> Alert:
        """Create alert from attack path detection"""
        
        risk_assessment = attack_path.get('risk_assessment', {})
        
        # Map risk level to alert severity
        risk_level = risk_assessment.get('risk_level', 'LOW')
        severity_map = {
            'CRITICAL': AlertSeverity.CRITICAL,
            'HIGH': AlertSeverity.HIGH,
            'MEDIUM': AlertSeverity.MEDIUM,
            'LOW': AlertSeverity.LOW
        }
        
        severity = severity_map.get(risk_level, AlertSeverity.LOW)
        
        # Generate alert title
        if attack_path.get('type') == 'privilege_escalation':
            title = f"Privilege Escalation Path Detected ({risk_level})"
        elif attack_path.get('public_access'):
            title = f"Public Resource Exposure Detected ({risk_level})"
        elif len(attack_path.get('providers', [])) > 1:
            title = f"Cross-Cloud Attack Path Detected ({risk_level})"
        else:
            title = f"Attack Path Detected ({risk_level})"
        
        # Generate description
        description = f"Attack path from {attack_path.get('source', 'unknown')} "
        description += f"to {attack_path.get('target', 'unknown')} "
        description += f"with {attack_path.get('hop_count', 0)} hops. "
        description += f"Risk score: {risk_assessment.get('raw_score', 0):.1f}"
        
        # Extract MITRE techniques
        mitre_techniques = risk_assessment.get('mitre_techniques', [])
        
        return Alert(
            alert_id=f"alert_{attack_path.get('path_id', 'unknown')}",
            title=title,
            description=description,
            severity=severity,
            source=attack_path.get('source', 'unknown'),
            target=attack_path.get('target', 'unknown'),
            path_id=attack_path.get('path_id'),
            risk_score=risk_assessment.get('raw_score'),
            mitre_techniques=mitre_techniques,
            remediation_priority=risk_assessment.get('remediation_priority', 5),
            timestamp=datetime.fromisoformat(attack_path.get('timestamp', datetime.utcnow().isoformat())),
            metadata={
                'attack_path': attack_path,
                'providers': attack_path.get('providers', []),
                'hop_count': attack_path.get('hop_count', 0),
                'confidence': risk_assessment.get('confidence', 0.5)
            }
        )
    
    def _check_rate_limit(self, alert: Alert) -> bool:
        """Apply rate limiting to prevent alert fatigue"""
        
        # Rate limit key based on alert source and type
        rate_key = f"{alert.source}:{alert.severity.value}"
        
        current_time = datetime.utcnow()
        
        if rate_key in self.rate_limit_cache:
            last_alert_time, count = self.rate_limit_cache[rate_key]
            
            # Check time window (e.g., max 5 alerts per hour for same source/severity)
            time_diff = (current_time - last_alert_time).total_seconds() / 3600
            
            if time_diff < 1 and count >= 5:  # 1 hour window
                return False
            
            # Update count
            if time_diff >= 1:
                self.rate_limit_cache[rate_key] = (current_time, 1)
            else:
                self.rate_limit_cache[rate_key] = (last_alert_time, count + 1)
        else:
            self.rate_limit_cache[rate_key] = (current_time, 1)
        
        # Clean old entries
        self._clean_rate_limit_cache()
        
        return True
    
    def _clean_rate_limit_cache(self):
        """Clean old rate limit cache entries"""
        current_time = datetime.utcnow()
        to_remove = []
        
        for key, (last_time, _) in self.rate_limit_cache.items():
            if (current_time - last_time).total_seconds() > 86400:  # 24 hours
                to_remove.append(key)
        
        for key in to_remove:
            del self.rate_limit_cache[key]
    
    def _meets_severity_threshold(self, alert: Alert, channel) -> bool:
        """Check if alert meets channel's severity threshold"""
        if hasattr(channel, 'min_severity'):
            severity_order = {
                AlertSeverity.CRITICAL: 5,
                AlertSeverity.HIGH: 4,
                AlertSeverity.MEDIUM: 3,
                AlertSeverity.LOW: 2,
                AlertSeverity.INFO: 1
            }
            
            alert_level = severity_order.get(alert.severity, 0)
            channel_level = severity_order.get(channel.min_severity, 0)
            
            return alert_level >= channel_level
        
        return True
    
    def get_alert_history(self, 
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history with optional filters"""
        
        filtered = self.alert_history
        
        if start_time:
            filtered = [h for h in filtered if h['timestamp'] >= start_time]
        
        if end_time:
            filtered = [h for h in filtered if h['timestamp'] <= end_time]
        
        return sorted(filtered, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def create_digest(self, 
                     time_window_hours: int = 24) -> Dict[str, Any]:
        """Create alert digest for given time window"""
        
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        recent_alerts = [h for h in self.alert_history if h['timestamp'] > cutoff_time]
        
        # Group by severity
        severity_counts = {}
        channel_counts = {}
        
        for alert in recent_alerts:
            # This is simplified - in reality we'd need to store more details
            pass
        
        return {
            'time_window_hours': time_window_hours,
            'total_alerts': len(recent_alerts),
            'severity_breakdown': severity_counts,
            'channel_usage': channel_counts,
            'timestamp': datetime.utcnow().isoformat()
        }

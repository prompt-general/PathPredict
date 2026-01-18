# alerts/channels/email.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import List, Dict, Any
from datetime import datetime
from ..manager import Alert, AlertSeverity

logger = logging.getLogger(__name__)

class EmailChannel:
    """Email alert channel"""
    
    def __init__(self,
                 smtp_server: str,
                 smtp_port: int,
                 username: str,
                 password: str,
                 from_address: str,
                 to_addresses: List[str],
                 min_severity: AlertSeverity = AlertSeverity.MEDIUM):
        
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.min_severity = min_severity
        
        # Test connection
        if not self._test_connection():
            raise ConnectionError("Cannot connect to SMTP server")
    
    async def send(self, alert: Alert) -> bool:
        """Send alert via email"""
        
        # Create email message
        message = self._create_email_message(alert)
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                
                for to_address in self.to_addresses:
                    message['To'] = to_address
                    server.send_message(message)
                
            logger.debug(f"Email alert sent: {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _create_email_message(self, alert: Alert) -> MIMEMultipart:
        """Create email message from alert"""
        
        # Create message container
        message = MIMEMultipart('alternative')
        message['Subject'] = f"[Path Predict] {alert.title}"
        message['From'] = self.from_address
        message['X-Priority'] = '1' if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH] else '3'
        
        # Create HTML content
        html = self._create_html_email(alert)
        
        # Create plain text content
        text = self._create_text_email(alert)
        
        # Attach parts
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        
        message.attach(part1)
        message.attach(part2)
        
        return message
    
    def _create_html_email(self, alert: Alert) -> str:
        """Create HTML email content"""
        
        # Severity badge color
        color_map = {
            AlertSeverity.CRITICAL: "red",
            AlertSeverity.HIGH: "orange",
            AlertSeverity.MEDIUM: "yellow",
            AlertSeverity.LOW: "green",
            AlertSeverity.INFO: "gray"
        }
        
        severity_color = color_map.get(alert.severity, "gray")
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .severity-badge {{ 
                    display: inline-block; 
                    padding: 5px 10px; 
                    border-radius: 3px; 
                    color: white; 
                    background-color: {severity_color};
                    font-weight: bold;
                }}
                .details {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
                .fact {{ margin-bottom: 10px; }}
                .fact-label {{ font-weight: bold; color: #666; }}
                .actions {{ margin-top: 20px; }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-right: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 {alert.title}</h1>
                    <span class="severity-badge">{alert.severity.value}</span>
                </div>
                
                <p>{alert.description}</p>
                
                <div class="details">
                    <div class="fact">
                        <span class="fact-label">Source:</span><br>
                        <code>{alert.source}</code>
                    </div>
                    <div class="fact">
                        <span class="fact-label">Target:</span><br>
                        <code>{alert.target}</code>
                    </div>
        """
        
        if alert.risk_score:
            html += f"""
                    <div class="fact">
                        <span class="fact-label">Risk Score:</span><br>
                        {alert.risk_score:.1f}/100
                    </div>
            """
        
        if alert.mitre_techniques:
            html += f"""
                    <div class="fact">
                        <span class="fact-label">MITRE Techniques:</span><br>
                        {', '.join(alert.mitre_techniques)}
                    </div>
            """
        
        html += f"""
                    <div class="fact">
                        <span class="fact-label">Detection Time:</span><br>
                        {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </div>
                    <div class="fact">
                        <span class="fact-label">Remediation Priority:</span><br>
                        {alert.remediation_priority}/5 (1 = highest)
                    </div>
                </div>
        """
        
        if alert.path_id:
            html += f"""
                <div class="actions">
                    <a href="https://path-predict.internal/paths/{alert.path_id}" class="button">
                        View Details
                    </a>
                </div>
            """
        
        html += """
                <hr>
                <p style="color: #666; font-size: 12px;">
                    This alert was generated by Path Predict. 
                    To modify alert settings, visit Path Predict dashboard.
                </p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_email(self, alert: Alert) -> str:
        """Create plain text email content"""
        text = f"""
        PATH PREDICT ALERT
        {'=' * 50}
        
        {alert.title}
        Severity: {alert.severity.value}
        
        {alert.description}
        
        Details:
        - Source: {alert.source}
        - Target: {alert.target}
        """
        
        if alert.risk_score:
            text += f"- Risk Score: {alert.risk_score:.1f}/100\n"
        
        if alert.mitre_techniques:
            text += f"- MITRE Techniques: {', '.join(alert.mitre_techniques)}\n"
        
        text += f"""
        - Detection Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
        - Remediation Priority: {alert.remediation_priority}/5 (1 = highest)
        
        {'=' * 50}
        
        This alert was generated by Path Predict.
        To modify alert settings, visit Path Predict dashboard.
        """
        
        return text
    
    def _test_connection(self) -> bool:
        """Test SMTP connection"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
            
            return True
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False

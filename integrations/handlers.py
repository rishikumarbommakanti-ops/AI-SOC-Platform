import requests
import json
import logging
from datetime import datetime
from typing import Dict, Any
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class IntegrationHandler(ABC):
    """Base class for integration handlers"""
    
    @abstractmethod
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def send_incident(self, incident: Dict[str, Any]) -> bool:
        pass

class SlackHandler(IntegrationHandler):
    """Slack integration for alerts and incidents"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.timeout = 10
    
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send threat alert to Slack"""
        try:
            message = self._format_alert(alert)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False
    
    def send_incident(self, incident: Dict[str, Any]) -> bool:
        """Send incident notification to Slack"""
        try:
            message = self._format_incident(incident)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack incident notification failed: {e}")
            return False
    
    def _format_alert(self, alert: Dict) -> Dict:
        """Format alert as Slack message"""
        color = "danger" if alert.get('severity') == 'CRITICAL' else "warning"
        return {
            "attachments": [{
                "color": color,
                "title": f"Threat Alert: {alert.get('type', 'Unknown')}",
                "text": alert.get('description', ''),
                "fields": [
                    {"title": "Severity", "value": alert.get('severity'), "short": True},
                    {"title": "Confidence", "value": str(alert.get('confidence')), "short": True},
                    {"title": "Timestamp", "value": alert.get('timestamp', datetime.now().isoformat())}
                ]
            }]
        }
    
    def _format_incident(self, incident: Dict) -> Dict:
        """Format incident as Slack message"""
        return {
            "attachments": [{
                "color": "danger",
                "title": f"Security Incident: {incident.get('type', 'Unknown')}",
                "text": incident.get('description', ''),
                "fields": [
                    {"title": "Status", "value": incident.get('status'), "short": True},
                    {"title": "Affected Systems", "value": str(incident.get('affected_systems', [])), "short": False},
                    {"title": "Response Time", "value": incident.get('response_time_ms', 'N/A')}
                ]
            }]
        }

class DiscordHandler(IntegrationHandler):
    """Discord integration for alerts and incidents"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.timeout = 10
    
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send threat alert to Discord"""
        try:
            message = self._format_alert(alert)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Discord alert failed: {e}")
            return False
    
    def send_incident(self, incident: Dict[str, Any]) -> bool:
        """Send incident notification to Discord"""
        try:
            message = self._format_incident(incident)
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=self.timeout
            )
            return response.status_code == 204
        except Exception as e:
            logger.error(f"Discord incident notification failed: {e}")
            return False
    
    def _format_alert(self, alert: Dict) -> Dict:
        """Format alert as Discord embed"""
        severity_colors = {
            'CRITICAL': 16711680,  # Red
            'HIGH': 16753920,      # Orange
            'MEDIUM': 16776960,    # Yellow
            'LOW': 65280            # Green
        }
        color = severity_colors.get(alert.get('severity'), 0)
        
        return {
            "embeds": [{
                "title": f"Threat Alert: {alert.get('type', 'Unknown')}",
                "description": alert.get('description', ''),
                "color": color,
                "fields": [
                    {"name": "Severity", "value": alert.get('severity'), "inline": True},
                    {"name": "Confidence", "value": str(alert.get('confidence')), "inline": True},
                    {"name": "Timestamp", "value": alert.get('timestamp', datetime.now().isoformat())}
                ]
            }]
        }
    
    def _format_incident(self, incident: Dict) -> Dict:
        """Format incident as Discord embed"""
        return {
            "embeds": [{
                "title": f"Security Incident: {incident.get('type', 'Unknown')}",
                "description": incident.get('description', ''),
                "color": 16711680,  # Red
                "fields": [
                    {"name": "Status", "value": incident.get('status'), "inline": True},
                    {"name": "Affected Systems", "value": str(incident.get('affected_systems', []))},
                    {"name": "Response Time", "value": f"{incident.get('response_time_ms', 'N/A')}ms"}
                ]
            }]
        }

class N8NHandler(IntegrationHandler):
    """n8n integration for workflow automation"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.timeout = 10
    
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert to n8n workflow"""
        try:
            payload = {
                "event_type": "threat.detected",
                "alert": alert,
                "timestamp": datetime.now().isoformat()
            }
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout
            )
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"n8n alert failed: {e}")
            return False
    
    def send_incident(self, incident: Dict[str, Any]) -> bool:
        """Send incident to n8n workflow"""
        try:
            payload = {
                "event_type": "incident.created",
                "incident": incident,
                "timestamp": datetime.now().isoformat()
            }
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout
            )
            return response.status_code in [200, 201]
        except Exception as e:
            logger.error(f"n8n incident notification failed: {e}")
            return False

class IntegrationManager:
    """Manages all integrations"""
    
    def __init__(self):
        self.handlers: Dict[str, IntegrationHandler] = {}
    
    def register_handler(self, name: str, handler: IntegrationHandler):
        """Register an integration handler"""
        self.handlers[name] = handler
    
    def broadcast_alert(self, alert: Dict[str, Any]) -> Dict[str, bool]:
        """Send alert to all registered handlers"""
        results = {}
        for name, handler in self.handlers.items():
            results[name] = handler.send_alert(alert)
        return results
    
    def broadcast_incident(self, incident: Dict[str, Any]) -> Dict[str, bool]:
        """Send incident to all registered handlers"""
        results = {}
        for name, handler in self.handlers.items():
            results[name] = handler.send_incident(incident)
        return results

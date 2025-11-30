"""Automated Incident Response Module"""
import logging
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)

class IncidentSeverity(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class IncidentResponder:
    """Automated incident response engine"""
    
    def __init__(self):
        self.playbooks = self._initialize_playbooks()
        self.incident_history = []
        logger.info("Incident responder initialized")
    
    def execute(self, incident):
        """Execute automated incident response"""
        try:
            # Determine incident severity
            severity = self._assess_severity(incident)
            
            # Get applicable playbooks
            applicable_playbooks = self._get_playbooks(incident['type'])
            
            # Execute response steps
            response_actions = []
            for playbook in applicable_playbooks:
                actions = self._execute_playbook(playbook, incident, severity)
                response_actions.extend(actions)
            
            # Log incident
            incident_record = {
                "timestamp": datetime.now().isoformat(),
                "type": incident['type'],
                "severity": severity.name,
                "actions_taken": response_actions,
                "status": "resolved" if severity.value <= 2 else "escalated"
            }
            self.incident_history.append(incident_record)
            
            return {
                "incident_id": len(self.incident_history),
                "severity": severity.name,
                "actions_executed": response_actions,
                "escalation_required": severity.value > 3
            }
        except Exception as e:
            logger.error(f"Error in incident response: {str(e)}")
            return {"error": str(e)}
    
    def _initialize_playbooks(self):
        """Initialize incident response playbooks"""
        return {
            "malware_detection": {
                "steps": [
                    "isolate_host",
                    "capture_memory",
                    "quarantine_file",
                    "notify_soc"
                ]
            },
            "unauthorized_access": {
                "steps": [
                    "revoke_credentials",
                    "kill_sessions",
                    "audit_logs",
                    "escalate_to_management"
                ]
            },
            "ddos_attack": {
                "steps": [
                    "enable_ddos_protection",
                    "block_malicious_ips",
                    "increase_capacity",
                    "alert_cdn"
                ]
            },
            "data_exfiltration": {
                "steps": [
                    "block_outbound_ips",
                    "revoke_api_keys",
                    "trigger_data_loss_prevention",
                    "escalate_to_ciso"
                ]
            }
        }
    
    def _assess_severity(self, incident):
        """Assess incident severity"""
        threat_level = incident.get('threat_level', 0.5)
        if threat_level > 0.9:
            return IncidentSeverity.CRITICAL
        elif threat_level > 0.7:
            return IncidentSeverity.HIGH
        elif threat_level > 0.5:
            return IncidentSeverity.MEDIUM
        elif threat_level > 0.3:
            return IncidentSeverity.LOW
        else:
            return IncidentSeverity.INFO
    
    def _get_playbooks(self, incident_type):
        """Get applicable playbooks for incident type"""
        return [self.playbooks.get(incident_type, {})]
    
    def _execute_playbook(self, playbook, incident, severity):
        """Execute individual playbook steps"""
        actions = []
        for step in playbook.get('steps', []):
            action_result = {
                "action": step,
                "status": "executed",
                "timestamp": datetime.now().isoformat(),
                "severity": severity.name
            }
            actions.append(action_result)
            logger.info(f"Executed: {step}")
        return actions

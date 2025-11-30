import re
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)

class LogSeverity(Enum):
    """Log severity levels"""
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"

class LogAnalyzer:
    """Real-time log analysis and anomaly detection"""
    
    def __init__(self):
        self.log_patterns = {
            'failed_login': r'(Failed|failed|FAILED).{0,50}(auth|login|password)',
            'privilege_escalation': r'(sudo|SUDO|privilege|escalation)',
            'file_access': r'(chmod|chown|rm|dd|shred)\s+',
            'network_scan': r'(nmap|masscan|zmap|shodan)',
            'sql_injection': r"(UNION|SELECT|OR\s+1=1|DROP|DELETE)",
            'command_injection': r'(;|\||&&|`|\$\()'
        }
        self.log_buffer = []
        self.anomalies = []
        self.baseline_metrics = defaultdict(list)
        
    def parse_log_line(self, log_line: str) -> Dict[str, Any]:
        """Parse a log line and extract metadata"""
        parsed = {
            'raw': log_line,
            'timestamp': datetime.now(),
            'severity': self._determine_severity(log_line),
            'source_ip': self._extract_ip(log_line),
            'user': self._extract_user(log_line),
            'event_type': self._classify_event(log_line),
            'threat_level': 0.0
        }
        return parsed
    
    def _determine_severity(self, log_line: str) -> LogSeverity:
        """Determine severity level from log content"""
        if any(keyword in log_line.upper() for keyword in ['CRITICAL', 'FATAL', 'EMERGENCY']):
            return LogSeverity.CRITICAL
        elif any(keyword in log_line.upper() for keyword in ['ERROR', 'ERR']):
            return LogSeverity.ERROR
        elif any(keyword in log_line.upper() for keyword in ['WARNING', 'WARN']):
            return LogSeverity.WARNING
        elif any(keyword in log_line.upper() for keyword in ['INFO']):
            return LogSeverity.INFO
        return LogSeverity.DEBUG
    
    def _extract_ip(self, log_line: str) -> str:
        """Extract IP address from log line"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, log_line)
        return match.group(0) if match else None
    
    def _extract_user(self, log_line: str) -> str:
        """Extract username from log line"""
        patterns = [r'user[=:]\s*([\w-]+)', r'\[([\w-]+)\]', r'(root|admin|user)\s']
        for pattern in patterns:
            match = re.search(pattern, log_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    def _classify_event(self, log_line: str) -> str:
        """Classify the type of security event"""
        for event_type, pattern in self.log_patterns.items():
            if re.search(pattern, log_line, re.IGNORECASE):
                return event_type
        return 'unknown'
    
    def analyze_log_stream(self, logs: List[str]) -> Dict[str, Any]:
        """Analyze a batch of logs for anomalies"""
        results = {
            'total_logs': len(logs),
            'anomalies_detected': [],
            'threat_level': 0.0,
            'statistics': defaultdict(int)
        }
        
        for log_line in logs:
            parsed = self.parse_log_line(log_line)
            self._check_anomaly(parsed, results)
            results['statistics'][parsed['event_type']] += 1
            
        results['threat_level'] = self._calculate_threat_level(results)
        return results
    
    def _check_anomaly(self, parsed_log: Dict, results: Dict):
        """Check if log entry represents an anomaly"""
        anomaly_score = 0.0
        
        if parsed_log['severity'] in [LogSeverity.CRITICAL, LogSeverity.ERROR]:
            anomaly_score += 0.3
        
        if parsed_log['event_type'] in ['failed_login', 'privilege_escalation', 'sql_injection']:
            anomaly_score += 0.4
        
        if parsed_log['source_ip'] and self._is_suspicious_ip(parsed_log['source_ip']):
            anomaly_score += 0.3
        
        if anomaly_score > 0.5:
            results['anomalies_detected'].append({
                'timestamp': parsed_log['timestamp'].isoformat(),
                'event_type': parsed_log['event_type'],
                'source_ip': parsed_log['source_ip'],
                'severity': parsed_log['severity'].value,
                'anomaly_score': round(anomaly_score, 2),
                'raw_log': parsed_log['raw'][:100]
            })
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP matches known suspicious patterns"""
        suspicious_ranges = [
            r'^192\.168\.',
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.'
        ]
        for pattern in suspicious_ranges:
            if re.match(pattern, ip):
                return True
        return False
    
    def _calculate_threat_level(self, results: Dict) -> float:
        """Calculate overall threat level (0.0-1.0)"""
        threat_score = 0.0
        
        threat_score += len(results['anomalies_detected']) * 0.1
        threat_score += results['statistics'].get('failed_login', 0) * 0.05
        threat_score += results['statistics'].get('privilege_escalation', 0) * 0.15
        threat_score += results['statistics'].get('sql_injection', 0) * 0.2
        
        return min(threat_score, 1.0)
    
    def detect_patterns(self, logs: List[str]) -> Dict[str, List[str]]:
        """Detect specific attack patterns in logs"""
        patterns_found = defaultdict(list)
        
        for log_line in logs:
            for pattern_name, pattern_regex in self.log_patterns.items():
                if re.search(pattern_regex, log_line, re.IGNORECASE):
                    patterns_found[pattern_name].append(log_line)
        
        return dict(patterns_found)
    
    def get_analytics(self) -> Dict[str, Any]:
        """Get analytics summary"""
        return {
            'total_logs_processed': len(self.log_buffer),
            'total_anomalies': len(self.anomalies),
            'event_distribution': dict(self.baseline_metrics),
            'last_analysis': datetime.now().isoformat()
        }

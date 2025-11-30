from datetime import datetime
from typing import Dict, List, Any
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    ISO_27001 = "ISO-27001"
    SOC2 = "SOC2"
    GDPR = "GDPR"
    NIST_CSF = "NIST-CSF"

class ComplianceStatus(Enum):
    """Compliance status"""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIAL_COMPLIANT = "PARTIAL_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"

class ComplianceMonitor:
    """Continuous compliance monitoring and reporting"""
    
    def __init__(self):
        self.compliance_rules = self._initialize_compliance_rules()
        self.audit_trail = []
        self.compliance_results = {}
        
    def _initialize_compliance_rules(self) -> Dict:
        """Initialize compliance rules for different frameworks"""
        return {
            'PCI-DSS': {
                'requirements': {
                    '1.1': 'Firewall configuration standards',
                    '2.1': 'Security parameters for system components',
                    '3.2': 'Render cardholder data unreadable',
                    '6.2': 'Security patches and updates',
                    '8.1': 'User access control policies',
                    '10.1': 'Audit trail implementation'
                },
                'critical_controls': ['3.2', '6.2', '8.1']
            },
            'HIPAA': {
                'requirements': {
                    '164.308': 'Administrative safeguards',
                    '164.310': 'Physical safeguards',
                    '164.312': 'Technical safeguards',
                    '164.314': 'Organizational policies'
                },
                'critical_controls': ['164.312', '164.314']
            },
            'ISO-27001': {
                'requirements': {
                    'A.5': 'Policies for information security',
                    'A.6': 'Organization of information security',
                    'A.7': 'Human resource security',
                    'A.8': 'Asset management',
                    'A.12': 'Operations security'
                },
                'critical_controls': ['A.5', 'A.12']
            }
        }
    
    def check_compliance(self, framework: str, asset_info: Dict) -> Dict[str, Any]:
        """Check asset compliance against framework requirements"""
        result = {
            'framework': framework,
            'asset_id': asset_info.get('id'),
            'assessment_timestamp': datetime.now().isoformat(),
            'overall_status': ComplianceStatus.NOT_ASSESSED.value,
            'compliance_score': 0.0,
            'findings': [],
            'recommendations': []
        }
        
        if framework not in self.compliance_rules:
            result['overall_status'] = ComplianceStatus.NOT_ASSESSED.value
            return result
        
        framework_rules = self.compliance_rules[framework]
        passing_checks = 0
        total_checks = len(framework_rules['requirements'])
        
        for control_id, description in framework_rules['requirements'].items():
            is_compliant = self._evaluate_control(asset_info, control_id, framework)
            
            if is_compliant:
                passing_checks += 1
            else:
                finding = {
                    'control_id': control_id,
                    'description': description,
                    'status': 'FAILED',
                    'severity': 'CRITICAL' if control_id in framework_rules['critical_controls'] else 'HIGH',
                    'remediation': self._get_remediation(control_id, framework)
                }
                result['findings'].append(finding)
        
        result['compliance_score'] = (passing_checks / total_checks) * 100 if total_checks > 0 else 0
        
        if result['compliance_score'] == 100:
            result['overall_status'] = ComplianceStatus.COMPLIANT.value
        elif result['compliance_score'] >= 80:
            result['overall_status'] = ComplianceStatus.PARTIAL_COMPLIANT.value
        else:
            result['overall_status'] = ComplianceStatus.NON_COMPLIANT.value
        
        # Log compliance check
        self.audit_trail.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'compliance_check',
            'framework': framework,
            'asset_id': asset_info.get('id'),
            'result': result['overall_status']
        })
        
        return result
    
    def _evaluate_control(self, asset: Dict, control_id: str, framework: str) -> bool:
        """Evaluate if asset meets specific control requirement"""
        # Simulate control evaluation
        control_checks = {
            'PCI-DSS': {
                '6.2': asset.get('patches_current', False),
                '8.1': asset.get('access_controls_enabled', False),
                '10.1': asset.get('audit_logging_enabled', False)
            },
            'HIPAA': {
                '164.312': asset.get('encryption_enabled', False),
                '164.314': asset.get('policies_documented', False)
            },
            'ISO-27001': {
                'A.5': asset.get('security_policies', False),
                'A.12': asset.get('operations_security', False)
            }
        }
        
        return control_checks.get(framework, {}).get(control_id, False)
    
    def _get_remediation(self, control_id: str, framework: str) -> str:
        """Get remediation steps for failed control"""
        remediation_map = {
            'PCI-DSS': {
                '6.2': 'Deploy latest security patches and updates',
                '8.1': 'Implement role-based access control (RBAC)',
                '10.1': 'Enable and configure audit logging'
            },
            'HIPAA': {
                '164.312': 'Enable encryption for data at rest and in transit',
                '164.314': 'Document and enforce security policies'
            },
            'ISO-27001': {
                'A.5': 'Develop and document information security policies',
                'A.12': 'Implement operational security procedures'
            }
        }
        
        return remediation_map.get(framework, {}).get(control_id, 'Review control requirement')
    
    def generate_audit_report(self, framework: str) -> Dict[str, Any]:
        """Generate audit report for compliance framework"""
        return {
            'report_timestamp': datetime.now().isoformat(),
            'framework': framework,
            'audit_trail_entries': len([a for a in self.audit_trail if a['framework'] == framework]),
            'compliance_trend': 'improving',
            'assets_compliant': len([r for r in self.compliance_results.values() if r['overall_status'] == 'COMPLIANT']),
            'assets_non_compliant': len([r for r in self.compliance_results.values() if r['overall_status'] == 'NON_COMPLIANT']),
            'critical_findings': len([f for c in self.compliance_results.values() for f in c.get('findings', []) if f['severity'] == 'CRITICAL'])
        }
    
    def scan_compliance_drift(self, assets: List[Dict]) -> Dict[str, Any]:
        """Scan for compliance drift across all assets"""
        drift_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_assets': len(assets),
            'frameworks_scanned': list(ComplianceFramework.__members__.keys()),
            'drift_detected': [],
            'compliance_summary': {}
        }
        
        for framework in ComplianceFramework.__members__.keys():
            framework_compliance = []
            for asset in assets:
                result = self.check_compliance(framework.replace('_', '-'), asset)
                framework_compliance.append(result)
                self.compliance_results[f"{asset['id']}_{framework}"] = result
            
            compliant_count = len([r for r in framework_compliance if r['overall_status'] == 'COMPLIANT'])
            non_compliant = len([r for r in framework_compliance if r['overall_status'] == 'NON_COMPLIANT'])
            
            if non_compliant > 0:
                drift_results['drift_detected'].append({
                    'framework': framework,
                    'non_compliant_assets': non_compliant,
                    'severity': 'HIGH' if non_compliant > len(assets) / 2 else 'MEDIUM'
                })
            
            drift_results['compliance_summary'][framework] = {
                'compliant': compliant_count,
                'non_compliant': non_compliant,
                'compliance_percentage': (compliant_count / len(assets) * 100) if assets else 0
            }
        
        return drift_results
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """Get compliance dashboard summary"""
        total_checks = len(self.compliance_results)
        compliant = len([r for r in self.compliance_results.values() if r['overall_status'] == 'COMPLIANT'])
        non_compliant = len([r for r in self.compliance_results.values() if r['overall_status'] == 'NON_COMPLIANT'])
        
        return {
            'dashboard_timestamp': datetime.now().isoformat(),
            'total_checks': total_checks,
            'compliant_count': compliant,
            'non_compliant_count': non_compliant,
            'compliance_percentage': (compliant / total_checks * 100) if total_checks > 0 else 0,
            'audit_trail_count': len(self.audit_trail),
            'critical_findings': len([f for c in self.compliance_results.values() for f in c.get('findings', []) if f['severity'] == 'CRITICAL']),
            'frameworks_monitored': list(self.compliance_rules.keys())
        }

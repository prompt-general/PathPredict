# compliance/framework.py
from enum import Enum
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from graph.connection import get_connection

logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """Supported compliance standards"""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    GDPR = "gdpr"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"

class ComplianceControl:
    """Individual compliance control"""
    
    def __init__(self, 
                 control_id: str,
                 standard: ComplianceStandard,
                 name: str,
                 description: str,
                 severity: str,
                 query: str,
                 remediation: str):
        self.control_id = control_id
        self.standard = standard
        self.name = name
        self.description = description
        self.severity = severity  # "critical", "high", "medium", "low"
        self.query = query
        self.remediation = remediation
    
    def check(self, conn) -> Dict[str, Any]:
        """Execute compliance check query"""
        try:
            results = conn.execute_query(self.query)
            
            return {
                "control_id": self.control_id,
                "name": self.name,
                "standard": self.standard.value,
                "severity": self.severity,
                "violations": len(results),
                "details": results,
                "status": "FAIL" if len(results) > 0 else "PASS",
                "checked_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Error executing compliance check {self.control_id}: {e}")
            return {
                "control_id": self.control_id,
                "name": self.name,
                "status": "ERROR",
                "error": str(e),
                "checked_at": datetime.utcnow().isoformat()
            }

class ComplianceManager:
    """Manage compliance checks across standards"""
    
    def __init__(self):
        self.conn = get_connection()
        self.controls = self._load_default_controls()
        self.check_history = []
    
    def _load_default_controls(self) -> List[ComplianceControl]:
        """Load default compliance controls"""
        controls = []
        
        # PCI-DSS Controls
        controls.extend(self._get_pci_dss_controls())
        
        # HIPAA Controls
        controls.extend(self._get_hipaa_controls())
        
        # SOC2 Controls
        controls.extend(self._get_soc2_controls())
        
        return controls
    
    def _get_pci_dss_controls(self) -> List[ComplianceControl]:
        """PCI-DSS compliance controls"""
        return [
            ComplianceControl(
                control_id="PCI-1.2",
                standard=ComplianceStandard.PCI_DSS,
                name="Public Access to Storage Resources",
                description="Check for publicly accessible storage resources (S3 buckets, etc.)",
                severity="critical",
                query="""
                MATCH (r:Resource)
                WHERE r.subtype IN ['Storage', 'Bucket']
                AND (r.public_access = true OR r.internet_facing = true)
                RETURN r.node_id, r.cloud_provider, r.public_access, r.internet_facing
                """,
                remediation="Ensure storage resources are not publicly accessible. Use private buckets with proper IAM policies."
            ),
            ComplianceControl(
                control_id="PCI-2.1",
                standard=ComplianceStandard.PCI_DSS,
                name="Default Passwords or No Password",
                description="Check for resources with default or no authentication",
                severity="high",
                query="""
                MATCH (r:Resource)
                WHERE r.subtype IN ['Database', 'Compute']
                AND (r.authentication = 'none' OR r.default_credentials = true)
                RETURN r.node_id, r.cloud_provider, r.authentication
                """,
                remediation="Ensure all resources have proper authentication enabled and default credentials are changed."
            ),
            ComplianceControl(
                control_id="PCI-7.1",
                standard=ComplianceStandard.PCI_DSS,
                name="Excessive IAM Permissions",
                description="Check for identities with excessive permissions",
                severity="high",
                query="""
                MATCH (i:Identity)
                WHERE i.privilege_level >= 0.8
                AND i.external = true
                RETURN i.node_id, i.cloud_provider, i.privilege_level
                """,
                remediation="Implement principle of least privilege. Review and restrict IAM permissions."
            )
        ]
    
    def _get_hipaa_controls(self) -> List[ComplianceControl]:
        """HIPAA compliance controls"""
        return [
            ComplianceControl(
                control_id="HIPAA-164.312",
                standard=ComplianceStandard.HIPAA,
                name="Encryption of PHI at Rest",
                description="Check for unencrypted storage containing potential PHI",
                severity="critical",
                query="""
                MATCH (r:Resource)
                WHERE r.subtype IN ['Storage', 'Database']
                AND r.encryption = false
                AND (r.tags CONTAINS 'phi' OR r.tags CONTAINS 'hipaa' OR r.contains_pii = true)
                RETURN r.node_id, r.cloud_provider, r.encryption, r.tags
                """,
                remediation="Enable encryption for all storage and database resources containing PHI."
            ),
            ComplianceControl(
                control_id="HIPAA-164.308",
                standard=ComplianceStandard.HIPAA,
                name="Access Controls for PHI",
                description="Check for excessive access to resources containing PHI",
                severity="high",
                query="""
                MATCH (r:Resource {contains_pii: true})
                MATCH (i:Identity)-[:CAN_ACCESS]->(r)
                WHERE i.privilege_level >= 0.6
                RETURN i.node_id, r.node_id, i.privilege_level
                """,
                remediation="Implement strict access controls for PHI. Use role-based access control and audit access logs."
            ),
            ComplianceControl(
                control_id="HIPAA-164.312.b",
                standard=ComplianceStandard.HIPAA,
                name="Audit Controls",
                description="Check if audit logging is enabled for critical resources",
                severity="medium",
                query="""
                MATCH (r:Resource)
                WHERE r.criticality >= 0.7
                AND r.audit_logging_enabled = false
                RETURN r.node_id, r.cloud_provider, r.criticality
                """,
                remediation="Enable audit logging for all critical resources. Monitor and review audit logs regularly."
            )
        ]
    
    def _get_soc2_controls(self) -> List[ComplianceControl]:
        """SOC2 compliance controls"""
        return [
            ComplianceControl(
                control_id="SOC2-CC6.1",
                standard=ComplianceStandard.SOC2,
                name="Logical Access Security",
                description="Check for logical access security violations",
                severity="high",
                query="""
                MATCH (i:Identity)
                WHERE i.mfa_enabled = false
                AND i.privilege_level >= 0.5
                RETURN i.node_id, i.cloud_provider, i.privilege_level, i.mfa_enabled
                """,
                remediation="Enable Multi-Factor Authentication for all privileged identities."
            ),
            ComplianceControl(
                control_id="SOC2-CC7.1",
                standard=ComplianceStandard.SOC2,
                name="System Operations",
                description="Check for system operations without proper change management",
                severity="medium",
                query="""
                MATCH (r:Resource)
                WHERE r.change_management_approved = false
                AND r.last_modified > datetime().epochSeconds - 86400
                RETURN r.node_id, r.cloud_provider, r.last_modified
                """,
                remediation="Implement change management process for all system modifications."
            ),
            ComplianceControl(
                control_id="SOC2-CC8.1",
                standard=ComplianceStandard.SOC2,
                name="Risk Assessment",
                description="Check for unassessed high-risk resources",
                severity="medium",
                query="""
                MATCH (r:Resource)
                WHERE r.risk_score >= 0.7
                AND r.risk_assessed = false
                RETURN r.node_id, r.cloud_provider, r.risk_score
                """,
                remediation="Perform risk assessment for all high-risk resources."
            )
        ]
    
    def run_compliance_check(self, 
                            standard: Optional[ComplianceStandard] = None,
                            control_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Run compliance checks"""
        
        # Filter controls
        controls_to_check = self.controls
        
        if standard:
            controls_to_check = [c for c in controls_to_check if c.standard == standard]
        
        if control_id:
            controls_to_check = [c for c in controls_to_check if c.control_id == control_id]
        
        results = []
        
        for control in controls_to_check:
            result = control.check(self.conn)
            results.append(result)
            
            # Store in history
            self.check_history.append({
                **result,
                "run_id": f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            })
        
        # Generate compliance report
        report = self._generate_compliance_report(results)
        
        return {
            "checks": results,
            "report": report,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _generate_compliance_report(self, 
                                  check_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance report from check results"""
        
        # Group by standard
        by_standard = {}
        for result in check_results:
            standard = result.get('standard')
            if standard not in by_standard:
                by_standard[standard] = []
            by_standard[standard].append(result)
        
        # Calculate compliance scores
        report = {
            "overall_score": 0,
            "by_standard": {},
            "summary": {
                "total_checks": len(check_results),
                "passed": 0,
                "failed": 0,
                "errors": 0
            },
            "critical_findings": [],
            "recommendations": []
        }
        
        for standard, results in by_standard.items():
            passed = sum(1 for r in results if r.get('status') == 'PASS')
            failed = sum(1 for r in results if r.get('status') == 'FAIL')
            errors = sum(1 for r in results if r.get('status') == 'ERROR')
            total = len(results)
            
            score = (passed / total * 100) if total > 0 else 100
            
            report['by_standard'][standard] = {
                "score": round(score, 2),
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "total": total
            }
            
            # Collect critical findings
            for result in results:
                if result.get('severity') == 'critical' and result.get('status') == 'FAIL':
                    report['critical_findings'].append({
                        "control_id": result['control_id'],
                        "name": result['name'],
                        "violations": result.get('violations', 0),
                        "standard": standard
                    })
            
            report['summary']['passed'] += passed
            report['summary']['failed'] += failed
            report['summary']['errors'] += errors
        
        # Calculate overall score
        if report['summary']['total_checks'] > 0:
            report['overall_score'] = round(
                (report['summary']['passed'] / report['summary']['total_checks'] * 100), 
                2
            )
        
        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(check_results)
        
        return report
    
    def _generate_recommendations(self, 
                                check_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate recommendations from check results"""
        
        recommendations = []
        high_priority = []
        
        for result in check_results:
            if result.get('status') == 'FAIL':
                severity = result.get('severity', 'medium')
                
                rec = {
                    "control_id": result['control_id'],
                    "name": result['name'],
                    "standard": result.get('standard'),
                    "violations": result.get('violations', 0),
                    "priority": "HIGH" if severity in ['critical', 'high'] else "MEDIUM",
                    "action": "Immediate remediation required" if severity == 'critical' else "Remediate within 30 days"
                }
                
                if severity in ['critical', 'high']:
                    high_priority.append(rec)
                else:
                    recommendations.append(rec)
        
        # High priority first
        recommendations = high_priority + recommendations
        
        return recommendations[:10]  # Limit to top 10
    
    def get_compliance_history(self, 
                              days: int = 30,
                              standard: Optional[ComplianceStandard] = None) -> List[Dict[str, Any]]:
        """Get compliance check history"""
        
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        filtered = [h for h in self.check_history 
                   if datetime.fromisoformat(h['checked_at']) > cutoff]
        
        if standard:
            filtered = [h for h in filtered if h.get('standard') == standard.value]
        
        # Group by date
        by_date = {}
        for check in filtered:
            date = check['checked_at'][:10]  # YYYY-MM-DD
            if date not in by_date:
                by_date[date] = []
            by_date[date].append(check)
        
        # Calculate daily scores
        history = []
        for date, checks in sorted(by_date.items()):
            passed = sum(1 for c in checks if c.get('status') == 'PASS')
            total = len(checks)
            score = (passed / total * 100) if total > 0 else 100
            
            history.append({
                "date": date,
                "score": round(score, 2),
                "checks_run": total,
                "checks_passed": passed
            })
        
        return history
    
    def export_compliance_report(self, 
                               format: str = "json",
                               include_details: bool = False) -> Dict[str, Any]:
        """Export comprehensive compliance report"""
        
        # Run all checks
        check_results = self.run_compliance_check()
        
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "tool": "Path Predict Compliance Scanner",
                "version": "1.0.0"
            },
            "summary": check_results['report'],
            "executive_summary": self._generate_executive_summary(check_results['report'])
        }
        
        if include_details:
            report["detailed_findings"] = check_results['checks']
        
        return report
    
    def _generate_executive_summary(self, 
                                  report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for compliance report"""
        
        critical_findings = report.get('critical_findings', [])
        high_priority = len([f for f in critical_findings if f.get('priority') == 'HIGH'])
        
        return {
            "overall_compliance_score": report['overall_score'],
            "risk_level": "HIGH" if report['overall_score'] < 70 else 
                         "MEDIUM" if report['overall_score'] < 85 else "LOW",
            "critical_findings_count": len(critical_findings),
            "high_priority_actions": high_priority,
            "key_risks": [
                {
                    "description": f"{len([f for f in critical_findings if f['standard'] == std])} critical findings",
                    "standard": std,
                    "impact": "High regulatory and security risk"
                }
                for std in ['pci_dss', 'hipaa']  # Focus on major standards
                if len([f for f in critical_findings if f['standard'] == std]) > 0
            ],
            "recommendations": [
                "Address critical findings immediately",
                "Implement continuous compliance monitoring",
                "Regularly review and update access controls"
            ]
        }

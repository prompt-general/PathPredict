from typing import Dict, Any, List
import math
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class RiskFactors:
    """Factors that contribute to risk scoring"""
    privilege_weight: float = 1.5  # Privilege escalation multiplier
    exposure_weight: float = 1.3   # Public exposure multiplier
    cross_cloud_weight: float = 1.4  # Cross-cloud multiplier
    business_criticality_weight: float = 1.6  # Business impact
    hop_count_weight: float = 0.9  # More hops = less direct, slightly less risk
    fresh_weight: float = 1.2      # Recent changes are higher risk


class RiskScoringEngine:
    """Calculate risk scores for attack paths"""
    
    def __init__(self):
        self.factors = RiskFactors()
    
    def score_attack_path(self, path: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score for an attack path"""
        
        # Base score components (0-1 scale)
        privilege_score = self._calculate_privilege_score(path)
        exposure_score = self._calculate_exposure_score(path)
        cross_cloud_score = self._calculate_cross_cloud_score(path)
        business_score = self._calculate_business_criticality(path)
        complexity_score = self._calculate_complexity_score(path)
        
        # Apply weights and combine
        weighted_score = (
            privilege_score * self.factors.privilege_weight +
            exposure_score * self.factors.exposure_weight +
            cross_cloud_score * self.factors.cross_cloud_weight +
            business_score * self.factors.business_criticality_weight
        ) * complexity_score * self.factors.hop_count_weight
        
        # Normalize to 0-100 scale
        normalized_score = min(100, max(0, weighted_score * 25))
        
        # Determine risk level
        risk_level = self._determine_risk_level(normalized_score)
        
        return {
            "raw_score": normalized_score,
            "risk_level": risk_level.value,
            "components": {
                "privilege_score": privilege_score,
                "exposure_score": exposure_score,
                "cross_cloud_score": cross_cloud_score,
                "business_score": business_score,
                "complexity_score": complexity_score,
            },
            "mitre_techniques": self._map_to_mitre(path),
            "remediation_priority": self._calculate_remediation_priority(normalized_score, risk_level),
            "confidence": self._calculate_confidence(path)
        }
    
    def _calculate_privilege_score(self, path: Dict[str, Any]) -> float:
        """Calculate privilege escalation risk"""
        score = 0.0
        
        # Check for admin/service account in path
        nodes = path.get('nodes', [])
        for node_id in nodes:
            if 'admin' in node_id.lower() or 'serviceaccount' in node_id.lower():
                score += 0.3
        
        # Check for privilege escalation patterns
        relationships = path.get('relationships', [])
        if 'CAN_ASSUME' in relationships:
            score += 0.4
        
        if 'MEMBER_OF' in relationships and 'admin' in str(nodes).lower():
            score += 0.3
        
        return min(1.0, score)
    
    def _calculate_exposure_score(self, path: Dict[str, Any]) -> float:
        """Calculate public exposure risk"""
        score = 0.0
        
        # Check for public resources
        if path.get('type') == 'public_exposure':
            if path.get('public_access'):
                score += 0.8
            elif path.get('internet_facing'):
                score += 0.5
        
        # Check for external identities
        nodes = path.get('nodes', [])
        for node_id in nodes:
            if 'external' in node_id.lower() or 'federated' in node_id.lower():
                score += 0.4
        
        return min(1.0, score)
    
    def _calculate_cross_cloud_score(self, path: Dict[str, Any]) -> float:
        """Calculate cross-cloud risk"""
        providers = path.get('providers', [])
        if len(providers) > 1:
            return 0.8  # High risk for cross-cloud
        elif len(providers) == 1 and providers[0] != 'aws':  # Non-AWS has some risk
            return 0.3
        return 0.1  # Single cloud, lower risk
    
    def _calculate_business_criticality(self, path: Dict[str, Any]) -> float:
        """Calculate business impact risk"""
        score = 0.0
        
        # Check for production resources
        nodes = path.get('nodes', [])
        for node_id in nodes:
            node_str = str(node_id).lower()
            if 'prod' in node_str:
                score += 0.6
            elif any(env in node_str for env in ['production', 'prd', 'live']):
                score += 0.6
            elif 'dev' in node_str or 'test' in node_str:
                score += 0.2
        
        # Check for data-related resources
        for node_id in nodes:
            if any(data_type in str(node_id).lower() 
                   for data_type in ['database', 'storage', 's3', 'rds', 'sql']):
                score += 0.4
        
        return min(1.0, score)
    
    def _calculate_complexity_score(self, path: Dict[str, Any]) -> float:
        """Calculate attack complexity (inverse relationship)"""
        hop_count = path.get('hop_count', 1)
        
        # Fewer hops = easier attack = higher risk
        if hop_count == 1:
            return 1.0
        elif hop_count <= 3:
            return 0.7
        elif hop_count <= 5:
            return 0.4
        else:
            return 0.2
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _map_to_mitre(self, path: Dict[str, Any]) -> List[str]:
        """Map attack path to MITRE ATT&CK techniques"""
        techniques = []
        
        # Privilege Escalation
        if path.get('type') == 'privilege_escalation':
            techniques.extend([
                "T1078.004 - Cloud Accounts",
                "T1136.003 - Cloud Account",
                "T1484 - Domain Policy Modification"
            ])
        
        # Public Exposure
        if path.get('public_access') or path.get('internet_facing'):
            techniques.extend([
                "T1190 - Exploit Public-Facing Application",
                "T1595 - Active Scanning"
            ])
        
        # Cross-Cloud
        providers = path.get('providers', [])
        if len(providers) > 1:
            techniques.extend([
                "T1535 - Unused/Unsupported Cloud Regions",
                "T1578 - Modify Cloud Compute Infrastructure"
            ])
        
        # Identity-based
        if 'CAN_ASSUME' in str(path.get('relationships', [])):
            techniques.extend([
                "T1550.002 - Use Alternate Authentication Material: Pass the Hash",
                "T1556.001 - Modify Authentication Process: Domain Controller Authentication"
            ])
        
        return list(set(techniques))[:5]  # Return unique, max 5
    
    def _calculate_remediation_priority(self, score: float, risk_level: RiskLevel) -> int:
        """Calculate remediation priority (1-5, 1 = highest)"""
        if risk_level == RiskLevel.CRITICAL:
            return 1
        elif risk_level == RiskLevel.HIGH:
            return 2
        elif risk_level == RiskLevel.MEDIUM:
            return 3
        elif risk_level == RiskLevel.LOW:
            return 4
        else:
            return 5
    
    def _calculate_confidence(self, path: Dict[str, Any]) -> float:
        """Calculate confidence score (0-1) in detection"""
        confidence = 0.5  # Base confidence
        
        # More hops = lower confidence (more potential for false positives)
        hop_count = path.get('hop_count', 1)
        if hop_count == 1:
            confidence += 0.3
        elif hop_count <= 3:
            confidence += 0.1
        else:
            confidence -= 0.2
        
        # Cross-cloud detection is less certain
        providers = path.get('providers', [])
        if len(providers) > 1:
            confidence -= 0.1
        
        # Recent paths are more certain
        if 'timestamp' in path:
            # If path is from last 24 hours, higher confidence
            confidence += 0.1
        
        return max(0.1, min(1.0, confidence))
    
    def batch_score_paths(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score multiple attack paths"""
        scored_paths = []
        for path in paths:
            scored_path = path.copy()
            scored_path['risk_assessment'] = self.score_attack_path(path)
            scored_paths.append(scored_path)
        
        # Sort by score (highest risk first)
        scored_paths.sort(
            key=lambda x: x['risk_assessment']['raw_score'], 
            reverse=True
        )
        
        return scored_paths

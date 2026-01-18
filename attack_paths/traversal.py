from enum import Enum
from typing import List, Dict, Any, Optional, Tuple
import logging
from graph.connection import get_connection
import networkx as nx
from datetime import datetime
from alerts.manager import AlertManager

logger = logging.getLogger(__name__)


class AttackPathType(Enum):
    """Types of attack paths we can detect"""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CROSS_CLOUD_FEDERATION = "cross_cloud_federation"
    PUBLIC_EXPOSURE = "public_exposure"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class AttackPathTemplate:
    """Predefined attack path traversal templates"""
    
    @staticmethod
    def privilege_escalation() -> str:
        """Detect privilege escalation paths"""
        return """
        // Find paths from low-privilege identities to high-privilege resources
        MATCH (start:Identity)
        WHERE start.subtype IN ['User', 'ServiceAccount']
        AND start.risk_score >= 0.3
        MATCH (target:Resource)
        WHERE target.criticality >= 0.7
        MATCH path = (start)-[:CAN_ASSUME|CAN_ACCESS|MEMBER_OF*1..5]->(target)
        WITH path, start, target,
             nodes(path) as path_nodes,
             relationships(path) as path_rels,
             length(path) as hop_count
        WHERE ALL(r IN path_rels WHERE r.valid_to IS NULL)
        AND hop_count <= 5
        RETURN 
            start.node_id as source_id,
            start.node_id as source_node_id,
            target.node_id as target_id,
            target.node_id as target_node_id,
            [node IN path_nodes | node.node_id] as node_ids,
            [r IN path_rels | type(r)] as relationship_types,
            hop_count,
            reduce(score = 0, n IN path_nodes | score + COALESCE(n.risk_score, 0)) as total_risk_score
        ORDER BY total_risk_score DESC
        LIMIT 50
        """
    
    @staticmethod
    def public_exposure() -> str:
        """Find publicly exposed resources"""
        return """
        // Find resources with public exposure
        MATCH (resource:Resource)
        WHERE resource.public_access = true
        OR resource.internet_facing = true
        OPTIONAL MATCH (identity:Identity)-[:CAN_ACCESS]->(resource)
        RETURN 
            resource.node_id as resource_id,
            resource.subtype as resource_type,
            resource.public_access,
            resource.internet_facing,
            COLLECT(DISTINCT identity.node_id) as accessible_by,
            resource.criticality as criticality_score
        ORDER BY criticality_score DESC
        """
    
    @staticmethod
    def cross_account_assume_role() -> str:
        """Find cross-account assume role paths"""
        return """
        // Find cross-account trust relationships
        MATCH (source_account:Account)
        MATCH (target_account:Account)
        WHERE source_account.node_id <> target_account.node_id
        MATCH (source_role:Role {cloud_provider: 'aws'})
        WHERE source_role.account_id = source_account.account_id
        MATCH (target_role:Role {cloud_provider: 'aws'})
        WHERE target_role.account_id = target_account.account_id
        MATCH path = (source_role)-[:CAN_ASSUME*1..3]->(target_role)
        WITH path, nodes(path) as path_nodes
        RETURN 
            source_account.account_id as source_account,
            target_account.account_id as target_account,
            [node IN path_nodes | node.node_id] as role_chain,
            length(path) as hop_count
        ORDER BY hop_count
        """
    
    @staticmethod
    def identity_chaining() -> str:
        """Find identity chaining opportunities"""
        return """
        // Find chains of identities that can assume each other
        MATCH path = (start:Identity)-[:CAN_ASSUME|MEMBER_OF*1..10]->(end:Identity)
        WHERE start.node_id <> end.node_id
        AND length(path) >= 3
        WITH path, nodes(path) as identities
        UNWIND identities as identity
        WITH path, identities, 
             COLLECT(DISTINCT identity.cloud_provider) as providers,
             COUNT(DISTINCT identity.cloud_provider) as provider_count
        WHERE provider_count >= 2
        RETURN 
            [id IN identities | id.node_id] as identity_chain,
            providers,
            provider_count,
            length(path) as chain_length
        ORDER BY provider_count DESC, chain_length
        LIMIT 25
        """


class AttackPathTraversal:
    """Execute attack path detection queries"""
    
    def __init__(self):
        self.connection = get_connection()
        self.cache = {}  # Simple query cache
    
    def detect_privilege_escalation(self, limit: int = 25) -> List[Dict[str, Any]]:
        """Detect privilege escalation paths"""
        query = AttackPathTemplate.privilege_escalation()
        results = self.connection.execute_query(query, {"limit": limit})
        return self._format_attack_paths(results, AttackPathType.PRIVILEGE_ESCALATION)
    
    def detect_public_exposure(self) -> List[Dict[str, Any]]:
        """Detect publicly exposed resources"""
        query = AttackPathTemplate.public_exposure()
        results = self.connection.execute_query(query)
        return self._format_public_exposure(results)
    
    def detect_cross_account_paths(self) -> List[Dict[str, Any]]:
        """Detect cross-account attack paths"""
        query = AttackPathTemplate.cross_account_assume_role()
        results = self.connection.execute_query(query)
        return self._format_cross_account_paths(results)
    
    def detect_identity_chains(self) -> List[Dict[str, Any]]:
        """Detect identity chaining paths"""
        query = AttackPathTemplate.identity_chaining()
        results = self.connection.execute_query(query)
        return self._format_identity_chains(results)
    
    def detect_all_paths(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run all detection queries"""
        return {
            "privilege_escalation": self.detect_privilege_escalation(),
            "public_exposure": self.detect_public_exposure(),
            "cross_account": self.detect_cross_account_paths(),
            "identity_chains": self.detect_identity_chains(),
        }
    
    def _format_attack_paths(self, results, path_type: AttackPathType) -> List[Dict[str, Any]]:
        """Format attack path results"""
        paths = []
        for result in results:
            path = {
                "path_id": f"{path_type.value}_{result['source_node_id']}_{result['target_node_id']}",
                "type": path_type.value,
                "source": result['source_node_id'],
                "target": result['target_node_id'],
                "nodes": result['node_ids'],
                "relationships": result['relationship_types'],
                "hop_count": result['hop_count'],
                "risk_score": result.get('total_risk_score', 0),
                "providers": list(set([n.split("::")[0] for n in result['node_ids']])),
                "timestamp": datetime.utcnow().isoformat()
            }
            paths.append(path)
        return paths
    
    def _format_public_exposure(self, results) -> List[Dict[str, Any]]:
        """Format public exposure results"""
        exposures = []
        for result in results:
            exposure = {
                "resource_id": result['resource_id'],
                "resource_type": result['resource_type'],
                "public_access": result['public_access'],
                "internet_facing": result['internet_facing'],
                "accessible_by": result['accessible_by'],
                "criticality": result['criticality_score'],
                "risk_level": "HIGH" if result['public_access'] else "MEDIUM" if result['internet_facing'] else "LOW",
                "timestamp": datetime.utcnow().isoformat()
            }
            exposures.append(exposure)
        return exposures
    
    def _format_cross_account_paths(self, results) -> List[Dict[str, Any]]:
        """Format cross-account path results"""
        paths = []
        for result in results:
            path = {
                "source_account": result['source_account'],
                "target_account": result['target_account'],
                "role_chain": result['role_chain'],
                "hop_count": result['hop_count'],
                "providers": ["aws"],  # Currently AWS-specific
                "timestamp": datetime.utcnow().isoformat()
            }
            paths.append(path)
        return paths
    
    def _format_identity_chains(self, results) -> List[Dict[str, Any]]:
        """Format identity chain results"""
        chains = []
        for result in results:
            chain = {
                "identity_chain": result['identity_chain'],
                "providers": result['providers'],
                "provider_count": result['provider_count'],
                "chain_length": result['chain_length'],
                "cross_cloud": result['provider_count'] > 1,
                "timestamp": datetime.utcnow().isoformat()
            }
            chains.append(chain)
        return chains
    
    def detect_and_alert(self, alert_manager: Optional[AlertManager] = None, 
                        min_severity: str = "HIGH"):
        """Detect attack paths and send alerts"""
        paths = self.detect_privilege_escalation()
        
        if alert_manager and paths:
            alert_manager.send_attack_path_alerts(paths, min_severity)
        
        return paths

    def find_paths_between(self, source_id: str, target_id: str, max_hops: int = 5) -> List[Dict[str, Any]]:
        """Find all paths between two nodes"""
        # Build query with literal max_hops
        query = f"""
        MATCH path = (source)-[*1..{max_hops}]->(target)
        WHERE source.node_id = $source_id
        AND target.node_id = $target_id
        AND ALL(r IN relationships(path) WHERE r.valid_to IS NULL)
        RETURN 
            [node IN nodes(path) | node.node_id] as nodes,
            [r IN relationships(path) | type(r)] as relationships,
            length(path) as hop_count,
            reduce(risk = 0, n IN nodes(path) | risk + COALESCE(n.risk_score, 0)) as total_risk
        ORDER BY hop_count, total_risk DESC
        LIMIT 10
        """
        
        results = self.connection.execute_query(query, {
            "source_id": source_id,
            "target_id": target_id
        })
        
        paths = []
        for i, result in enumerate(results):
            path = {
                "path_id": f"custom_{source_id}_{target_id}_{i}",
                "source": source_id,
                "target": target_id,
                "nodes": result['nodes'],
                "relationships": result['relationships'],
                "hop_count": result['hop_count'],
                "risk_score": result['total_risk'],
                "providers": list(set([n.split("::")[0] for n in result['nodes']])),
                "timestamp": datetime.utcnow().isoformat()
            }
            paths.append(path)
        
        return paths

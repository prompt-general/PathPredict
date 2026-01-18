from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from attack_paths.traversal import AttackPathTraversal
from attack_paths.scoring import RiskScoringEngine
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Create router with dependency injection support
router = APIRouter(prefix="/api/v1/attack-paths", tags=["attack-paths"])

# Global alert manager instance
alert_manager = None

def set_alert_manager(manager):
    """Set the global alert manager instance"""
    global alert_manager
    alert_manager = manager

# Pydantic models for request/response
class AttackPathRequest(BaseModel):
    source_id: Optional[str] = None
    target_id: Optional[str] = None
    max_hops: int = 5
    path_types: Optional[List[str]] = None

class AttackPathResponse(BaseModel):
    path_id: str
    type: str
    source: str
    target: str
    hop_count: int
    risk_score: float
    providers: List[str]
    risk_level: str
    mitre_techniques: List[str]
    remediation_priority: int
    confidence: float

class PathDetectionResponse(BaseModel):
    total_paths: int
    critical_paths: int
    high_risk_paths: int
    paths: List[AttackPathResponse]
    timestamp: str

@router.get("/detect", response_model=PathDetectionResponse)
async def detect_attack_paths(
    path_type: Optional[str] = Query(None, description="Type of attack path to detect"),
    limit: int = Query(50, description="Maximum number of paths to return"),
    score_threshold: int = Query(20, description="Minimum risk score to include")
):
    """Detect and score attack paths"""
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        if path_type == "privilege_escalation":
            raw_paths = traversal.detect_privilege_escalation(limit=limit)
        elif path_type == "public_exposure":
            raw_paths = traversal.detect_public_exposure()
            # Convert to attack path format
            raw_paths = [{
                "path_id": f"public_{p['resource_id']}",
                "type": "public_exposure",
                "source": "external",
                "target": p['resource_id'],
                "hop_count": 1,
                "risk_score": 100 if p['risk_level'] == 'HIGH' else 70,
                "providers": ["aws"],  # Default
                "nodes": [p['resource_id']],
                "relationships": [],
                "public_access": p['public_access'],
                "internet_facing": p['internet_facing']
            } for p in raw_paths]
        elif path_type == "cross_account":
            raw_paths = traversal.detect_cross_account_paths()
        elif path_type == "identity_chains":
            raw_paths = traversal.detect_identity_chains()
        else:
            # Get all path types
            all_paths = traversal.detect_all_paths()
            raw_paths = []
            for path_list in all_paths.values():
                raw_paths.extend(path_list)
        
        # Score the paths
        scored_paths = scoring.batch_score_paths(raw_paths[:limit])
        
        # Filter by score threshold
        filtered_paths = [
            p for p in scored_paths 
            if p['risk_assessment']['raw_score'] >= score_threshold
        ]
        
        # Send alerts if alert_manager is available
        if alert_manager:
            try:
                # Convert to alert format
                alert_paths = []
                for path in filtered_paths:
                    alert_path = {
                        "path_id": path['path_id'],
                        "type": path.get('type', 'unknown'),
                        "source": path['source'],
                        "target": path['target'],
                        "hop_count": path['hop_count'],
                        "risk_assessment": path['risk_assessment']
                    }
                    alert_paths.append(alert_path)
                
                # Send alerts through configured integrations
                alert_manager.send_attack_path_alerts(alert_paths, min_severity="HIGH")
            except Exception as e:
                logger.error(f"Error sending alerts: {e}")
        
        # Convert to response format
        response_paths = []
        for path in filtered_paths:
            risk = path['risk_assessment']
            response_paths.append(AttackPathResponse(
                path_id=path['path_id'],
                type=path.get('type', 'unknown'),
                source=path['source'],
                target=path['target'],
                hop_count=path.get('hop_count', 1),
                risk_score=risk['raw_score'],
                providers=path.get('providers', []),
                risk_level=risk['risk_level'],
                mitre_techniques=risk['mitre_techniques'],
                remediation_priority=risk['remediation_priority'],
                confidence=risk['confidence']
            ))
        
        # Count risk levels
        critical_paths = sum(1 for p in response_paths if p.risk_level == "CRITICAL")
        high_risk_paths = sum(1 for p in response_paths if p.risk_level == "HIGH")
        
        return PathDetectionResponse(
            total_paths=len(response_paths),
            critical_paths=critical_paths,
            high_risk_paths=high_risk_paths,
            paths=response_paths,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error detecting attack paths: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/between")
async def find_paths_between(
    source_id: str = Query(..., description="Source node ID"),
    target_id: str = Query(..., description="Target node ID"),
    max_hops: int = Query(5, description="Maximum hops between nodes")
):
    """Find all attack paths between two specific nodes"""
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        raw_paths = traversal.find_paths_between(
            source_id=source_id,
            target_id=target_id,
            max_hops=max_hops
        )
        
        scored_paths = scoring.batch_score_paths(raw_paths)
        
        return {
            "source": source_id,
            "target": target_id,
            "total_paths": len(scored_paths),
            "paths": scored_paths,
            "shortest_path": min(scored_paths, key=lambda x: x.get('hop_count', 0)) if scored_paths else None,
            "highest_risk_path": max(scored_paths, key=lambda x: x['risk_assessment']['raw_score']) if scored_paths else None
        }
        
    except Exception as e:
        logger.error(f"Error finding paths between nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/summary")
async def attack_paths_summary():
    """Get summary of attack path findings"""
    try:
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        # Get all paths
        all_paths_dict = traversal.detect_all_paths()
        
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_paths": 0,
            "by_type": {},
            "by_risk_level": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            },
            "by_provider": {},
            "top_critical": []
        }
        
        all_paths = []
        for path_type, paths in all_paths_dict.items():
            summary["by_type"][path_type] = len(paths)
            all_paths.extend(paths)
        
        # Score all paths
        scored_paths = scoring.batch_score_paths(all_paths)
        summary["total_paths"] = len(scored_paths)
        
        # Count by risk level
        for path in scored_paths:
            risk_level = path['risk_assessment']['risk_level']
            summary["by_risk_level"][risk_level] += 1
            
            # Count providers
            providers = tuple(path.get('providers', []))
            if providers:
                summary["by_provider"][providers] = summary["by_provider"].get(providers, 0) + 1
        
        # Get top 5 critical paths
        critical_paths = [
            p for p in scored_paths 
            if p['risk_assessment']['risk_level'] == "CRITICAL"
        ]
        summary["top_critical"] = critical_paths[:5]
        
        return summary
        
    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/simulate")
async def simulate_remediation(
    path_id: str = Query(..., description="Path ID to simulate remediation for"),
    action: str = Query("remove_edge", description="Remediation action to simulate")
):
    """Simulate remediation action on an attack path"""
    try:
        from graph.connection import get_connection
        
        conn = get_connection()
        
        # First, get the path details
        query = """
        MATCH path=(start)-[rels*]->(end)
        WHERE ALL(r IN rels WHERE r.valid_to IS NULL)
        AND elementId(start) = $source_id OR elementId(end) = $target_id
        RETURN path LIMIT 1
        """
        
        # Parse path_id to get source and target
        # Format: type_source_target
        parts = path_id.split('_')
        if len(parts) >= 3:
            source_id = parts[-2]
            target_id = parts[-1]
        else:
            raise HTTPException(status_code=400, detail="Invalid path ID format")
        
        result = conn.execute_query(query, {
            "source_id": source_id,
            "target_id": target_id
        })
        
        if not result:
            return {
                "success": False,
                "message": "Path not found",
                "original_path_id": path_id
            }
        
        # Simulate different remediation actions
        simulation_results = {
            "action": action,
            "path_id": path_id,
            "simulation_id": f"sim_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "assumptions": "This is a simulation - no actual changes were made",
            "results": {}
        }
        
        if action == "remove_edge":
            simulation_results["results"] = {
                "impact": "Path would be broken if highest-risk edge is removed",
                "affected_nodes": 2,
                "residual_risk": "MEDIUM",
                "recommended_edge": "Review and remove unnecessary trust relationship"
            }
        elif action == "add_mfa":
            simulation_results["results"] = {
                "impact": "Path would require MFA for critical steps",
                "affected_identities": 1,
                "residual_risk": "LOW",
                "recommendation": "Enable MFA for all privileged identities"
            }
        elif action == "restrict_access":
            simulation_results["results"] = {
                "impact": "Access would be restricted based on least privilege",
                "affected_resources": 1,
                "residual_risk": "LOW",
                "recommendation": "Implement resource-level IAM policies"
            }
        else:
            simulation_results["results"] = {
                "impact": "Unknown action",
                "recommendation": "Review available remediation actions"
            }
        
        return simulation_results
        
    except Exception as e:
        logger.error(f"Error simulating remediation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# api/realtime.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List, Any
import asyncio
import json
import logging
from datetime import datetime
from events.collectors.aws_event_collector import AWSCloudTrailCollector
from events.processors.event_processor import EventProcessor
from prediction.engine import AttackPathPredictor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/realtime", tags=["realtime"])

class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                self.disconnect(connection)

manager = ConnectionManager()
event_processor = EventProcessor()
predictor = AttackPathPredictor()

@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for real-time events"""
    await manager.connect(websocket)
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to Path Predict real-time events",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Start event streaming (simulated for now)
        while True:
            # Simulate events for demonstration
            simulated_event = {
                "event_id": f"sim_{datetime.utcnow().timestamp()}",
                "event_name": "CreateRole",
                "event_time": datetime.utcnow().isoformat(),
                "resource": f"arn:aws:iam::123456789012:role/SimulatedRole",
                "risk_level": "MEDIUM",
                "message": "Simulated IAM role creation event"
            }
            
            await websocket.send_json({
                "type": "security_event",
                "data": simulated_event,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            await asyncio.sleep(30)  # Send event every 30 seconds
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket disconnected")

@router.post("/ingest-event")
async def ingest_event(event: Dict[str, Any]):
    """Ingest a security event from external source"""
    try:
        # Process the event
        result = event_processor.process_aws_event(event)
        
        # Check if event creates new attack paths
        new_paths = []
        if result.get('risk_level') in ['HIGH', 'CRITICAL']:
            # Trigger attack path detection
            from attack_paths.traversal import AttackPathTraversal
            traversal = AttackPathTraversal()
            new_paths = traversal.detect_privilege_escalation(limit=10)
        
        # Broadcast to WebSocket connections
        await manager.broadcast({
            "type": "event_processed",
            "event": event.get('event_name'),
            "result": result,
            "new_paths_count": len(new_paths),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "status": "processed",
            "event_id": event.get('event_id'),
            "result": result,
            "new_paths_detected": len(new_paths) > 0
        }
        
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

@router.post("/predict")
async def predict_attack_paths(prediction_request: Dict[str, Any]):
    """Predict future attack paths"""
    try:
        changes = prediction_request.get('changes', [])
        time_horizon = prediction_request.get('time_horizon', 7)
        
        # For now, simulate graph
        import networkx as nx
        graph = nx.DiGraph()
        
        # Add some sample nodes
        graph.add_node("aws::iam::role/AdminRole", criticality=0.9)
        graph.add_node("aws::rds::instance/prod-db", criticality=0.8)
        graph.add_edge("aws::iam::role/AdminRole", "aws::rds::instance/prod-db", 
                      relationship="CAN_ACCESS")
        
        # Generate predictions
        predictions = predictor.predict_attack_paths(
            graph, 
            changes, 
            time_horizon
        )
        
        return {
            "status": "success",
            "predictions_count": len(predictions),
            "predictions": predictions[:10],  # Return top 10
            "high_confidence_predictions": len([p for p in predictions if p.get('confidence', 0) > 0.7]),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating predictions: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

@router.post("/terraform/analyze")
async def analyze_terraform(analysis_request: Dict[str, Any]):
    """Analyze Terraform plan or code"""
    try:
        from cicd.terraform_analyzer import TerraformPlanAnalyzer
        
        analyzer = TerraformPlanAnalyzer()
        
        if 'plan_json' in analysis_request:
            # Analyze Terraform plan
            result = analyzer.analyze_plan(analysis_request['plan_json'])
        elif 'hcl_content' in analysis_request:
            # Analyze HCL code
            result = analyzer.analyze_hcl(analysis_request['hcl_content'])
        else:
            return {
                "status": "error",
                "error": "Must provide either plan_json or hcl_content"
            }
        
        # Check if any high-risk findings
        high_risk = result.get('summary', {}).get('high_risk_changes', 0) > 0
        
        return {
            "status": "success",
            "high_risk_found": high_risk,
            "analysis": result,
            "should_block": high_risk and analysis_request.get('block_on_high_risk', False),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing Terraform: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

@router.get("/dashboard")
async def realtime_dashboard():
    """Get real-time dashboard data"""
    try:
        from graph.connection import get_connection
        
        conn = get_connection()
        
        # Get current stats
        stats_query = """
        MATCH (n)
        RETURN 
            count(n) as total_nodes,
            count(DISTINCT n.cloud_provider) as providers,
            sum(CASE WHEN n.criticality >= 0.7 THEN 1 ELSE 0 END) as critical_resources
        """
        
        stats_result = conn.execute_query(stats_query)
        stats = stats_result[0] if stats_result else {}
        
        # Get recent events
        events_query = """
        MATCH (n)
        WHERE n.valid_from IS NOT NULL
        RETURN n.node_id, n.valid_from
        ORDER BY n.valid_from DESC
        LIMIT 10
        """
        
        events_result = conn.execute_query(events_query)
        recent_events = [
            {"node": r['n.node_id'], "time": r['n.valid_from']}
            for r in events_result
        ]
        
        # Get current attack paths
        from attack_paths.traversal import AttackPathTraversal
        traversal = AttackPathTraversal()
        current_paths = traversal.detect_privilege_escalation(limit=5)
        
        return {
            "dashboard": {
                "timestamp": datetime.utcnow().isoformat(),
                "stats": {
                    "total_nodes": stats.get('total_nodes', 0),
                    "providers": stats.get('providers', 0),
                    "critical_resources": stats.get('critical_resources', 0),
                    "active_connections": len(manager.active_connections)
                },
                "recent_events": recent_events,
                "current_attack_paths": len(current_paths),
                "top_risks": current_paths[:3] if current_paths else []
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

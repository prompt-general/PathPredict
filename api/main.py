from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import strawberry
from strawberry.fastapi import GraphQLRouter
from typing import List, Optional
from pydantic import BaseModel
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Path Predict API",
    description="Multi-Cloud Attack Path Prediction Platform",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import attack paths router
from api.attack_paths import router as attack_paths_router

# Add attack paths router
app.include_router(attack_paths_router)

# Health check endpoint
@app.get("/")
async def root():
    return {
        "status": "active",
        "service": "Path Predict API",
        "version": "0.1.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        from graph.connection import get_connection
        conn = get_connection()
        # Test Neo4j connection
        result = conn.execute_query("RETURN 1 as test")
        neo4j_status = "healthy" if result else "unhealthy"
    except Exception as e:
        neo4j_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "neo4j": neo4j_status,
        "timestamp": datetime.utcnow().isoformat()
    }

# GraphQL schema
@strawberry.type
class AttackPath:
    path_id: str
    source: str
    target: str
    score: float
    steps: List[str]
    cloud_providers: List[str]

@strawberry.type
class Query:
    @strawberry.field
    def attack_paths(self, limit: int = 10) -> List[AttackPath]:
        """Get current attack paths"""
        from graph.connection import get_connection
        
        query = """
        MATCH path=(start:Identity)-[:CAN_ASSUME|CAN_ACCESS*1..3]->(target:Resource)
        WHERE target.criticality >= 0.7
        RETURN 
            elementId(start) as source_id,
            elementId(target) as target_id,
            [node in nodes(path) | node.node_id] as steps,
            length(path) as hop_count
        LIMIT $limit
        """
        
        conn = get_connection()
        results = conn.execute_query(query, {"limit": limit})
        
        paths = []
        for result in results:
            paths.append(AttackPath(
                path_id=f"path_{result['source_id']}_{result['target_id']}",
                source=result['source_id'],
                target=result['target_id'],
                score=1.0 / (result['hop_count'] or 1),  # Simple scoring
                steps=result['steps'],
                cloud_providers=["aws"]  # TODO: Detect from nodes
            ))
        
        return paths

# Create GraphQL schema
schema = strawberry.Schema(query=Query)

# Add GraphQL endpoint
graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")

# REST endpoints
@app.get("/api/v1/accounts")
async def list_accounts():
    """List all cloud accounts in the graph"""
    from graph.connection import get_connection
    
    query = """
    MATCH (a:Account)
    RETURN a.account_id, a.cloud_provider, a.name
    ORDER BY a.cloud_provider
    """
    
    conn = get_connection()
    results = conn.execute_query(query)
    
    return {
        "accounts": [
            {
                "account_id": r["a.account_id"],
                "cloud_provider": r["a.cloud_provider"],
                "name": r.get("a.name", "Unknown")
            }
            for r in results
        ]
    }

# Add a new health check endpoint for attack paths
@app.get("/api/v1/attack-paths/health")
async def attack_paths_health():
    """Health check for attack path engine"""
    try:
        from attack_paths.traversal import AttackPathTraversal
        from attack_paths.scoring import RiskScoringEngine
        
        traversal = AttackPathTraversal()
        scoring = RiskScoringEngine()
        
        # Test with a simple query
        test_paths = traversal.detect_privilege_escalation(limit=1)
        
        return {
            "status": "healthy",
            "components": {
                "traversal_engine": "ok",
                "scoring_engine": "ok",
                "graph_connection": "ok"
            },
            "test_paths_found": len(test_paths) > 0,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

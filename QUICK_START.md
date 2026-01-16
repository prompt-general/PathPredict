# Path Predict - Quick Start Guide

## 🚀 Getting Started

1. **Start the database and API:**
   ```bash
   docker-compose up -d
   python -m cli.main init
   ```

2. **Create sample attack graph:**
   ```bash
   python tests/sample_data.py
   ```

3. **Explore attack paths:**
   ```bash
   # Detect all attack paths
   python -m cli.main paths detect

   # Find paths between specific nodes
   python -m cli.main paths find \
     --source "aws::iam::user/ExternalContractor" \
     --target "aws::rds::instance/prod-database-1"

   # Get summary
   python -m cli.main paths summary
   ```

4. **Use the API:**
   ```bash
   # List detected attack paths
   curl http://localhost:8000/api/v1/attack-paths/detect?limit=5

   # Get summary
   curl http://localhost:8000/api/v1/attack-paths/summary

   # GraphQL endpoint
   curl -X POST http://localhost:8000/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "{ attackPaths(limit: 5) { pathId source target score } }"}'
   ```

5. **View in Neo4j Browser:**

   Open http://localhost:7474

   Login: neo4j/pathpredict123

   Try these queries:

   ```cypher
   // Find all attack paths
   MATCH path=(i:Identity)-[:CAN_ASSUME|CAN_ACCESS*1..3]->(r:Resource)
   WHERE r.criticality >= 0.7
   RETURN path LIMIT 10

   // Find publicly exposed resources
   MATCH (r:Resource)
   WHERE r.public_access = true OR r.internet_facing = true
   RETURN r.node_id, r.subtype, r.criticality
   ```

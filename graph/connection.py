from neo4j import GraphDatabase
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Neo4jConnection:
    """Manages Neo4j database connection"""
    
    def __init__(self, uri: str, username: str, password: str):
        self._uri = uri
        self._username = username
        self._password = password
        self._driver = None
        self._init_driver()
    
    def _init_driver(self):
        """Initialize Neo4j driver"""
        try:
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._username, self._password),
                max_connection_lifetime=3600,
                connection_acquisition_timeout=300
            )
            # Verify connection
            self._driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {self._uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self):
        """Close the database connection"""
        if self._driver:
            self._driver.close()
            logger.info("Neo4j connection closed")
    
    def execute_query(self, query: str, parameters: dict = None, **kwargs):
        """Execute a Cypher query"""
        with self._driver.session() as session:
            result = session.run(query, parameters or {}, **kwargs)
            return list(result)
    
    def create_constraints_and_indexes(self):
        """Create schema constraints and indexes"""
        from graph.schema import GraphSchema
        
        logger.info("Creating Neo4j constraints and indexes...")
        
        # Create constraints
        for constraint in GraphSchema.CONSTRAINTS:
            query = f"""
            CREATE CONSTRAINT IF NOT EXISTS 
            FOR (n:{constraint['label']}) 
            REQUIRE n.{constraint['property']} IS UNIQUE
            """
            self.execute_query(query)
            logger.info(f"Created constraint on {constraint['label']}.{constraint['property']}")
        
        # Create indexes
        for index in GraphSchema.INDEXES:
            query = f"""
            CREATE INDEX IF NOT EXISTS 
            FOR (n:{index['label']}) 
            ON (n.{index['property']})
            """
            self.execute_query(query)
            logger.info(f"Created index on {index['label']}.{index['property']}")
        
        logger.info("Schema setup completed")


# Singleton instance
_connection: Optional[Neo4jConnection] = None

def get_connection() -> Neo4jConnection:
    """Get or create Neo4j connection singleton"""
    global _connection
    if _connection is None:
        import os
        from dotenv import load_dotenv
        
        load_dotenv()
        
        _connection = Neo4jConnection(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            username=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "pathpredict123")
        )
        # Initialize schema
        _connection.create_constraints_and_indexes()
    
    return _connection

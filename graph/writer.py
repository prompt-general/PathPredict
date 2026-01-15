from datetime import datetime
from typing import List, Optional
import logging
from graph.schema import UnifiedNode, UnifiedRelationship
from graph.connection import get_connection

logger = logging.getLogger(__name__)


class TimeVersionedWriter:
    """Implements time-versioned graph writes"""
    
    def __init__(self, graph_version: str = "v1"):
        self.graph_version = graph_version
        self.connection = get_connection()
    
    def write_node(self, node: UnifiedNode) -> bool:
        """Write a node with time-versioning"""
        
        # Generate timestamp for this write
        valid_from = node.valid_from or datetime.utcnow()
        
        # First, close any existing active version
        close_query = """
        MATCH (n {node_id: $node_id})
        WHERE n.valid_to IS NULL AND n.valid_from IS NOT NULL
        SET n.valid_to = $valid_from
        RETURN n.node_id
        """
        self.connection.execute_query(close_query, {
            "node_id": node.node_id,
            "valid_from": valid_from
        })
        
        # Create new version
        create_query = """
        CREATE (n:%s:%s {
            node_id: $node_id,
            subtype: $subtype,
            cloud_provider: $cloud_provider,
            account_id: $account_id,
            region: $region,
            graph_version: $graph_version,
            valid_from: $valid_from,
            valid_to: NULL
        })
        SET n += $properties
        RETURN n.node_id
        """ % (node.node_type.value, node.subtype)
        
        result = self.connection.execute_query(create_query, {
            "node_id": node.node_id,
            "subtype": node.subtype,
            "cloud_provider": node.cloud_provider,
            "account_id": node.account_id,
            "region": node.region,
            "graph_version": self.graph_version,
            "valid_from": valid_from,
            "properties": node.properties
        })
        
        logger.debug(f"Wrote node: {node.node_id}")
        return len(result) > 0
    
    def write_relationship(self, rel: UnifiedRelationship) -> bool:
        """Write a relationship with time-versioning"""
        
        valid_from = rel.valid_from or datetime.utcnow()
        
        # Close existing relationship
        close_query = """
        MATCH (source {node_id: $source_id})
        MATCH (target {node_id: $target_id})
        MATCH (source)-[r:%s]->(target)
        WHERE r.valid_to IS NULL AND r.valid_from IS NOT NULL
        SET r.valid_to = $valid_from
        RETURN r
        """ % rel.relationship_type.value
        
        self.connection.execute_query(close_query, {
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "valid_from": valid_from
        })
        
        # Create new relationship
        create_query = """
        MATCH (source {node_id: $source_id})
        MATCH (target {node_id: $target_id})
        CREATE (source)-[r:%s {
            valid_from: $valid_from,
            valid: NULL
        }]->(target)
        SET r += $properties
        RETURN r
        """ % rel.relationship_type.value
        
        result = self.connection.execute_query(create_query, {
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "valid_from": valid_from,
            "properties": rel.properties
        })
        
        logger.debug(f"Wrote relationship: {rel.source_id} -> {rel.target_id}")
        return len(result) > 0

# prediction/feature_engineer.py
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
from graph.connection import get_connection
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

class MLFeatureEngineer:
    """Feature engineering for ML models"""
    
    def __init__(self):
        self.conn = get_connection()
        self.cache = {}
    
    def extract_graph_features(self, 
                             node_ids: Optional[List[str]] = None,
                             time_window_days: int = 30) -> pd.DataFrame:
        """Extract features from graph for ML training"""
        
        # Get time window
        cutoff_time = (datetime.utcnow() - timedelta(days=time_window_days)).isoformat()
        
        # Build NetworkX graph from Neo4j
        graph = self._build_subgraph(node_ids, cutoff_time)
        
        features = []
        
        # Node-level features
        for node, data in graph.nodes(data=True):
            node_features = self._extract_node_features(graph, node, data)
            features.append(node_features)
        
        # Graph-level features
        graph_features = self._extract_graph_level_features(graph)
        
        return pd.DataFrame(features), graph_features
    
    def _build_subgraph(self, 
                       node_ids: Optional[List[str]], 
                       cutoff_time: str) -> nx.DiGraph:
        """Build NetworkX graph from Neo4j data"""
        graph = nx.DiGraph()
        
        if node_ids:
            # Fetch specific nodes and their relationships
            query = """
            MATCH (n)
            WHERE n.node_id IN $node_ids AND n.valid_from >= $cutoff_time
            OPTIONAL MATCH (n)-[r]->(m)
            WHERE r.valid_from >= $cutoff_time
            RETURN n, r, m
            """
            params = {"node_ids": node_ids, "cutoff_time": cutoff_time}
        else:
            # Fetch all recent nodes
            query = """
            MATCH (n)-[r]->(m)
            WHERE n.valid_from >= $cutoff_time AND r.valid_from >= $cutoff_time
            RETURN n, r, m
            LIMIT 5000
            """
            params = {"cutoff_time": cutoff_time}
        
        results = self.conn.execute_query(query, params)
        
        for result in results:
            n = result['n']
            r = result['r']
            m = result['m']
            
            if n:
                graph.add_node(n['node_id'], **dict(n))
            
            if m:
                graph.add_node(m['node_id'], **dict(m))
            
            if r and n and m:
                graph.add_edge(n['node_id'], m['node_id'], **dict(r))
        
        return graph
    
    def _extract_node_features(self, 
                              graph: nx.DiGraph, 
                              node: str, 
                              node_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for a single node"""
        features = {}
        
        # Basic node properties
        features['node_id'] = node
        features['node_type'] = node_data.get('type', 'unknown')
        features['cloud_provider'] = node_data.get('cloud_provider', 'unknown')
        features['risk_score'] = node_data.get('risk_score', 0.0)
        features['criticality'] = node_data.get('criticality', 0.0)
        features['public'] = float(node_data.get('public', False))
        
        # Graph structural features
        features['degree_centrality'] = graph.degree(node)
        features['in_degree'] = graph.in_degree(node)
        features['out_degree'] = graph.out_degree(node)
        
        # Neighbor features
        predecessors = list(graph.predecessors(node))
        successors = list(graph.successors(node))
        
        features['num_predecessors'] = len(predecessors)
        features['num_successors'] = len(successors)
        
        # Neighbor risk aggregation
        if predecessors:
            pred_risks = [graph.nodes[p].get('risk_score', 0.0) for p in predecessors]
            features['avg_predecessor_risk'] = np.mean(pred_risks)
            features['max_predecessor_risk'] = np.max(pred_risks)
        else:
            features['avg_predecessor_risk'] = 0.0
            features['max_predecessor_risk'] = 0.0
        
        # Path-based features
        features['shortest_path_to_critical'] = self._shortest_path_to_critical(graph, node)
        features['reachable_critical_nodes'] = self._count_reachable_critical_nodes(graph, node)
        
        # Temporal features
        create_time = node_data.get('valid_from')
        if create_time:
            if isinstance(create_time, str):
                try:
                    create_dt = datetime.fromisoformat(create_time.replace('Z', '+00:00'))
                    days_since_creation = (datetime.utcnow() - create_dt).days
                    features['days_since_creation'] = days_since_creation
                except:
                    features['days_since_creation'] = 30
            else:
                features['days_since_creation'] = 30
        
        # Privilege features
        features['privilege_level'] = self._calculate_privilege_level(node_data)
        
        # Connectivity features
        features['betweenness_centrality'] = nx.betweenness_centrality(graph).get(node, 0.0)
        
        return features
    
    def _extract_graph_level_features(self, graph: nx.DiGraph) -> Dict[str, Any]:
        """Extract graph-level features"""
        features = {}
        
        if len(graph.nodes()) == 0:
            return features
        
        features['num_nodes'] = len(graph.nodes())
        features['num_edges'] = len(graph.edges())
        features['graph_density'] = nx.density(graph)
        
        # Connected components
        if nx.is_weakly_connected(graph):
            features['is_connected'] = 1.0
        else:
            features['is_connected'] = 0.0
        
        # Risk aggregation
        risk_scores = [data.get('risk_score', 0.0) for _, data in graph.nodes(data=True)]
        features['avg_risk_score'] = np.mean(risk_scores)
        features['max_risk_score'] = np.max(risk_scores)
        features['risk_variance'] = np.var(risk_scores)
        
        # Critical nodes
        critical_nodes = [n for n, data in graph.nodes(data=True) 
                         if data.get('criticality', 0.0) > 0.7]
        features['num_critical_nodes'] = len(critical_nodes)
        features['critical_node_ratio'] = len(critical_nodes) / len(graph.nodes())
        
        # Cross-cloud edges
        cross_cloud_edges = 0
        for u, v in graph.edges():
            u_provider = graph.nodes[u].get('cloud_provider', 'unknown')
            v_provider = graph.nodes[v].get('cloud_provider', 'unknown')
            if u_provider != v_provider:
                cross_cloud_edges += 1
        
        features['cross_cloud_edges'] = cross_cloud_edges
        features['cross_cloud_ratio'] = cross_cloud_edges / max(len(graph.edges()), 1)
        
        return features
    
    def _shortest_path_to_critical(self, 
                                  graph: nx.DiGraph, 
                                  start_node: str) -> float:
        """Calculate shortest path to any critical node"""
        try:
            critical_nodes = [n for n, data in graph.nodes(data=True) 
                            if data.get('criticality', 0.0) > 0.7]
            
            if not critical_nodes:
                return 0.0
            
            shortest_paths = []
            for critical_node in critical_nodes:
                try:
                    path_length = nx.shortest_path_length(graph, start_node, critical_node)
                    shortest_paths.append(path_length)
                except nx.NetworkXNoPath:
                    continue
            
            if shortest_paths:
                return min(shortest_paths)
            else:
                return 0.0
        except:
            return 0.0
    
    def _count_reachable_critical_nodes(self, 
                                       graph: nx.DiGraph, 
                                       start_node: str) -> int:
        """Count critical nodes reachable from start node"""
        try:
            reachable_nodes = nx.descendants(graph, start_node)
            critical_nodes = [n for n, data in graph.nodes(data=True) 
                            if data.get('criticality', 0.0) > 0.7]
            
            return len(set(reachable_nodes) & set(critical_nodes))
        except:
            return 0
    
    def _calculate_privilege_level(self, node_data: Dict[str, Any]) -> float:
        """Calculate privilege level based on node properties"""
        privilege_score = 0.0
        
        node_type = node_data.get('type', '').lower()
        
        # Identity nodes
        if 'admin' in str(node_data.get('name', '')).lower():
            privilege_score += 0.8
        if 'owner' in str(node_data.get('name', '')).lower():
            privilege_score += 0.9
        
        # Resource nodes
        if node_data.get('public', False):
            privilege_score += 0.3
        if node_data.get('internet_facing', False):
            privilege_score += 0.4
        
        # Policy nodes
        if node_data.get('permissions'):
            perms = str(node_data['permissions'])
            if '*' in perms or 'full' in perms.lower():
                privilege_score += 0.7
        
        return min(1.0, privilege_score)
    
    def create_training_dataset(self, 
                               time_window_days: int = 90,
                               sample_size: int = 1000) -> pd.DataFrame:
        """Create training dataset from historical data"""
        
        # Query historical attack paths
        query = """
        MATCH (ap:AttackPath)
        WHERE ap.valid_from >= datetime() - duration({days: $days})
        OPTIONAL MATCH (ap)-[:CONTAINS]->(n)
        RETURN ap.path_id as path_id,
               ap.risk_score as path_risk,
               ap.was_exploited as was_exploited,
               collect(DISTINCT n.node_id) as node_ids,
               ap.valid_from as detection_time
        ORDER BY ap.valid_from DESC
        LIMIT $limit
        """
        
        params = {
            "days": time_window_days,
            "limit": sample_size
        }
        
        results = self.conn.execute_query(query, params)
        
        dataset = []
        
        for result in results:
            path_id = result['path_id']
            path_risk = result['path_risk'] or 0.0
            was_exploited = result['was_exploited'] or False
            node_ids = result['node_ids']
            detection_time = result['detection_time']
            
            if not node_ids:
                continue
            
            # Extract features for nodes in this path
            features_df, graph_features = self.extract_graph_features(node_ids)
            
            if not features_df.empty:
                # Aggregate node features
                aggregated_features = {
                    'path_id': path_id,
                    'path_risk': path_risk,
                    'was_exploited': float(was_exploited),
                    'num_nodes': len(features_df),
                    'avg_node_risk': features_df['risk_score'].mean(),
                    'max_node_risk': features_df['risk_score'].max(),
                    'avg_criticality': features_df['criticality'].mean(),
                    'avg_degree': features_df['degree_centrality'].mean(),
                    'max_degree': features_df['degree_centrality'].max(),
                    'has_public_nodes': float((features_df['public'] > 0).any()),
                    'detection_hour': detection_time.hour if detection_time else 12
                }
                
                # Add graph features
                aggregated_features.update(graph_features)
                
                dataset.append(aggregated_features)
        
        return pd.DataFrame(dataset)

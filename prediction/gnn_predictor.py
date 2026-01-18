# prediction/gnn_predictor.py
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv, global_mean_pool
from torch_geometric.data import Data, DataLoader
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import logging
import networkx as nx
from datetime import datetime
import joblib

logger = logging.getLogger(__name__)

class GNNAttackPredictor(nn.Module):
    """Graph Neural Network for attack path prediction"""
    
    def __init__(self, 
                 num_node_features: int = 32,
                 num_edge_features: int = 16,
                 hidden_channels: int = 128,
                 num_layers: int = 3,
                 dropout: float = 0.3):
        super(GNNAttackPredictor, self).__init__()
        
        self.num_node_features = num_node_features
        self.num_edge_features = num_edge_features
        self.hidden_channels = hidden_channels
        self.dropout = dropout
        
        # Node feature encoders
        self.node_encoder = nn.Sequential(
            nn.Linear(num_node_features, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, hidden_channels)
        )
        
        # Edge feature encoders
        self.edge_encoder = nn.Sequential(
            nn.Linear(num_edge_features, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # GNN layers
        self.convs = nn.ModuleList()
        for i in range(num_layers):
            if i == 0:
                conv = GATConv(hidden_channels, hidden_channels // 2, heads=2, dropout=dropout)
            else:
                conv = GATConv(hidden_channels, hidden_channels // 2, heads=2, dropout=dropout)
            self.convs.append(conv)
        
        # Global pooling
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        
        # Prediction heads
        self.path_prediction_head = nn.Sequential(
            nn.Linear(hidden_channels * 2, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
        
        self.vulnerability_prediction_head = nn.Sequential(
            nn.Linear(hidden_channels, hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels // 2, 1),
            nn.Sigmoid()
        )
        
        self.escalation_prediction_head = nn.Sequential(
            nn.Linear(hidden_channels * 3, hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, 1),
            nn.Sigmoid()
        )
    
    def forward(self, 
                x: torch.Tensor,
                edge_index: torch.Tensor,
                edge_attr: torch.Tensor,
                batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        """
        Forward pass through the GNN
        
        Args:
            x: Node features [num_nodes, num_node_features]
            edge_index: Graph connectivity [2, num_edges]
            edge_attr: Edge features [num_edges, num_edge_features]
            batch: Batch vector [num_nodes]
        
        Returns:
            Dictionary with predictions
        """
        # Encode node features
        x = self.node_encoder(x)
        
        # Encode edge features
        edge_embedding = self.edge_encoder(edge_attr)
        
        # Apply GNN layers
        for conv in self.convs:
            x = conv(x, edge_index, edge_embedding)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Global graph representation
        if batch is not None:
            graph_embedding = global_mean_pool(x, batch)
        else:
            graph_embedding = x.mean(dim=0, keepdim=True)
        
        # Make predictions
        path_predictions = self.path_prediction_head(
            torch.cat([x[:len(graph_embedding)], graph_embedding], dim=1)
        )
        
        vulnerability_predictions = self.vulnerability_prediction_head(x)
        
        # For escalation predictions, we need pair-wise features
        if batch is not None:
            escalation_preds = torch.zeros(len(graph_embedding), 1, device=x.device)
        else:
            escalation_preds = torch.zeros(1, 1, device=x.device)
        
        return {
            "path_probabilities": path_predictions,
            "vulnerability_scores": vulnerability_predictions,
            "escalation_probabilities": escalation_preds
        }

class GNNTrainingPipeline:
    """Pipeline for training and evaluating GNN models"""
    
    def __init__(self, 
                 model: Optional[GNNAttackPredictor] = None,
                 device: str = "cuda" if torch.cuda.is_available() else "cpu"):
        self.device = torch.device(device)
        self.model = model.to(self.device) if model else None
        self.optimizer = None
        self.scaler = torch.cuda.amp.GradScaler() if device == "cuda" else None
        
    def prepare_training_data(self, 
                            attack_graphs: List[nx.DiGraph],
                            labels: List[Dict[str, Any]]) -> List[Data]:
        """Convert NetworkX graphs to PyTorch Geometric Data objects"""
        data_list = []
        
        for graph, label_dict in zip(attack_graphs, labels):
            # Extract node features
            node_features = []
            for node, node_data in graph.nodes(data=True):
                features = self._extract_node_features(node_data)
                node_features.append(features)
            
            # Extract edge features
            edge_indices = []
            edge_features = []
            for src, dst, edge_data in graph.edges(data=True):
                edge_indices.append([src, dst])
                features = self._extract_edge_features(edge_data)
                edge_features.append(features)
            
            # Convert to tensors
            x = torch.tensor(node_features, dtype=torch.float)
            edge_index = torch.tensor(edge_indices, dtype=torch.long).t().contiguous()
            edge_attr = torch.tensor(edge_features, dtype=torch.float)
            
            # Create labels
            y_path = torch.tensor([label_dict.get('has_attack_path', 0.0)], dtype=torch.float)
            y_vuln = torch.tensor([label_dict.get('vulnerability_score', 0.0)], dtype=torch.float)
            y_escalation = torch.tensor([label_dict.get('escalation_risk', 0.0)], dtype=torch.float)
            
            data = Data(
                x=x,
                edge_index=edge_index,
                edge_attr=edge_attr,
                y_path=y_path,
                y_vuln=y_vuln,
                y_escalation=y_escalation
            )
            
            data_list.append(data)
        
        return data_list
    
    def _extract_node_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract features from node data"""
        features = []
        
        # Node type encoding
        node_type = node_data.get('type', 'unknown')
        type_encoding = self._encode_node_type(node_type)
        features.extend(type_encoding)
        
        # Risk score
        features.append(node_data.get('risk_score', 0.0))
        
        # Criticality
        features.append(node_data.get('criticality', 0.0))
        
        # Cloud provider encoding
        provider = node_data.get('cloud_provider', 'unknown')
        provider_encoding = self._encode_cloud_provider(provider)
        features.extend(provider_encoding)
        
        # Public exposure
        features.append(float(node_data.get('public', False)))
        features.append(float(node_data.get('internet_facing', False)))
        
        # Privilege level
        features.append(node_data.get('privilege_level', 0.0))
        
        # Last modified (recency)
        last_modified = node_data.get('last_modified', 0)
        features.append(self._normalize_timestamp(last_modified))
        
        # Fill missing features with zeros
        expected_length = 32  # Should match num_node_features in model
        if len(features) < expected_length:
            features.extend([0.0] * (expected_length - len(features)))
        
        return features[:32]
    
    def _extract_edge_features(self, edge_data: Dict[str, Any]) -> List[float]:
        """Extract features from edge data"""
        features = []
        
        # Relationship type encoding
        rel_type = edge_data.get('type', 'unknown')
        type_encoding = self._encode_relationship_type(rel_type)
        features.extend(type_encoding)
        
        # Trust level
        features.append(edge_data.get('trust_level', 0.5))
        
        # Is cross-cloud
        features.append(float(edge_data.get('cross_cloud', False)))
        
        # Is transitive
        features.append(float(edge_data.get('transitive', False)))
        
        # Permission scope
        features.append(edge_data.get('permission_scope', 0.0))
        
        # Fill missing features
        expected_length = 16  # Should match num_edge_features in model
        if len(features) < expected_length:
            features.extend([0.0] * (expected_length - len(features)))
        
        return features[:16]
    
    def _encode_node_type(self, node_type: str) -> List[float]:
        """One-hot encode node type"""
        types = ['Identity', 'Resource', 'Policy', 'Account', 'AttackPath']
        encoding = [1.0 if node_type == t else 0.0 for t in types]
        
        # Add unknown type handling
        if sum(encoding) == 0:
            encoding = [0.2] * len(types)
        
        return encoding
    
    def _encode_cloud_provider(self, provider: str) -> List[float]:
        """One-hot encode cloud provider"""
        providers = ['aws', 'azure', 'gcp', 'unknown']
        encoding = [1.0 if provider == p else 0.0 for p in providers]
        
        if sum(encoding) == 0:
            encoding = [0.25] * len(providers)
        
        return encoding
    
    def _encode_relationship_type(self, rel_type: str) -> List[float]:
        """One-hot encode relationship type"""
        types = ['CAN_ASSUME', 'CAN_ACCESS', 'CONTAINS', 'TRUSTS', 'MEMBER_OF']
        encoding = [1.0 if rel_type == t else 0.0 for t in types]
        
        if sum(encoding) == 0:
            encoding = [0.2] * len(types)
        
        return encoding
    
    def _normalize_timestamp(self, timestamp: Any) -> float:
        """Normalize timestamp to [0, 1] range"""
        try:
            if isinstance(timestamp, (int, float)):
                days_ago = (datetime.now().timestamp() - timestamp) / (60 * 60 * 24)
                return max(0.0, min(1.0, 1.0 - (days_ago / 365)))  # 1 year window
            return 0.5
        except:
            return 0.5
    
    def train(self, 
              train_data: List[Data],
              val_data: Optional[List[Data]] = None,
              epochs: int = 100,
              batch_size: int = 32,
              learning_rate: float = 0.001):
        """Train the GNN model"""
        if not self.model:
            self.model = GNNAttackPredictor().to(self.device)
        
        self.optimizer = torch.optim.Adam(
            self.model.parameters(), 
            lr=learning_rate,
            weight_decay=5e-4
        )
        
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, 
            mode='min',
            factor=0.5,
            patience=10,
            verbose=True
        )
        
        train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=batch_size) if val_data else None
        
        best_val_loss = float('inf')
        
        for epoch in range(epochs):
            # Training phase
            self.model.train()
            train_loss = 0.0
            
            for batch in train_loader:
                batch = batch.to(self.device)
                self.optimizer.zero_grad()
                
                # Forward pass
                outputs = self.model(batch.x, batch.edge_index, batch.edge_attr, batch.batch)
                
                # Compute losses
                loss_path = F.binary_cross_entropy(outputs['path_probabilities'], batch.y_path)
                loss_vuln = F.mse_loss(outputs['vulnerability_scores'].mean(), batch.y_vuln)
                loss_escalation = F.binary_cross_entropy(outputs['escalation_probabilities'], batch.y_escalation)
                
                total_loss = loss_path + 0.5 * loss_vuln + 0.3 * loss_escalation
                
                # Backward pass
                if self.scaler:
                    self.scaler.scale(total_loss).backward()
                    self.scaler.step(self.optimizer)
                    self.scaler.update()
                else:
                    total_loss.backward()
                    self.optimizer.step()
                
                train_loss += total_loss.item()
            
            avg_train_loss = train_loss / len(train_loader)
            
            # Validation phase
            if val_loader:
                self.model.eval()
                val_loss = 0.0
                
                with torch.no_grad():
                    for batch in val_loader:
                        batch = batch.to(self.device)
                        outputs = self.model(batch.x, batch.edge_index, batch.edge_attr, batch.batch)
                        
                        loss_path = F.binary_cross_entropy(outputs['path_probabilities'], batch.y_path)
                        loss_vuln = F.mse_loss(outputs['vulnerability_scores'].mean(), batch.y_vuln)
                        total_loss = loss_path + 0.5 * loss_vuln
                        
                        val_loss += total_loss.item()
                
                avg_val_loss = val_loss / len(val_loader)
                
                # Update learning rate
                scheduler.step(avg_val_loss)
                
                # Save best model
                if avg_val_loss < best_val_loss:
                    best_val_loss = avg_val_loss
                    self.save_model(f"models/gnn_best_epoch_{epoch}.pt")
                
                logger.info(f"Epoch {epoch+1}/{epochs} | "
                          f"Train Loss: {avg_train_loss:.4f} | "
                          f"Val Loss: {avg_val_loss:.4f}")
            else:
                logger.info(f"Epoch {epoch+1}/{epochs} | Train Loss: {avg_train_loss:.4f}")
        
        # Save final model
        self.save_model("models/gnn_final.pt")
    
    def predict(self, 
                graph: nx.DiGraph,
                node_pairs: Optional[List[Tuple[str, str]]] = None) -> Dict[str, Any]:
        """Make predictions for a single graph"""
        self.model.eval()
        
        # Convert graph to Data object
        data_list = self.prepare_training_data([graph], [{}])
        if not data_list:
            return {}
        
        data = data_list[0].to(self.device)
        
        with torch.no_grad():
            outputs = self.model(data.x, data.edge_index, data.edge_attr)
        
        # Process outputs
        predictions = {
            "overall_risk": float(outputs['path_probabilities'].mean().cpu()),
            "node_vulnerabilities": {},
            "recommended_monitoring": []
        }
        
        # Extract node vulnerabilities
        for i, (node, _) in enumerate(graph.nodes(data=True)):
            if i < len(outputs['vulnerability_scores']):
                predictions['node_vulnerabilities'][node] = float(
                    outputs['vulnerability_scores'][i].cpu()
                )
        
        # Generate recommendations
        high_vuln_nodes = sorted(
            predictions['node_vulnerabilities'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        for node, score in high_vuln_nodes:
            if score > 0.7:
                predictions['recommended_monitoring'].append({
                    "node": node,
                    "score": score,
                    "action": "IMMEDIATE_REVIEW",
                    "reason": "High vulnerability score detected"
                })
        
        return predictions
    
    def save_model(self, path: str):
        """Save model to disk"""
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict() if self.optimizer else None,
            'config': {
                'num_node_features': self.model.num_node_features,
                'num_edge_features': self.model.num_edge_features,
                'hidden_channels': self.model.hidden_channels,
                'dropout': self.model.dropout
            }
        }, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """Load model from disk"""
        checkpoint = torch.load(path, map_location=self.device)
        
        if self.model is None:
            config = checkpoint['config']
            self.model = GNNAttackPredictor(**config).to(self.device)
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        
        if checkpoint['optimizer_state_dict'] and self.optimizer:
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        logger.info(f"Model loaded from {path}")

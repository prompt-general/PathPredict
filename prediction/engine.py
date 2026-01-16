# prediction/engine.py
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import hashlib
import networkx as nx

logger = logging.getLogger(__name__)


class AttackPathPredictor:
    """Predicts future attack paths using ML and heuristics"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.feature_encoders = {}
        self.load_model(model_path)
        self.prediction_cache = {}
    
    def load_model(self, model_path: Optional[str] = None):
        """Load trained model or initialize with default"""
        if model_path:
            try:
                self.model = joblib.load(model_path)
                logger.info(f"Loaded prediction model from {model_path}")
            except:
                logger.warning(f"Could not load model from {model_path}, using heuristics")
                self.model = None
        else:
            logger.info("Using heuristic prediction model")
    
    def train_model(self, training_data: List[Dict[str, Any]]):
        """Train prediction model on historical attack paths"""
        logger.info(f"Training prediction model on {len(training_data)} samples")
        
        # Prepare features and labels
        X, y = self._prepare_training_data(training_data)
        
        if len(X) < 100:
            logger.warning(f"Insufficient training data: {len(X)} samples")
            return False
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X, y)
        
        # Save model
        model_path = "models/attack_path_predictor.pkl"
        joblib.dump(self.model, model_path)
        logger.info(f"Model trained and saved to {model_path}")
        
        return True
    
    def predict_attack_paths(self, 
                           current_graph: nx.DiGraph,
                           changes: List[Dict[str, Any]],
                           time_horizon: int = 7  # days
                           ) -> List[Dict[str, Any]]:
        """Predict attack paths that could emerge"""
        logger.info(f"Predicting attack paths for {len(changes)} changes")
        
        predictions = []
        
        # 1. Heuristic predictions
        heuristic_predictions = self._heuristic_predictions(current_graph, changes)
        predictions.extend(heuristic_predictions)
        
        # 2. ML predictions if model is available
        if self.model:
            ml_predictions = self._ml_predictions(current_graph, changes)
            predictions.extend(ml_predictions)
        
        # 3. Time-based predictions
        time_predictions = self._time_based_predictions(current_graph, time_horizon)
        predictions.extend(time_predictions)
        
        # Deduplicate and score predictions
        unique_predictions = self._deduplicate_predictions(predictions)
        scored_predictions = self._score_predictions(unique_predictions)
        
        # Sort by confidence
        scored_predictions.sort(key=lambda x: x['confidence'], reverse=True)
        
        return scored_predictions[:50]  # Return top 50 predictions
    
    def _heuristic_predictions(self, 
                              graph: nx.DiGraph,
                              changes: List[Dict[str, Any]]
                              ) -> List[Dict[str, Any]]:
        """Generate predictions using heuristic rules"""
        predictions = []
        
        for change in changes:
            change_type = change.get('type')
            node_id = change.get('node_id')
            
            if change_type == 'role_created':
                # Predict trust relationships
                pred = self._predict_role_trust(graph, node_id, change)
                predictions.append(pred)
            
            elif change_type == 'policy_attached':
                # Predict privilege escalation
                pred = self._predict_privilege_escalation(graph, node_id, change)
                predictions.append(pred)
            
            elif change_type == 'instance_launched':
                # Predict lateral movement
                pred = self._predict_lateral_movement(graph, node_id, change)
                predictions.append(pred)
        
        return predictions
    
    def _predict_role_trust(self, 
                           graph: nx.DiGraph,
                           role_id: str,
                           change: Dict[str, Any]
                           ) -> Dict[str, Any]:
        """Predict who might assume this role"""
        # Analyze existing trust patterns in the graph
        similar_roles = self._find_similar_roles(graph, role_id)
        
        predicted_trusts = []
        for similar_role in similar_roles[:3]:  # Top 3 similar roles
            # Get who can assume the similar role
            trustors = list(graph.predecessors(similar_role))
            
            for trustor in trustors:
                if trustor != role_id:
                    predicted_trusts.append({
                        "source": trustor,
                        "target": role_id,
                        "confidence": 0.6,
                        "reason": f"Similar to {similar_role} which {trustor} can assume"
                    })
        
        return {
            "prediction_id": f"trust_pred_{hashlib.md5(role_id.encode()).hexdigest()[:8]}",
            "type": "trust_prediction",
            "node": role_id,
            "predicted_trusts": predicted_trusts,
            "confidence": 0.7 if predicted_trusts else 0.3,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _predict_privilege_escalation(self,
                                     graph: nx.DiGraph,
                                     node_id: str,
                                     change: Dict[str, Any]
                                     ) -> Dict[str, Any]:
        """Predict privilege escalation opportunities"""
        policy_arn = change.get('policy_arn', '')
        
        # Check if policy is high-risk
        high_risk_keywords = ['Admin', 'Power', 'FullAccess', 'IAMFull']
        is_high_risk = any(keyword in policy_arn for keyword in high_risk_keywords)
        
        if not is_high_risk:
            return {
                "prediction_id": f"priv_pred_{hashlib.md5(node_id.encode()).hexdigest()[:8]}",
                "type": "privilege_prediction",
                "node": node_id,
                "predicted_paths": [],
                "confidence": 0.2,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Find resources this role could now access
        predicted_paths = []
        
        # Get all high-value resources in graph
        high_value_resources = [
            n for n, data in graph.nodes(data=True)
            if data.get('criticality', 0) > 0.7
        ]
        
        for resource in high_value_resources[:5]:  # Limit to 5 resources
            predicted_paths.append({
                "source": node_id,
                "target": resource,
                "confidence": 0.8,
                "reason": f"High-risk policy {policy_arn} grants access to critical resource"
            })
        
        return {
            "prediction_id": f"priv_pred_{hashlib.md5(node_id.encode()).hexdigest()[:8]}",
            "type": "privilege_prediction",
            "node": node_id,
            "predicted_paths": predicted_paths,
            "confidence": 0.8 if predicted_paths else 0.3,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _predict_lateral_movement(self,
                                 graph: nx.DiGraph,
                                 instance_id: str,
                                 change: Dict[str, Any]
                                 ) -> Dict[str, Any]:
        """Predict lateral movement from new instance"""
        is_public = change.get('public_ip') or change.get('internet_facing', False)
        
        if not is_public:
            return {
                "prediction_id": f"lat_pred_{hashlib.md5(instance_id.encode()).hexdigest()[:8]}",
                "type": "lateral_movement_prediction",
                "node": instance_id,
                "predicted_movements": [],
                "confidence": 0.2,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Find other instances in same subnet/VPC
        similar_instances = self._find_similar_instances(graph, instance_id)
        
        predicted_movements = []
        for target_instance in similar_instances[:3]:
            predicted_movements.append({
                "source": instance_id,
                "target": target_instance,
                "confidence": 0.7,
                "reason": "Public instance in same network segment"
            })
        
        return {
            "prediction_id": f"lat_pred_{hashlib.md5(instance_id.encode()).hexdigest()[:8]}",
            "type": "lateral_movement_prediction",
            "node": instance_id,
            "predicted_movements": predicted_movements,
            "confidence": 0.7 if predicted_movements else 0.3,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _ml_predictions(self,
                       graph: nx.DiGraph,
                       changes: List[Dict[str, Any]]
                       ) -> List[Dict[str, Any]]:
        """Generate predictions using ML model"""
        if not self.model:
            return []
        
        predictions = []
        
        # Extract features from graph and changes
        features = self._extract_prediction_features(graph, changes)
        
        if features.empty:
            return predictions
        
        # Make predictions
        try:
            probabilities = self.model.predict_proba(features)
            
            for idx, prob in enumerate(probabilities):
                if prob[1] > 0.5:  # Probability of attack path
                    prediction = {
                        "prediction_id": f"ml_pred_{idx}",
                        "type": "ml_prediction",
                        "confidence": float(prob[1]),
                        "features": features.iloc[idx].to_dict(),
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    predictions.append(prediction)
        
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
        
        return predictions
    
    def _time_based_predictions(self,
                               graph: nx.DiGraph,
                               time_horizon: int
                               ) -> List[Dict[str, Any]]:
        """Predict attack paths based on temporal patterns"""
        predictions = []
        
        # Analyze historical attack path creation times
        # For now, use simple time-of-day patterns
        
        hour = datetime.utcnow().hour
        
        # Higher risk during off-hours (attackers often act then)
        if 0 <= hour < 6 or 18 <= hour < 24:
            risk_multiplier = 1.5
        else:
            risk_multiplier = 1.0
        
        # Find vulnerable nodes
        vulnerable_nodes = [
            n for n, data in graph.nodes(data=True)
            if data.get('risk_score', 0) > 0.6
        ]
        
        for node in vulnerable_nodes[:10]:  # Limit to 10 nodes
            predictions.append({
                "prediction_id": f"time_pred_{hashlib.md5(node.encode()).hexdigest()[:8]}",
                "type": "temporal_prediction",
                "node": node,
                "confidence": 0.4 * risk_multiplier,
                "reason": f"High-risk node more vulnerable during current time (hour: {hour})",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return predictions
    
    def _find_similar_roles(self, graph: nx.DiGraph, role_id: str) -> List[str]:
        """Find roles similar to the given role"""
        # Simple similarity based on name patterns
        role_name = role_id.split('::')[-1].lower()
        
        similar = []
        for node, data in graph.nodes(data=True):
            if 'role' in node.lower() and node != role_id:
                node_name = node.split('::')[-1].lower()
                
                # Check for name similarity
                if any(word in node_name for word in role_name.split('_')):
                    similar.append(node)
                elif role_name.split('_')[0] == node_name.split('_')[0]:
                    similar.append(node)
        
        return similar[:5]  # Return top 5 similar roles
    
    def _find_similar_instances(self, graph: nx.DiGraph, instance_id: str) -> List[str]:
        """Find instances similar to the given instance"""
        # Group by likely subnet/VPC based on ID pattern
        instance_prefix = '_'.join(instance_id.split('_')[:3])
        
        similar = []
        for node in graph.nodes():
            if 'instance' in node.lower() and node != instance_id:
                if instance_prefix in node:
                    similar.append(node)
        
        return similar[:5]  # Return top 5 similar instances
    
    def _extract_prediction_features(self,
                                    graph: nx.DiGraph,
                                    changes: List[Dict[str, Any]]
                                    ) -> pd.DataFrame:
        """Extract features for ML prediction"""
        features = []
        
        for change in changes:
            # Basic features
            feature_dict = {
                'change_type': change.get('type', 'unknown'),
                'node_type': change.get('node_type', 'unknown'),
                'has_public_access': int(change.get('public_ip', False) or change.get('internet_facing', False)),
                'is_high_risk_policy': int(self._is_high_risk_policy(change.get('policy_arn', ''))),
                'time_of_day': datetime.utcnow().hour,
                'day_of_week': datetime.utcnow().weekday(),
                'graph_size': len(graph.nodes()),
                'graph_density': nx.density(graph) if len(graph.nodes()) > 1 else 0,
            }
            
            features.append(feature_dict)
        
        if features:
            return pd.DataFrame(features)
        return pd.DataFrame()
    
    def _is_high_risk_policy(self, policy_arn: str) -> bool:
        """Check if policy ARN indicates high risk"""
        high_risk_indicators = [
            'AdministratorAccess',
            'PowerUserAccess',
            'IAMFullAccess',
            'AmazonS3FullAccess',
            'ResourceGroupsTaggingFullAccess'
        ]
        
        return any(indicator in policy_arn for indicator in high_risk_indicators)
    
    def _prepare_training_data(self, 
                              attack_paths: List[Dict[str, Any]]
                              ) -> Tuple[pd.DataFrame, np.ndarray]:
        """Prepare training data from historical attack paths"""
        features = []
        labels = []
        
        for path in attack_paths:
            # Feature engineering
            feature_dict = {
                'path_length': path.get('hop_count', 1),
                'has_cross_cloud': int(len(path.get('providers', [])) > 1),
                'has_public_exposure': int(path.get('public_access', False)),
                'has_privilege_escalation': int('CAN_ASSUME' in str(path.get('relationships', []))),
                'avg_node_risk': path.get('risk_score', 0) / max(path.get('hop_count', 1), 1),
                'time_to_detection_hours': path.get('time_to_detection_hours', 24),
                'was_exploited': int(path.get('was_exploited', False))
            }
            
            features.append(feature_dict)
            labels.append(1)  # This is an actual attack path
        
        # Add negative samples (non-attack paths)
        # For now, generate synthetic negatives
        num_negatives = len(features)
        for _ in range(num_negatives):
            feature_dict = {
                'path_length': np.random.randint(1, 5),
                'has_cross_cloud': np.random.choice([0, 1], p=[0.9, 0.1]),
                'has_public_exposure': np.random.choice([0, 1], p=[0.8, 0.2]),
                'has_privilege_escalation': np.random.choice([0, 1], p=[0.7, 0.3]),
                'avg_node_risk': np.random.uniform(0, 0.5),
                'time_to_detection_hours': np.random.uniform(1, 168),
                'was_exploited': 0
            }
            
            features.append(feature_dict)
            labels.append(0)
        
        return pd.DataFrame(features), np.array(labels)
    
    def _deduplicate_predictions(self, predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate predictions"""
        unique_predictions = {}
        
        for pred in predictions:
            pred_key = json.dumps({
                'type': pred.get('type'),
                'node': pred.get('node', ''),
                'confidence': round(pred.get('confidence', 0), 2)
            }, sort_keys=True)
            
            if pred_key not in unique_predictions:
                unique_predictions[pred_key] = pred
        
        return list(unique_predictions.values())
    
    def _score_predictions(self, predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score and rank predictions"""
        for pred in predictions:
            # Adjust confidence based on additional factors
            base_confidence = pred.get('confidence', 0.5)
            
            # Time-based adjustment
            hour = datetime.utcnow().hour
            if 0 <= hour < 6:  # Early morning
                time_factor = 1.2
            elif 18 <= hour < 24:  # Evening
                time_factor = 1.1
            else:
                time_factor = 1.0
            
            # Type-based adjustment
            pred_type = pred.get('type', '')
            if 'ml_prediction' in pred_type:
                type_factor = 1.3
            elif 'privilege_prediction' in pred_type:
                type_factor = 1.2
            else:
                type_factor = 1.0
            
            final_confidence = min(0.95, base_confidence * time_factor * type_factor)
            pred['confidence'] = round(final_confidence, 3)
            
            # Add risk level
            if final_confidence >= 0.8:
                pred['risk_level'] = 'HIGH'
            elif final_confidence >= 0.6:
                pred['risk_level'] = 'MEDIUM'
            else:
                pred['risk_level'] = 'LOW'
        
        return predictions

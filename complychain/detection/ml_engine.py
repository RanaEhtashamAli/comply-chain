"""
Machine Learning Engine for ComplyChain threat detection.

This module provides ML-based anomaly detection using Isolation Forest
and other algorithms for GLBA compliance monitoring.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

from ..exceptions import ModelTrainingError, ThreatScanException
from ..config.logging_config import get_logger

logger = get_logger(__name__)


class MLEngine:
    """Machine Learning Engine for threat detection."""
    
    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize ML Engine.
        
        Args:
            model_path: Path to store/load ML models
        """
        self.model_path = Path(model_path) if model_path else Path("./models")
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.metrics: Dict[str, float] = {}
        
        # Load existing model if available
        self._load_model()
    
    def _load_model(self) -> None:
        """Load existing model and scaler if available."""
        model_file = self.model_path / "isolation_forest.pkl"
        scaler_file = self.model_path / "scaler.pkl"
        metadata_file = self.model_path / "model_metadata.json"
        
        if model_file.exists() and scaler_file.exists():
            try:
                self.model = joblib.load(model_file)
                self.scaler = joblib.load(scaler_file)
                
                if metadata_file.exists():
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        self.feature_names = metadata.get('feature_names', [])
                        self.metrics = metadata.get('metrics', {})
                
                logger.info("Loaded existing ML model and scaler")
            except Exception as e:
                logger.warning(f"Failed to load existing model: {e}")
                self._initialize_new_model()
        else:
            self._initialize_new_model()
    
    def _initialize_new_model(self) -> None:
        """Initialize new model and scaler."""
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        logger.info("Initialized new ML model")
    
    def _extract_features(self, transaction: Dict[str, Any]) -> np.ndarray:
        """
        Extract numerical features from transaction data.
        
        Args:
            transaction: Transaction data dictionary
            
        Returns:
            Feature array
        """
        features = []
        
        # Transaction amount features
        amount = float(transaction.get('amount', 0))
        features.extend([
            amount,
            np.log1p(amount) if amount > 0 else 0,
            amount / 1000,  # Normalized amount
        ])
        
        # Time-based features
        timestamp = transaction.get('timestamp', 0)
        if timestamp:
            features.extend([
                timestamp % 86400,  # Time of day
                timestamp % 604800,  # Day of week
                timestamp % 2592000,  # Day of month
            ])
        else:
            features.extend([0, 0, 0])
        
        # Geographic features
        features.extend([
            float(transaction.get('latitude', 0)),
            float(transaction.get('longitude', 0)),
        ])
        
        # Account features
        features.extend([
            float(transaction.get('account_age_days', 0)),
            float(transaction.get('transaction_count', 0)),
            float(transaction.get('avg_transaction_amount', 0)),
        ])
        
        # Risk indicators
        risk_indicators = [
            'is_high_value',
            'is_cross_border',
            'is_wire_transfer',
            'is_new_recipient',
            'is_after_hours',
        ]
        
        for indicator in risk_indicators:
            features.append(float(transaction.get(indicator, False)))
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict[str, Any]], 
              validation_data: Optional[List[Dict[str, Any]]] = None) -> Dict[str, float]:
        """
        Train the ML model on transaction data.
        
        Args:
            training_data: List of transaction dictionaries for training
            validation_data: Optional validation data for metrics
            
        Returns:
            Training metrics
        """
        if not training_data:
            raise ModelTrainingError("No training data provided")
        
        logger.info(f"Training ML model on {len(training_data)} transactions")
        
        # Extract features from training data
        X_train = []
        for transaction in training_data:
            features = self._extract_features(transaction)
            X_train.append(features.flatten())
        
        X_train = np.array(X_train)
        
        # Update feature names
        self.feature_names = [
            'amount', 'log_amount', 'normalized_amount',
            'time_of_day', 'day_of_week', 'day_of_month',
            'latitude', 'longitude',
            'account_age', 'transaction_count', 'avg_amount',
            'is_high_value', 'is_cross_border', 'is_wire_transfer',
            'is_new_recipient', 'is_after_hours'
        ]
        
        # Fit scaler and transform data
        if self.scaler is None:
            raise ModelTrainingError("Scaler not initialized")
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train model
        if self.model is None:
            raise ModelTrainingError("Model not initialized")
        self.model.fit(X_train_scaled)
        
        # Calculate training metrics
        train_predictions = self.model.predict(X_train_scaled)
        train_scores = self.model.score_samples(X_train_scaled)
        
        metrics = {
            'training_samples': len(training_data),
            'anomaly_ratio': np.mean(train_predictions == -1),
            'avg_anomaly_score': np.mean(train_scores),
        }
        
        # Calculate validation metrics if provided
        if validation_data:
            val_metrics = self._calculate_validation_metrics(validation_data)
            metrics.update(val_metrics)
        
        self.metrics = metrics
        
        # Save model and metadata
        self._save_model()
        
        logger.info(f"Training completed. Metrics: {metrics}")
        return metrics
    
    def _calculate_validation_metrics(self, validation_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate validation metrics."""
        X_val = []
        y_true = []  # Assuming we have labels for validation
        
        for transaction in validation_data:
            features = self._extract_features(transaction)
            X_val.append(features.flatten())
            y_true.append(transaction.get('is_anomaly', 0))
        
        X_val = np.array(X_val)
        if self.scaler is None or self.model is None:
            raise ModelTrainingError("Model or scaler not initialized")
        X_val_scaled = self.scaler.transform(X_val)
        
        predictions = self.model.predict(X_val_scaled)
        scores = self.model.score_samples(X_val_scaled)
        
        # Convert predictions to binary (1 for anomaly, 0 for normal)
        y_pred = (predictions == -1).astype(int)
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average='binary', zero_division=0
        )
        
        try:
            auc = roc_auc_score(y_true, scores)
        except ValueError:
            auc = 0.5  # Default if only one class present
        
        return {
            'validation_samples': len(validation_data),
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc_score': auc,
            'val_anomaly_ratio': np.mean(y_pred),
        }
    
    def predict(self, transaction: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if a transaction is anomalous.
        
        Args:
            transaction: Transaction data dictionary
            
        Returns:
            Tuple of (is_anomaly, anomaly_score)
        """
        if self.model is None or self.scaler is None:
            raise ThreatScanException("ML model not trained")
        
        features = self._extract_features(transaction)
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        score = self.model.score_samples(features_scaled)[0]
        
        is_anomaly = prediction == -1
        return is_anomaly, score
    
    def _save_model(self) -> None:
        """Save model, scaler, and metadata."""
        try:
            # Save model
            model_file = self.model_path / "isolation_forest.pkl"
            joblib.dump(self.model, model_file)
            
            # Save scaler
            scaler_file = self.model_path / "scaler.pkl"
            joblib.dump(self.scaler, scaler_file)
            
            # Save metadata
            metadata = {
                'feature_names': self.feature_names,
                'metrics': self.metrics,
                'model_type': 'IsolationForest',
                'scaler_type': 'StandardScaler',
            }
            
            metadata_file = self.model_path / "model_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Saved ML model to {self.model_path}")
        except Exception as e:
            raise ModelTrainingError(f"Failed to save model: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            'model_path': str(self.model_path),
            'is_trained': self.model is not None,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'metrics': self.metrics,
        } 
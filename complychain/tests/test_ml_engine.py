"""Tests for complychain.detection.ml_engine."""

import pytest
from pathlib import Path
from complychain.detection.ml_engine import MLEngine
from complychain.exceptions import ModelTrainingError, ThreatScanException


SAMPLE_TX = [
    {'amount': 5_000,  'beneficiary': 'Alice', 'sender': 'Bob',  'cross_border': False},
    {'amount': 12_000, 'beneficiary': 'Carol', 'sender': 'Dave', 'cross_border': True},
    {'amount': 3_000,  'beneficiary': 'Eve',   'sender': 'Frank','cross_border': False},
    {'amount': 8_000,  'beneficiary': 'Grace', 'sender': 'Hank', 'cross_border': True},
    {'amount': 1_500,  'beneficiary': 'Ivy',   'sender': 'Jack', 'cross_border': False},
]


def test_initialize_new_model(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    assert engine.model is not None
    assert engine.scaler is not None


def test_train_returns_metrics(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    metrics = engine.train(SAMPLE_TX)
    assert 'training_samples' in metrics
    assert metrics['training_samples'] == len(SAMPLE_TX)
    assert 'anomaly_ratio' in metrics


def test_predict_after_train(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    engine.train(SAMPLE_TX)
    is_anomaly, score = engine.predict(SAMPLE_TX[0])
    assert isinstance(is_anomaly, bool)
    assert isinstance(score, float)


def test_predict_without_train_raises(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    # model is initialised but not fitted
    with pytest.raises(ThreatScanException):
        engine.predict({'amount': 1000})


def test_model_persists_to_disk(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    engine.train(SAMPLE_TX)
    assert (tmp_path / 'isolation_forest.pkl').exists()
    assert (tmp_path / 'scaler.pkl').exists()
    assert (tmp_path / 'model_metadata.json').exists()


def test_model_reloads_from_disk(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    engine.train(SAMPLE_TX)

    engine2 = MLEngine(model_path=tmp_path)
    assert engine2.model is not None
    is_anomaly, score = engine2.predict(SAMPLE_TX[0])
    assert isinstance(is_anomaly, bool)


def test_train_empty_data_raises(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    with pytest.raises(ModelTrainingError):
        engine.train([])


def test_get_model_info(tmp_path):
    engine = MLEngine(model_path=tmp_path)
    engine.train(SAMPLE_TX)
    info = engine.get_model_info()
    assert info['is_trained'] is True
    assert info['feature_count'] > 0

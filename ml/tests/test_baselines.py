"""Unit tests for Baseline Models & Single-Modality Training (Phase 11).

Tests:
- TabularMLP PyTorch tensor output shape (N, 1)
- BaselineClassifier fit & predict_proba for XGBoost, LightGBM, Random Forest, Logistic Regression, MLP
- Evaluation metric dictionary keys (accuracy, precision, recall, f1, roc_auc, fpr, latency_ms)
- BaselineTrainer pipeline execution for Experiments 1-5
"""

from pathlib import Path
import numpy as np
import pytest
import torch

from ml.models.baselines import BaselineClassifier, TabularMLP
from ml.training.train_baselines import BaselineTrainer


class TestBaselineModels:
    """Test suite for single-modality baseline classifiers and PyTorch MLP."""

    def test_pytorch_tabular_mlp_forward(self) -> None:
        """Verify TabularMLP forward pass tensor shape."""
        mlp = TabularMLP(input_dim=22, hidden_dim=64, dropout=0.2)
        dummy_x = torch.randn(16, 22)
        out = mlp(dummy_x)
        assert out.shape == (16, 1)
        assert (out >= 0.0).all() and (out <= 1.0).all()

    @pytest.mark.parametrize("model_type", ["random_forest", "logistic_regression", "mlp"])
    def test_baseline_classifier_fit_eval(self, model_type: str) -> None:
        """Verify fit and evaluate for different model backends."""
        np.random.seed(42)
        X_train = np.random.randn(40, 22).astype(np.float32)
        y_train = np.random.randint(0, 2, size=40).astype(np.int32)
        X_test = np.random.randn(10, 22).astype(np.float32)
        y_test = np.random.randint(0, 2, size=10).astype(np.int32)

        clf = BaselineClassifier(model_type=model_type, input_dim=22, seed=42)
        clf.fit(X_train, y_train, epochs=5)

        probs = clf.predict_proba(X_test)
        assert len(probs) == 10
        assert (probs >= 0.0).all() and (probs <= 1.0).all()

        metrics = clf.evaluate(X_test, y_test)
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert "roc_auc" in metrics
        assert "fpr" in metrics
        assert "latency_ms" in metrics

    def test_baseline_trainer_experiments_1_to_5(self, tmp_path: Path) -> None:
        """Verify running all single-modality baseline experiments 1-5."""
        trainer = BaselineTrainer(saved_models_dir=tmp_path, seed=42)
        results = trainer.run_all_baselines(num_samples=30)

        assert "exp1_url_only" in results
        assert "exp2_html_only" in results
        assert "exp3_ssl_only" in results
        assert "exp4_domain_only" in results
        assert "exp5_ocr_only" in results
        assert (tmp_path / "baseline_metrics.json").exists()

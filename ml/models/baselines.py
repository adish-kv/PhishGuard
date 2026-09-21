"""Standalone Baseline ML & PyTorch Models for Single-Modality Experiments.

Implements baseline classifiers for Experiments 1-5:
- PyTorch Tabular MLP (Multi-Layer Perceptron)
- XGBoost Classifier
- LightGBM Classifier
- Random Forest Classifier
- Logistic Regression Baseline

Computes real evaluation metrics:
- Precision, Recall, F1-Score, Accuracy
- ROC-AUC (Area Under ROC Curve)
- False Positive Rate (FPR)
- Average Inference Latency (ms per sample)
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

try:
    import xgboost as xgb
    _XGB_AVAILABLE = True
except ImportError:
    _XGB_AVAILABLE = False

try:
    import lightgbm as lgb
    _LGB_AVAILABLE = True
except ImportError:
    _LGB_AVAILABLE = False

from backend.app.core.logging import get_logger

logger = get_logger(__name__)


# PyTorch Tabular Neural Network Classifier
class TabularMLP(nn.Module):
    """Multi-Layer Perceptron for tabular feature vectors.

    Architecture:
        Input(dim) → Dense(128) → BatchNorm → ReLU → Dropout(0.3)
                  → Dense(64)  → BatchNorm → ReLU → Dropout(0.2)
                  → Dense(32)  → ReLU
                  → Dense(1)   → Sigmoid
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128, dropout: float = 0.3) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.BatchNorm1d(hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout * 0.7),
            nn.Linear(hidden_dim // 2, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# Universal Baseline Classifier Wrapper
class BaselineClassifier:
    """Unified wrapper for training and evaluating baseline classifiers.

    Supported model_type options:
        - "xgboost": XGBoost Gradient Boosted Trees
        - "lightgbm": LightGBM Classifier
        - "random_forest": Scikit-Learn Random Forest
        - "logistic_regression": Scikit-Learn Logistic Regression
        - "mlp": PyTorch Tabular MLP
    """

    def __init__(
        self,
        model_type: str = "xgboost",
        input_dim: int = 22,
        seed: int = 42,
        **model_params: Any,
    ) -> None:
        self.model_type = model_type.lower()
        self.input_dim = input_dim
        self.seed = seed
        self.scaler = StandardScaler()
        self.model: Any = None
        self.pytorch_model: TabularMLP | None = None

        self._init_model(**model_params)

    def _init_model(self, **params: Any) -> None:
        if self.model_type == "xgboost":
            if _XGB_AVAILABLE:
                self.model = xgb.XGBClassifier(
                    n_estimators=params.get("n_estimators", 100),
                    max_depth=params.get("max_depth", 6),
                    learning_rate=params.get("learning_rate", 0.1),
                    random_state=self.seed,
                    eval_metric="logloss",
                )
            else:
                logger.warning("XGBoost not available. Falling back to Random Forest.")
                self.model = RandomForestClassifier(n_estimators=100, random_state=self.seed)

        elif self.model_type == "lightgbm":
            if _LGB_AVAILABLE:
                self.model = lgb.LGBMClassifier(
                    n_estimators=params.get("n_estimators", 100),
                    max_depth=params.get("max_depth", 6),
                    learning_rate=params.get("learning_rate", 0.1),
                    random_state=self.seed,
                    verbose=-1,
                )
            else:
                logger.warning("LightGBM not available. Falling back to Random Forest.")
                self.model = RandomForestClassifier(n_estimators=100, random_state=self.seed)

        elif self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=params.get("n_estimators", 100),
                max_depth=params.get("max_depth", 10),
                random_state=self.seed,
            )

        elif self.model_type == "logistic_regression":
            self.model = LogisticRegression(
                max_iter=params.get("max_iter", 1000),
                random_state=self.seed,
            )

        elif self.model_type == "mlp":
            self.pytorch_model = TabularMLP(
                input_dim=self.input_dim,
                hidden_dim=params.get("hidden_dim", 128),
                dropout=params.get("dropout", 0.3),
            )
        else:
            raise ValueError(f"Unknown model_type: {self.model_type}")

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray | None = None,
        y_val: np.ndarray | None = None,
        epochs: int = 30,
        batch_size: int = 32,
        lr: float = 0.001,
    ) -> dict[str, Any]:
        """Fit baseline model on training data.

        Args:
            X_train: Training features array shape (N, dim).
            y_train: Training binary labels array shape (N,).
            X_val: Optional validation features.
            y_val: Optional validation labels.
            epochs: Epochs for PyTorch MLP.
            batch_size: Batch size for PyTorch MLP.
            lr: Learning rate for PyTorch MLP.

        Returns:
            Dictionary with training history metrics.
        """
        # Standardize features
        X_train_scaled = self.scaler.fit_transform(X_train)

        if self.model_type == "mlp" and self.pytorch_model is not None:
            return self._fit_pytorch(X_train_scaled, y_train, X_val, y_val, epochs, batch_size, lr)
        else:
            start_t = time.perf_counter()
            self.model.fit(X_train_scaled, y_train)
            train_time = round(time.perf_counter() - start_t, 3)
            logger.info(f"Fitted {self.model_type} baseline in {train_time}s")
            return {"fit_time_seconds": train_time}

    def _fit_pytorch(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray | None,
        y_val: np.ndarray | None,
        epochs: int,
        batch_size: int,
        lr: float,
    ) -> dict[str, Any]:
        """Train PyTorch MLP using AdamW optimizer and Binary Cross-Entropy Loss."""
        torch.manual_seed(self.seed)
        model = self.pytorch_model
        assert model is not None

        ds = TensorDataset(
            torch.tensor(X_train, dtype=torch.float32),
            torch.tensor(y_train, dtype=torch.float32).unsqueeze(1),
        )
        loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

        criterion = nn.BCELoss()
        optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

        history: dict[str, list[float]] = {"loss": []}

        model.train()
        for ep in range(epochs):
            ep_loss = 0.0
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                out = model(batch_x)
                loss = criterion(out, batch_y)
                loss.backward()
                optimizer.step()
                ep_loss += loss.item() * len(batch_x)
            avg_loss = ep_loss / len(X_train)
            history["loss"].append(avg_loss)

        return {"epochs": epochs, "final_loss": history["loss"][-1]}

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict phishing probabilities (range 0.0 to 1.0).

        Args:
            X: Feature matrix shape (N, dim).

        Returns:
            Numpy array of phishing probabilities shape (N,).
        """
        X_scaled = self.scaler.transform(X)

        if self.model_type == "mlp" and self.pytorch_model is not None:
            self.pytorch_model.eval()
            with torch.no_grad():
                tensor_x = torch.tensor(X_scaled, dtype=torch.float32)
                probs = self.pytorch_model(tensor_x).cpu().numpy().squeeze()
                if probs.ndim == 0:
                    probs = np.array([float(probs)])
                return probs
        else:
            if hasattr(self.model, "predict_proba"):
                return self.model.predict_proba(X_scaled)[:, 1]
            else:
                return self.model.predict(X_scaled).astype(float)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
        """Evaluate model on test dataset and calculate metrics.

        Args:
            X_test: Test features.
            y_test: Test ground truth labels (0=benign, 1=phishing).
            threshold: Decision threshold.

        Returns:
            Dictionary containing accuracy, precision, recall, f1, roc_auc, fpr, and latency.
        """
        start_t = time.perf_counter()
        probs = self.predict_proba(X_test)
        total_time_ms = (time.perf_counter() - start_t) * 1000
        latency_per_sample_ms = total_time_ms / max(len(X_test), 1)

        preds = (probs >= threshold).astype(int)

        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))

        try:
            auc = float(roc_auc_score(y_test, probs))
        except Exception:
            auc = 0.5

        # False Positive Rate: FP / (FP + TN)
        cm = confusion_matrix(y_test, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
        fpr = float(fp / max(fp + tn, 1))

        return {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "roc_auc": round(auc, 4),
            "fpr": round(fpr, 4),
            "latency_ms": round(latency_per_sample_ms, 3),
        }

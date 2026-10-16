"""Train Stage 1 GBDT Model on Genuine Dataset.

Wrapper aligning with project training pipeline and genuine PhishTank/Tranco data.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure root directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import numpy as np

from ml.datasets.downloader import DatasetDownloader
from ml.training.train_real_phish_model import extract_features_from_samples, train_phish_model


def generate_stage1_dataset(num_samples: int = 5000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Extract genuine 22-dimensional Stage 1 feature vectors from genuine PhishTank & Tranco datasets.

    Args:
        num_samples: Total number of samples (balanced 50% benign, 50% phishing).
        seed: Random seed for sampling.

    Returns:
        Tuple of (feature matrix X, label vector y).
    """
    samples_per_class = num_samples // 2
    downloader = DatasetDownloader()
    samples, _ = downloader.build_genuine_dataset(samples_per_class=samples_per_class, seed=seed)
    X, y, _ = extract_features_from_samples(samples)
    return X, y


def train_and_save_stage1_model() -> None:
    """Train GBDT Stage 1 model on genuine dataset and serialize to disk."""
    train_phish_model(samples_per_class=2500, seed=42)


if __name__ == "__main__":
    train_and_save_stage1_model()

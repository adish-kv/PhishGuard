"""Unit tests for the PyTorch 6-Modal Multimodal Fusion Architecture (Phase 12).

Tests:
- Forward pass tensor output shape (N, 1) across all 6 subnets
- Modality masking forward pass
- Full multimodal training & evaluation runner for Experiment 6
"""

from pathlib import Path
import numpy as np
import pytest
import torch

from ml.models.fusion_model import MultimodalFusionModel
from ml.training.train_fusion import FusionTrainer


class TestMultimodalFusionModel:
    """Test suite for PyTorch MultimodalFusionModel."""

    def test_forward_pass_shape(self) -> None:
        """Verify forward pass output shape is (batch_size, 1)."""
        model = MultimodalFusionModel()

        x_url = torch.randn(8, 22)
        x_html = torch.randn(8, 28)
        x_ssl = torch.randn(8, 10)
        x_domain = torch.randn(8, 6)
        x_ocr = torch.randn(8, 13)
        x_visual = torch.randn(8, 512)

        out = model(x_url, x_html, x_ssl, x_domain, x_ocr, x_visual)
        assert out.shape == (8, 1)
        assert (out >= 0.0).all() and (out <= 1.0).all()

    def test_modality_masking(self) -> None:
        """Verify forwarding with zeroed modality masks for partial modal inference."""
        model = MultimodalFusionModel()

        x_url = torch.randn(4, 22)
        x_html = torch.randn(4, 28)
        x_ssl = torch.randn(4, 10)
        x_domain = torch.randn(4, 6)
        x_ocr = torch.randn(4, 13)
        x_visual = torch.randn(4, 512)

        # Zero out visual & OCR modalities
        vis_mask = torch.zeros(4, 64)
        ocr_mask = torch.zeros(4, 32)

        out = model(
            x_url, x_html, x_ssl, x_domain, x_ocr, x_visual,
            ocr_mask=ocr_mask, visual_mask=vis_mask
        )
        assert out.shape == (4, 1)

    def test_fusion_trainer_experiment_6(self, tmp_path: Path) -> None:
        """Verify end-to-end training and evaluation of Experiment 6."""
        trainer = FusionTrainer(saved_models_dir=tmp_path, seed=42)
        metrics = trainer.train_and_evaluate(num_samples=30, epochs=3, batch_size=16)

        assert "exp6_full_multimodal_f1" in metrics
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert "roc_auc" in metrics
        assert "fpr" in metrics
        assert "latency_ms" in metrics
        assert (tmp_path / "fusion_model.pt").exists()
        assert (tmp_path / "fusion_metrics.json").exists()

"""PyTorch Multimodal Feature Fusion Architecture for PhishGuard.

Fuses 6 distinct modalities into a unified representation:
- URL Subnet: 22d → 32d
- HTML Subnet: 28d → 32d
- SSL Subnet: 10d → 16d
- Domain Subnet: 6d → 16d
- OCR Subnet: 13d → 32d
- Visual Projector: 512d CLIP → 64d

Total Fused Dimension = 32 + 32 + 16 + 16 + 32 + 64 = 192 dimensions.

Dense Fusion Head:
    Dense(192 → 128) → BatchNorm → ReLU → Dropout(0.3)
 →  Dense(128 → 64)  → BatchNorm → ReLU → Dropout(0.2)
 →  Dense(64 → 1)    → Sigmoid

Supports Modality Masking:
    - Allows evaluating partial modality inputs (for ablation studies and adaptive staging).
"""

from __future__ import annotations

from typing import Any

import torch
import torch.nn as nn


class URLSubnet(nn.Module):
    """Sub-network for 22-dimensional URL feature vector."""

    def __init__(self, in_dim: int = 22, out_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 48),
            nn.BatchNorm1d(48),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(48, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class HTMLSubnet(nn.Module):
    """Sub-network for 28-dimensional HTML DOM feature vector."""

    def __init__(self, in_dim: int = 28, out_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class SSLSubnet(nn.Module):
    """Sub-network for 10-dimensional SSL feature vector."""

    def __init__(self, in_dim: int = 10, out_dim: int = 16) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 24),
            nn.ReLU(),
            nn.Linear(24, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class DomainSubnet(nn.Module):
    """Sub-network for 6-dimensional Domain WHOIS feature vector."""

    def __init__(self, in_dim: int = 6, out_dim: int = 16) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 16),
            nn.ReLU(),
            nn.Linear(16, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class OCRSubnet(nn.Module):
    """Sub-network for 13-dimensional OCR feature vector."""

    def __init__(self, in_dim: int = 13, out_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class VisualProjector(nn.Module):
    """Projection head for 512-dimensional CLIP vision embedding."""

    def __init__(self, in_dim: int = 512, out_dim: int = 64) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, out_dim),
            nn.ReLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class MultimodalFusionModel(nn.Module):
    """6-Modal Feature Fusion PyTorch Neural Network.

    Fuses URL, HTML, SSL, Domain, OCR, and Visual features.
    """

    def __init__(
        self,
        url_dim: int = 22,
        html_dim: int = 28,
        ssl_dim: int = 10,
        domain_dim: int = 6,
        ocr_dim: int = 13,
        visual_dim: int = 512,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        self.url_subnet = URLSubnet(in_dim=url_dim, out_dim=32)
        self.html_subnet = HTMLSubnet(in_dim=html_dim, out_dim=32)
        self.ssl_subnet = SSLSubnet(in_dim=ssl_dim, out_dim=16)
        self.domain_subnet = DomainSubnet(in_dim=domain_dim, out_dim=16)
        self.ocr_subnet = OCRSubnet(in_dim=ocr_dim, out_dim=32)
        self.visual_projector = VisualProjector(in_dim=visual_dim, out_dim=64)

        total_fused_dim = 32 + 32 + 16 + 16 + 32 + 64  # 192

        self.fusion_head = nn.Sequential(
            nn.Linear(total_fused_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(dropout * 0.7),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x_url: torch.Tensor,
        x_html: torch.Tensor,
        x_ssl: torch.Tensor,
        x_domain: torch.Tensor,
        x_ocr: torch.Tensor,
        x_visual: torch.Tensor,
        url_mask: torch.Tensor | None = None,
        html_mask: torch.Tensor | None = None,
        ssl_mask: torch.Tensor | None = None,
        domain_mask: torch.Tensor | None = None,
        ocr_mask: torch.Tensor | None = None,
        visual_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Forward pass through subnets and fusion head.

        Args:
            x_url: (N, 22) tensor
            x_html: (N, 28) tensor
            x_ssl: (N, 10) tensor
            x_domain: (N, 6) tensor
            x_ocr: (N, 13) tensor
            x_visual: (N, 512) tensor
            *_mask: Optional (N, 1) boolean or float masks to zero out missing modalities

        Returns:
            (N, 1) tensor of phishing probability scores (0.0 to 1.0).
        """
        h_url = self.url_subnet(x_url)
        h_html = self.html_subnet(x_html)
        h_ssl = self.ssl_subnet(x_ssl)
        h_domain = self.domain_subnet(x_domain)
        h_ocr = self.ocr_subnet(x_ocr)
        h_visual = self.visual_projector(x_visual)

        # Apply modality masks if present
        if url_mask is not None:
            h_url = h_url * url_mask
        if html_mask is not None:
            h_html = h_html * html_mask
        if ssl_mask is not None:
            h_ssl = h_ssl * ssl_mask
        if domain_mask is not None:
            h_domain = h_domain * domain_mask
        if ocr_mask is not None:
            h_ocr = h_ocr * ocr_mask
        if visual_mask is not None:
            h_visual = h_visual * visual_mask

        # Concatenate 6 projected feature vectors (total 192d)
        fused_vector = torch.cat(
            [h_url, h_html, h_ssl, h_domain, h_ocr, h_visual], dim=-1
        )

        # Compute final phishing probability score
        output = self.fusion_head(fused_vector)
        return output

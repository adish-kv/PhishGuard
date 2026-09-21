"""SQLAlchemy database models for PhishGuard.

Defines all database tables for:
- Analysis requests and results
- Feature storage (URL, HTML, SSL, Domain, OCR, Visual)
- Model predictions with version tracking
- Experiment tracking
- Dataset sample management

Every prediction is stored with its model version for reproducibility.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

try:
    from sqlalchemy.dialects.postgresql import JSONB as JSONType
except ImportError:
    from sqlalchemy import JSON as JSONType

from backend.app.core.database import Base


def generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


class AnalysisRequest(Base):
    """Tracks each URL analysis request.

    Stores the input URL, analysis mode, and current status.
    Links to all feature extractions and the final result.
    """

    __tablename__ = "analysis_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url = Column(Text, nullable=False, index=True)
    mode = Column(String(20), nullable=False, default="adaptive")  # "full" or "adaptive"
    status = Column(
        String(20), nullable=False, default="pending"
    )  # pending, processing, completed, failed
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    result = relationship("AnalysisResult", back_populates="request", uselist=False)
    url_features = relationship("URLFeatures", back_populates="request", uselist=False)
    html_features = relationship("HTMLFeatures", back_populates="request", uselist=False)
    ssl_features = relationship("SSLFeatures", back_populates="request", uselist=False)
    domain_features = relationship(
        "DomainFeatures", back_populates="request", uselist=False
    )
    ocr_results = relationship("OCRResults", back_populates="request", uselist=False)
    visual_embedding = relationship(
        "VisualEmbedding", back_populates="request", uselist=False
    )


class AnalysisResult(Base):
    """Final analysis result with prediction and explanation.

    Stores the model's prediction, confidence, and which modalities
    were used. Links back to the request and stores the model version
    for reproducibility.
    """

    __tablename__ = "analysis_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    prediction = Column(String(20), nullable=False)  # "benign" or "phishing"
    confidence = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # "low", "medium", "high", "critical"
    model_version = Column(String(50), nullable=False)
    feature_schema_version = Column(String(50), nullable=False, default="v1.0")
    explanation = Column(JSONType, nullable=True)
    latency_ms = Column(Float, nullable=True)
    modalities_used = Column(Integer, nullable=True)
    decision_stage = Column(
        String(20), nullable=True
    )  # "stage1", "stage2", "stage3", "stage4"
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    request = relationship("AnalysisRequest", back_populates="result")


class URLFeatures(Base):
    """Extracted URL lexical and structural features.

    Stores the 22-dimensional URL feature vector as JSON.
    """

    __tablename__ = "url_features"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    features = Column(JSONType, nullable=False)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="url_features")


class HTMLFeatures(Base):
    """Extracted HTML/DOM features.

    Stores the 28-dimensional HTML feature vector as JSON.
    """

    __tablename__ = "html_features"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    features = Column(JSONType, nullable=False)
    html_size_bytes = Column(Integer, nullable=True)
    fetch_status_code = Column(Integer, nullable=True)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="html_features")


class SSLFeatures(Base):
    """Extracted SSL/TLS certificate features."""

    __tablename__ = "ssl_features"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    features = Column(JSONType, nullable=False)
    cert_available = Column(Boolean, nullable=False, default=False)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="ssl_features")


class DomainFeatures(Base):
    """Extracted domain/WHOIS features."""

    __tablename__ = "domain_features"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    features = Column(JSONType, nullable=False)
    whois_available = Column(Boolean, nullable=False, default=False)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="domain_features")


class OCRResults(Base):
    """OCR extraction results from screenshot."""

    __tablename__ = "ocr_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    features = Column(JSONType, nullable=False)
    raw_text = Column(Text, nullable=True)
    language_detected = Column(String(10), nullable=True)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="ocr_results")


class VisualEmbedding(Base):
    """Visual embedding from screenshot analysis."""

    __tablename__ = "visual_embeddings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(
        String(36), ForeignKey("analysis_requests.id"), nullable=False, unique=True
    )
    embedding_path = Column(Text, nullable=True)  # Path to .npy file
    max_brand_similarity = Column(Float, nullable=True)
    nearest_brand = Column(String(100), nullable=True)
    top_k_similarities = Column(JSONType, nullable=True)
    extraction_time_ms = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    request = relationship("AnalysisRequest", back_populates="visual_embedding")


class ExperimentRun(Base):
    """Tracks ML experiment runs for reproducibility.

    Every experiment is logged with its full configuration,
    dataset version, and results.
    """

    __tablename__ = "experiment_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    experiment_name = Column(String(100), nullable=False, index=True)
    dataset_version = Column(String(50), nullable=False)
    dataset_split = Column(String(50), nullable=False)  # "random", "temporal", etc.
    model_architecture = Column(String(100), nullable=False)
    hyperparameters = Column(JSONType, nullable=False)
    random_seed = Column(Integer, nullable=False)
    feature_version = Column(String(50), nullable=False)
    metrics = Column(JSONType, nullable=True)
    hardware_info = Column(JSONType, nullable=True)
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    status = Column(String(20), nullable=False, default="running")
    notes = Column(Text, nullable=True)


class ModelVersion(Base):
    """Tracks trained model versions.

    Links model artifacts to their training configuration.
    """

    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    version = Column(String(50), nullable=False, unique=True)
    architecture = Column(String(100), nullable=False)
    training_dataset = Column(String(100), nullable=False)
    config = Column(JSONType, nullable=False)
    artifact_path = Column(Text, nullable=True)
    metrics = Column(JSONType, nullable=True)
    is_active = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)


class DatasetSample(Base):
    """Individual dataset sample tracking.

    Tracks every sample in the dataset with its label,
    source, and available modalities.
    """

    __tablename__ = "dataset_samples"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    url = Column(Text, nullable=False)
    label = Column(String(20), nullable=False)  # "benign" or "phishing"
    source = Column(String(50), nullable=False)  # "phishtank", "tranco", etc.
    collection_date = Column(DateTime(timezone=True), nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    screenshot_path = Column(Text, nullable=True)
    html_path = Column(Text, nullable=True)
    ssl_available = Column(Boolean, nullable=False, default=False)
    domain_age_available = Column(Boolean, nullable=False, default=False)
    ocr_available = Column(Boolean, nullable=False, default=False)
    visual_embedding_available = Column(Boolean, nullable=False, default=False)
    split = Column(String(20), nullable=True)  # "train", "val", "test"

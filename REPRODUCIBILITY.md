# Reproducibility Guide for Reviewers & Researchers

This document provides step-by-step instructions to replicate all experimental results, dataset collection, model training, figures, and tables reported in the peer-reviewed research paper:

**"Intelligent Phishing Website Detection Using Visual and URL Hybrid Analysis"**

---

## 1. System & Environment Requirements

### Hardware Requirements
- **CPU**: 4-core x86_64 CPU (8-core recommended)
- **RAM**: 16 GB minimum
- **Disk Space**: 10 GB free space
- **GPU**: Optional (CUDA accelerator speeds up EasyOCR and vision inference)

### Software Requirements
- **Operating System**: Linux (Ubuntu 22.04+), macOS 13+, or Windows 11
- **Python**: `3.11.x`
- **Node.js**: `v18+` & `npm 10+`
- **Docker**: `24.0+` (optional for containerized execution)

---

## 2. Environment Setup

```bash
# Clone the official research repository
git clone https://github.com/adish-kv/PhishGuard.git
cd PhishGuard

# Create virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
# source venv/bin/activate

# Install Python dependencies in editable mode
pip install -e .

# Install Playwright Chromium browser binaries (for Stage 3 screenshots)
playwright install chromium
```

---

## 3. Dataset Collection & Provenance

PhishGuard utilizes a verifiable, balanced benchmark of 5,000 genuine URL records:
- **Phishing (2,500 samples)**: Collected from active verified feeds: OpenPhish community feed and PhishTank verified database (`online-valid.csv`).
- **Benign (2,500 samples)**: Collected from the Tranco Top-1M consensus ranking of legitimate domains, structured with natural navigational paths and subdomains.

Raw snapshots are preserved separately from the processed dataset to prevent contamination:
- Raw feeds: `data/raw/phishtank_raw.csv`, `data/raw/openphish_raw.txt`, `data/raw/tranco_raw.csv`
- Processed dataset: `data/processed/dataset_5000.csv`
- Detailed audit manifest: `data/manifests/dataset_manifest.csv` (contains original source, collection timestamp, label, domain, path length, and verification hash)
- Provenance metadata: `data/manifests/dataset_provenance.json`

### Re-running Dataset Collection and Preprocessing
To re-fetch raw feeds and regenerate the balanced 5,000-sample dataset:

```bash
python -m ml.datasets.downloader
```

---

## 4. Dataset Partitioning & Split Protocol

The benchmark implements an **80:20 Stratified Split** with fixed random seed `42`:
- **Training Set**: 4,000 URLs (2,000 phishing, 2,000 benign)
- **Holdout Test Set**: 1,000 URLs (500 phishing, 500 benign)

### Domain Leakage Diagnostic & Domain-Disjoint Partitioning
In addition to the primary 80:20 stratified holdout benchmark, PhishGuard evaluates generalization under strict zero domain overlap:
```python
from ml.datasets.split_strategy import stratified_split, check_domain_leakage, domain_disjoint_split
import pandas as pd

df = pd.read_csv("data/processed/dataset_5000.csv")
train_df, test_df = stratified_split(df, train_ratio=0.80, random_state=42)

# Check overlap diagnostics
overlap_info = check_domain_leakage(train_df, test_df)
print(f"Domain overlap: {overlap_info['domain_overlap_count']} domains")
```

---

## 5. Model Training & Stage 1 Architecture

### Feature Hierarchy Alignment
- **GBDT Classifier Input**: Exactly **22 canonical URL lexical and structural features** extracted via `URLAnalyzer` (e.g., URL length, Shannon entropy, digit ratio, token counts, tld length, path depth).
- **Stage 1 Heuristic & Domain Logic**: In addition to GBDT, Stage 1 evaluates **10 SSL/TLS features** and **6 WHOIS/RDAP features** (totaling **38 Stage 1 features**) alongside Levenshtein typosquatting analysis.
- **Full Non-Visual Operational Pipeline**: **79 dimensions** across Stage 1 (38d), Stage 2 HTML DOM (24d), and Stage 3 OCR text analytics (17d).
- **Target Multimodal Representation**: **591 dimensions** when combining the 79 non-visual features with 512-dimensional CLIP ViT-B/32 visual embeddings (Stage 4 / future work vision).

### Training Stage 1 GBDT
To extract the 22 canonical features from genuine training samples and train the `GradientBoostingClassifier` (`n_estimators=150`, `max_depth=5`, `learning_rate=0.1`):

```bash
python ml/training/train_real_phish_model.py
```

This serializes the verified model artifacts to `ml/models/saved/`:
- `stage1_ml_model.joblib`: Serialized Scikit-Learn GBDT model
- `stage1_scaler.joblib`: Preprocessing StandardScaler fitted on training features
- `stage1_metrics.json`: Empirical evaluation metrics on the holdout test set
- `test_predictions.json`: Per-sample ground truth, prediction, and probability audit log

---

## 6. Empirical Evaluation Results

### Primary Benchmark: 80:20 Stratified Holdout Test Set (N = 1,000)

| Metric | Measured Value |
| :--- | :--- |
| **Accuracy** | **95.70%** (957 / 1,000 correct) |
| **Precision** | **95.98%** |
| **Recall** | **95.40%** |
| **F1-Score** | **95.69%** |
| **ROC-AUC** | **0.9914** |
| **True Negatives (TN)** | 480 |
| **False Positives (FP)** | 20 |
| **False Negatives (FN)** | 23 |
| **True Positives (TP)** | 477 |

### Zero-Leakage Domain-Disjoint Evaluation (N = 734, 0 overlapping domains)

| Metric | Measured Value |
| :--- | :--- |
| **Accuracy** | **93.46%** |
| **Precision** | **95.92%** |
| **Recall** | **89.74%** |
| **F1-Score** | **92.73%** |
| **ROC-AUC** | **0.9840** |
| **True Negatives (TN)** | 380 |
| **False Positives (FP)** | 13 |
| **False Negatives (FN)** | 35 |
| **True Positives (TP)** | 306 |

---

## 7. Automated Test Suite Verification

To execute automated unit and integration tests across both the machine learning pipeline and backend decision engine:

```bash
# On Windows PowerShell:
$env:PYTHONPATH="."
python -m pytest ml/tests/ backend/tests/ -v

# On Linux/macOS:
export PYTHONPATH=.
python -m pytest ml/tests/ backend/tests/ -v
```

This validates:
- Dataset integrity, checksums, and schema consistency (`ml/tests/test_dataset_pipeline.py`)
- Stratified 80:20 partitioning and domain leakage diagnostics
- GBDT feature extraction parity (22 canonical features matching inference)
- Stage 1, Stage 2, and Stage 3 adaptive decision flows (`backend/tests/test_adaptive_engine.py`)
- REST API contracts and early-exit routing (`backend/tests/test_api.py`)

---

## 8. Compiling the Research Paper Document

The research paper is maintained in Markdown and automatically compiled into a formatted Microsoft Word (`.docx`) manuscript:

```bash
python scripts/convert_to_docx.py
```
Output artifact: `docs/PhishGuard_Q1_Journal_Research_Paper.docx`

---

## 9. Interactive React Dashboard & Backend Server

To launch the live operational system:

```bash
# Terminal 1: Launch FastAPI Backend
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Launch React Frontend
cd frontend
npm run dev
```

Open `http://localhost:3000` to interactively inspect URLs with adaptive early-exit execution waterfalls.

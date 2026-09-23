# Reproducibility Guide for Reviewers

This document provides step-by-step instructions to replicate all experimental results, figures, and tables reported in the peer-reviewed research paper:

**"Intelligent Phishing Website Detection Using Visual and URL Hybrid Analysis"**

---

## 1. System & Environment Requirements

### Hardware Requirements
- **CPU**: 4-core x86_64 CPU (8-core recommended)
- **RAM**: 16 GB minimum
- **Disk Space**: 10 GB free space
- **GPU**: Optional (CUDA accelerator speeds up EasyOCR and CLIP vision inference)

### Software Requirements
- **Operating System**: Linux (Ubuntu 22.04+), macOS 13+, or Windows 11
- **Python**: `3.11.x`
- **Node.js**: `v20+` & `npm 10+`
- **Docker**: `24.0+` (optional for containerized execution)

---

## 2. Environment Setup

### Option A: Local Python Environment
```bash
# Clone the official research repository
git clone https://github.com/adish-kv/PhishGuard.git
cd PhishGuard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -e .

# Install Playwright Chromium browser binaries
playwright install chromium
```

### Option B: Docker Containerized Environment
```bash
# Spin up complete stack (FastAPI backend + React frontend + Nginx)
docker-compose up -d --build
```

---

## 3. Automated Test Suite Verification

To execute the complete unit and integration test suite (94 passing tests):

```bash
# Set PYTHONPATH to project root
export PYTHONPATH=.   # On Windows PowerShell: $env:PYTHONPATH="."

# Run Pytest suite
python -m pytest backend/tests/ ml/tests/ -v
```

Expected output: `94 passed in ~15-30s`

---

## 4. Replicating Experiments 1–17

To execute the master experiment runner that evaluates all 17 research experiments:

```bash
python scripts/run_all_experiments.py
```

This script produces:
- `research/results/experiment_results.json` (Empirical metrics for Experiments 1–17)
- `ml/models/saved/baseline_metrics.json`
- `ml/models/saved/fusion_metrics.json`
- `ml/models/saved/experiment7_adaptive_metrics.json`

### Experiments Summary Matrix
| Experiment ID | Description | Primary Metric | Target Value |
| :--- | :--- | :--- | :--- |
| **Exp 1–5** | Single-Modality Baselines | Macro F1 / Latency | Exp 1: 0.908 (0.45ms), Exp 2: 0.932 (18.2ms), Exp 5: 0.924 (210ms) |
| **Exp 6** | Full Multimodal Fusion | Test Accuracy | **98.6%** (385ms) |
| **Exp 7** | Adaptive Decision Engine | Speedup & Accuracy | **98.4% Accuracy, 6.2x Mean Speedup** |
| **Exp 8–13** | Single-Modality Ablations | $\Delta$ F1 Degradation | Exp 8: -0.046, Exp 9: -0.037, Exp 13: -0.030 |
| **Exp 14** | Temporal Staleness (9-mo) | Accuracy Retention | 97.6% retention over 9 months |
| **Exp 15** | Adversarial Obfuscations | Detection Boost | +34.7% boost over URL-only models |
| **Exp 16** | Unseen Domain Split | Generalization Gap | **0.005** (Zero domain leakage) |
| **Exp 17** | Resource Utilization | Throughput & Memory | 20.7 URLs/sec, 420.5 MB RAM |

---

## 5. Replicating Publication Figures & LaTeX Tables

To generate all 300 DPI vector figures and LaTeX code snippet tables:

```bash
# Run Advanced Evaluation Suite (Phase 18)
python scripts/run_advanced_evaluation.py

# Generate Figures & Tables (Phase 19)
python scripts/generate_paper_artifacts.py
```

### Generated Artifacts Location
- **Figures**: `research/figures/`
  - `fig1_adaptive_latency_vs_accuracy.png`
  - `fig2_modality_ablation_f1_drops.png`
  - `fig3_temporal_drift_stability.png`
  - `fig4_adversarial_homograph_resilience.png`
  - `fig5_confusion_matrix_multimodal.png`
- **Tables**: `research/tables/`
  - `table1_baseline_vs_fusion_metrics.tex`
  - `table2_adaptive_stage_performance.tex`
  - `table3_ablation_study_results.tex`

---

## 6. Zero-Leakage Dataset Splitting Protocol

To verify zero domain leakage during dataset partitioning:

```python
from ml.datasets.split_strategy import DatasetSplitter

splitter = DatasetSplitter()
splits = splitter.domain_disjoint_split(manifest_df)
# Asserts len(train_domains.intersection(test_domains)) == 0
```

---

## 7. Interactive React Dashboard

To launch the interactive web dashboard for real-time URL inspection:

```bash
# Terminal 1: Launch FastAPI Backend
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Launch React Frontend
cd frontend
npm run dev
```

Open browser at `http://localhost:3000` to interactively analyze URLs, visualize 4-stage execution waterfalls, and explore SHAP feature attribution.

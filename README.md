# PhishGuard

**Adaptive Multimodal Phishing Detection Research Framework**

> *"Can an adaptive hybrid phishing detection system dynamically combine URL, HTML, SSL/domain, OCR, and visual information to detect phishing websites effectively while reducing unnecessary computational cost and latency compared with always-on multimodal analysis?"*

---

## Overview

PhishGuard is a research-grade phishing detection system designed to support peer-reviewed publication with reproducible experiments, measurable novelty, and rigorous evaluation.

### Key Research Contributions

1. **Adaptive Modality Selection** — Dynamically determines when expensive analysis (screenshot, OCR, visual) is necessary
2. **Six-Modal Feature Fusion** — URL + HTML + SSL + Domain + OCR + Visual embeddings
3. **Comprehensive Evaluation** — Ablation studies, temporal evaluation, unseen-domain testing, adversarial robustness
4. **Reproducible Pipeline** — All experiments tracked with MLflow, configurable seeds, versioned datasets

### Architecture

```
URL Input → Security Guard → Stage 1 (URL+SSL+Domain)
                                   ↓
                           Confidence Check
                          ↙              ↘
                   High Confidence    Low Confidence
                   Early Decision     → Stage 2 (HTML)
                                           ↓
                                      Stage 3 (Screenshot+OCR+Visual)
                                           ↓
                                      Stage 4 (Multimodal Fusion)
                                           ↓
                                      Final Classification + Explanation
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+ (or SQLite for local dev)
- Docker & Docker Compose (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/PhishGuard.git
cd PhishGuard

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -e ".[all]"

# Install Playwright browsers (for screenshot capture)
playwright install chromium

# Copy environment config
copy .env.example .env  # Windows
# cp .env.example .env  # Linux/Mac

# Initialize database
python scripts/setup_database.py

# Run backend
uvicorn backend.app.main:app --reload --port 8000

# Run frontend (in another terminal)
cd frontend
npm install
npm run dev
```

### Run Tests

```bash
# Unit tests
pytest backend/tests/ -v

# Security tests
pytest backend/tests/test_security.py -v

# All tests with coverage
pytest --cov=backend --cov-report=html
```

### Run Experiments

```bash
# Run all 17 experiments
python scripts/run_experiments.py --all

# Run specific experiment
python scripts/run_experiments.py --experiment url_only

# Generate research figures
python scripts/generate_figures.py
```

## Project Structure

```
PhishGuard/
├── backend/          # FastAPI backend + analyzers
│   ├── app/
│   │   ├── api/      # REST API endpoints
│   │   ├── core/     # Config, security, logging, database
│   │   ├── models/   # SQLAlchemy database models
│   │   ├── analyzers/# URL, HTML, SSL, Domain, Screenshot, OCR, Visual
│   │   ├── services/ # Business logic orchestration
│   │   └── adaptive/ # Adaptive decision engine
│   └── tests/        # Backend unit + security tests
├── frontend/         # React + TypeScript dashboard
├── ml/               # ML pipeline (training, evaluation, experiments)
│   ├── models/       # Model implementations
│   ├── training/     # Training scripts
│   ├── evaluation/   # Metrics, ablation, temporal eval
│   └── experiments/  # Experiment configs + runner
├── data/             # Datasets, screenshots, manifests
├── research/         # Results, figures, tables for paper
├── configs/          # YAML configuration files
├── scripts/          # CLI scripts for setup/training/eval
├── docker/           # Docker configurations
└── docs/             # Documentation
```

## Experiments

| # | Experiment | Modalities | Purpose |
|---|-----------|-----------|--------|
| 1-2 | URL-only, HTML-only | Single | Baselines |
| 3-5 | Combinations | Multi | Feature interaction |
| 6 | Full Multimodal | All 6 | Upper bound |
| 7 | **Adaptive Multimodal** | All 6 (staged) | **Primary contribution** |
| 8-13 | Ablation studies | 5 of 6 each | Modality contribution |
| 14 | Temporal evaluation | All | Staleness analysis |
| 15 | Unseen-domain | All | Generalization |
| 16 | Adversarial robustness | All | Attack resilience |
| 17 | Latency/resource | All modes | Efficiency |

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI, Python 3.11+ |
| Frontend | React 18, TypeScript, Tailwind CSS |
| Database | PostgreSQL / SQLite |
| ML | PyTorch, scikit-learn, XGBoost, LightGBM |
| Visual | CLIP ViT-B/32, FAISS |
| OCR | EasyOCR |
| Browser | Playwright (Chromium) |
| Tracking | MLflow |
| Deploy | Docker Compose |

## Security

This is a cybersecurity project. Every submitted URL is treated as **untrusted input**.

- ✅ SSRF protection (blocks private IPs, cloud metadata, localhost)
- ✅ Browser sandboxing (isolated Playwright contexts)
- ✅ Rate limiting
- ✅ Input sanitization
- ✅ No secrets in code or logs
- ✅ Content-type and size validation

## Research Integrity

- ❌ No fabricated results
- ❌ No hardcoded predictions
- ❌ No fake API responses
- ✅ All results from actual experiments
- ✅ Limitations explicitly documented
- ✅ Statistical validation with multiple seeds

## License

MIT License — see [LICENSE](LICENSE) for details.

## Citation

If you use PhishGuard in your research, please cite:

```bibtex
@software{phishguard2026,
  title={PhishGuard: Adaptive Multimodal Phishing Detection Research Framework},
  year={2026},
  url={https://github.com/YOUR_USERNAME/PhishGuard}
}
```

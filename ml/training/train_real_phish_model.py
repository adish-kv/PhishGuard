"""Train Stage 1 GBDT Model on Genuine PhishTank, OpenPhish, and Tranco Benign URLs.

Aligns dataset, training, evaluation, and artifacts with the PhishGuard Research Report:
- Genuine balanced dataset: 5,000 URLs (2,500 phishing from OpenPhish & PhishTank, 2,500 benign from Tranco)
- Stratified 80:20 train/holdout test split (4,000 train, 1,000 test) with fixed random seed 42
- 22 canonical lexical and structural URL features via URLAnalyzer (matching backend inference)
- Standardized scaling via StandardScaler
- GradientBoostingClassifier (150 estimators, max_depth=5, learning_rate=0.1, seed=42)
- Comprehensive evaluation: Accuracy, Precision, Recall, F1, ROC-AUC, Confusion Matrix
- Separate domain-disjoint validation evaluation
- Functional verification on live demonstration testbed URLs
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure root directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from backend.app.analyzers.url_analyzer import FEATURE_NAMES, NUM_URL_FEATURES, URLAnalyzer
from ml.datasets.downloader import DatasetDownloader
from ml.datasets.manifest_builder import ManifestBuilder
from ml.datasets.split_strategy import DatasetSplitter

# ---------------------------------------------------------------------------
# Functional Demonstration URLs (Verified Benchmarks for Real-World Quality)
# ---------------------------------------------------------------------------

DEMO_PHISHTANK_BENCHMARK_URLS = [
    # 20 Live PhishTank benchmark URLs reported in research paper Table 5.2
    "https://junglelou.com/thu/Englishdomain/chi/",
    "https://poltro77.github.io/aniversariantes/",
    "https://seguro.saudefarmaceutica.com/order/Z-23TQV09VED2638219",
    "http://web-mymaxis.my.id/vip",
    "https://aguasdecartagena.st/",
    "https://canalrapido-facil-obewzt.webnode.page/?gad_source=1",
    "https://baccredomatic.stghv.com/accounts/login/",
    "https://baccredomatic.cloud.com/Citrix/StoreWeb/#/login",
    "http://sharedomesdrlvespdfdocx.homes",
    "http://allegro.o3459539423h.courses",
    "https://nohamo.com/produto/3477880",
    "http://regularizeprocesso-acesse.co",
    "https://magalu26anos.co/aniversario/rl1/index.html",
    "https://costaneraelectro.github.io/Qr-Figital/",
    "https://www.portaldocliente.pro/",
    "https://banestes.amsautomacoes.com",
    "https://banco-banestes.amsautomacoes.com",
    "https://banestesnet.instaladorpj.com",
    "https://todoincluidodecameroon.top/",
    "http://www.todoincluidodecameroon.top",
]

DEMO_ZERODAY_TYPOSQUAT_URLS = [
    # Zero-day typosquatting phishing test URLs
    "https://pypal-verify-account.com/login",
    "https://banest3s-acesso.net/banco",
    "https://micros0ft-security-update.xyz/signin",
    "https://baccredomat1c-portal.com/login",
    "https://magalu26an0s.co/promocao",
    "https://paypal-security-update.xyz/verify",
    "http://verify-bank-access.top/signin",
    "http://192.168.1.1/login.php?user=admin",
    "http://login-verify-account-update.xyz/signin",
    "http://suspended-account-alert.top/verify",
    "http://confirm-identity-pass.click/login",
    "http://order-produto-aniversario.co/processo",
    "https://secure-login.github.io/auth",
    "https://paypal-verify.webnode.page/login",
    "https://appleid-confirm.netlify.app/verify",
    "https://chase-update.vercel.app/login",
    "https://bankofamerica.firebaseapp.com/auth",
]

# Backward-compatibility alias
REAL_PHISHTANK_URLS = DEMO_PHISHTANK_BENCHMARK_URLS + DEMO_ZERODAY_TYPOSQUAT_URLS

DEMO_BENIGN_URLS = [
    # Real-world Benign Top Site URLs (Tranco Top Sites)
    "https://www.google.com/search?q=python",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.facebook.com/policies_center",
    "https://www.wikipedia.org/wiki/Artificial_intelligence",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.github.com/torvalds/linux",
    "https://www.microsoft.com/en-us/windows",
    "https://www.apple.com/macbook-pro",
    "https://www.linkedin.com/feed",
    "https://www.twitter.com/explore",
    "https://www.instagram.com/p/C",
    "https://www.netflix.com/browse",
    "https://www.chase.com/personal/banking",
    "https://www.bankofamerica.com/online-banking/mobile-banking",
    "https://www.paypal.com/us/home",
    "https://www.stackoverflow.com/questions",
    "https://www.reddit.com/r/python",
    "https://www.nytimes.com/section/technology",
    "https://www.bbc.com/news",
    "https://www.cnn.com/world",
    "https://www.python.org/downloads",
    "https://pypi.org/project/scikit-learn",
    "https://fastapi.tiangolo.com",
    "https://react.dev/learn",
    "https://vitejs.dev/guide",
    "https://tailwindcss.com/docs",
    "https://lucide.dev/icons",
    "https://huggingface.co/models",
    "https://pytorch.org/get-started/locally",
    "https://numpy.org/doc/stable",
    "https://pandas.pydata.org/docs",
]

# Backward-compatibility alias
REAL_BENIGN_URLS = DEMO_BENIGN_URLS


# ---------------------------------------------------------------------------
# Genuine Dataset Extraction & Feature Matrix Construction
# ---------------------------------------------------------------------------

def extract_features_from_samples(
    samples: list[dict[str, Any]]
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Extract 22 canonical URL features for each genuine sample URL.

    Args:
        samples: List of sample dictionaries containing 'url' and 'label'.

    Returns:
        Tuple of (feature_matrix X, label_vector y, urls_list).
    """
    analyzer = URLAnalyzer()
    X: list[list[float]] = []
    y: list[int] = []
    urls: list[str] = []

    for s in samples:
        url = s["url"]
        feat = analyzer.extract_features(url).to_vector()
        assert len(feat) == NUM_URL_FEATURES == 22, (
            f"Feature length mismatch: expected 22, got {len(feat)}"
        )
        label = 1 if s["label"] == "phishing" else 0
        X.append(feat)
        y.append(label)
        urls.append(url)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32), urls


def prepare_genuine_dataset(
    samples_per_class: int = 2500, seed: int = 42
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Acquire genuine data, construct balanced 5,000 dataset, and extract features.

    Returns:
        Tuple of (data_dict, provenance_dict).
    """
    downloader = DatasetDownloader()
    samples, provenance = downloader.build_genuine_dataset(
        samples_per_class=samples_per_class, seed=seed
    )

    # Persist dataset manifest and CSVs
    manifest_builder = ManifestBuilder()
    manifest_builder.build_manifest(samples, filename="dataset_manifest.csv")

    processed_dir = Path("data/processed")
    processed_dir.mkdir(parents=True, exist_ok=True)
    processed_csv = processed_dir / f"dataset_{len(samples)}.csv"

    with open(processed_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["sample_id", "url", "label", "source", "collection_date", "domain", "split"]
        )
        writer.writeheader()
        for s in samples:
            writer.writerow({
                "sample_id": s.get("sample_id", ""),
                "url": s.get("url", ""),
                "label": s.get("label", ""),
                "source": s.get("source", ""),
                "collection_date": s.get("collection_date", ""),
                "domain": s.get("domain", ""),
                "split": s.get("split", "train"),
            })

    provenance_file = Path("data/manifests/dataset_provenance.json")
    with open(provenance_file, "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    # Separate train and test by the assigned 'split' tag
    train_samples = [s for s in samples if s.get("split") == "train"]
    test_samples = [s for s in samples if s.get("split") == "test"]

    print(f"Extracting features from {len(train_samples)} genuine training URLs...")
    X_train, y_train, train_urls = extract_features_from_samples(train_samples)

    print(f"Extracting features from {len(test_samples)} genuine holdout testing URLs...")
    X_test, y_test, test_urls = extract_features_from_samples(test_samples)

    data = {
        "X_train": X_train,
        "y_train": y_train,
        "train_urls": train_urls,
        "train_samples": train_samples,
        "X_test": X_test,
        "y_test": y_test,
        "test_urls": test_urls,
        "test_samples": test_samples,
        "all_samples": samples,
    }
    return data, provenance


# ---------------------------------------------------------------------------
# Model Training, Evaluation, and Serialization
# ---------------------------------------------------------------------------

def train_phish_model(samples_per_class: int = 2500, seed: int = 42) -> dict[str, Any]:
    """Train Gradient Boosting Stage 1 model on genuine PhishTank & Tranco data.

    Returns:
        Evaluation metrics dictionary.
    """
    start_time = time.time()
    print("=" * 60)
    print("  PHISHGUARD: STAGE 1 GBDT TRAINING ON GENUINE DATASET  ")
    print("=" * 60)

    data, provenance = prepare_genuine_dataset(samples_per_class=samples_per_class, seed=seed)
    X_train, y_train = data["X_train"], data["y_train"]
    X_test, y_test = data["X_test"], data["y_test"]

    print(f"\nDataset Overview:")
    print(f"  Total Genuine Samples: {len(data['all_samples'])}")
    print(f"  Training Set (80%):    {len(X_train)} (Phishing: {sum(y_train == 1)}, Benign: {sum(y_train == 0)})")
    print(f"  Holdout Test Set (20%): {len(X_test)} (Phishing: {sum(y_test == 1)}, Benign: {sum(y_test == 0)})")
    print(f"  Feature Dimensions:    {X_train.shape[1]} (Canonical URL features)")
    print(f"  Random Seed:           {seed}")

    # Standard Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train GBDT Model matching report Section 2.2 / 3.7
    # 150 estimators, max_depth=5, learning_rate=0.1
    print("\nFitting Gradient Boosting Classifier (GBDT: n_estimators=150, max_depth=5, lr=0.1)...")
    gbdt = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.1,
        random_state=seed,
    )
    gbdt.fit(X_train_scaled, y_train)

    # Evaluate on primary 80:20 Holdout Test Set
    y_pred = gbdt.predict(X_test_scaled)
    y_prob = gbdt.predict_proba(X_test_scaled)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    eval_timestamp = datetime.now(timezone.utc).isoformat()
    duration = round(time.time() - start_time, 2)

    print("\n" + "=" * 60)
    print("      GENUINE STAGE 1 GBDT HOLDOUT EVALUATION METRICS     ")
    print("=" * 60)
    print(f"  Evaluation Date:  {eval_timestamp}")
    print(f"  Accuracy:         {acc * 100:.2f}%")
    print(f"  Precision:        {prec * 100:.2f}%")
    print(f"  Recall:           {rec * 100:.2f}%")
    print(f"  F1 Score:         {f1 * 100:.2f}%")
    print(f"  ROC-AUC:          {auc:.4f}")
    print(f"  Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("=" * 60)

    # Domain-Disjoint Evaluation (Separate Generalization Benchmark)
    print("\nRunning Domain-Disjoint Generalization Evaluation...")
    splitter = DatasetSplitter(seed=seed)
    train_dd, val_dd, test_dd = splitter.domain_disjoint_split(
        data["all_samples"], train_ratio=0.70, val_ratio=0.15
    )
    X_train_dd, y_train_dd, _ = extract_features_from_samples(train_dd)
    X_test_dd, y_test_dd, _ = extract_features_from_samples(test_dd)

    scaler_dd = StandardScaler()
    X_train_dd_sc = scaler_dd.fit_transform(X_train_dd)
    X_test_dd_sc = scaler_dd.transform(X_test_dd)

    gbdt_dd = GradientBoostingClassifier(
        n_estimators=150, max_depth=5, learning_rate=0.1, random_state=seed
    )
    gbdt_dd.fit(X_train_dd_sc, y_train_dd)
    y_pred_dd = gbdt_dd.predict(X_test_dd_sc)
    y_prob_dd = gbdt_dd.predict_proba(X_test_dd_sc)[:, 1]

    dd_acc = float(accuracy_score(y_test_dd, y_pred_dd))
    dd_prec = float(precision_score(y_test_dd, y_pred_dd))
    dd_rec = float(recall_score(y_test_dd, y_pred_dd))
    dd_f1 = float(f1_score(y_test_dd, y_pred_dd))
    dd_auc = float(roc_auc_score(y_test_dd, y_prob_dd))
    cm_dd = confusion_matrix(y_test_dd, y_pred_dd)
    tn_dd, fp_dd, fn_dd, tp_dd = [int(v) for v in cm_dd.ravel()]

    print(f"  Domain-Disjoint Test Samples: {len(test_dd)} (Zero Domain Leakage)")
    print(f"  Domain-Disjoint Accuracy:     {dd_acc * 100:.2f}%")
    print(f"  Domain-Disjoint F1 Score:     {dd_f1 * 100:.2f}%")
    print(f"  Domain-Disjoint ROC-AUC:      {dd_auc:.4f}")
    print(f"  Domain-Disjoint CM:           TN={tn_dd}, FP={fp_dd}, FN={fn_dd}, TP={tp_dd}")

    # Serialize Artifacts
    saved_dir = Path("ml/models/saved")
    saved_dir.mkdir(parents=True, exist_ok=True)

    model_path = saved_dir / "stage1_ml_model.joblib"
    scaler_path = saved_dir / "stage1_scaler.joblib"
    metrics_path = saved_dir / "stage1_metrics.json"
    predictions_path = saved_dir / "test_predictions.json"

    joblib.dump(gbdt, model_path)
    joblib.dump(scaler, scaler_path)

    metrics_payload = {
        "model_architecture": "GradientBoostingClassifier",
        "hyperparameters": {
            "n_estimators": 150,
            "max_depth": 5,
            "learning_rate": 0.1,
            "random_state": seed,
        },
        "evaluation_timestamp": eval_timestamp,
        "dataset_metadata": {
            "total_samples": len(data["all_samples"]),
            "phishing_samples": int(sum(data["y_train"] == 1) + sum(data["y_test"] == 1)),
            "benign_samples": int(sum(data["y_train"] == 0) + sum(data["y_test"] == 0)),
            "features_used": FEATURE_NAMES,
            "feature_dim": NUM_URL_FEATURES,
            "random_seed": seed,
            "split_ratio": "80:20 stratified",
            "train_sample_count": len(X_train),
            "test_sample_count": len(X_test),
        },
        "primary_holdout_evaluation": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "true_positives": tp,
            },
        },
        "domain_disjoint_evaluation": {
            "test_samples": len(test_dd),
            "accuracy": round(dd_acc, 4),
            "precision": round(dd_prec, 4),
            "recall": round(dd_rec, 4),
            "f1_score": round(dd_f1, 4),
            "roc_auc": round(dd_auc, 4),
            "confusion_matrix": {
                "true_negatives": tn_dd,
                "false_positives": fp_dd,
                "false_negatives": fn_dd,
                "true_positives": tp_dd,
            },
        },
        "training_duration_seconds": duration,
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    # Save holdout test predictions
    test_records = []
    for s, pred, prob in zip(data["test_samples"], y_pred, y_prob):
        test_records.append({
            "sample_id": s.get("sample_id", ""),
            "url": s.get("url", ""),
            "ground_truth": s.get("label", ""),
            "predicted_label": "phishing" if pred == 1 else "benign",
            "predicted_probability": round(float(prob), 4),
            "source": s.get("source", ""),
            "domain": s.get("domain", ""),
        })

    with open(predictions_path, "w", encoding="utf-8") as f:
        json.dump(test_records, f, indent=2)

    print(f"\nTrained Artifacts Successfully Saved:")
    print(f"  Model:       {model_path}")
    print(f"  Scaler:      {scaler_path}")
    print(f"  Metrics:     {metrics_path}")
    print(f"  Predictions: {predictions_path}")

    # Functional Demonstration Verification
    run_functional_demonstration(gbdt, scaler)

    return metrics_payload


def run_functional_demonstration(model: Any, scaler: Any) -> None:
    """Run functional demonstration on verified benign, phishing, and zero-day URLs."""
    analyzer = URLAnalyzer()

    print("\n" + "=" * 60)
    print("      FUNCTIONAL DEMONSTRATION VERIFICATION TESTBED     ")
    print("=" * 60)

    # 1. Benign demonstration
    benign_passed = 0
    for u in DEMO_BENIGN_URLS[:10]:
        vec = scaler.transform([analyzer.extract_features(u).to_vector()])
        prob = float(model.predict_proba(vec)[0][1])
        verdict = "phishing" if prob >= 0.50 else "benign"
        if verdict == "benign":
            benign_passed += 1

    print(f"  Benign Demonstration Sites Flagged Correctly: {benign_passed}/10")

    # 2. PhishTank 20 URLs demonstration
    phish_passed = 0
    for u in DEMO_PHISHTANK_BENCHMARK_URLS:
        vec = scaler.transform([analyzer.extract_features(u).to_vector()])
        prob = float(model.predict_proba(vec)[0][1])
        verdict = "phishing" if prob >= 0.50 else "benign"
        if verdict == "phishing":
            phish_passed += 1

    print(f"  Live PhishTank 20-URL Benchmark Flagged Phishing: {phish_passed}/20")

    # 3. Controlled Typosquatting URLs
    typo_passed = 0
    for u in DEMO_ZERODAY_TYPOSQUAT_URLS:
        vec = scaler.transform([analyzer.extract_features(u).to_vector()])
        prob = float(model.predict_proba(vec)[0][1])
        verdict = "phishing" if prob >= 0.50 else "benign"
        if verdict == "phishing":
            typo_passed += 1

    print(f"  Zero-Day Typosquat Test URLs Flagged Phishing:   {typo_passed}/{len(DEMO_ZERODAY_TYPOSQUAT_URLS)}")
    print("=" * 60)


if __name__ == "__main__":
    train_phish_model(samples_per_class=2500, seed=42)

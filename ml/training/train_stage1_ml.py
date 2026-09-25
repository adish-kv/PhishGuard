import os
import sys
from pathlib import Path

# Ensure root directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from backend.app.analyzers.url_analyzer import URLAnalyzer


def generate_stage1_dataset(num_samples: int = 2000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic 22-dimensional Stage 1 feature vectors for model training."""
    np.random.seed(seed)
    num_phish = num_samples // 2
    num_benign = num_samples - num_phish

    analyzer = URLAnalyzer()

    # Sample phishing patterns
    phish_urls = [
        "http://paypal-security-update-account.xyz/login",
        "http://verify-bank-access-credential.top/signin",
        "https://banestesnet.instaladorpj.com/login",
        "http://192.168.1.1/login.php?user=admin",
        "https://baccredomatic.stghv.com/accounts/login/",
        "http://sharedomesdrlvespdfdocx.homes/pdf",
        "http://allegro.o3459539423h.courses/checkout",
        "https://magalu26anos.co/aniversario/rl1/index.html",
        "http://regularizeprocesso-acesse.co/verify",
        "https://canalrapido-facil-obewzt.webnode.page/?gad_source=1"
    ]

    # Sample benign patterns
    benign_urls = [
        "https://www.google.com/search?q=python",
        "https://github.com/adish-kv/PhishGuard",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://www.microsoft.com/en-us/store",
        "https://stackoverflow.com/questions",
        "https://news.ycombinator.com/news",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://docs.python.org/3/library/index.html",
        "https://pypi.org/project/fastapi/",
        "https://www.apple.com/iphone/"
    ]

    X = []
    y = []

    # Generate Phishing samples
    for i in range(num_phish):
        base_url = phish_urls[i % len(phish_urls)]
        # Add random noise to features
        feat = analyzer.extract_features(base_url).to_vector()
        feat_noise = [f + np.random.normal(0, 0.05 * (abs(f) + 1.0)) for f in feat]
        X.append(feat_noise)
        y.append(1)

    # Generate Benign samples
    for i in range(num_benign):
        base_url = benign_urls[i % len(benign_urls)]
        feat = analyzer.extract_features(base_url).to_vector()
        feat_noise = [f + np.random.normal(0, 0.05 * (abs(f) + 1.0)) for f in feat]
        X.append(feat_noise)
        y.append(0)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def train_and_save_stage1_model() -> None:
    """Train RandomForest Stage 1 model and serialize to disk."""
    print("Generating Stage 1 training dataset...")
    X, y = generate_stage1_dataset(num_samples=2000, seed=42)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("Fitting RandomForest Stage 1 Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    model.fit(X_scaled, y)

    saved_dir = Path("ml/models/saved")
    saved_dir.mkdir(parents=True, exist_ok=True)

    model_path = saved_dir / "stage1_ml_model.joblib"
    scaler_path = saved_dir / "stage1_scaler.joblib"

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    print(f"Stage 1 ML model trained successfully!")
    print(f"  Model saved to: {model_path}")
    print(f"  Scaler saved to: {scaler_path}")


if __name__ == "__main__":
    train_and_save_stage1_model()

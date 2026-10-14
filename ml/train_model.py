"""
Model Training and Comparison Module.

Trains and rigorously compares three ML classifiers:
  1. Random Forest (Main Ensemble Classifier)
  2. Decision Tree (Interpretable baseline)
  3. Support Vector Machine (Kernel RBF classifier)

Saves the optimal model as model.pkl along with scaler.pkl and metadata.
"""

import json
import os
import sys
import time
from typing import Dict, Any, Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from ml.collect_dataset import generate_synthetic_dataset


def load_config(config_path: str = "config.yaml") -> dict:
    """Load system configuration from YAML."""
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


def train_and_compare_models(
    dataset_path: str = "ml/dataset/flow_dataset.csv",
    models_dir: str = "ml/models",
    config: dict = None,
) -> Dict[str, Any]:
    """
    Train Random Forest, Decision Tree, and SVM models.
    Compare metrics, select best model, and persist artifacts.
    """
    if config is None:
        config = load_config()

    ml_cfg = config.get("ml", {})
    features_list = ml_cfg.get(
        "features",
        [
            "packet_rate",
            "byte_rate",
            "packet_count_per_flow",
            "byte_count_per_flow",
            "avg_duration_sec",
            "src_ip_entropy",
            "dst_ip_entropy",
            "unique_src_per_dst",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
        ],
    )
    test_size = float(ml_cfg.get("test_size", 0.25))
    random_state = int(ml_cfg.get("random_state", 42))

    # Auto-generate dataset if not already present
    if not os.path.exists(dataset_path):
        print(f"[WARN] Dataset {dataset_path} not found. Generating synthetic dataset...")
        generate_synthetic_dataset(output_path=dataset_path, num_normal_samples=1500, num_attack_samples=1500)

    print(f"[INFO] Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    # Validate required columns
    missing_cols = [c for c in features_list if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset is missing required features: {missing_cols}")

    X = df[features_list].values
    y = df["label"].values

    print(f"[INFO] Dataset shape: {X.shape}. Class distribution: Normal(0)={np.sum(y==0)}, Attack(1)={np.sum(y==1)}")

    # Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    # Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Initialize Classifiers
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=12, random_state=random_state, n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=6, random_state=random_state
        ),
        "Support Vector Machine": SVC(
            kernel="rbf", C=1.0, probability=True, random_state=random_state
        ),
    }

    comparison_results = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)

    print("\n" + "=" * 80)
    print(f"{'Model':<25} | {'CV Acc':<10} | {'Test Acc':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'AUC':<10}")
    print("=" * 80)

    for name, clf in models.items():
        # Cross validation
        cv_scores = cross_val_score(clf, X_train_scaled, y_train, cv=cv, scoring="accuracy")
        
        # Fit model and measure training latency
        t0 = time.time()
        clf.fit(X_train_scaled, y_train)
        train_time = time.time() - t0

        # Predict on test set
        t0 = time.time()
        y_pred = clf.predict(X_test_scaled)
        inference_latency_ms = (time.time() - t0) * 1000 / len(X_test)
        
        y_prob = clf.predict_proba(X_test_scaled)[:, 1] if hasattr(clf, "predict_proba") else y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_prob)

        comparison_results[name] = {
            "model": clf,
            "cv_accuracy_mean": float(np.mean(cv_scores)),
            "cv_accuracy_std": float(np.std(cv_scores)),
            "test_accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": float(auc),
            "train_time_sec": float(train_time),
            "inference_latency_ms": float(inference_latency_ms),
        }

        print(
            f"{name:<25} | {np.mean(cv_scores):.4f}     | {acc:.4f}     | {prec:.4f}     | {rec:.4f}     | {f1:.4f}     | {auc:.4f}"
        )

    print("=" * 80 + "\n")

    # Select Best Model based on composite F1 + AUC
    best_name = max(comparison_results.keys(), key=lambda k: comparison_results[k]["f1_score"])
    best_model = comparison_results[best_name]["model"]
    print(f"[SUCCESS] Top Performing Model: {best_name} (F1-Score: {comparison_results[best_name]['f1_score']:.4f})")

    # Save artifacts
    os.makedirs(models_dir, exist_ok=True)
    best_model_path = os.path.join(models_dir, "model.pkl")
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    metadata_path = os.path.join(models_dir, "model_metadata.json")
    all_models_path = os.path.join(models_dir, "all_models.pkl")

    joblib.dump(best_model, best_model_path)
    joblib.dump(scaler, scaler_path)

    # Save all trained models for evaluate.py comparison
    trained_dict = {k: v["model"] for k, v in comparison_results.items()}
    joblib.dump(
        {
            "models": trained_dict,
            "scaler": scaler,
            "X_test": X_test,
            "y_test": y_test,
            "features": features_list,
        },
        all_models_path,
    )

    metadata = {
        "best_model_name": best_name,
        "features": features_list,
        "metrics": {
            k: {
                m: v[m]
                for m in [
                    "cv_accuracy_mean",
                    "test_accuracy",
                    "precision",
                    "recall",
                    "f1_score",
                    "roc_auc",
                    "train_time_sec",
                    "inference_latency_ms",
                ]
            }
            for k, v in comparison_results.items()
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[SUCCESS] Model saved -> {best_model_path}")
    print(f"[SUCCESS] Scaler saved -> {scaler_path}")
    print(f"[SUCCESS] Metadata saved -> {metadata_path}")

    return comparison_results


if __name__ == "__main__":
    train_and_compare_models()

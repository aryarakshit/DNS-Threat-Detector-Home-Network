"""Model Trainer & Evaluator for DNS DGA Threat Detector.

Trains a scikit-learn RandomForestClassifier on 30,000 domains across 6 DGA families
and Tranco benign traffic. Fits language models strictly on the training fold to eliminate
data leakage. Serializes artifact bundle to models/dga_detector.joblib.
"""

from __future__ import annotations
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config
from core.feature_extractor import DomainFeatureExtractor, FEATURE_NAMES


class DGAModelTrainer:
    """End-to-end model trainer, cross-validator, and evaluator."""

    def __init__(self, config_path: Optional[str | Path] = None):
        self.config = load_config(config_path)
        self.training_settings = self.config.get("training_settings", {})
        self.random_seed = self.training_settings.get("random_seed", 42)
        self.n_estimators = self.training_settings.get("n_estimators", 200)
        self.max_depth = self.training_settings.get("max_depth", 18)
        self.test_split_ratio = self.training_settings.get("test_split_ratio", 0.20)

        self.extractor = DomainFeatureExtractor(use_offline_tld=True)
        self.model: Optional[RandomForestClassifier] = None
        self.evaluation_results: Dict[str, Any] = {}

    def load_dataset(
        self,
        benign_csv: Optional[str | Path] = None,
        malicious_csv: Optional[str | Path] = None
    ) -> pd.DataFrame:
        """Load and merge benign and malicious labeled corpora."""
        data_dir = PROJECT_ROOT / "data"
        b_path = Path(benign_csv) if benign_csv else data_dir / "tranco_benign_sample.csv"
        m_path = Path(malicious_csv) if malicious_csv else data_dir / "dga_malicious_sample.csv"

        if not b_path.is_file() or not m_path.is_file():
            from core.dga_generators import build_datasets
            print("Corpus files missing. Generating automatically...")
            build_datasets(
                benign_count=self.training_settings.get("benign_sample_size", 15000),
                malicious_count=self.training_settings.get("malicious_sample_size", 15000),
                data_dir=data_dir,
                seed=self.random_seed
            )

        df_b = pd.read_csv(b_path)
        df_m = pd.read_csv(m_path)
        combined = pd.concat([df_b, df_m], ignore_index=True)
        # Shuffle deterministically
        combined = combined.sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)
        return combined

    def train_and_evaluate(
        self,
        save_path: Optional[str | Path] = None
    ) -> Dict[str, Any]:
        """Execute full training pipeline with strict anti-leakage isolation."""
        print("Loading dataset...")
        df = self.load_dataset()
        print(f"Total dataset: {len(df)} samples ({sum(df['label'] == 0)} benign, {sum(df['label'] == 1)} malicious)")

        # 1. Stratified Split (80% Train, 20% Test)
        train_df, test_df = train_test_split(
            df,
            test_size=self.test_split_ratio,
            random_state=self.random_seed,
            stratify=df["label"]
        )
        train_df = train_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)
        print(f"Train set: {len(train_df)} samples | Test set: {len(test_df)} samples")

        # 2. Strict Anti-Leakage Feature Extraction
        print("Fitting n-gram language models strictly on benign training split...")
        benign_train_domains = train_df[train_df["label"] == 0]["domain"].tolist()
        self.extractor.fit_language_model(benign_train_domains)

        print("Extracting 14 mathematical features for training split...")
        t0 = time.time()
        X_train_df = self.extractor.extract_features_dataframe(train_df["domain"])
        X_test_df = self.extractor.extract_features_dataframe(test_df["domain"])
        print(f"Feature extraction complete in {time.time() - t0:.2f}s")

        X_train = X_train_df[FEATURE_NAMES].values
        y_train = train_df["label"].values
        X_test = X_test_df[FEATURE_NAMES].values
        y_test = test_df["label"].values

        # 3. 5-Fold Stratified Cross-Validation on Training Split
        print("Running 5-fold Stratified Cross-Validation on training split...")
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.random_seed)
        cv_model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_seed,
            n_jobs=-1
        )
        cv_scores = cross_validate(
            cv_model,
            X_train,
            y_train,
            cv=cv,
            scoring=["precision", "recall", "f1", "roc_auc"],
            n_jobs=-1
        )
        cv_metrics = {
            "cv_f1_mean": float(np.mean(cv_scores["test_f1"])),
            "cv_f1_std": float(np.std(cv_scores["test_f1"])),
            "cv_precision_mean": float(np.mean(cv_scores["test_precision"])),
            "cv_recall_mean": float(np.mean(cv_scores["test_recall"])),
            "cv_roc_auc_mean": float(np.mean(cv_scores["test_roc_auc"])),
        }
        print(f"5-Fold CV Mean F1: {cv_metrics['cv_f1_mean']:.4f} | Precision: {cv_metrics['cv_precision_mean']:.4f} | Recall: {cv_metrics['cv_recall_mean']:.4f}")

        # 4. Train Final Model on Full Training Split
        print(f"Training final RandomForestClassifier (n_estimators={self.n_estimators}, max_depth={self.max_depth})...")
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_seed,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)

        # 5. Held-Out Test Evaluation
        print("Evaluating model on held-out test set...")
        y_pred = self.model.predict(X_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]

        precision = float(precision_score(y_test, y_pred))
        recall = float(recall_score(y_test, y_pred))
        f1 = float(f1_score(y_test, y_pred))
        roc_auc = float(roc_auc_score(y_test, y_prob))
        cm = confusion_matrix(y_test, y_pred).tolist()

        # 6. Per-Family Recall Breakdown
        test_df["predicted"] = y_pred
        test_df["prob_dga"] = y_prob
        per_family_recall: Dict[str, float] = {}

        families = ["cryptolocker", "necurs", "qakbot", "conficker", "bamital", "suppobox_matsnu"]
        for fam in families:
            fam_subset = test_df[test_df["class_name"] == fam]
            if len(fam_subset) > 0:
                fam_recall = float((fam_subset["predicted"] == 1).mean())
                per_family_recall[fam] = round(fam_recall * 100.0, 2)
            else:
                per_family_recall[fam] = 0.0

        # Benign False Positive Rate / Specificity
        benign_subset = test_df[test_df["class_name"] == "benign"]
        benign_fp_rate = float((benign_subset["predicted"] == 1).mean())
        specificity = 1.0 - benign_fp_rate

        # 7. Feature Importances
        importances = self.model.feature_importances_
        feature_importance_ranking = sorted(
            [{"feature": f, "importance": round(float(imp), 5)} for f, imp in zip(FEATURE_NAMES, importances)],
            key=lambda x: x["importance"],
            reverse=True
        )

        results = {
            "overall_metrics": {
                "precision": round(precision * 100.0, 2),
                "recall": round(recall * 100.0, 2),
                "f1_score": round(f1 * 100.0, 2),
                "roc_auc": round(roc_auc, 5),
                "specificity": round(specificity * 100.0, 2),
                "false_positive_rate": round(benign_fp_rate * 100.0, 2),
            },
            "confusion_matrix": {
                "tn": cm[0][0],
                "fp": cm[0][1],
                "fn": cm[1][0],
                "tp": cm[1][1],
            },
            "cv_metrics": cv_metrics,
            "per_family_recall": per_family_recall,
            "feature_importance_ranking": feature_importance_ranking,
            "test_sample_size": len(test_df),
            "train_sample_size": len(train_df),
            "hyperparameters": {
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "random_seed": self.random_seed,
            }
        }
        self.evaluation_results = results

        # 8. Print Clean Summary
        print("\n" + "=" * 55)
        print("          DGA DETECTOR EVALUATION SUMMARY")
        print("=" * 55)
        print(f"  Precision:       {results['overall_metrics']['precision']}%")
        print(f"  Recall:          {results['overall_metrics']['recall']}%")
        print(f"  F1-Score:        {results['overall_metrics']['f1_score']}%")
        print(f"  ROC-AUC:         {results['overall_metrics']['roc_auc']}")
        print(f"  Specificity:     {results['overall_metrics']['specificity']}%")
        print("-" * 55)
        print("  Confusion Matrix:")
        print(f"    TN: {cm[0][0]:<6}  FP: {cm[0][1]:<6}")
        print(f"    FN: {cm[1][0]:<6}  TP: {cm[1][1]:<6}")
        print("-" * 55)
        print("  Per-Family Detection Recall:")
        for fam, rec in per_family_recall.items():
            print(f"    - {fam:<18}: {rec}%")
        print("=" * 55 + "\n")

        # 9. Serialize Artifact Bundle
        out_path = Path(save_path) if save_path else PROJECT_ROOT / "models" / "dga_detector.joblib"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "model": self.model,
            "extractor": self.extractor,
            "feature_names": FEATURE_NAMES,
            "metrics": results,
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }
        joblib.dump(bundle, out_path, compress=3)
        print(f"Model and feature extractor bundle serialized to -> {out_path}")

        # Also write metrics JSON for reporting
        metrics_json_path = PROJECT_ROOT / "models" / "evaluation_metrics.json"
        with open(metrics_json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        return results


def load_detector_bundle(bundle_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Load the trained model and feature extractor bundle."""
    path = Path(bundle_path) if bundle_path else PROJECT_ROOT / "models" / "dga_detector.joblib"
    if not path.is_file():
        raise FileNotFoundError(f"Model bundle not found at {path}. Run model_trainer.py first.")
    return joblib.load(path)


def predict_domain(
    domain: str,
    bundle: Optional[Dict[str, Any]] = None,
    threshold: float = 0.65
) -> Dict[str, Any]:
    """Run inference on a single domain using the trained detector bundle."""
    if bundle is None:
        bundle = load_detector_bundle()

    model = bundle["model"]
    extractor = bundle["extractor"]

    feats = extractor.extract_features(domain)
    feat_vector = np.array([[feats[col] for col in FEATURE_NAMES]])

    prob_dga = float(model.predict_proba(feat_vector)[0, 1])
    is_dga = bool(prob_dga >= threshold)

    return {
        "domain": domain,
        "sld": extractor.extract_sld(domain),
        "prob_dga": round(prob_dga, 5),
        "is_dga": is_dga,
        "features": feats
    }


if __name__ == "__main__":
    trainer = DGAModelTrainer()
    results = trainer.train_and_evaluate()

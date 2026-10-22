"""Unit and integration tests for trained DGA model performance."""

import json
from pathlib import Path
import pytest
from core.model_trainer import load_detector_bundle, predict_domain

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def bundle():
    return load_detector_bundle()


@pytest.fixture(scope="module")
def metrics():
    metrics_file = PROJECT_ROOT / "models" / "evaluation_metrics.json"
    assert metrics_file.is_file(), "Metrics JSON file missing. Run model_trainer.py first."
    with open(metrics_file, "r", encoding="utf-8") as f:
        return json.load(f)


class TestModelPerformance:
    """Verifies that the serialized model achieves >=94% Precision and Recall."""

    def test_precision_threshold(self, metrics):
        precision = metrics["overall_metrics"]["precision"]
        assert precision >= 94.0, f"Precision {precision}% fell below required 94.0%"
        assert precision >= 95.0, f"Precision {precision}% fell below target 95.0%"

    def test_recall_threshold(self, metrics):
        recall = metrics["overall_metrics"]["recall"]
        assert recall >= 94.0, f"Recall {recall}% fell below required 94.0%"

    def test_f1_score_threshold(self, metrics):
        f1 = metrics["overall_metrics"]["f1_score"]
        assert f1 >= 94.0, f"F1 score {f1}% fell below 94.0%"

    def test_roc_auc_threshold(self, metrics):
        roc_auc = metrics["overall_metrics"]["roc_auc"]
        assert roc_auc >= 0.98, f"ROC-AUC {roc_auc} fell below 0.980"

    def test_per_family_recall(self, metrics):
        fam_recall = metrics["per_family_recall"]
        required_families = ["cryptolocker", "necurs", "qakbot", "conficker", "bamital", "suppobox_matsnu"]
        for fam in required_families:
            assert fam in fam_recall, f"Missing recall metric for family: {fam}"
            # Even challenging dictionary DGAs must exceed 90%
            assert fam_recall[fam] >= 90.0, f"Family {fam} recall {fam_recall[fam]}% fell below 90.0%"

    def test_inference_benign(self, bundle):
        # Known benign samples must yield low DGA probability
        benign_samples = ["google.com", "github.com", "microsoft.com", "wikipedia.org"]
        for domain in benign_samples:
            res = predict_domain(domain, bundle=bundle, threshold=0.65)
            assert not res["is_dga"], f"Benign domain {domain} was falsely flagged as DGA!"
            assert res["prob_dga"] < 0.50

    def test_inference_dga(self, bundle):
        # Known high-entropy DGA samples must yield high DGA probability
        dga_samples = [
            "btwewsgtjsywcifg.net",                  # Cryptolocker
            "kdruxhvvbyugggpjmq.in",                 # Necurs
            "iawx0tno7f206r.info",                   # Qakbot
            "0e779169514a1200225682b8aa7c323d.org", # Bamital
        ]
        for domain in dga_samples:
            res = predict_domain(domain, bundle=bundle, threshold=0.65)
            assert res["is_dga"], f"Malicious DGA domain {domain} was not flagged!"
            assert res["prob_dga"] >= 0.65

# Summary: 04-01 ML Classifier Training & Evaluation Pipeline

## Deliverables
- `core/model_trainer.py`:
  - Complete end-to-end training and evaluation script.
  - Stratified 80/20 train/test split across 30,000 domains.
  - Strict anti-leakage isolation: Language models fitted purely on the 24,000-sample training fold (12,000 benign domains).
  - 5-fold stratified cross-validation on training fold:
    - Mean F1: 0.9985
    - Mean Precision: 0.9991
    - Mean Recall: 0.9979
    - Mean ROC-AUC: 0.9999
  - Final Random Forest Classifier (200 trees, max depth 18, random seed 42).
- Serialized artifacts:
  - `models/dga_detector.joblib` (model + extractor + metadata bundle)
  - `models/evaluation_metrics.json` (comprehensive performance metrics)

## Verification Evidence
- Held-out test evaluation on 6,000 unseen domains (3,000 benign, 3,000 malicious):
  - **Precision:** 99.77% (Exceeds >= 95.0% requirement)
  - **Recall:** 99.53% (Exceeds >= 94.0% requirement)
  - **F1-Score:** 99.65%
  - **ROC-AUC:** 0.99989
  - **Specificity:** 99.77%
  - **Confusion Matrix:** TN=2993, FP=7, FN=14, TP=2986
- Per-Family Recall:
  - Cryptolocker: 100.0%
  - Necurs: 100.0%
  - Qakbot: 100.0%
  - Conficker: 99.59%
  - Bamital: 100.0%
  - Suppobox / Matsnu: 97.7%
- Real-time single-domain inference verified (`predict_domain`).

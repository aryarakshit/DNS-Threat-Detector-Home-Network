# Roadmap: Home-Network DNS DGA & C2 Threat Detector

## Overview

Build, train, evaluate, and deploy a production-grade DNS DGA and C2 Threat Detector for home networks. The pipeline progresses from configuration and authentic DGA corpus synthesis to 14-feature information-theoretic feature extraction, scikit-learn ML training (reaching >=95% Precision and >=94% Recall), Pi-hole and Zeek DNS log parsing with a 7-day 140,000-query simulator, and automated SOC investigation dossier generation with full test verification.

## Phases

- [x] **Phase 1: Environment Setup & Configuration** - Establish directory layout, `requirements.txt`, and `config/detector_config.yaml`.
- [x] **Phase 2: DGA Generators & Tranco Corpus Builder** - Implement 6 DGA algorithms and synthesize 30,000 labeled domains.
- [x] **Phase 3: Lexical & Information-Theoretic Feature Extractor** - Implement 14 mathematical features and offline `tldextract` engine.
- [ ] **Phase 4: ML Classifier Training & Evaluation Pipeline** - Train Random Forest model, compute cross-validation metrics, serialize to `models/dga_detector.joblib`.
- [ ] **Phase 5: Pi-hole & Zeek Log Parsers & 7-Day Simulator** - Build parsers for Pi-hole and Zeek and generate 140,000 realistic DNS queries.
- [ ] **Phase 6: Threat Hunter, SOC Dossier Reporting, Runner & Verification** - Implement triage engine, `run_dns_detector.py`, `reports/dns_threat_study_report.md`, and 100% passing test suite.

## Phase Details

### Phase 1: Environment Setup & Configuration
**Goal**: Create directory layout, specify dependencies, and configure detector parameters.
**Depends on**: Nothing
**Requirements**: CONF-01, CONF-02, CONF-03
**Success Criteria**:
  1. Workspace initialized with `config/`, `data/`, `models/`, `core/`, `reports/`, and `tests/`.
  2. `requirements.txt` specifies all required packages.
  3. `config/detector_config.yaml` is fully populated with training parameters, 6 DGA families, and 5 home LAN devices.
**Plans**: 1 plan

Plans:
- [x] 01-01: Create workspace directory tree, `requirements.txt`, and `config/detector_config.yaml`.

### Phase 2: DGA Generators & Tranco Corpus Builder
**Goal**: Implement authentic DGA family generators and produce 30,000 balanced domains.
**Depends on**: Phase 1
**Requirements**: DGA-01, DGA-02, DGA-03, DGA-04, DGA-05, DGA-06, CORP-01, CORP-02, CORP-03
**Success Criteria**:
  1. 6 DGA generators implement Cryptolocker, Necurs, Qakbot, Conficker, Bamital, and Suppobox deterministically.
  2. Tranco benign corpus builder produces 15,000 realistic domains.
  3. `data/tranco_benign_sample.csv` and `data/dga_malicious_sample.csv` are populated with labeled data.
**Plans**: 1 plan

Plans:
- [x] 02-01: Implement `core/dga_generators.py` and generate benign/malicious CSV datasets.

### Phase 3: Lexical & Information-Theoretic Feature Extractor
**Goal**: Implement the 14-feature extraction engine with Laplace-smoothed n-grams.
**Depends on**: Phase 2
**Requirements**: FEAT-01, FEAT-02, FEAT-03, FEAT-04, FEAT-05, FEAT-06
**Success Criteria**:
  1. `core/feature_extractor.py` extracts SLD offline using `tldextract`.
  2. Shannon entropy, metric entropy, lexical ratios, consonant/digit streaks, and transition frequencies compute correctly.
  3. Bigram and trigram log-likelihood tables train cleanly on benign splits without leakage.
**Plans**: 1 plan

Plans:
- [x] 03-01: Implement `core/feature_extractor.py` and verify feature extraction across diverse sample domains.

### Phase 4: ML Classifier Training & Evaluation Pipeline
**Goal**: Train Random Forest classifier and serialize model bundle.
**Depends on**: Phase 3
**Requirements**: ML-01, ML-02, ML-03, ML-04, ML-05
**Success Criteria**:
  1. `core/model_trainer.py` executes 5-fold stratified cross validation.
  2. Model achieves >=95.0% Precision and >=94.0% Recall on held-out test data.
  3. Serialized bundle saved to `models/dga_detector.joblib` containing model, n-gram tables, and feature list.
**Plans**: 1 plan

Plans:
- [ ] 04-01: Implement `core/model_trainer.py`, train model, verify metric thresholds, and serialize `models/dga_detector.joblib`.

### Phase 5: Pi-hole & Zeek Log Parsers & 7-Day Simulator
**Goal**: Ingest real network logs and simulate 7-day home DNS traffic.
**Depends on**: Phase 4
**Requirements**: LOG-01, LOG-02, SIM-01, SIM-02, SIM-03
**Success Criteria**:
  1. Parsers handle `pihole.log`, `pihole-FTL.db`, and Zeek `dns.log` (TSV and JSON).
  2. Generator produces 140,000 DNS queries across 7 days in `data/home_dns_7days.jsonl`.
  3. Dataset includes realistic normal traffic, benign high-entropy CDN/DKIM false-positive candidates, and active DGA/C2 bursts.
**Plans**: 1 plan

Plans:
- [ ] 05-01: Implement `core/log_parsers.py` with multi-format log parsers and 7-day traffic generator.

### Phase 6: Threat Hunter, SOC Dossier Reporting, Runner & Verification
**Goal**: Implement triage correlation, master runner, SOC report generator, and unit test suite.
**Depends on**: Phase 5
**Requirements**: HUNT-01, HUNT-02, HUNT-03, REP-01, RUN-01, TEST-01, TEST-02, TEST-03, TEST-04
**Success Criteria**:
  1. `core/threat_hunter.py` flags anomalous domains and differentiates real DGA beacons from benign CDN anomalies using NXDOMAIN ratios.
  2. `run_dns_detector.py` provides end-to-end execution.
  3. `reports/dns_threat_study_report.md` documents investigation dossiers and resume bullet.
  4. `pytest tests/` passes 100% across all unit and performance tests.
**Plans**: 2 plans

Plans:
- [ ] 06-01: Implement `core/threat_hunter.py`, `run_dns_detector.py`, and SOC reporting generator.
- [ ] 06-02: Implement `tests/` unit test suite and verify 100% pass with pytest and README documentation.

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Environment Setup & Configuration | 1/1 | Complete | 2026-10-23 |
| 2. DGA Generators & Tranco Corpus Builder | 1/1 | Complete | 2026-10-23 |
| 3. Lexical & Information-Theoretic Feature Extractor | 1/1 | Complete | 2026-10-23 |
| 4. ML Classifier Training & Evaluation Pipeline | 0/1 | Not started | - |
| 5. Pi-hole & Zeek Log Parsers & 7-Day Simulator | 0/1 | Not started | - |
| 6. Threat Hunter, SOC Dossier Reporting, Runner & Verification | 0/2 | Not started | - |

### Phase 7: Environment Setup and Configuration

**Goal:** [To be planned]
**Requirements**: TBD
**Depends on:** Phase 6
**Plans:** 0 plans

Plans:
- [ ] TBD (run /gsd-plan-phase 7 to break down)

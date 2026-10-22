# Home-Network DNS DGA & C2 Threat Detector (`dns-dga-threat-detector`)

## What This Is

A production-grade, hybrid Information-Theoretic (Shannon Entropy + N-gram Perplexity) and Machine Learning classifier that detects Domain Generation Algorithms (DGAs) and Command-and-Control (C2) DNS beacons on home networks. It ingests Pi-hole and Zeek network DNS logs, correlates client query velocities and NXDOMAIN bursts, and generates structured SOC investigation dossiers separating genuine threats from noisy benign anomalies (CDNs, DKIM, smart TVs).

## Core Value

Accurately detect evasion-capable DGA malware and C2 beaconing in home network DNS traffic with >=95% precision and >=94% recall while eliminating false positives from benign high-entropy infrastructure.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] **CONF-01**: Environment and configuration setup (`detector_config.yaml` and `requirements.txt`).
- [ ] **DGA-01**: Deterministic Python reimplementation of 6 authentic DGA families (Cryptolocker, Necurs, Qakbot, Conficker, Bamital, Suppobox).
- [ ] **CORP-01**: Synthesize/sample 15,000 benign Tranco domains and 15,000 malicious DGA domains into training datasets.
- [ ] **FEAT-01**: 14 information-theoretic and lexical feature extractors with offline `tldextract` extraction.
- [ ] **FEAT-02**: Bigram and trigram language probability tables with Laplace smoothing fitted strictly on the training fold without data leakage.
- [ ] **ML-01**: Train Random Forest classifier on 30,000 domains with 5-fold stratified cross-validation achieving >=95% precision and >=94% recall.
- [ ] **ML-02**: Model serialization to `models/dga_detector.joblib` including model, n-gram profiles, and feature metadata.
- [ ] **LOG-01**: Multi-format log parser for Pi-hole (`dnsmasq` & SQLite `pihole-FTL.db`) and Zeek (`dns.log` TSV & JSON).
- [ ] **SIM-01**: Deterministic 7-day home network DNS traffic simulator (140,000 queries across 5 devices) with normal, benign high-entropy CDN/DKIM, and malicious C2/DGA beacons.
- [ ] **HUNT-01**: Fast-path pre-filtering for `.arpa`, `.local`, and Tranco Top-10k.
- [ ] **HUNT-02**: Behavioral host correlation (NXDOMAIN burst ratio, query periodicity, subdomain entropy) and triage classification.
- [ ] **REP-01**: Automated SOC investigation dossier generator producing `reports/dns_threat_study_report.md` with metrics, confusion matrix, and resume bullet.
- [ ] **TEST-01**: Comprehensive unit test suite (`tests/`) verifying feature extraction, DGA generation, parsers, and performance criteria passing 100% with `pytest`.
- [ ] **RUN-01**: Master CLI runner (`run_dns_detector.py`) orchestrating corpus building, training, log generation, threat hunting, and reporting.

### Out of Scope

- Deep Packet Inspection (DPI) of payload contents (DNS metadata only).
- Active live blocking / DNS sinkholing (detection and triage focus).
- Cloud-hosted SIEM integration (Splunk, Sentinel) — local file and markdown reporting focus for home network SOC.

## Context

- Home networks run noisy devices (Smart TVs, iOS/Android telemetry, CloudFront/Akamai CDNs, DKIM email validations) that trigger false positives in naive entropy detectors.
- Malware families evade static IP/domain blocklists by dynamically generating hundreds to thousands of candidate domains.
- A hybrid approach combining lexical mathematical features + behavioral correlation (NXDOMAIN ratio >85%, query periodicity) reliably isolates real threats.

## Constraints

- **Python Runtime**: Compatible with Python 3.10+ (tested on Python 3.14).
- **Offline Reliability**: `tldextract` must operate in offline snapshot mode without requiring live external HTTP lookups.
- **Data Leakage**: Benign n-gram tables must only be learned from the training split.
- **Accuracy Targets**: Precision >= 95.0% and Recall >= 94.0% on held-out evaluation test set.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Scikit-learn Random Forest with 14 features | Balances high recall across diverse DGA families with fast CPU inference | — Pending |
| Behavioral NXDOMAIN correlation | Prevents flagging high-entropy benign CDNs that resolve successfully with NOERROR | — Pending |
| Dual-mode support (Real logs + Synthetic 7-day) | Allows turnkey evaluation anywhere while supporting real Pi-hole/Zeek deployments | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

---
*Last updated: 2026-10-23 after initialization*

# Requirements: Home-Network DNS DGA & C2 Threat Detector

**Defined:** 2026-10-23  
**Core Value:** Accurately detect evasion-capable DGA malware and C2 beaconing in home network DNS traffic with >=95% precision and >=94% recall while eliminating false positives from benign high-entropy infrastructure.

## v1 Requirements

### 1. Configuration & Dependencies
- [ ] **CONF-01**: Project directory layout initialized as per blueprint Section 3.
- [ ] **CONF-02**: `requirements.txt` containing all runtime dependencies.
- [ ] **CONF-03**: `config/detector_config.yaml` specifying training parameters, 6 DGA families, 5 home network devices, and triage thresholds.

### 2. DGA Generators & Tranco Corpus
- [ ] **DGA-01**: Deterministic Python implementation of Cryptolocker DGA (date-seeded PRNG, 12-16 chars).
- [ ] **DGA-02**: Deterministic Python implementation of Necurs DGA (modular arithmetic PRNG, 9-21 chars).
- [ ] **DGA-03**: Deterministic Python implementation of Qakbot DGA (alphanumeric PRNG, 10-22 chars).
- [ ] **DGA-04**: Deterministic Python implementation of Conficker DGA (short PRNG, 8-11 chars).
- [ ] **DGA-05**: Deterministic Python implementation of Bamital DGA (hexadecimal MD5 style, 32 chars).
- [ ] **DGA-06**: Deterministic Python implementation of Suppobox/Matsnu DGA (dictionary-word concatenation).
- [ ] **CORP-01**: Tranco Top-1M benign corpus loader/synthesizer generating 15,000 domains.
- [ ] **CORP-02**: Malicious corpus generation across 6 DGA families generating 15,000 domains.
- [ ] **CORP-03**: Datasets saved to `data/tranco_benign_sample.csv` and `data/dga_malicious_sample.csv`.

### 3. Feature Engineering
- [ ] **FEAT-01**: SLD and subdomain extraction using `tldextract` in offline snapshot mode.
- [ ] **FEAT-02**: Shannon entropy $H(S)$ and normalized metric entropy $H_{\text{norm}}(S)$.
- [ ] **FEAT-03**: Lexical character ratios: length, vowel ratio, consonant ratio, digit ratio, hex ratio, unique char ratio.
- [ ] **FEAT-04**: Structural transition features: max consecutive consonant streak, max digit streak, transition frequency.
- [ ] **FEAT-05**: Laplace-smoothed benign bigram log-likelihood $LL_2(S)$ and trigram log-likelihood $LL_3(S)$ with rare bigram ratio $R_{\text{rare}}$.
- [ ] **FEAT-06**: Strict anti-leakage guarantee (n-gram statistics fit only on training split).

### 4. Machine Learning Classifier
- [ ] **ML-01**: Scikit-learn RandomForestClassifier pipeline integrating all 14 features.
- [ ] **ML-02**: 5-Fold Stratified Cross-Validation on training split.
- [ ] **ML-03**: Held-out test evaluation achieving >=95.0% Precision and >=94.0% Recall.
- [ ] **ML-04**: Per-family recall breakdown across all 6 DGA families.
- [ ] **ML-05**: Model serialization to `models/dga_detector.joblib` with feature metadata and language model tables.

### 5. DNS Log Parsers & Network Simulation
- [ ] **LOG-01**: Pi-hole parser supporting standard `pihole.log` (`dnsmasq`) and `pihole-FTL.db` SQLite.
- [ ] **LOG-02**: Zeek parser supporting TSV (`dns.log`) and JSON line formats.
- [ ] **SIM-01**: 7-Day home network DNS traffic simulator producing 140,000 events in `data/home_dns_7days.jsonl`.
- [ ] **SIM-02**: Inclusion of realistic benign high-entropy CDN/DKIM domains (e.g. CloudFront, Spotify, Razorpay).
- [ ] **SIM-03**: Inclusion of active DGA/C2 bursts from `192.168.1.55` and `192.168.1.99` with >85% NXDOMAIN ratios.

### 6. Threat Hunting, Reporting & CLI
- [ ] **HUNT-01**: Pre-filter cache skipping `.arpa`, `.local`, and Tranco Top-10k.
- [ ] **HUNT-02**: Behavioral telemetry correlation per domain (query volume, NXDOMAIN counts/ratio, source IPs, beacon intervals).
- [ ] **HUNT-03**: Automated SOC triage classifying Confirmed DGA Beacon, DNS Tunneling, and Investigated Benign Anomaly.
- [ ] **REP-01**: Automated Markdown report generator creating `reports/dns_threat_study_report.md` with investigation dossiers and resume bullet.
- [ ] **RUN-01**: Master script `run_dns_detector.py` providing complete end-to-end orchestration and CLI flags.

### 7. Verification & Testing
- [ ] **TEST-01**: Unit tests for Shannon entropy and 6 DGA generators (`tests/test_dga_and_features.py`).
- [ ] **TEST-02**: Model performance assertions for Precision >=94% and Recall >=94% (`tests/test_model_performance.py`).
- [ ] **TEST-03**: Log parsing tests for Pi-hole and Zeek (`tests/test_log_parsers.py`).
- [ ] **TEST-04**: 100% pytest pass across all tests.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Live DNS packet sniffing | Focus is on Pi-hole / Zeek telemetry log streams and reproducibility |
| Automated firewall / DNS sinkholing | Safety constraint; provides SOC investigation dossiers rather than modifying network rules |
| Deep packet payload inspection | DNS metadata & query names provide sufficient signal for DGA/C2 classification |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CONF-01, CONF-02, CONF-03 | Phase 1 | Pending |
| DGA-01, DGA-02, DGA-03, DGA-04, DGA-05, DGA-06, CORP-01, CORP-02, CORP-03 | Phase 2 | Pending |
| FEAT-01, FEAT-02, FEAT-03, FEAT-04, FEAT-05, FEAT-06 | Phase 3 | Pending |
| ML-01, ML-02, ML-03, ML-04, ML-05 | Phase 4 | Pending |
| LOG-01, LOG-02, SIM-01, SIM-02, SIM-03 | Phase 5 | Pending |
| HUNT-01, HUNT-02, HUNT-03, REP-01, RUN-01 | Phase 6 | Pending |
| TEST-01, TEST-02, TEST-03, TEST-04 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 28 total
- Mapped to phases: 28
- Unmapped: 0 ✓

---
*Requirements defined: 2026-10-23*

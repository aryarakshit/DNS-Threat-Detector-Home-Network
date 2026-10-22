# Summary: 03-01 Lexical & Information-Theoretic Feature Extractor

## Deliverables
- `core/feature_extractor.py`:
  - `DomainFeatureExtractor` class operating in offline mode using `tldextract` with zero external network dependency.
  - Implemented all 14 mathematical & information-theoretic features:
    1. Shannon entropy $H(S)$
    2. Normalized metric entropy $H_{\text{norm}}(S)$
    3. Length $L$
    4. Vowel-to-length ratio $R_v$
    5. Consonant-to-length ratio $R_c$
    6. Digit-to-length ratio $R_d$
    7. Hexadecimal ratio $R_{\text{hex}}$
    8. Longest consonant streak $C_{\max}$
    9. Longest digit streak $D_{\max}$
    10. Character transition frequency $T_{\text{switch}}$
    11. Unique character ratio $U(S)$
    12. Benign bigram log-likelihood $LL_2(S)$ (Laplace-smoothed)
    13. Benign trigram log-likelihood $LL_3(S)$ (Laplace-smoothed)
    14. Rare bigram ratio $R_{\text{rare}}$
  - Strict anti-leakage mechanism: `fit_language_model(benign_domains)` learns n-gram language model statistics strictly from training splits.
  - Vectorized feature extraction method `extract_features_dataframe()`.

## Verification Evidence
- Tested feature extraction against benign benchmarks and malicious DGA samples.
- Verified mathematical properties: identical characters yield $H(S) = 0.0$, 4 distinct uniform characters yield $H(S) = 2.0$, consonant and digit streaks compute contiguous runs accurately.
- Confirmed zero network calls and full offline execution.

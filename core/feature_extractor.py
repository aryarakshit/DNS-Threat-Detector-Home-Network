"""Lexical & Information-Theoretic Feature Extractor for DNS Domains.

Computes the 14 mathematical features specified in Section 5B:
1.  Character Shannon Entropy: H(S)
2.  Normalized Metric Entropy: H_norm(S)
3.  Domain Length: L
4.  Vowel-to-Length Ratio: R_v
5.  Consonant-to-Length Ratio: R_c
6.  Digit-to-Length Ratio: R_d
7.  Hexadecimal Character Ratio: R_hex
8.  Longest Consecutive Consonant Streak: C_max
9.  Longest Consecutive Digit Streak: D_max
10. Character Transition Frequency: T_switch
11. Unique Character Ratio: U(S)
12. Benign Bigram Log-Likelihood Score: LL_2(S)
13. Benign Trigram Log-Likelihood Score: LL_3(S)
14. Rare Bigram Ratio: R_rare
"""

from __future__ import annotations
import collections
import math
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import numpy as np
import pandas as pd
import tldextract

# Project path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FEATURE_NAMES: List[str] = [
    "shannon_entropy",
    "normalized_entropy",
    "length",
    "vowel_ratio",
    "consonant_ratio",
    "digit_ratio",
    "hex_ratio",
    "max_consonant_streak",
    "max_digit_streak",
    "transition_frequency",
    "unique_char_ratio",
    "bigram_log_likelihood",
    "trigram_log_likelihood",
    "rare_bigram_ratio",
]

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
DIGITS = set("0123456789")
HEX_CHARS = set("0123456789abcdef")
VALID_CHARS = sorted(list(set("abcdefghijklmnopqrstuvwxyz0123456789-")))
VOCAB_SIZE = len(VALID_CHARS) + 1  # +1 for smoothing / out-of-alphabet


class DomainFeatureExtractor:
    """Extracts lexical and information-theoretic features from domain names.

    Ensures zero network access via tldextract offline snapshot mode.
    Fits bigram and trigram empirical language distributions on benign training domains
    to avoid data leakage.
    """

    def __init__(self, use_offline_tld: bool = True):
        # Configure tldextract in offline snapshot mode
        if use_offline_tld:
            self.extractor = tldextract.TLDExtract(
                cache_dir=False,
                suffix_list_urls=None
            )
        else:
            self.extractor = tldextract.TLDExtract()

        # Language model frequency tables
        self.unigram_counts: collections.Counter = collections.Counter()
        self.bigram_counts: collections.Counter = collections.Counter()
        self.trigram_counts: collections.Counter = collections.Counter()
        self.total_bigrams: int = 0
        self.is_fitted: bool = False

    def extract_sld(self, domain_or_fqdn: str) -> str:
        """Extract Second-Level Domain (SLD) string, normalized to lowercase."""
        if not domain_or_fqdn or not isinstance(domain_or_fqdn, str):
            return ""
        clean = domain_or_fqdn.strip().lower().rstrip(".")
        extracted = self.extractor(clean)
        sld = extracted.domain
        if not sld:
            # Fallback for localhost or unregistered domains
            parts = clean.split(".")
            sld = parts[0] if parts else clean
        return sld

    def fit_language_model(self, benign_domains: Iterable[str]) -> "DomainFeatureExtractor":
        """Fit empirical bigram and trigram frequency tables from benign training domains.

        Anti-leakage requirement: Call this strictly on the training fold.
        """
        self.unigram_counts.clear()
        self.bigram_counts.clear()
        self.trigram_counts.clear()
        self.total_bigrams = 0

        for item in benign_domains:
            sld = self.extract_sld(item)
            if not sld:
                continue
            # Filter non-alphanumeric/hyphen
            chars = [c for c in sld if c in VALID_CHARS]
            length = len(chars)
            for c in chars:
                self.unigram_counts[c] += 1

            for i in range(length - 1):
                bg = (chars[i], chars[i + 1])
                self.bigram_counts[bg] += 1
                self.total_bigrams += 1

            for i in range(length - 2):
                tg = (chars[i], chars[i + 1], chars[i + 2])
                self.trigram_counts[tg] += 1

        self.is_fitted = True
        return self

    @staticmethod
    def calculate_shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy H(S) = -sum(P(c) * log2(P(c)))."""
        if not s:
            return 0.0
        length = len(s)
        counts = collections.Counter(s)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def calculate_normalized_entropy(s: str, entropy: float) -> float:
        """Calculate normalized metric entropy H_norm(S) = H(S) / log2(max(L, 2))."""
        length = len(s)
        if length <= 1:
            return 0.0
        max_possible = math.log2(max(length, 2))
        return float(entropy / max_possible) if max_possible > 0 else 0.0

    @staticmethod
    def calculate_consonant_streak(s: str) -> int:
        """Calculate longest run of consecutive consonants."""
        max_streak = 0
        current_streak = 0
        for c in s:
            if c in CONSONANTS:
                current_streak += 1
                if current_streak > max_streak:
                    max_streak = current_streak
            else:
                current_streak = 0
        return max_streak

    @staticmethod
    def calculate_digit_streak(s: str) -> int:
        """Calculate longest run of consecutive digits."""
        max_streak = 0
        current_streak = 0
        for c in s:
            if c in DIGITS:
                current_streak += 1
                if current_streak > max_streak:
                    max_streak = current_streak
            else:
                current_streak = 0
        return max_streak

    @staticmethod
    def calculate_transition_frequency(s: str) -> float:
        """Calculate character transition frequency across letter/digit/hyphen types."""
        length = len(s)
        if length <= 1:
            return 0.0

        def get_type(c: str) -> int:
            if c in DIGITS:
                return 1
            if c in CONSONANTS or c in VOWELS:
                return 0
            return 2  # Hyphen or other

        switches = 0
        prev_type = get_type(s[0])
        for i in range(1, length):
            curr_type = get_type(s[i])
            if curr_type != prev_type:
                switches += 1
            prev_type = curr_type

        return float(switches / (length - 1))

    def calculate_n_gram_features(self, s: str) -> Tuple[float, float, float]:
        """Compute bigram log-likelihood, trigram log-likelihood, and rare bigram ratio."""
        length = len(s)
        if length <= 1:
            default_ll = math.log10(1.0 / VOCAB_SIZE)
            return default_ll, default_ll, 0.0

        chars = [c for c in s if c in VALID_CHARS]
        if len(chars) <= 1:
            default_ll = math.log10(1.0 / VOCAB_SIZE)
            return default_ll, default_ll, 0.0

        num_bigrams = len(chars) - 1
        ll2_sum = 0.0
        rare_count = 0

        for i in range(num_bigrams):
            c1, c2 = chars[i], chars[i + 1]
            c1_count = self.unigram_counts.get(c1, 0)
            c1_c2_count = self.bigram_counts.get((c1, c2), 0)

            # Laplace-smoothed probability: P(c2 | c1)
            p_bg = (c1_c2_count + 1.0) / (c1_count + VOCAB_SIZE)
            ll2_sum += math.log10(p_bg)

            # Empirical probability in Tranco
            empirical_prob = (c1_c2_count / self.total_bigrams) if self.total_bigrams > 0 else 0.0
            if empirical_prob < 1e-4:
                rare_count += 1

        avg_ll2 = float(ll2_sum / num_bigrams)
        rare_ratio = float(rare_count / num_bigrams)

        # Trigram log-likelihood
        num_trigrams = len(chars) - 2
        if num_trigrams > 0:
            ll3_sum = 0.0
            for i in range(num_trigrams):
                c1, c2, c3 = chars[i], chars[i + 1], chars[i + 2]
                bg_count = self.bigram_counts.get((c1, c2), 0)
                tg_count = self.trigram_counts.get((c1, c2, c3), 0)
                # Laplace-smoothed trigram probability
                p_tg = (tg_count + 1.0) / (bg_count + VOCAB_SIZE)
                ll3_sum += math.log10(p_tg)
            avg_ll3 = float(ll3_sum / num_trigrams)
        else:
            avg_ll3 = avg_ll2

        return avg_ll2, avg_ll3, rare_ratio

    def extract_features_from_sld(self, sld: str) -> Dict[str, float]:
        """Compute all 14 features for an already-extracted SLD string."""
        length = len(sld)
        if length == 0:
            return {name: 0.0 for name in FEATURE_NAMES}

        vowel_count = sum(1 for c in sld if c in VOWELS)
        consonant_count = sum(1 for c in sld if c in CONSONANTS)
        digit_count = sum(1 for c in sld if c in DIGITS)
        hex_count = sum(1 for c in sld if c in HEX_CHARS)
        unique_count = len(set(sld))

        entropy = self.calculate_shannon_entropy(sld)
        norm_entropy = self.calculate_normalized_entropy(sld, entropy)
        max_cons_streak = self.calculate_consonant_streak(sld)
        max_dig_streak = self.calculate_digit_streak(sld)
        transition_freq = self.calculate_transition_frequency(sld)

        ll2, ll3, rare_bg_ratio = self.calculate_n_gram_features(sld)

        return {
            "shannon_entropy": round(entropy, 5),
            "normalized_entropy": round(norm_entropy, 5),
            "length": float(length),
            "vowel_ratio": round(vowel_count / length, 5),
            "consonant_ratio": round(consonant_count / length, 5),
            "digit_ratio": round(digit_count / length, 5),
            "hex_ratio": round(hex_count / length, 5),
            "max_consonant_streak": float(max_cons_streak),
            "max_digit_streak": float(max_dig_streak),
            "transition_frequency": round(transition_freq, 5),
            "unique_char_ratio": round(unique_count / length, 5),
            "bigram_log_likelihood": round(ll2, 5),
            "trigram_log_likelihood": round(ll3, 5),
            "rare_bigram_ratio": round(rare_bg_ratio, 5),
        }

    def extract_features(self, domain_or_fqdn: str) -> Dict[str, float]:
        """Extract all 14 features from any raw domain name or FQDN."""
        sld = self.extract_sld(domain_or_fqdn)
        return self.extract_features_from_sld(sld)

    def extract_features_dataframe(
        self,
        domains: Sequence[str],
        include_sld: bool = False
    ) -> pd.DataFrame:
        """Vectorized feature extraction across a sequence of domains."""
        records = []
        slds = []
        for d in domains:
            sld = self.extract_sld(d)
            feats = self.extract_features_from_sld(sld)
            records.append(feats)
            if include_sld:
                slds.append(sld)

        df = pd.DataFrame(records, columns=FEATURE_NAMES)
        if include_sld:
            df.insert(0, "sld", slds)
            df.insert(0, "domain", list(domains))
        return df


def get_feature_names() -> List[str]:
    """Return ordered list of the 14 feature column names."""
    return list(FEATURE_NAMES)


if __name__ == "__main__":
    extractor = DomainFeatureExtractor()
    test_corpus = ["google.com", "microsoft.com", "github.com", "amazon.com", "wikipedia.org"]
    extractor.fit_language_model(test_corpus)

    test_domains = [
        "google.com",
        "btwewsgtjsywcifg.net",          # Cryptolocker
        "kdruxhvvbyugggpjmq.in",         # Necurs
        "0e779169514a1200225682b8aa7c323d.org", # Bamital
        "markerregionspider.ru",         # Suppobox
        "d3g9k8x2p1q4.cloudfront.net",   # CDN hash
    ]
    df_res = extractor.extract_features_dataframe(test_domains, include_sld=True)
    print("Feature Extraction Demo:")
    print(df_res[["domain", "shannon_entropy", "vowel_ratio", "digit_ratio", "hex_ratio", "max_consonant_streak", "bigram_log_likelihood"]])

"""Unit tests for DGA generators and lexical/information-theoretic features."""

import math
import pytest
from core.dga_generators import (
    generate_bamital,
    generate_conficker,
    generate_cryptolocker,
    generate_dga_domains,
    generate_necurs,
    generate_qakbot,
    generate_suppobox,
)
from core.feature_extractor import DomainFeatureExtractor, FEATURE_NAMES


class TestDGAGenerators:
    """Tests for all 6 open-source DGA family implementations."""

    def test_cryptolocker(self):
        domains = generate_cryptolocker(count=50, seed=123)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert 12 <= len(sld) <= 16
            assert sld.isalpha()
            assert sld.islower()
            assert any(d.endswith(f".{tld}") for tld in ["com", "net", "biz", "org", "ru", "co.uk"])

    def test_necurs(self):
        domains = generate_necurs(count=50, seed=456)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert 9 <= len(sld) <= 21
            assert sld.isalpha()
            assert any(d.endswith(f".{tld}") for tld in ["com", "in", "xyz", "top", "work", "club"])

    def test_qakbot(self):
        domains = generate_qakbot(count=50, seed=789)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert 10 <= len(sld) <= 22
            assert sld.isalnum()
            assert any(d.endswith(f".{tld}") for tld in ["com", "net", "org", "info", "biz"])

    def test_conficker(self):
        domains = generate_conficker(count=50, seed=101)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert 8 <= len(sld) <= 11
            assert sld.isalpha()
            assert any(d.endswith(f".{tld}") for tld in ["com", "net", "org", "info", "cc"])

    def test_bamital(self):
        domains = generate_bamital(count=50, seed=202)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert len(sld) == 32
            # Hexadecimal check
            int(sld, 16)
            assert any(d.endswith(f".{tld}") for tld in ["org", "info", "cz.cc"])

    def test_suppobox(self):
        domains = generate_suppobox(count=50, seed=303)
        assert len(domains) == 50
        for d in domains:
            sld = d.split(".")[0]
            assert 14 <= len(sld) <= 24
            assert sld.isalpha()
            assert any(d.endswith(f".{tld}") for tld in ["com", "net", "ru"])

    def test_deterministic_reproducibility(self):
        d1 = generate_dga_domains("cryptolocker", count=10, seed=999)
        d2 = generate_dga_domains("cryptolocker", count=10, seed=999)
        assert d1 == d2


class TestFeatureExtractor:
    """Tests for 14 mathematical & information-theoretic features."""

    @pytest.fixture
    def extractor(self):
        ext = DomainFeatureExtractor(use_offline_tld=True)
        # Seed small language model for testing
        ext.fit_language_model(["google.com", "microsoft.com", "github.com", "amazon.com"])
        return ext

    def test_shannon_entropy_properties(self, extractor):
        # Uniform repeat string has entropy 0
        assert extractor.calculate_shannon_entropy("aaaaaa") == 0.0

        # Uniform 4-character alphabet has entropy 2.0 (log2(4) = 2.0)
        assert math.isclose(extractor.calculate_shannon_entropy("abcd"), 2.0, rel_tol=1e-5)

        # Longer random string has higher entropy
        h_low = extractor.calculate_shannon_entropy("aaaabbbb")
        h_high = extractor.calculate_shannon_entropy("abcdefgh")
        assert h_high > h_low

    def test_normalized_entropy_bounded(self, extractor):
        h = extractor.calculate_shannon_entropy("abcdefgh")
        norm_h = extractor.calculate_normalized_entropy("abcdefgh", h)
        assert 0.0 <= norm_h <= 1.0

    def test_streak_calculations(self, extractor):
        # Consonant streak
        assert extractor.calculate_consonant_streak("strr") == 4
        assert extractor.calculate_consonant_streak("aeiou") == 0
        assert extractor.calculate_consonant_streak("bbaacc") == 2

        # Digit streak
        assert extractor.calculate_digit_streak("12345") == 5
        assert extractor.calculate_digit_streak("a1b22c333") == 3
        assert extractor.calculate_digit_streak("abcdef") == 0

    def test_transition_frequency(self, extractor):
        # "a1b2" has 3 transitions over 3 pairs -> 1.0
        assert math.isclose(extractor.calculate_transition_frequency("a1b2"), 1.0, rel_tol=1e-5)
        # "aaaa" has 0 transitions -> 0.0
        assert extractor.calculate_transition_frequency("aaaa") == 0.0

    def test_feature_vector_completeness(self, extractor):
        feats = extractor.extract_features("test-domain.co.uk")
        assert len(feats) == 14
        for name in FEATURE_NAMES:
            assert name in feats
            assert isinstance(feats[name], (int, float))
            assert not math.isnan(feats[name])
            assert not math.isinf(feats[name])

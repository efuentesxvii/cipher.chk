"""
Test Suite — Password Security Analysis Engine
================================================
Tests cover:
  - EntropyScorer      : boundary cases, charset detection
  - PatternDetector    : each pattern category
  - CrackTimeEstimator : formula correctness, ordering of scenarios
  - PasswordAnalyzer   : integration tests, known-weak passwords
  - SuggestionGenerator: ensures relevant suggestions surface

Run with:
    python -m pytest tests/test_analyzer.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import math
import pytest
from engine.analyzer import (
    EntropyScorer,
    PatternDetector,
    CrackTimeEstimator,
    PasswordAnalyzer,
    StrengthLabel,
)


# ---------------------------------------------------------------------------
# EntropyScorer
# ---------------------------------------------------------------------------

class TestEntropyScorer:
    def setup_method(self):
        self.scorer = EntropyScorer()

    def test_empty_password_returns_zero(self):
        result = self.scorer.score("")
        assert result.bits == 0
        assert result.charset_size == 0

    def test_lowercase_only_charset(self):
        result = self.scorer.score("abcdef")
        assert result.charset_size == 26
        assert result.uppercase_count == 0
        assert result.digit_count == 0
        assert result.special_count == 0

    def test_all_charsets_present(self):
        result = self.scorer.score("Abc1!")
        assert result.charset_size == 26 + 26 + 10 + 32
        assert result.lowercase_count >= 1
        assert result.uppercase_count >= 1
        assert result.digit_count >= 1
        assert result.special_count >= 1

    def test_entropy_increases_with_length(self):
        short  = self.scorer.score("abcdef")
        long   = self.scorer.score("abcdefghijklmnop")
        assert long.bits > short.bits

    def test_entropy_increases_with_charset_size(self):
        lower_only = self.scorer.score("abcdefgh")
        mixed      = self.scorer.score("Abcdef1!")  # same length, more pools
        assert mixed.bits > lower_only.bits

    def test_entropy_formula(self):
        """Verify H = L * log2(N) for lowercase-only password."""
        pw = "abcdefghij"  # 10 chars, lowercase only
        result = self.scorer.score(pw)
        expected = round(10 * math.log2(26), 2)
        assert result.bits == expected

    def test_unique_char_count(self):
        result = self.scorer.score("aaabbb")
        assert result.unique_chars == 2

    def test_digit_only_charset(self):
        result = self.scorer.score("123456")
        assert result.charset_size == 10
        assert result.digit_count == 6


# ---------------------------------------------------------------------------
# PatternDetector
# ---------------------------------------------------------------------------

class TestPatternDetector:
    def setup_method(self):
        self.detector = PatternDetector()

    def _has_pattern(self, password: str, pattern_name: str) -> bool:
        return any(p.name == pattern_name for p in self.detector.detect(password))

    def test_keyboard_walk_qwerty(self):
        assert self._has_pattern("qwerty123", "Keyboard walk")

    def test_keyboard_walk_asdf(self):
        assert self._has_pattern("asdfghjkl", "Keyboard walk")

    def test_keyboard_walk_numeric(self):
        assert self._has_pattern("password1234", "Keyboard walk")

    def test_keyboard_walk_not_detected_for_random(self):
        assert not self._has_pattern("xkP9!mQ2vR", "Keyboard walk")

    def test_leet_substitution_detected(self):
        assert self._has_pattern("P@ssw0rd", "L33tspeak substitution")

    def test_leet_single_substitution_not_flagged(self):
        # Only 1 substitution — below threshold of 2
        assert not self._has_pattern("p@ssword", "L33tspeak substitution")

    def test_date_year_detected(self):
        assert self._has_pattern("summer2023", "Date pattern")

    def test_date_slash_pattern_detected(self):
        assert self._has_pattern("john12/85", "Date pattern")

    def test_repeated_chars_detected(self):
        assert self._has_pattern("passaaa1", "Repeated characters")

    def test_no_repetition_for_normal_password(self):
        assert not self._has_pattern("correcthorse", "Repeated characters")

    def test_common_suffix_123(self):
        assert self._has_pattern("dragon123", "Common suffix")

    def test_common_suffix_exclamation(self):
        assert self._has_pattern("monkey!", "Common suffix")

    def test_no_common_suffix_for_strong_tail(self):
        assert not self._has_pattern("xK9!mQ2vR@", "Common suffix")

    def test_all_lowercase_flagged(self):
        assert self._has_pattern("secretpassword", "All lowercase")

    def test_all_uppercase_flagged(self):
        assert self._has_pattern("SECRETPASSWORD", "All uppercase")

    def test_mixed_case_not_flagged(self):
        assert not self._has_pattern("SecretPassword", "All lowercase")
        assert not self._has_pattern("SecretPassword", "All uppercase")

    def test_multiple_patterns_can_stack(self):
        # "qwerty123!" has keyboard walk + common suffix + date walk
        patterns = self.detector.detect("qwerty123!")
        names = [p.name for p in patterns]
        assert len(names) >= 2  # At least keyboard walk + something


# ---------------------------------------------------------------------------
# CrackTimeEstimator
# ---------------------------------------------------------------------------

class TestCrackTimeEstimator:
    def setup_method(self):
        from engine.analyzer import EntropyScorer
        self.estimator = CrackTimeEstimator()
        self.scorer    = EntropyScorer()

    def test_scenarios_ordered_correctly(self):
        """Fastest attack (offline fast hash) must always be <= slowest (online throttled)."""
        entropy = self.scorer.score("Test1234!")
        result  = self.estimator.estimate(entropy)
        assert result.offline_fast_hash_seconds <= result.offline_slow_hash_seconds
        assert result.offline_slow_hash_seconds <= result.online_unthrottled_seconds
        assert result.online_unthrottled_seconds <= result.online_throttled_seconds

    def test_longer_password_takes_longer(self):
        e_short = self.scorer.score("abc12!")
        e_long  = self.scorer.score("abc12!XYZ789#@$qrs")
        r_short = self.estimator.estimate(e_short)
        r_long  = self.estimator.estimate(e_long)
        assert r_long.offline_fast_hash_seconds > r_short.offline_fast_hash_seconds

    def test_human_readable_seconds(self):
        result = self.estimator.estimate(self.scorer.score("a"))
        assert "second" in result.human_readable(result.offline_fast_hash_seconds)

    def test_human_readable_centuries(self):
        result = self.estimator.estimate(self.scorer.score("xK9!mQ2vR@nP7#dL3$"))
        label = result.human_readable(result.offline_fast_hash_seconds)
        # Long strong password should be centuries or years at minimum
        assert any(word in label for word in ["year", "centur", "month"])

    def test_guesses_positive(self):
        entropy = self.scorer.score("hello")
        result  = self.estimator.estimate(entropy)
        assert result.guesses_estimate > 0


# ---------------------------------------------------------------------------
# PasswordAnalyzer (integration)
# ---------------------------------------------------------------------------

class TestPasswordAnalyzer:
    def setup_method(self):
        self.analyzer = PasswordAnalyzer()

    def test_empty_password_raises(self):
        with pytest.raises(ValueError):
            self.analyzer.analyze("")

    def test_very_weak_password(self):
        result = self.analyzer.analyze("123")
        assert result.strength in (StrengthLabel.VERY_WEAK, StrengthLabel.WEAK)
        assert result.score < 40

    def test_known_weak_passwords(self):
        weak_passwords = ["password", "qwerty", "123456", "abc123", "letmein"]
        for pw in weak_passwords:
            result = self.analyzer.analyze(pw)
            assert result.strength in (
                StrengthLabel.VERY_WEAK,
                StrengthLabel.WEAK,
                StrengthLabel.FAIR,
            ), f"Expected weak/fair for '{pw}', got {result.strength}"

    def test_strong_password(self):
        result = self.analyzer.analyze("xK9!mQ2vR@nP7#dL3$")
        assert result.strength in (StrengthLabel.STRONG, StrengthLabel.VERY_STRONG)
        assert result.score >= 60

    def test_score_bounded_0_100(self):
        for pw in ["a", "password123", "xK9!mQ2vR@nP7#dL3$", "A" * 30]:
            result = self.analyzer.analyze(pw)
            assert 0 <= result.score <= 100, f"Score out of bounds for '{pw}': {result.score}"

    def test_analysis_result_has_suggestions(self):
        result = self.analyzer.analyze("password123")
        assert len(result.suggestions) > 0

    def test_strong_password_fewer_patterns(self):
        weak   = self.analyzer.analyze("qwerty123!")
        strong = self.analyzer.analyze("xK9!mQ2vR@nP7#dL3$")
        assert len(strong.patterns) <= len(weak.patterns)

    def test_result_fields_populated(self):
        result = self.analyzer.analyze("TestPass1!")
        assert result.password_length == len("TestPass1!")
        assert result.entropy is not None
        assert result.crack_time is not None
        assert isinstance(result.strength, StrengthLabel)

    def test_leet_password_not_rated_strong(self):
        """P@ssw0rd should not be rated Strong despite special chars."""
        result = self.analyzer.analyze("P@ssw0rd")
        assert result.strength not in (StrengthLabel.STRONG, StrengthLabel.VERY_STRONG)

    def test_score_increases_with_complexity(self):
        scores = [
            self.analyzer.analyze("abc").score,
            self.analyzer.analyze("Abc1!").score,
            self.analyzer.analyze("Abc1!xyz9@").score,
            self.analyzer.analyze("xK9!mQ2vR@nP7#dL3$").score,
        ]
        # Each should be >= the previous (not strictly, but on average)
        assert scores[-1] > scores[0]


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

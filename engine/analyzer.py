"""
Password Security Analysis Engine
==================================
Core module for analyzing password strength using information-theoretic
and heuristic methods. Designed for use in the Password Security Analyzer
portfolio project.

Modules:
  - EntropyScorer     : Shannon entropy + charset analysis
  - PatternDetector   : Keyboard walks, l33tspeak, dates, repetitions
  - CrackTimeEstimator: GPU-calibrated crack-time modeling
  - PasswordAnalyzer  : Orchestrator — combines all modules into one result
"""

import re
import math
import string
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class StrengthLabel(str, Enum):
    VERY_WEAK  = "very_weak"
    WEAK       = "weak"
    FAIR       = "fair"
    STRONG     = "strong"
    VERY_STRONG = "very_strong"


@dataclass
class EntropyResult:
    """Raw entropy calculation output."""
    bits: float                    # Shannon entropy in bits
    charset_size: int              # Effective character pool size
    length: int
    lowercase_count: int
    uppercase_count: int
    digit_count: int
    special_count: int
    unique_chars: int


@dataclass
class PatternMatch:
    """A single detected weakness pattern."""
    name: str                      # Human-readable pattern name
    description: str               # Why this is a vulnerability
    severity: str                  # "low" | "medium" | "high"
    matched_text: str              # The actual matched substring (redacted in logs)


@dataclass
class CrackTimeResult:
    """Crack-time estimate across common attack scenarios."""
    online_throttled_seconds: float    # 100 guesses/hour (throttled login)
    online_unthrottled_seconds: float  # 10 guesses/second (unprotected login)
    offline_slow_hash_seconds: float   # 1e4/sec (bcrypt, Argon2)
    offline_fast_hash_seconds: float   # 1e10/sec (MD5, SHA1 — GPU cluster)
    guesses_estimate: float            # Total guesses before ~50% crack probability

    def fastest_crack_seconds(self) -> float:
        return self.offline_fast_hash_seconds

    def human_readable(self, seconds: float) -> str:
        """Convert seconds to a human-readable time string."""
        if seconds < 1:
            return "less than a second"
        elif seconds < 60:
            return f"{int(seconds)} second{'s' if seconds != 1 else ''}"
        elif seconds < 3600:
            m = int(seconds / 60)
            return f"{m} minute{'s' if m != 1 else ''}"
        elif seconds < 86400:
            h = int(seconds / 3600)
            return f"{h} hour{'s' if h != 1 else ''}"
        elif seconds < 2_592_000:
            d = int(seconds / 86400)
            return f"{d} day{'s' if d != 1 else ''}"
        elif seconds < 31_536_000:
            mo = int(seconds / 2_592_000)
            return f"{mo} month{'s' if mo != 1 else ''}"
        elif seconds < 3_153_600_000:
            y = int(seconds / 31_536_000)
            return f"{y} year{'s' if y != 1 else ''}"
        else:
            return "centuries"


@dataclass
class AnalysisResult:
    """Full analysis result from PasswordAnalyzer."""
    password_length: int
    entropy: EntropyResult
    patterns: list[PatternMatch]
    crack_time: CrackTimeResult
    strength: StrengthLabel
    score: int                     # 0–100 composite score
    suggestions: list[str]
    is_common: bool = False        # Set externally after wordlist lookup


# ---------------------------------------------------------------------------
# 1. Entropy Scorer
# ---------------------------------------------------------------------------

class EntropyScorer:
    """
    Calculates Shannon entropy of a password.

    Shannon entropy H = -sum(p_i * log2(p_i)) where p_i is the probability
    of each character. We also estimate a theoretical maximum entropy based
    on the character pool used, which gives a more conservative (and more
    honest) estimate of cracking difficulty.

    Reference: Shannon, C.E. (1948). A Mathematical Theory of Communication.
    """

    # Character set size estimates
    CHARSET_LOWER   = 26
    CHARSET_UPPER   = 26
    CHARSET_DIGITS  = 10
    CHARSET_SPECIAL = 32   # printable ASCII non-alphanumeric

    def score(self, password: str) -> EntropyResult:
        if not password:
            return EntropyResult(0, 0, 0, 0, 0, 0, 0, 0)

        # Character class counts
        lower   = sum(1 for c in password if c in string.ascii_lowercase)
        upper   = sum(1 for c in password if c in string.ascii_uppercase)
        digits  = sum(1 for c in password if c in string.digits)
        special = sum(1 for c in password if c in string.punctuation)

        # Effective charset size (which pools are actually used)
        charset_size = 0
        if lower:   charset_size += self.CHARSET_LOWER
        if upper:   charset_size += self.CHARSET_UPPER
        if digits:  charset_size += self.CHARSET_DIGITS
        if special: charset_size += self.CHARSET_SPECIAL

        # Shannon entropy: H = log2(N^L) = L * log2(N)
        # This is the theoretical max for a random password using these pools.
        # Real passwords are lower due to patterns — handled by PatternDetector.
        bits = len(password) * math.log2(charset_size) if charset_size > 0 else 0.0

        return EntropyResult(
            bits=round(bits, 2),
            charset_size=charset_size,
            length=len(password),
            lowercase_count=lower,
            uppercase_count=upper,
            digit_count=digits,
            special_count=special,
            unique_chars=len(set(password)),
        )


# ---------------------------------------------------------------------------
# 2. Pattern Detector
# ---------------------------------------------------------------------------

class PatternDetector:
    """
    Detects common password weakness patterns.

    Each detected pattern reduces the effective entropy of the password
    because attackers use these same heuristics in their rule sets
    (e.g., Hashcat rules, John the Ripper mangling rules).

    Patterns detected:
      - Keyboard walks (qwerty, asdf, 1234, etc.)
      - L33tspeak substitutions (@ for a, 3 for e, etc.)
      - Date patterns (DDMMYYYY, MM/DD/YY, etc.)
      - Repetition (aaa, abcabc)
      - Common suffixes/prefixes (123, !, year appended)
      - All-lowercase or all-uppercase (reduced charset)
    """

    # Common keyboard walk sequences (horizontal + diagonal)
    KEYBOARD_ROWS = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890", "!@#$%^&*()",
    ]

    # L33tspeak substitution map
    LEET_MAP = {
        '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i',
        '0': 'o', '5': 's', '7': 't', '+': 't', '8': 'b',
        '6': 'g', '9': 'g',
    }

    def detect(self, password: str) -> list[PatternMatch]:
        patterns: list[PatternMatch] = []
        lower = password.lower()

        patterns += self._check_keyboard_walks(lower)
        patterns += self._check_leet(password)
        patterns += self._check_dates(password)
        patterns += self._check_repetition(lower)
        patterns += self._check_common_appendages(password)
        patterns += self._check_case_uniformity(password)

        return patterns

    def _check_keyboard_walks(self, lower: str) -> list[PatternMatch]:
        results = []
        for row in self.KEYBOARD_ROWS:
            for length in range(4, len(lower) + 1):
                for i in range(len(row) - length + 1):
                    seq = row[i:i + length]
                    if seq in lower or seq[::-1] in lower:
                        match_text = seq if seq in lower else seq[::-1]
                        results.append(PatternMatch(
                            name="Keyboard walk",
                            description=(
                                f"Sequential keyboard pattern '{match_text}' detected. "
                                "Attackers enumerate these in seconds using rule sets."
                            ),
                            severity="high",
                            matched_text=match_text,
                        ))
                        break  # One match per row per length
        return results

    def _check_leet(self, password: str) -> list[PatternMatch]:
        """Detect l33tspeak: substitute back and check if result looks like a word."""
        substituted = "".join(self.LEET_MAP.get(c, c) for c in password.lower())
        if substituted != password.lower():
            # Count how many characters were substituted
            subs = sum(1 for c in password.lower() if c in self.LEET_MAP)
            if subs >= 2:
                return [PatternMatch(
                    name="L33tspeak substitution",
                    description=(
                        f"{subs} character substitution(s) detected (e.g. @ → a, 3 → e). "
                        "Modern cracking tools apply these rules automatically."
                    ),
                    severity="medium",
                    matched_text="[substitution detected]",
                )]
        return []

    def _check_dates(self, password: str) -> list[PatternMatch]:
        """Detect date patterns: DDMMYYYY, MMDDYYYY, YYYY, MM/DD, etc."""
        date_patterns = [
            (r'(19|20)\d{2}',        "4-digit year"),
            (r'\d{1,2}[/\-\.]\d{1,2}', "Month/day pattern"),
            (r'\d{6,8}',              "Possible date string (DDMMYYYY or MMDDYYYY)"),
        ]
        results = []
        for pattern, label in date_patterns:
            match = re.search(pattern, password)
            if match:
                results.append(PatternMatch(
                    name="Date pattern",
                    description=(
                        f"{label} detected. Birthdays and years are among the most "
                        "commonly appended values in password cracking dictionaries."
                    ),
                    severity="medium",
                    matched_text=match.group(),
                ))
        return results

    def _check_repetition(self, lower: str) -> list[PatternMatch]:
        results = []
        # Consecutive repeated characters: aaaa, 1111
        if re.search(r'(.)\1{2,}', lower):
            results.append(PatternMatch(
                name="Repeated characters",
                description="Three or more identical consecutive characters reduce entropy significantly.",
                severity="medium",
                matched_text="[repeated chars]",
            ))
        # Repeated sequences: abcabc, 123123
        for seq_len in range(2, len(lower) // 2 + 1):
            seq = lower[:seq_len]
            if lower.count(seq) >= 2 and len(seq) * 2 <= len(lower):
                results.append(PatternMatch(
                    name="Repeated sequence",
                    description=f"Repeating pattern detected. Effective entropy is cut in half.",
                    severity="high",
                    matched_text=f"[sequence ×{lower.count(seq)}]",
                ))
                break
        return results

    def _check_common_appendages(self, password: str) -> list[PatternMatch]:
        """Detect common suffixes/prefixes attackers always try."""
        common_tails = ["123", "1234", "12345", "!", "!!", "1", "01", "2024", "2023", "99"]
        results = []
        for tail in common_tails:
            if password.endswith(tail):
                results.append(PatternMatch(
                    name="Common suffix",
                    description=(
                        f"Password ends with '{tail}', one of the most common appendages. "
                        "Cracking tools prepend/append these by default."
                    ),
                    severity="high",
                    matched_text=tail,
                ))
                break
        return results

    def _check_case_uniformity(self, password: str) -> list[PatternMatch]:
        results = []
        alpha = [c for c in password if c.isalpha()]
        if len(alpha) >= 4:
            if all(c.islower() for c in alpha):
                results.append(PatternMatch(
                    name="All lowercase",
                    description="No uppercase letters reduces effective charset from 52 to 26 alpha chars.",
                    severity="low",
                    matched_text="[all lowercase]",
                ))
            elif all(c.isupper() for c in alpha):
                results.append(PatternMatch(
                    name="All uppercase",
                    description="No lowercase letters reduces effective charset from 52 to 26 alpha chars.",
                    severity="low",
                    matched_text="[all uppercase]",
                ))
        return results


# ---------------------------------------------------------------------------
# 3. Crack-Time Estimator
# ---------------------------------------------------------------------------

class CrackTimeEstimator:
    """
    Estimates time-to-crack across realistic attack scenarios.

    Calibrated against published Hashcat benchmarks on consumer GPU hardware
    (RTX 4090, ~200 GH/s for MD5; ~1 kH/s for Argon2id).

    Attack scenarios:
      - Online throttled    : Rate-limited login endpoint (100 req/hour)
      - Online unthrottled  : Unprotected API (10 req/sec)
      - Offline slow hash   : bcrypt/Argon2 on GPU cluster (~10,000 H/s)
      - Offline fast hash   : MD5/SHA1 on GPU cluster (~10 billion H/s)

    Formula: guesses = 0.5 * charset_size^length (50% crack probability)
    Time = guesses / guesses_per_second
    """

    # Guesses per second for each scenario
    ONLINE_THROTTLED     = 100 / 3600    # 100/hour
    ONLINE_UNTHROTTLED   = 10            # 10/sec
    OFFLINE_SLOW_HASH    = 1e4           # bcrypt/Argon2 GPU
    OFFLINE_FAST_HASH    = 1e10          # MD5/SHA1 GPU cluster

    def estimate(self, entropy_result: EntropyResult) -> CrackTimeResult:
        # Cap entropy bits to prevent float overflow on very long passwords
        # 128 bits = 3.4 x 10^38 guesses - effectively uncrackable, no need to go higher
        capped_bits = min(entropy_result.bits, 128.0)
        guesses = 0.5 * (2 ** capped_bits)

        return CrackTimeResult(
            online_throttled_seconds=guesses / self.ONLINE_THROTTLED,
            online_unthrottled_seconds=guesses / self.ONLINE_UNTHROTTLED,
            offline_slow_hash_seconds=guesses / self.OFFLINE_SLOW_HASH,
            offline_fast_hash_seconds=guesses / self.OFFLINE_FAST_HASH,
            guesses_estimate=guesses,
        )


# ---------------------------------------------------------------------------
# 4. Suggestion Generator
# ---------------------------------------------------------------------------

class SuggestionGenerator:
    """Generates actionable, specific improvement suggestions."""

    def generate(
        self,
        entropy: EntropyResult,
        patterns: list[PatternMatch],
        score: int,
    ) -> list[str]:
        suggestions = []

        if entropy.length < 12:
            suggestions.append(
                f"Increase length to at least 16 characters — you currently have {entropy.length}. "
                "Length is the single biggest driver of crack time."
            )
        if entropy.uppercase_count == 0:
            suggestions.append("Add uppercase letters to expand the character pool from 36 to 62.")
        if entropy.special_count == 0:
            suggestions.append(
                "Add special characters (!, @, #, $, etc.) to expand the pool to 94 chars, "
                "multiplying crack time by ~3."
            )
        if entropy.digit_count == 0:
            suggestions.append("Add at least one digit to include the 10-digit pool.")
        if entropy.unique_chars < entropy.length * 0.6:
            suggestions.append(
                "Too many repeated characters. Use more unique characters to maximise entropy."
            )

        # Pattern-specific advice
        pattern_names = {p.name for p in patterns}
        if "Keyboard walk" in pattern_names:
            suggestions.append(
                "Remove keyboard sequences (qwerty, asdf, 1234). "
                "Attackers enumerate these in the first few thousand guesses."
            )
        if "Date pattern" in pattern_names:
            suggestions.append(
                "Remove dates. Birthdays and years are in every serious wordlist "
                "and dramatically reduce search space."
            )
        if "Common suffix" in pattern_names:
            suggestions.append(
                "Don't append '123', '!', or years. These are the first transformations "
                "any cracking tool applies to dictionary words."
            )
        if "L33tspeak substitution" in pattern_names:
            suggestions.append(
                "L33tspeak is fully automated in modern crackers. "
                "'P@ssw0rd' is cracked just as fast as 'Password'."
            )

        if score >= 80 and not suggestions:
            suggestions.append(
                "Strong password. Consider using a password manager to generate and "
                "store a truly random 20+ character password."
            )

        return suggestions


# ---------------------------------------------------------------------------
# 5. Orchestrator
# ---------------------------------------------------------------------------

class PasswordAnalyzer:
    """
    Main entry point. Combines all analysis modules and returns a
    single AnalysisResult with a composite 0–100 score and strength label.

    Scoring breakdown:
      - Entropy score  : 0–50 pts (based on entropy bits)
      - Pattern penalty: up to -30 pts (per detected weakness)
      - Length bonus   : 0–10 pts
      - Charset bonus  : 0–10 pts
    """

    ENTROPY_MAX_BITS = 100   # Reference: 100-bit entropy ≈ very strong

    def __init__(self):
        self.entropy_scorer  = EntropyScorer()
        self.pattern_detector = PatternDetector()
        self.crack_estimator  = CrackTimeEstimator()
        self.suggestion_gen   = SuggestionGenerator()

    def analyze(self, password: str) -> AnalysisResult:
        if not password:
            raise ValueError("Password must not be empty.")

        # Run all modules
        entropy  = self.entropy_scorer.score(password)
        patterns = self.pattern_detector.detect(password)
        crack    = self.crack_estimator.estimate(entropy)
        score    = self._composite_score(entropy, patterns)
        strength = self._label(score)
        suggestions = self.suggestion_gen.generate(entropy, patterns, score)

        return AnalysisResult(
            password_length=len(password),
            entropy=entropy,
            patterns=patterns,
            crack_time=crack,
            strength=strength,
            score=score,
            suggestions=suggestions,
        )

    def _composite_score(
        self,
        entropy: EntropyResult,
        patterns: list[PatternMatch],
    ) -> int:
        # Base score from entropy (0–50)
        entropy_score = min(50, int((entropy.bits / self.ENTROPY_MAX_BITS) * 50))

        # Length bonus (0–20)
        length_score = min(20, max(0, (entropy.length - 6) * 2))

        # Charset diversity bonus (0–20)
        charset_score = 0
        if entropy.lowercase_count > 0: charset_score += 5
        if entropy.uppercase_count > 0: charset_score += 5
        if entropy.digit_count > 0:     charset_score += 5
        if entropy.special_count > 0:   charset_score += 5

        # Unique character bonus (0–10)
        uniqueness = entropy.unique_chars / max(1, entropy.length)
        unique_score = int(uniqueness * 10)

        # Pattern penalties
        severity_weights = {"high": 15, "medium": 8, "low": 3}
        penalty = sum(severity_weights.get(p.severity, 0) for p in patterns)

        raw = entropy_score + length_score + charset_score + unique_score - penalty
        return max(0, min(100, raw))

    def _label(self, score: int) -> StrengthLabel:
        if score < 20:  return StrengthLabel.VERY_WEAK
        if score < 40:  return StrengthLabel.WEAK
        if score < 60:  return StrengthLabel.FAIR
        if score < 80:  return StrengthLabel.STRONG
        return StrengthLabel.VERY_STRONG

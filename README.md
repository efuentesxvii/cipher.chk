# Password Security Analyzer

![CI](https://github.com/efuentesxvii/cipher.chk/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-teal)
![License](https://img.shields.io/badge/license-MIT-green)

A full-stack password security tool built to demonstrate applied web security concepts: information-theoretic entropy scoring, heuristic pattern detection, GPU-calibrated crack-time modeling, and a privacy-preserving breach lookup using the HaveIBeenPwned k-anonymity API.

> Built as a portfolio project showcasing application security fundamentals — not intended as a production credential manager.

---

## Features

- **Entropy scoring** — Shannon entropy calculation (`H = L × log₂(N)`) with effective charset analysis
- **Pattern detection** — keyboard walks, l33tspeak substitutions, date patterns, repeated sequences, common suffixes
- **Crack-time modeling** — four attack scenarios calibrated against Hashcat RTX 4090 benchmarks (online throttled → offline GPU cluster)
- **k-Anonymity breach check** — HIBP lookup that sends only 5 SHA-1 hex chars to the API; matching done locally; plaintext never leaves the server
- **Rate limiting** — per-IP limits on all endpoints (slowapi)
- **Input sanitization** — control character stripping, length cap, injection prevention
- **Audit logging** — request metadata stored as SHA-256 hash only; raw password never persisted
- **CI/CD pipeline** — GitHub Actions runs pytest + Bandit static security scan on every push

---

## Architecture

```
password-analyzer/
├── engine/
│   └── analyzer.py          # Core analysis: entropy, patterns, crack-time
├── api/
│   └── main.py              # FastAPI: /analyze, /breach-check, /health
├── tests/
│   ├── test_analyzer.py     # 32 engine unit tests
│   └── test_api.py          # 20 API integration tests
├── docs/
│   └── THREAT_MODEL.md      # STRIDE threat model
└── .github/workflows/
    └── ci.yml               # pytest + Bandit on push
```

### Request lifecycle

```
Browser  →  POST /analyze  →  Input validation (Pydantic)
                           →  Rate limiter (30 req/min/IP)
                           →  EntropyScorer
                           →  PatternDetector
                           →  CrackTimeEstimator
                           →  Audit log (SHA-256 hash only)
                           →  JSON response
```

### k-Anonymity breach check

```
Client password  →  SHA-1 hash locally
                 →  Send first 5 hex chars to HIBP  (e.g. "5BAA6")
                 ←  HIBP returns ~500 matching suffixes
                 →  Match full hash suffix locally
                 →  Return breach count — plaintext never sent
```

---

## Security design decisions

| Decision | Rationale |
|---|---|
| k-Anonymity for HIBP lookup | Prevents the breach-check API from learning what password was queried |
| SHA-256 audit hashing | Enables deduplication and audit trails without storing credentials |
| Control character stripping | Prevents null byte injection and escape sequence abuse |
| Rate limiting on `/breach-check` (10/min) | More restrictive than `/analyze` to protect the external HIBP dependency |
| CORS origin allowlist | Restricts which frontends can call the API |
| Pydantic input model | Validation runs before any application logic — fail fast, fail loudly |

For full threat analysis, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Getting started

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
git clone https://github.com/YOURUSERNAME/password-analyzer.git
cd password-analyzer

pip install -r requirements.txt
```

### Run the API

```bash
uvicorn api.main:app --reload
```

API is now running at `http://localhost:8000`.  
Interactive docs at `http://localhost:8000/docs`.

### Run tests

```bash
# All tests
python -m pytest tests/ -v

# Engine only
python -m pytest tests/test_analyzer.py -v

# API only
python -m pytest tests/test_api.py -v
```

### Run Bandit security scan

```bash
bandit -r engine/ api/ -ll
```

---

## API reference

### `POST /analyze`

Analyze a password and return a full security report.

**Rate limit:** 30 requests/minute per IP

**Request body:**
```json
{ "password": "your-password-here" }
```

**Response:**
```json
{
  "score": 72,
  "strength": "strong",
  "entropy": {
    "bits": 65.4,
    "charset_size": 94,
    "length": 10,
    "lowercase_count": 4,
    "uppercase_count": 2,
    "digit_count": 2,
    "special_count": 2,
    "unique_chars": 10
  },
  "crack_time": {
    "online_throttled": "centuries",
    "online_unthrottled": "3 years",
    "offline_slow_hash": "4 hours",
    "offline_fast_hash": "less than a second"
  },
  "patterns": [
    {
      "name": "Common suffix",
      "description": "Ends with '123'...",
      "severity": "high"
    }
  ],
  "suggestions": [
    "Remove keyboard sequences..."
  ]
}
```

---

### `GET /breach-check?password={password}`

Check a password against the HaveIBeenPwned database using k-anonymity.

**Rate limit:** 10 requests/minute per IP

**Response:**
```json
{
  "breached": true,
  "breach_count": 3861493,
  "note": "Found in 3,861,493 known data breaches. Do not use this password."
}
```

---

### `GET /health`

```json
{ "status": "ok", "version": "1.0.0", "timestamp": "2024-01-01T00:00:00+00:00" }
```

---

## Scoring methodology

The composite 0–100 score is calculated as:

| Component | Max points | Notes |
|---|---|---|
| Entropy score | 50 | `min(50, entropy_bits / 100 × 50)` |
| Length bonus | 20 | `min(20, (length - 6) × 2)` |
| Charset diversity | 20 | 5 pts per character class used |
| Uniqueness | 10 | `unique_chars / length × 10` |
| Pattern penalties | −15 to −30 per pattern | High: −15, Medium: −8, Low: −3 |

Strength labels: `very_weak` (0–19) · `weak` (20–39) · `fair` (40–59) · `strong` (60–79) · `very_strong` (80–100)

---

## Crack-time scenarios

Calibrated against published Hashcat benchmarks on an RTX 4090:

| Scenario | Speed | Real-world analogy |
|---|---|---|
| Online throttled | 100 req/hour | Rate-limited login endpoint |
| Online unthrottled | 10 req/second | Unprotected API endpoint |
| Offline slow hash | 10,000 H/s | bcrypt or Argon2id on GPU |
| Offline fast hash | 10,000,000,000 H/s | MD5 or SHA-1 on GPU cluster |

---

## Threat model

A full STRIDE threat model is documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), covering:

- Trust boundaries and data flow
- All six STRIDE categories applied to each component
- Implemented mitigations with code references
- Accepted risks and production hardening checklist

---

## References

- Shannon, C.E. (1948). *A Mathematical Theory of Communication*
- [HaveIBeenPwned k-Anonymity model](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [Hashcat benchmarks — RTX 4090](https://hashcat.net/forum/thread-10803.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

---

## License

MIT — see [LICENSE](LICENSE)
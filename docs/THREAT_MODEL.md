# Threat Model — Password Security Analyzer

**Version:** 1.0  
**Date:** 2026  
**Author:** Euclides Fuentes  
**Methodology:** STRIDE  

---

## 1. Overview

This document models the security threats present in the Password Security Analyzer, a web application that accepts password input, performs entropy and pattern analysis, and optionally checks the password against the HaveIBeenPwned breach database.

The goal of this threat model is to identify attack surfaces, enumerate threats using the STRIDE framework, and document the mitigations implemented — as well as risks that are accepted or deferred.

---

## 2. System Description

### Components

| Component | Technology | Purpose |
|---|---|---|
| Frontend | HTML / JavaScript | User input, live analysis display |
| API | Python / FastAPI | Analysis orchestration, HIBP proxy |
| Analysis Engine | Python | Entropy scoring, pattern detection, crack-time estimation |
| External API | HaveIBeenPwned (HIBP) | Breach database lookup |
| Audit Log | In-memory (demo) | Request metadata logging |

### Data Flow

```
User (browser)
    │
    │  HTTPS POST /analyze  {password: "..."}
    ▼
FastAPI Backend
    ├── Input validation & sanitization
    ├── Rate limiter (slowapi, per-IP)
    ├── Analysis Engine (local)
    │       ├── EntropyScorer
    │       ├── PatternDetector
    │       └── CrackTimeEstimator
    ├── Audit log (SHA-256 hash only — no plaintext)
    │
    │  GET https://api.pwnedpasswords.com/range/{5-char prefix}
    ▼
HIBP API (external)
    │
    │  Returns ~500 hash suffixes matching the prefix
    ▼
FastAPI Backend
    └── Local suffix match → breach count returned to client
```

### Trust Boundaries

1. **Browser → API**: untrusted. All input validated server-side.
2. **API → HIBP**: semi-trusted third party. Response is treated as data, not instructions.
3. **API → Audit log**: trusted internal write. No user-controlled data written verbatim.

---

## 3. Assets

| Asset | Sensitivity | Why It Matters |
|---|---|---|
| Raw password input | Critical | Direct credential exposure if logged or leaked |
| SHA-1 hash prefix (sent to HIBP) | Low | 5 chars of SHA-1 is not reversible |
| SHA-256 audit hash | Low | One-way; used only for deduplication |
| Analysis results | Low | Metadata about password quality; not a credential |
| API server | High | Compromise enables MitM on all analysis requests |

---

## 4. STRIDE Analysis

STRIDE categorizes threats into six types:

| Letter | Threat Type | Violated Property |
|---|---|---|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

---

### 4.1 Spoofing

#### STRIDE-S-01 — Client spoofs a trusted origin

**Component:** CORS middleware  
**Description:** An attacker hosts a malicious page that calls the API, spoofing an allowed origin via a crafted `Origin` header.  
**Likelihood:** Medium  
**Impact:** Medium — attacker can submit passwords to the analysis endpoint  

**Mitigation (implemented):**  
CORS is locked to an explicit allowlist in `main.py`. Requests from unlisted origins are rejected at the middleware layer before reaching any endpoint logic.

```python
allow_origins=[
    "http://localhost:3000",
    "http://localhost:5500",
    # production frontend URL added here
]
```

**Residual risk:** CORS is enforced by the browser, not the server. A non-browser client (curl, Python requests) can send any origin header. The rate limiter provides the primary defense against automated abuse from non-browser clients.

---

#### STRIDE-S-02 — Attacker impersonates the HIBP API

**Component:** Breach-check endpoint  
**Description:** An attacker performs a DNS hijack or MitM to return crafted HIBP responses, either suppressing breach results or injecting malicious data.  
**Likelihood:** Low  
**Impact:** Low — response is used only to display a breach count; no code execution  

**Mitigation (implemented):**  
All HIBP requests use HTTPS. The response is parsed as plain text (line-split, colon-split) — no deserialization, no execution.  

**Residual risk:** Certificate pinning is not implemented. A sophisticated MitM with a rogue CA could suppress breach results. Acceptable risk for a portfolio/demo deployment.

---

### 4.2 Tampering

#### STRIDE-T-01 — Malicious input via password field

**Component:** `POST /analyze` input validation  
**Description:** An attacker submits a crafted password string containing SQL injection fragments, shell metacharacters, null bytes, or Unicode escape sequences, attempting to corrupt logs, crash the engine, or probe the backend.  
**Likelihood:** High (automated scanners will attempt this)  
**Impact:** Low (mitigated)  

**Mitigation (implemented):**  
Input is validated in the Pydantic model before reaching any application logic:

- Length capped at 256 characters
- Leading/trailing whitespace stripped
- Control characters (null bytes, escape sequences `\x00–\x1f`) stripped via regex
- Empty string after sanitization is rejected with 422

The analysis engine operates purely in Python with no SQL, shell calls, or file writes — there is no injection surface downstream of the validator.

**Residual risk:** None identified for current implementation scope.

---

#### STRIDE-T-02 — Tampering with audit log entries

**Component:** Audit log  
**Description:** An attacker with write access to the server modifies audit log entries to remove evidence of their activity.  
**Likelihood:** Low  
**Impact:** Medium — loss of forensic record  

**Mitigation (partial):**  
Current implementation uses an in-memory list — appropriate for a demo. In a production deployment, audit logs should be written to an append-only store (e.g., write-once S3 bucket, immutable database table, or a SIEM).  

**Residual risk:** In-memory log is lost on process restart and offers no tamper evidence. **Accepted for demo scope.**

---

### 4.3 Repudiation

#### STRIDE-R-01 — User denies submitting a password for analysis

**Component:** Audit log  
**Description:** A user claims they never submitted a particular password, contesting that the service analyzed or stored it.  
**Likelihood:** Low  
**Impact:** Low  

**Mitigation (implemented):**  
Every analysis request writes an audit entry containing a truncated SHA-256 hash of the password, the request timestamp, result score, and strength label. The raw password is never stored — only its hash — so the log proves a request was made without retaining the credential itself.

**Residual risk:** Truncated hash (`[:16]`) reduces collision resistance for forensic purposes. In a production system, store the full SHA-256.

---

### 4.4 Information Disclosure

#### STRIDE-I-01 — Password leaked in server logs

**Component:** Logging / audit layer  
**Description:** The raw password is inadvertently written to application logs (e.g., via a default FastAPI request logger, an unhandled exception traceback, or a debug print statement).  
**Likelihood:** Medium (common developer mistake)  
**Impact:** Critical — direct credential exposure  

**Mitigation (implemented):**  
- No `print()` statements in application code
- FastAPI's default access log does not log request bodies
- The audit function explicitly receives only the SHA-256 hash, never the raw password
- Pydantic validation errors do not echo the submitted value back in the 422 response body

**Residual risk:** Exception tracebacks in unhandled error paths could include the password if it appears in a stack frame. A production deployment should use a structured exception handler that scrubs sensitive fields.

---

#### STRIDE-I-02 — Password prefix leaked to HIBP

**Component:** `GET /breach-check`  
**Description:** More than 5 characters of the SHA-1 hash are sent to HIBP, narrowing the anonymity set and making the lookup reversible via rainbow table.  
**Likelihood:** Low (requires code change)  
**Impact:** High — would break the k-anonymity guarantee  

**Mitigation (implemented):**  
The k-anonymity implementation is explicit and tested:

```python
sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
prefix    = sha1_hash[:5]   # only this is sent
suffix    = sha1_hash[5:]   # kept local
```

A dedicated test (`test_kanonymity_prefix_is_5_chars`) asserts that the full hash does not appear in the HIBP request URL on every CI run.

**Residual risk:** None for current implementation.

---

#### STRIDE-I-03 — Analysis results reveal password structure to a network observer

**Component:** API response  
**Description:** The JSON response includes entropy bits, charset size, and detected patterns. An observer on the network could use this to narrow guesses about the password.  
**Likelihood:** Low (requires network access)  
**Impact:** Low  

**Mitigation:**  
Deploy with HTTPS (TLS 1.2+). Analysis results are metadata about password quality, not the password itself — disclosure risk is low even if intercepted.

---

### 4.5 Denial of Service

#### STRIDE-D-01 — Rate exhaustion via high-volume requests

**Component:** `POST /analyze`, `GET /breach-check`  
**Description:** An attacker floods the API with requests to exhaust CPU (analysis engine) or trigger HIBP rate limiting on the server's IP.  
**Likelihood:** High (trivial to automate)  
**Impact:** Medium — legitimate users denied service  

**Mitigation (implemented):**  
- `POST /analyze`: 30 requests/minute per IP (slowapi)
- `GET /breach-check`: 10 requests/minute per IP (more restrictive due to external dependency)
- 256-character input cap prevents large-payload attacks

```python
@limiter.limit("30/minute")   # /analyze
@limiter.limit("10/minute")   # /breach-check
```

**Residual risk:** IP-based rate limiting can be bypassed by distributed botnets. A production deployment should add a CAPTCHA for anonymous users or require authentication.

---

#### STRIDE-D-02 — HIBP dependency causes cascading failure

**Component:** Breach-check endpoint  
**Description:** HIBP is unavailable or slow, causing the breach-check endpoint to hang and exhaust server threads.  
**Likelihood:** Low (HIBP is highly available)  
**Impact:** Medium — breach-check endpoint unavailable  

**Mitigation (implemented):**  
All HIBP requests use a 5-second timeout. `TimeoutException` is caught and returns a `503 Service Unavailable` rather than hanging.

```python
async with httpx.AsyncClient(timeout=5.0) as client:
    ...
except httpx.TimeoutException:
    raise HTTPException(status_code=503, ...)
```

**Residual risk:** The `/analyze` endpoint is independent of HIBP — a HIBP outage only affects breach checking, not core analysis.

---

### 4.6 Elevation of Privilege

#### STRIDE-E-01 — Unauthorized access to audit log endpoint

**Component:** `GET /audit-log`  
**Description:** The dev-only audit log endpoint is exposed without authentication in the current implementation. An attacker who discovers the URL can read all audit metadata.  
**Likelihood:** Medium (endpoint is discoverable via `/docs`)  
**Impact:** Low (no passwords stored; only hashes and metadata)  

**Mitigation (partial):**  
The endpoint is marked `include_in_schema=False` (hidden from the public OpenAPI docs). A code comment explicitly flags it as dev-only.

**Residual risk:** The endpoint is still accessible at runtime. **For production: remove the endpoint entirely or protect it behind an admin authentication middleware.** This is a known and accepted gap in the demo implementation.

---

## 5. Attack Surface Summary

| Surface | Exposure | Primary Control |
|---|---|---|
| `POST /analyze` | Public | Rate limit + input validation |
| `GET /breach-check` | Public | Rate limit + k-anonymity |
| `GET /health` | Public | Read-only, no sensitive data |
| `GET /audit-log` | Dev only | Hidden from schema; remove in prod |
| HIBP outbound call | Server-initiated | HTTPS + 5s timeout |
| Audit log storage | Internal | SHA-256 hash only; no plaintext |

---

## 6. Mitigations Implemented vs. Deferred

### Implemented
- [x] Input length cap (256 chars)
- [x] Control character stripping
- [x] Rate limiting per IP (slowapi)
- [x] CORS origin allowlist
- [x] k-Anonymity HIBP lookup (5-char prefix only)
- [x] SHA-256 audit hashing (no plaintext storage)
- [x] HTTPS for all external calls
- [x] 5-second HIBP timeout with graceful 503
- [x] Audit log endpoint hidden from public schema

### Deferred (production hardening)
- [ ] Replace in-memory audit log with append-only persistent store
- [ ] Add authentication to `/audit-log` or remove it
- [ ] Structured exception handler to scrub passwords from tracebacks
- [ ] Full SHA-256 (not truncated) in audit entries
- [ ] CAPTCHA or auth for anonymous API access
- [ ] TLS certificate pinning for HIBP requests
- [ ] Secrets management (environment variable validation on startup)

---

## 7. References

- [STRIDE Threat Modeling — Microsoft SDL](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [HaveIBeenPwned k-Anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Shannon, C.E. (1948). A Mathematical Theory of Communication](https://people.math.harvard.edu/~ctm/home/text/others/shannon/entropy/entropy.pdf)

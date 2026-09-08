import hashlib
import logging
import re
import sys
import os
import time
from datetime import datetime, timezone
from typing import Optional

# Allow engine imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from engine.analyzer import PasswordAnalyzer, StrengthLabel

# ---------------------------------------------------------------------------
# Logging — structured, never logs raw passwords
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("password-analyzer")


# ---------------------------------------------------------------------------
# Rate limiter (slowapi wraps limits per IP)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Password Security Analyzer",
    description="Analysis engine with entropy scoring, pattern detection, and HIBP breach lookup.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ---------------------------------------------------------------------------
# CORS — lock to your frontend origin in production
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        # Add your deployed frontend URL here, e.g.:
        # "https://yourusername.github.io",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Audit log — metadata only, no plaintext
# ---------------------------------------------------------------------------

audit_log: list[dict] = []   # In-memory for demo; swap for SQLite/Postgres in prod

def audit(event: str, password_sha256: str, metadata: dict) -> None:
    """Log an analysis event. The password is stored only as SHA-256 — never plaintext."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "password_hash": password_sha256[:16] + "...",  # truncated — not reversible
        **metadata,
    }
    audit_log.append(entry)
    logger.info("AUDIT %s | len=%s score=%s",
                event,
                metadata.get("length", "?"),
                metadata.get("score", "?"))


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Strip leading/trailing whitespace
        v = v.strip()

        # Reject empty
        if not v:
            raise ValueError("Password must not be empty.")

        # Hard cap — prevents DoS via absurdly long input
        if len(v) > 256:
            raise ValueError("Password must be 256 characters or fewer.")

        # Strip non-printable control characters (null bytes, escape sequences, etc.)
        # This prevents injection attempts via unusual byte sequences
        v = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", v)

        if not v:
            raise ValueError("Password contains only invalid characters.")

        return v


class PatternOut(BaseModel):
    name: str
    description: str
    severity: str


class EntropyOut(BaseModel):
    bits: float
    charset_size: int
    length: int
    lowercase_count: int
    uppercase_count: int
    digit_count: int
    special_count: int
    unique_chars: int


class CrackTimeOut(BaseModel):
    online_throttled: str
    online_unthrottled: str
    offline_slow_hash: str
    offline_fast_hash: str
    guesses_estimate: float


class AnalyzeResponse(BaseModel):
    score: int
    strength: str
    entropy: EntropyOut
    crack_time: CrackTimeOut
    patterns: list[PatternOut]
    suggestions: list[str]
    is_breached: Optional[bool] = None   # None = not checked; True/False = HIBP result


class BreachCheckResponse(BaseModel):
    breached: bool
    breach_count: int
    note: str


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


# ---------------------------------------------------------------------------
# Singleton analyzer (loaded once at startup)
# ---------------------------------------------------------------------------

analyzer = PasswordAnalyzer()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze password strength",
    description=(
        "Runs entropy scoring, pattern detection, crack-time estimation, "
        "and returns a 0–100 composite score with actionable suggestions. "
        "Rate limited to 30 requests/minute per IP."
    ),
)
@limiter.limit("30/minute")
async def analyze_password(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    pw = body.password

    try:
        result = analyzer.analyze(pw)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    # Audit: hash the password with SHA-256 before any logging
    pw_hash = hashlib.sha256(pw.encode()).hexdigest()
    audit("analyze", pw_hash, {
        "length": len(pw),
        "score": result.score,
        "strength": result.strength.value,
        "pattern_count": len(result.patterns),
    })

    ct = result.crack_time

    return AnalyzeResponse(
        score=result.score,
        strength=result.strength.value,
        entropy=EntropyOut(
            bits=result.entropy.bits,
            charset_size=result.entropy.charset_size,
            length=result.entropy.length,
            lowercase_count=result.entropy.lowercase_count,
            uppercase_count=result.entropy.uppercase_count,
            digit_count=result.entropy.digit_count,
            special_count=result.entropy.special_count,
            unique_chars=result.entropy.unique_chars,
        ),
        crack_time=CrackTimeOut(
            online_throttled=ct.human_readable(ct.online_throttled_seconds),
            online_unthrottled=ct.human_readable(ct.online_unthrottled_seconds),
            offline_slow_hash=ct.human_readable(ct.offline_slow_hash_seconds),
            offline_fast_hash=ct.human_readable(ct.offline_fast_hash_seconds),
            guesses_estimate=ct.guesses_estimate,
        ),
        patterns=[
            PatternOut(name=p.name, description=p.description, severity=p.severity)
            for p in result.patterns
        ],
        suggestions=result.suggestions,
    )


@app.get(
    "/breach-check",
    response_model=BreachCheckResponse,
    summary="Check password against HaveIBeenPwned (k-anonymity)",
    description=(
        "Implements the HIBP k-anonymity model: the password is hashed with SHA-1, "
        "and ONLY the first 5 hex characters are sent to the HIBP API. "
        "The full hash never leaves this server. The matching is done locally. "
        "Rate limited to 10 requests/minute per IP."
    ),
)
@limiter.limit("10/minute")
async def breach_check(request: Request, password: str) -> BreachCheckResponse:
    """
    k-Anonymity implementation:
      1. SHA-1 hash the password locally
      2. Send only the first 5 hex chars (the 'prefix') to HIBP
      3. HIBP returns all hashes that share that prefix (~500 on average)
      4. We search the returned list locally for our full hash suffix
      5. The plaintext password never leaves this server

    This means HIBP never sees enough information to reconstruct the password,
    even if the API response is intercepted.
    """
    # Input validation
    password = password.strip()
    if not password or len(password) > 256:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be between 1 and 256 characters.",
        )

    # Step 1: SHA-1 hash (HIBP uses SHA-1 specifically)
    sha1_hash = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper() # nosec B324
    prefix    = sha1_hash[:5]    # sent to HIBP
    suffix    = sha1_hash[5:]    # kept local, used for matching

    # Step 2: Query HIBP with prefix only
    hibp_url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                hibp_url,
                headers={"Add-Padding": "true"},   # HIBP padding header hides result count
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="HIBP API timed out. Try again shortly.",
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"HIBP API returned {e.response.status_code}.",
        )
    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not reach HIBP API.",
        )

    # Step 3: Parse response — format is "SUFFIX:COUNT\r\n" per line
    breach_count = 0
    breached = False

    for line in response.text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        line_suffix, count_str = parts
        if line_suffix.upper() == suffix:
            try:
                breach_count = int(count_str.strip())
                breached = True
            except ValueError:
                pass
            break

    # Audit — log hash prefix only (not even the full hash)
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    audit("breach-check", pw_hash, {
        "length": len(password),
        "hibp_prefix": prefix,          # safe to log — 5 chars of SHA-1 is not reversible
        "breached": breached,
        "breach_count": breach_count,
    })

    note = (
        f"Found in {breach_count:,} known data breaches. Do not use this password."
        if breached
        else "Not found in known breach databases. Still verify strength above."
    )

    return BreachCheckResponse(
        breached=breached,
        breach_count=breach_count,
        note=note,
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    include_in_schema=False,
)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="1.0.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/audit-log", include_in_schema=False)
async def get_audit_log(request: Request):
    """
    Dev-only endpoint — view the in-memory audit log.
    In production: remove this or protect behind auth middleware.
    """
    return JSONResponse(content={"entries": audit_log[-50:]})


# ---------------------------------------------------------------------------
# Run directly: python api/main.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) # nosec B104

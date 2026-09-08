import hashlib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient, ASGITransport, Response

from api.main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client():
    """Async test client wrapping the FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# POST /analyze
# ---------------------------------------------------------------------------

class TestAnalyzeEndpoint:

    @pytest.mark.asyncio
    async def test_valid_password_returns_200(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_response_schema(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        data = resp.json()
        assert "score" in data
        assert "strength" in data
        assert "entropy" in data
        assert "crack_time" in data
        assert "patterns" in data
        assert "suggestions" in data

    @pytest.mark.asyncio
    async def test_score_in_range(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        data = resp.json()
        assert 0 <= data["score"] <= 100

    @pytest.mark.asyncio
    async def test_weak_password_low_score(self, client):
        resp = await client.post("/analyze", json={"password": "password123"})
        data = resp.json()
        assert data["score"] < 60

    @pytest.mark.asyncio
    async def test_strong_password_high_score(self, client):
        resp = await client.post("/analyze", json={"password": "xK9!mQ2vR@nP7#dL3$"})
        data = resp.json()
        assert data["score"] >= 60

    @pytest.mark.asyncio
    async def test_empty_password_returns_422(self, client):
        resp = await client.post("/analyze", json={"password": ""})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_password_too_long_returns_422(self, client):
        resp = await client.post("/analyze", json={"password": "A" * 257})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_body_returns_422(self, client):
        resp = await client.post("/analyze", json={})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_control_chars_stripped(self, client):
        # Null bytes and escape chars should be stripped, not cause a 500
        resp = await client.post("/analyze", json={"password": "Test\x00Pass\x1b1!"})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_entropy_fields_present(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        entropy = resp.json()["entropy"]
        for field in ["bits", "charset_size", "length", "lowercase_count",
                      "uppercase_count", "digit_count", "special_count", "unique_chars"]:
            assert field in entropy, f"Missing entropy field: {field}"

    @pytest.mark.asyncio
    async def test_crack_time_fields_present(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        ct = resp.json()["crack_time"]
        for field in ["online_throttled", "online_unthrottled",
                      "offline_slow_hash", "offline_fast_hash"]:
            assert field in ct

    @pytest.mark.asyncio
    async def test_patterns_is_list(self, client):
        resp = await client.post("/analyze", json={"password": "qwerty123!"})
        assert isinstance(resp.json()["patterns"], list)

    @pytest.mark.asyncio
    async def test_pattern_has_severity(self, client):
        resp = await client.post("/analyze", json={"password": "qwerty123!"})
        patterns = resp.json()["patterns"]
        if patterns:
            assert "severity" in patterns[0]
            assert patterns[0]["severity"] in ("low", "medium", "high")

    @pytest.mark.asyncio
    async def test_suggestions_is_list(self, client):
        resp = await client.post("/analyze", json={"password": "password"})
        assert isinstance(resp.json()["suggestions"], list)
        assert len(resp.json()["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_strength_is_valid_label(self, client):
        resp = await client.post("/analyze", json={"password": "TestPass1!"})
        valid = {"very_weak", "weak", "fair", "strong", "very_strong"}
        assert resp.json()["strength"] in valid

    @pytest.mark.asyncio
    async def test_max_length_password_accepted(self, client):
        resp = await client.post("/analyze", json={"password": "A" * 256})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /breach-check  (HIBP mocked — no real network calls)
# ---------------------------------------------------------------------------

def _make_hibp_response(suffix: str, count: int = 5) -> str:
    """Build a fake HIBP range response containing the given suffix."""
    lines = [
        f"AAAAABBBBBCCCCCDDDDDEEEEEFFFFFF0:1",
        f"{suffix.upper()}:{count}",
        f"FFFFFFEEEEEDDDDDCCCCCBBBBBAAAAA0:2",
    ]
    return "\r\n".join(lines)


class TestBreachCheckEndpoint:

    @pytest.mark.asyncio
    async def test_health_check_passes(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_breach_check_empty_password(self, client):
        resp = await client.get("/breach-check", params={"password": ""})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_breach_check_too_long(self, client):
        resp = await client.get("/breach-check", params={"password": "A" * 257})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_breached_password_detected(self, client):
        """Mock HIBP to return a match for 'password'."""
        pw = "password"
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        suffix = sha1[5:]

        mock_resp = MagicMock()
        mock_resp.text = _make_hibp_response(suffix, count=3861493)
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("api.main.httpx.AsyncClient", return_value=mock_client):
            resp = await client.get("/breach-check", params={"password": pw})

        assert resp.status_code == 200
        data = resp.json()
        assert data["breached"] is True
        assert data["breach_count"] == 3861493

    @pytest.mark.asyncio
    async def test_clean_password_not_breached(self, client):
        """Mock HIBP to return no match for a unique password."""
        pw = "xK9!mQ2vR@nP7#dL3$_unique_2024"
        mock_resp = MagicMock()
        mock_resp.text = "AAAAABBBBBCCCCCDDDDDEEEEEFFFFFF0:1\r\nFFFFFEEEEEDDDDDCCCCCBBBBBAAAAA0:2"
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("api.main.httpx.AsyncClient", return_value=mock_client):
            resp = await client.get("/breach-check", params={"password": pw})

        assert resp.status_code == 200
        data = resp.json()
        assert data["breached"] is False
        assert data["breach_count"] == 0

    @pytest.mark.asyncio
    async def test_kanonymity_prefix_is_5_chars(self, client):
        """Verify that only a 5-char prefix would be sent — we check the mock call args."""
        pw = "testpassword"
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        expected_prefix = sha1[:5]

        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("api.main.httpx.AsyncClient", return_value=mock_client):
            await client.get("/breach-check", params={"password": pw})

        call_url = mock_client.get.call_args[0][0]
        assert call_url.endswith(expected_prefix), (
            f"Expected HIBP URL to end with prefix '{expected_prefix}', got: {call_url}"
        )
        # Critically — the full hash must NOT appear in the URL
        assert sha1 not in call_url, "Full SHA-1 hash leaked into HIBP request URL!"

    @pytest.mark.asyncio
    async def test_hibp_timeout_returns_503(self, client):
        import httpx as _httpx
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=_httpx.TimeoutException("timeout"))

        with patch("api.main.httpx.AsyncClient", return_value=mock_client):
            resp = await client.get("/breach-check", params={"password": "test"})

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_response_has_note_field(self, client):
        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("api.main.httpx.AsyncClient", return_value=mock_client):
            resp = await client.get("/breach-check", params={"password": "test"})

        assert "note" in resp.json()


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:

    @pytest.mark.asyncio
    async def test_returns_200(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_status_is_ok(self, client):
        resp = await client.get("/health")
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_has_timestamp(self, client):
        resp = await client.get("/health")
        assert "timestamp" in resp.json()

    @pytest.mark.asyncio
    async def test_has_version(self, client):
        resp = await client.get("/health")
        assert "version" in resp.json()


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

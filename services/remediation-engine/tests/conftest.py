import os

import pytest

# Captured before the autouse fixture removes it, for the opt-in live test only.
LIVE_GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")


@pytest.fixture(autouse=True)
def _no_live_gemini(monkeypatch):
    """Tests never call the real Gemini API; they inject recorded responses through httpx.MockTransport.
    The opt-in live test reads LIVE_GEMINI_KEY explicitly."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("app.llm.gemini_adapter.RETRY_DELAY_S", 0, raising=False)

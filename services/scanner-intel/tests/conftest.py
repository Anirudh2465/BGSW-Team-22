import pytest


@pytest.fixture(autouse=True)
def _no_live_registry(monkeypatch):
    """Tests never call the real npm / PyPI / Maven Central; tests that need registry data inject
    a RegistryClient with an httpx.MockTransport serving recorded responses."""
    monkeypatch.setenv("DETECTOR_REGISTRY_OFFLINE", "true")

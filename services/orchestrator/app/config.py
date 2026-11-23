import os

class OrchestratorConfig:
    POSTGRES_URL: str = os.getenv("POSTGRES_URL", "postgresql://guardian:guardian_dev@postgres:5432/guardian")
    LAUNCHER_URL: str = os.getenv("LAUNCHER_URL", "http://launcher:8001")
    SCANNER_INTEL_URL: str = os.getenv("SCANNER_INTEL_URL", "http://scanner-intel:8002")
    REMEDIATION_ENGINE_URL: str = os.getenv("REMEDIATION_ENGINE_URL", "http://remediation-engine:8003")
    RECURSION_LIMIT: int = int(os.getenv("RECURSION_LIMIT", "60"))
    AUDIT_ED25519_PRIVATE_KEY_HEX: str = os.getenv(
        "AUDIT_ED25519_PRIVATE_KEY_HEX",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    )

config = OrchestratorConfig()

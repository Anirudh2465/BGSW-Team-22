import os


class OrchestratorConfig:
    POSTGRES_URL: str = os.getenv("POSTGRES_URL", "postgresql://guardian:guardian_dev@postgres:5432/guardian")
    # "postgres" in docker compose; "memory" for local dev and unit tests
    ARTIFACT_BACKEND: str = os.getenv("ARTIFACT_BACKEND", "memory")
    LAUNCHER_URL: str = os.getenv("LAUNCHER_URL", "http://launcher:8001")
    SCANNER_INTEL_URL: str = os.getenv("SCANNER_INTEL_URL", "http://scanner-intel:8002")
    REMEDIATION_ENGINE_URL: str = os.getenv("REMEDIATION_ENGINE_URL", "http://remediation-engine:8003")
    # Shared secret for service-to-service calls (launcher stages, internal artifact API)
    INTERNAL_API_TOKEN: str = os.getenv("INTERNAL_API_TOKEN", "")
    RECURSION_LIMIT: int = int(os.getenv("RECURSION_LIMIT", "60"))
    # Per-stage HTTP timeouts (seconds); sandboxes enforce their own limits underneath
    STAGE_TIMEOUTS = {
        "clone": float(os.getenv("STAGE1_HTTP_TIMEOUT_S", "420")),
        "resolve": float(os.getenv("STAGE2_HTTP_TIMEOUT_S", "1500")),
        "scan": float(os.getenv("STAGE3_HTTP_TIMEOUT_S", "1100")),
        "verify": float(os.getenv("STAGE4_HTTP_TIMEOUT_S", "1500")),
    }
    ANALYSIS_TIMEOUT_S: float = float(os.getenv("ANALYSIS_HTTP_TIMEOUT_S", "300"))
    # Optional Neo4j graph export (docker compose --profile neo4j); empty URI disables it
    NEO4J_URI: str = os.getenv("NEO4J_URI", "")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")
    NEO4J_BROWSER_URL: str = os.getenv("NEO4J_BROWSER_URL", "http://localhost:7474")
    AUDIT_ED25519_PRIVATE_KEY_HEX: str = os.getenv(
        "AUDIT_ED25519_PRIVATE_KEY_HEX",
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    )


config = OrchestratorConfig()

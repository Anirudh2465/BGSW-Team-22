import hashlib
import json
from typing import List, Dict, Any

class SinkholeLogger:
    """Observes and captures unauthorized network outbound attempts during Stage 2 install hooks."""

    def __init__(self):
        self.sinkhole_events: List[Dict[str, Any]] = []

    def log_egress_attempt(self, domain: str, port: int, payload_snippet: str = "") -> None:
        event = {
            "domain": domain,
            "port": port,
            "snippet": payload_snippet[:256],
            "severity": "CRITICAL"
        }
        self.sinkhole_events.append(event)

    def export_evidence_artifact(self) -> tuple[str, str]:
        """Returns JSON serialized string and its SHA-256 hash."""
        raw_json = json.dumps(self.sinkhole_events, sort_keys=True)
        sha256_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        return raw_json, sha256_hash

    def has_anomalies(self) -> bool:
        return len(self.sinkhole_events) > 0

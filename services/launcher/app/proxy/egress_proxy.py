import time
import logging
from typing import List, Dict, Any
from ..allowlist import is_domain_allowed

logger = logging.getLogger("launcher.egress_proxy")

class EgressProxy:
    """Forward proxy enforcing strict allowlist of external package registries & git hosts."""

    def __init__(self, port: int = 8080):
        self.port = port
        self.access_logs: List[Dict[str, Any]] = []

    def check_request(self, target_host: str, method: str = "GET", path: str = "/") -> bool:
        allowed = is_domain_allowed(target_host)
        record = {
            "target_host": target_host,
            "method": method,
            "path": path,
            "allowed": allowed,
            "timestamp": time.time()
        }
        self.access_logs.append(record)
        if not allowed:
            logger.warning(f"Blocked unauthorized egress to: {target_host}")
        return allowed

    def get_logs(self) -> List[Dict[str, Any]]:
        return list(self.access_logs)

    def clear_logs(self):
        self.access_logs.clear()

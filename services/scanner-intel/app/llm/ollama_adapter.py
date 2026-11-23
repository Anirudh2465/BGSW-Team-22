import os
import re
import json
import logging
import httpx
from typing import Dict, Any, List, Optional

logger = logging.getLogger("scanner_intel.ollama_adapter")

PURL_REGEX = re.compile(r"^pkg:[a-zA-Z0-9.\-_]+/[a-zA-Z0-9.\-_/]+(@[a-zA-Z0-9.\-_]+)?(\?.*)?$")

class OllamaAdapter:
    """Interacts with local Qwen2.5-Coder-7B with schema-locked JSON and rule-only fallback."""

    def __init__(self):
        self.enabled = os.getenv("ENABLE_OLLAMA", "false").lower() in ("true", "1")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://ollama:11434")
        self.model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    def query_schema_locked_purls(self, raw_input_names: List[str]) -> List[str]:
        """Returns regex-validated purls only. Invariant 4: No free text allowed."""
        if not self.enabled:
            return self._rule_fallback_purls(raw_input_names)

        prompt = (
            "Given the following package names, return a JSON object with a 'purls' array of standard package URLs. "
            "Output strictly valid JSON and nothing else.\n"
            f"Packages: {json.dumps(raw_input_names)}"
        )

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(f"{self.ollama_url}/api/generate", json={
                    "model": self.model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False
                })
                if res.status_code == 200:
                    data = res.json()
                    parsed = json.loads(data.get("response", "{}"))
                    candidate_purls = parsed.get("purls", [])
                    # Invariant 4: Enforce strict regex validation
                    return [p for p in candidate_purls if isinstance(p, str) and PURL_REGEX.match(p)]
        except Exception as e:
            logger.warning(f"Ollama call failed, falling back to rule-only mode: {e}")

        return self._rule_fallback_purls(raw_input_names)

    def _rule_fallback_purls(self, package_names: List[str]) -> List[str]:
        """Deterministic rule-only purl synthesis."""
        result = []
        for name in package_names:
            clean = name.strip().lower()
            if clean.startswith("log4j"):
                result.append(f"pkg:maven/org.apache.logging.log4j/{clean}@2.14.1")
            elif clean:
                result.append(f"pkg:generic/{clean}@1.0.0")
        return result

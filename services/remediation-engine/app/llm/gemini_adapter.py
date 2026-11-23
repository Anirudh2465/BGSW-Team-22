import os
import hashlib
import json
import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("remediation_engine.gemini_adapter")

class GeminiAdapter:
    """Batched, input-hash-cached Gemini client operating strictly on IDs & JSON (Invariant 4)."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self.cache: Dict[str, int] = {}

    def pick_best_remediation(self, finding_id: str, purl: str, candidates: List[str]) -> int:
        """
        Invariant 4: Gemini receives ONLY validated metadata and candidates.
        NEVER passes raw repo text.
        Returns the chosen index in candidates.
        """
        if not candidates:
            return 0

        # Input-hash based deterministic cache
        cache_key = hashlib.sha256(f"{finding_id}:{purl}:{','.join(candidates)}".encode("utf-8")).hexdigest()
        if cache_key in self.cache:
            return self.cache[cache_key]

        # If no API key or test environment, use deterministic rule selection (highest patch version)
        if not self.api_key or self.api_key.startswith("your_"):
            chosen_idx = len(candidates) - 1
            self.cache[cache_key] = chosen_idx
            return chosen_idx

        # Batched Gemini API call with temperature=0
        prompt = (
            "You are a secure dependency resolution agent. Given a vulnerable purl and a list of candidate purls, "
            "select the index of the safest, non-breaking version that addresses the vulnerability.\n"
            f"Vulnerable PURL: {purl}\n"
            f"Candidates: {json.dumps(candidates)}\n"
            "Return JSON with key 'chosen_index' (integer) only."
        )

        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.0, "response_mime_type": "application/json"}
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    parsed = json.loads(text)
                    chosen_idx = int(parsed.get("chosen_index", len(candidates) - 1))
                    if 0 <= chosen_idx < len(candidates):
                        self.cache[cache_key] = chosen_idx
                        return chosen_idx
        except Exception as e:
            logger.warning(f"Gemini API request failed, falling back to rule selection: {e}")

        chosen_idx = len(candidates) - 1
        self.cache[cache_key] = chosen_idx
        return chosen_idx

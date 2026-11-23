import re
from typing import List, Dict, Any, Literal

class StaticReachabilityScanner:
    """Performs static code inspection to classify vulnerability reachability into Tiers 1, 2, or 3."""

    def evaluate_reachability(self, component_name: str, codebase_files: Dict[str, str]) -> Literal[1, 2, 3]:
        """
        Tier 1: Confirmed call path / direct invocation
        Tier 2: Import statement / AST match
        Tier 3: String match / ripgrep reference
        """
        import_pattern = rf"(import\s+.*{re.escape(component_name)}|from\s+.*{re.escape(component_name)}|require\(['\"].*{re.escape(component_name)})"
        call_pattern = rf"{re.escape(component_name)}\.[\w_]+\("

        tier_found = 3
        has_import = False
        has_call = False

        for path, content in codebase_files.items():
            if re.search(import_pattern, content):
                has_import = True
            if re.search(call_pattern, content):
                has_call = True

        if has_import and has_call:
            return 1
        elif has_import:
            return 2
        return 3

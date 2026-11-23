"""Glue between the assessment and the artifact store (used by POST /assess and the detector).

Inputs and outputs move by SHA-256 only: the SBOM is read from the artifact store, and the raw
tool outputs, the enrichment and both reports are written back. Tool outputs are stored with the
exact bytes the report hashed, so ``Evidence.artifact_sha256`` always resolves.
"""

import os
import tempfile
from pathlib import Path
from typing import Callable, Dict, Tuple

from .. import artifact_client as artifacts
from .assess import AssessmentResult, assess_sbom
from .enrich import Feeds
from .scanners import ToolRun, run_all

JSON = "application/json"
MARKDOWN = "text/markdown"

# Overridable for tests (recorded tool output, mocked feeds).
run_tools: Callable[[Path], Dict[str, ToolRun]] = run_all
make_feeds: Callable[[], Feeds] = lambda: Feeds(offline=os.getenv("VULN_FEEDS_OFFLINE", "false").lower() in ("1", "true"))


class SbomNotFound(LookupError):
    """The SBOM artifact could not be read (missing, unreachable or failed hash verification)."""


def assess_artifact(run_id: str, sbom_sha256: str, stage: str = "detect") -> Tuple[AssessmentResult, Dict[str, object]]:
    try:
        sbom = artifacts.artifact_client.get(sbom_sha256)  # hash-verified
    except artifacts.ArtifactError as exc:
        raise SbomNotFound(str(exc)) from exc
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sbom.cdx.json"
        path.write_bytes(sbom)
        runs = run_tools(path)
    result = assess_sbom(sbom, runs, make_feeds())

    refs: Dict[str, object] = {"sbom": sbom_sha256, "raw": {}}
    for tool, raw in sorted(result.raw_outputs.items()):
        refs["raw"][tool] = artifacts.artifact_client.put(run_id, stage, JSON, raw)
    refs["enrichment"] = artifacts.artifact_client.put(run_id, stage, JSON, result.enrichment_json)
    refs["report"] = artifacts.artifact_client.put(run_id, stage, JSON, result.report_json)
    refs["report_md"] = artifacts.artifact_client.put(run_id, stage, MARKDOWN, result.report_md.encode("utf-8"))
    assert refs["enrichment"] == result.report["enrichment_sha256"]
    return result, refs

"""Command line: assess one CycloneDX SBOM.

    python -m app.vuln.cli assess path/to/sbom.cdx.json --out report.json --md report.md

By default Grype and OSV-Scanner run from PATH. ``--grype-json`` / ``--osv-json`` use recorded tool
output instead (marked "recorded" in the report). ``--offline-feeds`` skips EPSS/KEV downloads
(values become "unknown" unless the 24-hour cache has them).
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

from .assess import assess_sbom
from .enrich import Feeds
from .scanners import TOOLS, ToolRun, load_recorded, run_grype, run_osv


def _recorded(tool: str, path: str, meta_path: str = None) -> ToolRun:
    meta = json.loads(Path(meta_path).read_text(encoding="utf-8")) if meta_path else None
    return load_recorded(tool, Path(path).read_bytes(), meta)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.vuln.cli", description="Deterministic SBOM vulnerability assessment")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess", help="assess one CycloneDX JSON SBOM")
    a.add_argument("sbom")
    a.add_argument("--out", help="write report.json here")
    a.add_argument("--md", help="write report.md here")
    a.add_argument("--findings", help="write contract Finding objects (JSON list) here")
    a.add_argument("--grype-json", help="use recorded Grype JSON instead of running grype")
    a.add_argument("--grype-meta", help="tool/DB metadata for the recorded Grype JSON")
    a.add_argument("--osv-json", help="use recorded OSV-Scanner JSON instead of running osv-scanner")
    a.add_argument("--osv-meta", help="tool/DB metadata for the recorded OSV-Scanner JSON")
    a.add_argument("--tools", default=",".join(TOOLS), help="comma list of tools to run (default: both)")
    a.add_argument("--offline-feeds", action="store_true", help="do not download EPSS/KEV")
    a.add_argument("--cache-dir", help="feed cache directory (default ~/.cache/guardian-vuln)")
    a.add_argument("--limit", type=int, default=0, help="rows to print (0 = all)")
    args = ap.parse_args(argv)

    sbom_path = Path(args.sbom)
    try:
        sbom_bytes = sbom_path.read_bytes()
    except OSError as exc:
        print(f"cannot read SBOM: {exc}", file=sys.stderr)
        return 2

    enabled = {t.strip() for t in args.tools.split(",") if t.strip()}
    runs: Dict[str, ToolRun] = {}
    for tool in TOOLS:
        recorded = args.grype_json if tool == "grype" else args.osv_json
        meta = args.grype_meta if tool == "grype" else args.osv_meta
        if tool not in enabled:
            runs[tool] = ToolRun(tool, "not_run", error="disabled with --tools")
        elif recorded:
            runs[tool] = _recorded(tool, recorded, meta)
        else:
            runs[tool] = run_grype(sbom_path) if tool == "grype" else run_osv(sbom_path)

    try:
        result = assess_sbom(sbom_bytes, runs, Feeds(cache_dir=args.cache_dir, offline=args.offline_feeds))
    except ValueError as exc:
        print(f"assessment failed: {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_bytes(result.report_json)
    if args.md:
        Path(args.md).write_text(result.report_md, encoding="utf-8")
    if args.findings:
        Path(args.findings).write_text(json.dumps([f.model_dump() for f in result.findings], indent=2) + "\n", encoding="utf-8")
    from .report import to_table
    print(to_table(result.report, args.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())

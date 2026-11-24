"""Refresh the popular-package snapshots used by the typosquat and slopsquat detectors.

The detectors never download anything at run time: they read the snapshot files in
``app/detectors/data/``. Run this script by hand (it needs internet) and commit the result:

    python services/scanner-intel/scripts/update_top_packages.py
    # or, if Python's HTTP client cannot reach the sites, download with curl and pass the files:
    curl -L -o pypi.json https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json
    curl -L -o top.js https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js
    python services/scanner-intel/scripts/update_top_packages.py pypi.json top.js

Sources (both public, no account needed):
- PyPI: hugovk/top-pypi-packages (monthly download counts from the public BigQuery dataset)
- npm:  wooorm/npm-high-impact (packages with the most downloads or dependents)
Maven has no public popularity list; ``top_maven.txt`` is curated by hand.
"""

import datetime
import json
import re
import sys
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "app" / "detectors" / "data"
LIMIT = 15000  # all names count as "known legitimate"; the first TARGET_TOP_N are typosquat targets
PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
NPM_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-top-packages/1.0"})
    with urllib.request.urlopen(req, timeout=60) as res:
        return res.read()


def write(name: str, source: str, names) -> None:
    today = datetime.date.today().isoformat()
    unique = list(dict.fromkeys(n.strip() for n in names if n and n.strip()))[:LIMIT]
    header = f"# source: {source}\n# fetched: {today}\n# count: {len(unique)}\n"
    (DATA / name).write_text(header + "\n".join(unique) + "\n", encoding="utf-8")
    print(f"{name}: {len(unique)} names")


def main(argv) -> int:
    """Optional arguments: already-downloaded copies (``<pypi.json> <top.js>``), e.g. fetched with curl."""
    DATA.mkdir(parents=True, exist_ok=True)
    pypi_raw = Path(argv[0]).read_bytes() if len(argv) > 0 else fetch(PYPI_URL)
    npm_raw = Path(argv[1]).read_bytes() if len(argv) > 1 else fetch(NPM_URL)
    pypi = json.loads(pypi_raw)
    write("top_pypi.txt", PYPI_URL, (row["project"] for row in pypi["rows"]))
    npm = npm_raw.decode("utf-8")
    write("top_npm.txt", NPM_URL, re.findall(r"^\s*'([^']+)',?\s*$", npm, re.M))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

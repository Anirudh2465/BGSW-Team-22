#!/bin/sh
# Bake the vulnerability databases into the image (build time only; runs never download).
set -eu
mkdir -p "$GRYPE_DB_CACHE_DIR" "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
GRYPE_DB_AUTO_UPDATE=true grype db update
grype db status -o json > /opt/vulndb/grype-db.json
# Exit code 1 means "vulnerabilities found" (the seed SBOM is vulnerable on purpose).
rc=0
osv-scanner scan source -L /opt/vulndb/seed.cdx.json --offline-vulnerabilities --download-offline-databases \
  --format json > /dev/null || rc=$?
[ "$rc" -le 1 ] || { echo "osv-scanner database download failed ($rc)"; exit 1; }
python3 - <<'PY'
import json, os, pathlib, datetime
root = pathlib.Path(os.environ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"]) / "osv-scalibr"
zips = sorted(root.glob("*/all.zip"))
if not zips:
    raise SystemExit("no OSV offline databases were downloaded")
when = max(z.stat().st_mtime for z in zips)
manifest = {"mode": "offline", "ecosystems": [z.parent.name for z in zips],
            "downloaded": datetime.datetime.fromtimestamp(when, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bytes": sum(z.stat().st_size for z in zips)}
pathlib.Path("/opt/vulndb/osv-db.json").write_text(json.dumps(manifest, sort_keys=True))
print("osv offline databases:", manifest)
PY

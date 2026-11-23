# Pinned, open-source vulnerability scanners (Apache-2.0). Bump versions deliberately.
FROM anchore/grype:v0.121.1 AS grype
FROM ghcr.io/google/osv-scanner:v2.7.0 AS osv

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

COPY --from=grype /grype /usr/local/bin/grype
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner

# Reproducible scans: databases are baked in at build time and never auto-updated at run time.
# The report records each tool's version and database date. Rebuild the image to refresh them.
ENV GRYPE_DB_CACHE_DIR=/opt/vulndb/grype \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_VALIDATE_AGE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/opt/vulndb/osv \
    OSV_DB_MANIFEST=/opt/vulndb/osv-db.json \
    VULN_FEED_CACHE=/var/cache/guardian-vuln
COPY services/scanner-intel/vulndb/seed.cdx.json services/scanner-intel/vulndb/bake.sh /opt/vulndb/
RUN sh /opt/vulndb/bake.sh

COPY packages/contracts /app/packages/contracts
RUN pip install --no-cache-dir -e /app/packages/contracts

COPY services/scanner-intel /app/services/scanner-intel
RUN pip install --no-cache-dir -e /app/services/scanner-intel

ENV PYTHONPATH="/app"
EXPOSE 8002

CMD ["uvicorn", "services.scanner-intel.app.main:app", "--host", "0.0.0.0", "--port", "8002"]

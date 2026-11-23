# Stage 3 sandbox: offline scanners. Always runs with --network=none.
# Tool versions are pinned; bump them deliberately.
FROM anchore/syft:v1.18.1 AS syft
FROM aquasec/trivy:0.58.1 AS trivy
FROM trufflesecurity/trufflehog:3.88.0 AS trufflehog

FROM node:20-alpine3.20
RUN apk add --no-cache ca-certificates tar git \
 && npm install -g --omit=dev @cyclonedx/cdxgen@11.0.0 \
 && npm cache clean --force \
 && adduser -D -u 10001 guardian
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
USER 10001
WORKDIR /workspace

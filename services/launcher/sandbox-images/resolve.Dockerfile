# Stage 2 sandbox: package managers for resolution. Install hooks also run here,
# with the sinkhole proxy as the only network exit. curl/wget are present so that
# hook scripts that use them are observed rather than failing silently.
# Syft and Cosign read base images from their registries (through the egress proxy) for the
# image scan; layers are parsed as data, nothing inside an image is executed.
# Tool versions are pinned; bump them deliberately (syft matches the scan image).
FROM anchore/syft:v1.18.1 AS syft
FROM gcr.io/projectsigstore/cosign:v2.4.1 AS cosign

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tar git curl \
        nodejs npm \
        openjdk17-jdk maven \
        python3 py3-pip \
 && adduser -D -u 10001 guardian
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
USER 10001
WORKDIR /workspace

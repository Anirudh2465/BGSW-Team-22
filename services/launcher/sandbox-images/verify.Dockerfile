# Stage 4 sandbox: apply a remediation patch to a clean copy of the source, build, test, re-resolve and
# produce a post-patch SBOM. Network only through the launcher's allowlist proxy (registries).
# Tool versions are pinned; bump them deliberately (syft matches the scan image; Maven, JDK, Node and
# Python come from the pinned Alpine release, the same as the resolve image).
FROM anchore/syft:v1.18.1 AS syft

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tar patch git \
        nodejs npm \
        openjdk17-jdk maven \
        python3 py3-pip \
 && adduser -D -u 10001 guardian
COPY --from=syft /syft /usr/local/bin/syft
ENV SYFT_CHECK_FOR_APP_UPDATE=false
USER 10001
WORKDIR /workspace

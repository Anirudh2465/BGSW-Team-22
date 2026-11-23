# Stage 1 sandbox: git only. Runs with an internal network whose only peer is the
# launcher's allowlist proxy.
FROM alpine:3.20
RUN apk add --no-cache git ca-certificates tar \
 && adduser -D -u 10001 guardian
USER 10001
WORKDIR /workspace

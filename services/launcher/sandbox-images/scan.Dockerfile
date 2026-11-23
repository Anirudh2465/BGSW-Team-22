FROM alpine:3.19
RUN apk add --no-cache ca-certificates
# Invariant: scan image runs with --network=none
WORKDIR /workspace

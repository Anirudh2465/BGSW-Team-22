# Stage 4 sandbox: build and test a patched worktree.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tar patch git nodejs npm openjdk17-jdk maven python3 py3-pip \
 && adduser -D -u 10001 guardian
USER 10001
WORKDIR /workspace

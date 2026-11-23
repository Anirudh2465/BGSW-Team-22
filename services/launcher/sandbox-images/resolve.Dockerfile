# Stage 2 sandbox: package managers for resolution. Install hooks also run here,
# with the sinkhole proxy as the only network exit. curl/wget are present so that
# hook scripts that use them are observed rather than failing silently.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tar git curl \
        nodejs npm \
        openjdk17-jdk maven \
        python3 py3-pip \
 && adduser -D -u 10001 guardian
USER 10001
WORKDIR /workspace

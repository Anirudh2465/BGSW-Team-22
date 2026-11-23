FROM alpine:3.19
RUN apk add --no-cache git ca-certificates
WORKDIR /workspace
ENTRYPOINT ["git"]

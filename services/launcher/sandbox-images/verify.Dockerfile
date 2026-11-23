FROM alpine:3.19
RUN apk add --no-cache patch git nodejs npm openjdk17 maven python3 py3-pip
WORKDIR /workspace

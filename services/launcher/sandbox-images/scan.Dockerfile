# Stage 3 sandbox: offline scanners. Always runs with --network=none.
# Tool versions are pinned; bump them deliberately.
FROM anchore/syft:v1.18.1 AS syft
FROM aquasec/trivy:0.58.1 AS trivy
FROM trufflesecurity/trufflehog:3.88.0 AS trufflehog

# Class-graph extractor: JavaParser (hash-pinned) + a small AST-facts emitter.
# Only the image build fetches the jar; the scan itself never has a network.
FROM eclipse-temurin:17-jdk-alpine AS classgraph
ARG JAVAPARSER_VERSION=3.26.2
ARG JAVAPARSER_SHA256=3e3e0c65d57d12797dbead3df1ebb28e7583737d0cd1f2a898dba6febd50ab88
WORKDIR /build
RUN wget -q -O javaparser-core.jar \
      "https://repo1.maven.org/maven2/com/github/javaparser/javaparser-core/${JAVAPARSER_VERSION}/javaparser-core-${JAVAPARSER_VERSION}.jar" \
 && echo "${JAVAPARSER_SHA256}  javaparser-core.jar" | sha256sum -c -
COPY javaparser/ClassGraphExtractor.java .
RUN javac --release 17 -cp javaparser-core.jar -d classes ClassGraphExtractor.java \
 && jar --create --file class-graph.jar -C classes .

FROM node:20-alpine3.20
RUN apk add --no-cache ca-certificates tar git openjdk17-jre-headless \
 && npm install -g --omit=dev @cyclonedx/cdxgen@11.0.0 \
 && npm cache clean --force \
 && adduser -D -u 10001 guardian
COPY --from=syft /syft /usr/local/bin/syft
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=classgraph /build/javaparser-core.jar /build/class-graph.jar /opt/guardian/
RUN printf '#!/bin/sh\nexec java -Xss8m -Xmx1g -XX:-UsePerfData -XX:TieredStopAtLevel=1 -cp /opt/guardian/javaparser-core.jar:/opt/guardian/class-graph.jar ClassGraphExtractor "$@"\n' \
      > /usr/local/bin/javaparser \
 && chmod 0755 /usr/local/bin/javaparser
USER 10001
WORKDIR /workspace

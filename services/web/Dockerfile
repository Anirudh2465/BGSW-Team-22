# Built from the repository root (docker-compose: context ".").
FROM node:20-alpine AS builder
WORKDIR /app

COPY services/web/package*.json ./
RUN npm install --no-audit --no-fund

COPY services/web/ ./
# Browser-side URLs are inlined at build time.
ARG NEXT_PUBLIC_ORCHESTRATOR_URL=http://localhost:8000
ARG NEXT_PUBLIC_ORCHESTRATOR_WS_URL=ws://localhost:8000
ENV NEXT_PUBLIC_ORCHESTRATOR_URL=$NEXT_PUBLIC_ORCHESTRATOR_URL \
    NEXT_PUBLIC_ORCHESTRATOR_WS_URL=$NEXT_PUBLIC_ORCHESTRATOR_WS_URL \
    NEXT_TELEMETRY_DISABLED=1
# Fail the image build if the app does not compile.
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN adduser -D -u 10001 web
COPY --from=builder --chown=web /app/.next/standalone ./
COPY --from=builder --chown=web /app/.next/static ./.next/static
USER web

EXPOSE 3000
CMD ["node", "server.js"]

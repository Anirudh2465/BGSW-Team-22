FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY packages/contracts /app/packages/contracts
RUN pip install --no-cache-dir -e /app/packages/contracts

COPY services/remediation-engine /app/services/remediation-engine
RUN pip install --no-cache-dir -e /app/services/remediation-engine

ENV PYTHONPATH="/app"
EXPOSE 8003

CMD ["uvicorn", "services.remediation-engine.app.main:app", "--host", "0.0.0.0", "--port", "8003"]

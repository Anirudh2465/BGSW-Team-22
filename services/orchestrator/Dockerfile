FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY packages/contracts /app/packages/contracts
RUN pip install --no-cache-dir -e /app/packages/contracts

COPY services/orchestrator /app/services/orchestrator
RUN pip install --no-cache-dir -e /app/services/orchestrator

ENV PYTHONPATH="/app"
EXPOSE 8000

CMD ["uvicorn", "services.orchestrator.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

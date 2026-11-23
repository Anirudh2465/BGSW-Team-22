FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ripgrep \
    && rm -rf /var/lib/apt/lists/*

COPY packages/contracts /app/packages/contracts
RUN pip install --no-cache-dir -e /app/packages/contracts

COPY services/scanner-intel /app/services/scanner-intel
RUN pip install --no-cache-dir -e /app/services/scanner-intel

ENV PYTHONPATH="/app"
EXPOSE 8002

CMD ["uvicorn", "services.scanner-intel.app.main:app", "--host", "0.0.0.0", "--port", "8002"]

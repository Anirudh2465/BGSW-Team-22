FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY packages/contracts /app/packages/contracts
RUN pip install --no-cache-dir -e /app/packages/contracts

COPY services/launcher /app/services/launcher
RUN pip install --no-cache-dir -e /app/services/launcher

ENV PYTHONPATH="/app"
EXPOSE 8001

CMD ["uvicorn", "services.launcher.app.main:app", "--host", "0.0.0.0", "--port", "8001"]

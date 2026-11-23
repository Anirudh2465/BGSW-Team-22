import logging
from typing import Optional

logger = logging.getLogger("orchestrator.db.session")

class DatabaseSessionManager:
    """Manages database connection pool and schema lifecycle."""

    def __init__(self, postgres_url: str):
        self.postgres_url = postgres_url
        self.connected = False

    async def connect(self):
        logger.info(f"Connecting to Postgres at {self.postgres_url.split('@')[-1]}")
        self.connected = True

    async def disconnect(self):
        self.connected = False

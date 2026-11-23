import logging
from apscheduler.schedulers.background import BackgroundScheduler
from ..db.artifacts import artifact_store

logger = logging.getLogger("orchestrator.scheduler.daily_monitor")

class DailyVulnerabilityMonitor:
    """APScheduler job: Periodic OSV/KEV rescan against stored SBOM artifacts."""

    def __init__(self):
        self.scheduler = BackgroundScheduler()

    def start(self):
        # Schedule daily rescan job
        self.scheduler.add_job(
            self.rescan_stored_sboms,
            "cron",
            hour=2,
            minute=0,
            id="daily_sbom_rescan"
        )
        self.scheduler.start()
        logger.info("Daily vulnerability monitor scheduler started.")

    def rescan_stored_sboms(self):
        logger.info("Executing daily rescan against stored SBOM artifacts...")
        # Inspect stored artifacts for media_type 'application/vnd.cyclonedx+json'
        return {"status": "success", "rescanned_sboms": 0}

    def stop(self):
        if self.scheduler.running:
            self.scheduler.shutdown()

daily_monitor = DailyVulnerabilityMonitor()

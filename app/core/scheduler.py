"""
Background sync scheduler for the Wazuh-TI platform.

Uses APScheduler's BackgroundScheduler to run threat feed synchronization
at configurable intervals. Supports:
- Starting/stopping the scheduler
- Updating the sync interval at runtime
- Triggering an immediate sync run
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from app.utils.logger import get_logger

logger = get_logger(__name__)

JOB_ID = "wazuh_ti_sync"


class SyncScheduler:
    """
    Background scheduler for periodic threat feed synchronization.

    Args:
        sync_function: Callable to execute on each sync interval.
                       This should be the full pipeline function.
        interval_minutes: Minutes between sync runs (default: 60).
    """

    def __init__(self, sync_function: callable, interval_minutes: int = 60):
        self.sync_function = sync_function
        self.interval_minutes = interval_minutes
        self._scheduler = BackgroundScheduler(daemon=True)
        self._running = False

    @property
    def is_running(self) -> bool:
        """Return whether the scheduler is currently active."""
        return self._running

    def start(self) -> None:
        """Start the background scheduler with the configured interval."""
        if self._running:
            logger.warning("Scheduler is already running")
            return

        self._scheduler.add_job(
            self.sync_function,
            trigger=IntervalTrigger(minutes=self.interval_minutes),
            id=JOB_ID,
            name="Wazuh-TI Feed Sync",
            replace_existing=True,
        )
        self._scheduler.start()
        self._running = True
        logger.info(
            f"Scheduler started — syncing every {self.interval_minutes} minutes"
        )

    def stop(self) -> None:
        """Stop the background scheduler."""
        if not self._running:
            return

        self._scheduler.shutdown(wait=False)
        self._running = False
        logger.info("Scheduler stopped")

    def update_interval(self, new_interval_minutes: int) -> None:
        """
        Update the sync interval for the running scheduler.

        Args:
            new_interval_minutes: New interval in minutes.
        """
        self.interval_minutes = new_interval_minutes

        if self._running:
            self._scheduler.reschedule_job(
                JOB_ID,
                trigger=IntervalTrigger(minutes=new_interval_minutes),
            )
            logger.info(f"Scheduler interval updated to {new_interval_minutes} minutes")

    def trigger_now(self) -> None:
        """
        Trigger an immediate sync run in a background thread.
        Does not affect the regular schedule.
        """
        import threading
        thread = threading.Thread(target=self.sync_function, daemon=True)
        thread.start()
        logger.info("Immediate sync triggered in background thread")

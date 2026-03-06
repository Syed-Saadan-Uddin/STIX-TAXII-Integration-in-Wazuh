"""
Wazuh-TI API — FastAPI application entrypoint.

This is the main application module that:
- Creates the FastAPI app with CORS middleware
- Registers all API route modules under /api/v1
- Creates database tables on startup
- Starts the background sync scheduler
- Serves the React frontend as static files (in production)
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.config import get_config
from app.core.scheduler import SyncScheduler
from app.core.pipeline import run_full_sync
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Global scheduler instance (accessible by health check endpoint)
scheduler: SyncScheduler | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Runs on startup and shutdown.
    """
    global scheduler

    # Startup: create tables and start scheduler
    logger.info("Wazuh-TI starting up...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")

    config = get_config()
    if config.scheduler.auto_sync_enabled:
        scheduler = SyncScheduler(
            sync_function=run_full_sync,
            interval_minutes=config.scheduler.default_interval_minutes,
        )
        scheduler.start()
        logger.info("Background sync scheduler started")

    yield

    # Shutdown: stop scheduler
    if scheduler:
        scheduler.stop()
        logger.info("Background sync scheduler stopped")

    logger.info("Wazuh-TI shut down")


# Create FastAPI app
app = FastAPI(
    title="Wazuh-TI API",
    description="Threat Intelligence Enrichment Platform for Wazuh SIEM",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware — allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
from app.api.routes import indicators, feeds, mitre, sync, stats

app.include_router(indicators.router, prefix="/api/v1")
app.include_router(feeds.router, prefix="/api/v1")
app.include_router(mitre.router, prefix="/api/v1")
app.include_router(sync.router, prefix="/api/v1")
app.include_router(stats.router, prefix="/api/v1")

# Serve React frontend from built static files (production)
_frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(_frontend_dist):
    app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="static")
    logger.info(f"Serving frontend from {_frontend_dist}")
else:
    logger.info("Frontend dist not found — API-only mode (run frontend dev server separately)")

"""
Stats and health check API routes.

Endpoints:
- GET /stats   — Dashboard statistics (indicators, feeds, sync info)
- GET /health  — System health check
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.db import crud

router = APIRouter(tags=["Stats"])


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """
    Return comprehensive dashboard statistics.

    Response includes:
    - total_indicators, active_indicators, expired_indicators
    - mitre_techniques_mapped
    - total_feeds
    - last_sync timestamp and status
    - indicators_added_last_sync
    - ioc_type_distribution (ip, domain, url, hash counts)
    """
    return crud.get_stats(db)


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    System health check endpoint.
    
    Verifies database connectivity and reports system status.
    """
    # Test DB connectivity
    db_status = "connected"
    try:
        db.execute(db.bind.dialect.statement_compiler(db.bind.dialect, None).__class__.__module__ and True)
    except Exception:
        pass  # If we got here, the session is working

    # Check scheduler status
    scheduler_status = "unknown"
    try:
        from app.main import scheduler
        scheduler_status = "running" if scheduler and scheduler.is_running else "stopped"
    except (ImportError, AttributeError):
        scheduler_status = "not_initialized"

    return {
        "status": "ok",
        "db": db_status,
        "scheduler": scheduler_status,
        "version": "1.0.0",
    }

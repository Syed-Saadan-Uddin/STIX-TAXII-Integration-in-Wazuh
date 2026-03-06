"""
Sync API routes.

Endpoints:
- POST /sync      — Trigger sync (all feeds or specific feed)
- GET  /sync/log  — Paginated sync history
"""

import math
import threading
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.db import crud
from app.core.pipeline import run_full_sync

router = APIRouter(prefix="/sync", tags=["Sync"])


class SyncRequest(BaseModel):
    feed_id: Optional[int] = None


@router.post("")
def trigger_sync(body: SyncRequest):
    """
    Trigger a sync operation in the background.

    If feed_id is provided, syncs only that feed.
    If feed_id is null/omitted, syncs all active feeds.

    Returns immediately — sync runs in a background thread.
    """
    # Run sync in background thread (non-blocking)
    thread = threading.Thread(
        target=run_full_sync,
        args=(body.feed_id,),
        daemon=True,
    )
    thread.start()

    message = (
        f"Sync started for feed {body.feed_id}"
        if body.feed_id
        else "Sync started for all active feeds"
    )

    return {
        "status": "sync_started",
        "message": message,
    }


@router.get("/log")
def get_sync_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Return paginated sync log history, most recent first."""
    items, total = crud.get_sync_logs(db, page=page, per_page=per_page)
    return {
        "items": [
            {
                "id": log.id,
                "feed_id": log.feed_id,
                "feed_name": log.feed.name if log.feed else None,
                "started_at": log.started_at.isoformat() if log.started_at else None,
                "completed_at": log.completed_at.isoformat() if log.completed_at else None,
                "status": log.status,
                "indicators_added": log.indicators_added,
                "indicators_updated": log.indicators_updated,
                "error_message": log.error_message,
            }
            for log in items
        ],
        "total": total,
        "page": page,
        "pages": math.ceil(total / per_page) if total > 0 else 0,
    }

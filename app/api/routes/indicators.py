"""
Indicator API routes.

Endpoints:
- GET  /indicators          — Paginated list with optional filters
- GET  /indicators/search   — Full-text search on indicator value
- GET  /indicators/{id}     — Single indicator detail with MITRE techniques
"""

import math
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.db import crud

router = APIRouter(prefix="/indicators", tags=["Indicators"])


@router.get("")
def list_indicators(
    type: str = Query(None, description="Filter by IOC type: ip, domain, url, hash"),
    is_active: bool = Query(None, description="Filter by active status"),
    feed_id: int = Query(None, description="Filter by source feed ID"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    db: Session = Depends(get_db),
):
    """Return paginated list of indicators with optional filters."""
    items, total = crud.get_indicators(
        db, type=type, is_active=is_active, feed_id=feed_id,
        page=page, per_page=per_page,
    )
    return {
        "items": [_serialize_indicator(ind) for ind in items],
        "total": total,
        "page": page,
        "pages": math.ceil(total / per_page) if total > 0 else 0,
    }


@router.get("/search")
def search_indicators(
    q: str = Query(..., min_length=1, description="Search query"),
    db: Session = Depends(get_db),
):
    """Full-text search on indicator value field (SQL LIKE)."""
    items = crud.search_indicators(db, q)
    return {
        "items": [_serialize_indicator(ind) for ind in items],
        "total": len(items),
    }


@router.get("/{indicator_id}")
def get_indicator(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    """Return a single indicator by ID, including linked MITRE techniques."""
    indicator = crud.get_indicator_by_id(db, indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    data = _serialize_indicator(indicator)
    # Include MITRE technique IDs
    data["mitre_techniques"] = [
        {
            "technique_id": m.technique.technique_id,
            "name": m.technique.name,
            "tactic": m.technique.tactic,
        }
        for m in indicator.mitre_mappings
    ]
    return data


def _serialize_indicator(ind) -> dict:
    """Convert an Indicator ORM object to a JSON-serializable dict."""
    return {
        "id": ind.id,
        "value": ind.value,
        "type": ind.type,
        "confidence": ind.confidence,
        "source_feed_id": ind.source_feed_id,
        "stix_id": ind.stix_id,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        "expires": ind.expires.isoformat() if ind.expires else None,
        "is_active": ind.is_active,
    }

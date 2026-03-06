"""
Database CRUD operations for the Wazuh-TI platform.

All database operations are centralized here — no raw SQL in routes.
Every function accepts a SQLAlchemy Session as its first argument.

Sections:
- Feeds: CRUD for TAXII feed configurations
- Indicators: paginated queries, search, upsert, expiration
- MITRE: technique upsert, linking, aggregation
- Stats: dashboard statistics
- Sync Log: audit trail for sync operations
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, case, desc
from app.db.models import Feed, Indicator, MitreTechnique, IndicatorMitreMap, SyncLog


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------

def get_all_feeds(db: Session) -> list[Feed]:
    """Return all configured TAXII feeds."""
    return db.query(Feed).order_by(Feed.created_at.desc()).all()


def get_feed_by_id(db: Session, feed_id: int) -> Feed | None:
    """Return a single feed by its primary key, or None."""
    return db.query(Feed).filter(Feed.id == feed_id).first()


def create_feed(db: Session, feed_data: dict) -> Feed:
    """Create a new feed from a dictionary of fields."""
    feed = Feed(**feed_data)
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed


def update_feed(db: Session, feed_id: int, updates: dict) -> Feed | None:
    """
    Update an existing feed with the given key-value pairs.
    Returns the updated feed, or None if not found.
    """
    feed = db.query(Feed).filter(Feed.id == feed_id).first()
    if not feed:
        return None
    for key, value in updates.items():
        if hasattr(feed, key):
            setattr(feed, key, value)
    db.commit()
    db.refresh(feed)
    return feed


def delete_feed(db: Session, feed_id: int) -> bool:
    """Delete a feed by ID. Returns True if deleted, False if not found."""
    feed = db.query(Feed).filter(Feed.id == feed_id).first()
    if not feed:
        return False
    db.delete(feed)
    db.commit()
    return True


def update_last_sync(db: Session, feed_id: int, timestamp: datetime) -> None:
    """Update the last_sync timestamp for a feed."""
    feed = db.query(Feed).filter(Feed.id == feed_id).first()
    if feed:
        feed.last_sync = timestamp
        db.commit()


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

def get_indicators(
    db: Session,
    type: str = None,
    is_active: bool = None,
    feed_id: int = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[Indicator], int]:
    """
    Paginated indicator query with optional filters.
    Returns (list_of_indicators, total_count).
    """
    query = db.query(Indicator)

    if type is not None:
        query = query.filter(Indicator.type == type)
    if is_active is not None:
        query = query.filter(Indicator.is_active == is_active)
    if feed_id is not None:
        query = query.filter(Indicator.source_feed_id == feed_id)

    total = query.count()
    items = (
        query
        .order_by(Indicator.last_seen.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return items, total


def get_indicator_by_id(db: Session, indicator_id: int) -> Indicator | None:
    """Return a single indicator by primary key, or None."""
    return db.query(Indicator).filter(Indicator.id == indicator_id).first()


def search_indicators(db: Session, query_str: str) -> list[Indicator]:
    """Full-text search on the indicator value field (SQL LIKE)."""
    return (
        db.query(Indicator)
        .filter(Indicator.value.ilike(f"%{query_str}%"))
        .order_by(Indicator.last_seen.desc())
        .limit(200)
        .all()
    )


def upsert_indicator(
    db: Session,
    value: str,
    type: str,
    confidence: int | None,
    feed_id: int | None,
    stix_id: str | None,
    expires: datetime | None,
) -> tuple[Indicator, bool]:
    """
    Insert or update an indicator, deduplicated by (value, type).
    Returns (indicator, was_created: bool).
    If the indicator already exists, updates last_seen, confidence, and stix_id.
    """
    existing = (
        db.query(Indicator)
        .filter(Indicator.value == value, Indicator.type == type)
        .first()
    )

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        if confidence is not None:
            existing.confidence = confidence
        if stix_id:
            existing.stix_id = stix_id
        if expires:
            existing.expires = expires
        existing.is_active = True
        db.commit()
        db.refresh(existing)
        return existing, False

    new_indicator = Indicator(
        value=value,
        type=type,
        confidence=confidence,
        source_feed_id=feed_id,
        stix_id=stix_id,
        expires=expires,
    )
    db.add(new_indicator)
    db.commit()
    db.refresh(new_indicator)
    return new_indicator, True


def expire_old_indicators(db: Session) -> int:
    """
    Mark indicators as inactive where expires < now.
    Returns the count of indicators deactivated.
    """
    now = datetime.now(timezone.utc)
    count = (
        db.query(Indicator)
        .filter(Indicator.expires != None, Indicator.expires < now, Indicator.is_active == True)
        .update({Indicator.is_active: False})
    )
    db.commit()
    return count


# ---------------------------------------------------------------------------
# MITRE Techniques
# ---------------------------------------------------------------------------

def get_all_techniques(db: Session) -> list[MitreTechnique]:
    """Return all MITRE ATT&CK techniques."""
    return db.query(MitreTechnique).order_by(MitreTechnique.technique_id).all()


def get_technique_by_id(db: Session, technique_id: str) -> MitreTechnique | None:
    """Return a technique by its T-number ID (e.g. T1059)."""
    return (
        db.query(MitreTechnique)
        .filter(MitreTechnique.technique_id == technique_id)
        .first()
    )


def upsert_technique(
    db: Session,
    technique_id: str,
    name: str | None = None,
    tactic: str | None = None,
    description: str | None = None,
) -> MitreTechnique:
    """Insert or update a MITRE technique by its T-number."""
    existing = (
        db.query(MitreTechnique)
        .filter(MitreTechnique.technique_id == technique_id)
        .first()
    )

    if existing:
        if name:
            existing.name = name
        if tactic:
            existing.tactic = tactic
        if description:
            existing.description = description
        db.commit()
        db.refresh(existing)
        return existing

    technique = MitreTechnique(
        technique_id=technique_id,
        name=name,
        tactic=tactic,
        description=description,
    )
    db.add(technique)
    db.commit()
    db.refresh(technique)
    return technique


def link_indicator_technique(db: Session, indicator_id: int, mitre_id: int) -> None:
    """
    Create a many-to-many link between an indicator and a technique.
    Silently skips if the link already exists.
    """
    existing = (
        db.query(IndicatorMitreMap)
        .filter(
            IndicatorMitreMap.indicator_id == indicator_id,
            IndicatorMitreMap.mitre_id == mitre_id,
        )
        .first()
    )
    if not existing:
        mapping = IndicatorMitreMap(indicator_id=indicator_id, mitre_id=mitre_id)
        db.add(mapping)
        db.commit()


def get_techniques_with_counts(db: Session) -> list[dict]:
    """
    Return all techniques with the count of linked indicators.
    Result: [{technique_id, name, tactic, indicator_count}, ...]
    """
    results = (
        db.query(
            MitreTechnique.technique_id,
            MitreTechnique.name,
            MitreTechnique.tactic,
            MitreTechnique.description,
            func.count(IndicatorMitreMap.indicator_id).label("indicator_count"),
        )
        .outerjoin(IndicatorMitreMap, MitreTechnique.id == IndicatorMitreMap.mitre_id)
        .group_by(MitreTechnique.id)
        .order_by(desc("indicator_count"))
        .all()
    )
    return [
        {
            "technique_id": r.technique_id,
            "name": r.name,
            "tactic": r.tactic,
            "description": r.description,
            "indicator_count": r.indicator_count,
        }
        for r in results
    ]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_stats(db: Session) -> dict:
    """
    Return dashboard statistics summarizing the current state of the platform.
    """
    total = db.query(func.count(Indicator.id)).scalar() or 0
    active = db.query(func.count(Indicator.id)).filter(Indicator.is_active == True).scalar() or 0
    expired = total - active
    mitre_count = db.query(func.count(MitreTechnique.id)).scalar() or 0
    feed_count = db.query(func.count(Feed.id)).scalar() or 0

    # Last sync info
    last_log = (
        db.query(SyncLog)
        .filter(SyncLog.status != "running")
        .order_by(SyncLog.completed_at.desc())
        .first()
    )

    # IOC type distribution
    type_dist = (
        db.query(Indicator.type, func.count(Indicator.id))
        .group_by(Indicator.type)
        .all()
    )
    ioc_type_distribution = {t: c for t, c in type_dist}

    return {
        "total_indicators": total,
        "active_indicators": active,
        "expired_indicators": expired,
        "mitre_techniques_mapped": mitre_count,
        "total_feeds": feed_count,
        "last_sync": last_log.completed_at.isoformat() if last_log and last_log.completed_at else None,
        "last_sync_status": last_log.status if last_log else None,
        "indicators_added_last_sync": last_log.indicators_added if last_log else 0,
        "ioc_type_distribution": ioc_type_distribution,
    }


# ---------------------------------------------------------------------------
# Sync Log
# ---------------------------------------------------------------------------

def create_sync_log(db: Session, feed_id: int | None) -> SyncLog:
    """Create a new sync log entry with status 'running'."""
    log = SyncLog(feed_id=feed_id, status="running")
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def complete_sync_log(
    db: Session,
    log_id: int,
    status: str,
    added: int,
    updated: int,
    error: str | None = None,
) -> None:
    """Mark a sync log entry as complete with final status and counts."""
    log = db.query(SyncLog).filter(SyncLog.id == log_id).first()
    if log:
        log.status = status
        log.completed_at = datetime.now(timezone.utc)
        log.indicators_added = added
        log.indicators_updated = updated
        log.error_message = error
        db.commit()


def get_sync_logs(
    db: Session,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[SyncLog], int]:
    """Paginated sync log query, most recent first."""
    query = db.query(SyncLog).order_by(SyncLog.started_at.desc())
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total

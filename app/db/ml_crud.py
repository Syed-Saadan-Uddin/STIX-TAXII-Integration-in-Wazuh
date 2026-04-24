"""
ML-specific database operations.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, desc
from sqlalchemy.orm import Session, joinedload

from app.db.models import HostAssetProfile, Indicator, ThreatPrediction, WazuhAlert


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso_datetime(value: str | None) -> datetime:
    """Best-effort timestamp parser for Wazuh alert payloads."""
    if not value:
        return _utcnow()

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return _utcnow()

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def upsert_host_profile(db: Session, data: dict) -> HostAssetProfile:
    host_name = (data.get("host_name") or "").strip()
    existing = db.query(HostAssetProfile).filter(HostAssetProfile.host_name == host_name).first()

    if existing:
        for key, value in data.items():
            if hasattr(existing, key):
                setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        return existing

    profile = HostAssetProfile(**data)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


def get_host_profiles(db: Session) -> list[HostAssetProfile]:
    return db.query(HostAssetProfile).order_by(desc(HostAssetProfile.criticality), HostAssetProfile.host_name).all()


def get_host_profile_by_name(db: Session, host_name: str | None) -> HostAssetProfile | None:
    if not host_name:
        return None
    return db.query(HostAssetProfile).filter(HostAssetProfile.host_name == host_name).first()


def get_indicator_matches(db: Session, candidates: list[str]) -> list[Indicator]:
    values = [value for value in {c for c in candidates if c}]
    if not values:
        return []

    return (
        db.query(Indicator)
        .filter(Indicator.is_active == True, Indicator.value.in_(values))
        .all()
    )


def get_alert_history_stats(
    db: Session,
    *,
    source_ip: str | None,
    host_name: str | None,
    rule_id: str | None,
    process_name: str | None,
    reference_time: datetime,
) -> dict:
    """Aggregate rolling counts used for feature engineering."""
    windows = {
        "frequency_1h": reference_time - timedelta(hours=1),
        "frequency_24h": reference_time - timedelta(hours=24),
        "repeat_behavior_7d": reference_time - timedelta(days=7),
    }

    def _count_since(column, value, since: datetime) -> int:
        if not value:
            return 0
        return (
            db.query(func.count(WazuhAlert.id))
            .filter(column == value, WazuhAlert.alert_timestamp >= since)
            .scalar()
            or 0
        )

    return {
        "frequency_1h": _count_since(WazuhAlert.source_ip, source_ip, windows["frequency_1h"]),
        "frequency_24h": _count_since(WazuhAlert.source_ip, source_ip, windows["frequency_24h"]),
        "same_rule_24h": _count_since(WazuhAlert.rule_id, rule_id, windows["frequency_24h"]),
        "same_host_24h": _count_since(WazuhAlert.host_name, host_name, windows["frequency_24h"]),
        "same_process_24h": _count_since(WazuhAlert.process_name, process_name, windows["frequency_24h"]),
        "repeat_behavior_7d": max(
            _count_since(WazuhAlert.source_ip, source_ip, windows["repeat_behavior_7d"]),
            _count_since(WazuhAlert.rule_id, rule_id, windows["repeat_behavior_7d"]),
        ),
    }


def create_alert(db: Session, normalized_alert: dict) -> WazuhAlert:
    host_profile = get_host_profile_by_name(db, normalized_alert.get("host_name"))
    alert = WazuhAlert(
        wazuh_event_id=normalized_alert["wazuh_event_id"],
        alert_timestamp=normalized_alert["alert_timestamp"],
        agent_id=normalized_alert.get("agent_id"),
        host_name=normalized_alert.get("host_name"),
        rule_id=normalized_alert.get("rule_id"),
        rule_level=normalized_alert.get("rule_level", 0),
        rule_description=normalized_alert.get("rule_description"),
        source_ip=normalized_alert.get("source_ip"),
        destination_ip=normalized_alert.get("destination_ip"),
        user_name=normalized_alert.get("user_name"),
        process_name=normalized_alert.get("process_name"),
        mitre_tactic=normalized_alert.get("mitre_tactic"),
        mitre_technique_id=normalized_alert.get("mitre_technique_id"),
        mitre_technique_name=normalized_alert.get("mitre_technique_name"),
        event_category=normalized_alert.get("event_category"),
        raw_payload=json.dumps(normalized_alert.get("raw_payload", {})),
        host_profile_id=host_profile.id if host_profile else None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alert_by_event_id(db: Session, event_id: str) -> WazuhAlert | None:
    return db.query(WazuhAlert).filter(WazuhAlert.wazuh_event_id == event_id).first()


def upsert_prediction(db: Session, alert_id: int, prediction: dict) -> ThreatPrediction:
    record = db.query(ThreatPrediction).filter(ThreatPrediction.alert_id == alert_id).first()

    payload = {
        "model_name": prediction["model_name"],
        "model_version": prediction["model_version"],
        "threat_priority": prediction["threat_priority"],
        "risk_score": prediction["risk_score"],
        "materialization_probability": prediction["materialization_probability"],
        "confidence_score": prediction["confidence_score"],
        "recommended_action": prediction["recommended_action"],
        "predicted_next_attack_stage": prediction["predicted_next_attack_stage"],
        "top_factors": json.dumps(prediction.get("top_factors", [])),
        "feature_snapshot": json.dumps(prediction.get("feature_snapshot", {})),
        "enrichment_summary": json.dumps(prediction.get("enrichment_summary", {})),
    }

    if record:
        for key, value in payload.items():
            setattr(record, key, value)
    else:
        record = ThreatPrediction(alert_id=alert_id, **payload)
        db.add(record)

    db.commit()
    db.refresh(record)
    return record


def list_recent_predictions(
    db: Session,
    *,
    limit: int = 25,
    priority: str | None = None,
) -> list[ThreatPrediction]:
    query = (
        db.query(ThreatPrediction)
        .options(joinedload(ThreatPrediction.alert))
        .join(WazuhAlert)
        .order_by(ThreatPrediction.created_at.desc())
    )
    if priority:
        query = query.filter(ThreatPrediction.threat_priority.ilike(priority))
    return query.limit(limit).all()


def get_prediction_overview(db: Session) -> dict:
    total_alerts = db.query(func.count(WazuhAlert.id)).scalar() or 0
    total_predictions = db.query(func.count(ThreatPrediction.id)).scalar() or 0
    avg_risk = db.query(func.avg(ThreatPrediction.risk_score)).scalar() or 0
    avg_probability = db.query(func.avg(ThreatPrediction.materialization_probability)).scalar() or 0

    priority_rows = (
        db.query(ThreatPrediction.threat_priority, func.count(ThreatPrediction.id))
        .group_by(ThreatPrediction.threat_priority)
        .all()
    )
    action_rows = (
        db.query(ThreatPrediction.recommended_action, func.count(ThreatPrediction.id))
        .group_by(ThreatPrediction.recommended_action)
        .all()
    )
    tactic_rows = (
        db.query(
            func.coalesce(WazuhAlert.mitre_tactic, "Unmapped").label("tactic"),
            func.count(ThreatPrediction.id).label("count"),
        )
        .join(WazuhAlert, ThreatPrediction.alert_id == WazuhAlert.id)
        .group_by("tactic")
        .order_by(desc("count"))
        .all()
    )
    stage_rows = (
        db.query(
            func.coalesce(ThreatPrediction.predicted_next_attack_stage, "Unknown").label("stage"),
            func.count(ThreatPrediction.id).label("count"),
        )
        .group_by("stage")
        .order_by(desc("count"))
        .all()
    )

    critical_count = (
        db.query(func.count(ThreatPrediction.id))
        .filter(ThreatPrediction.threat_priority.in_(["Critical", "High"]))
        .scalar()
        or 0
    )

    latest = (
        db.query(ThreatPrediction)
        .order_by(ThreatPrediction.created_at.desc())
        .first()
    )
    timeline_records = (
        db.query(ThreatPrediction)
        .options(joinedload(ThreatPrediction.alert))
        .join(WazuhAlert, ThreatPrediction.alert_id == WazuhAlert.id)
        .order_by(ThreatPrediction.created_at.desc())
        .limit(24)
        .all()
    )
    timeline = []
    for record in reversed(timeline_records):
        created_at = record.created_at or _utcnow()
        alert = record.alert
        timeline.append(
            {
                "created_at": created_at.isoformat(),
                "time_label": created_at.strftime("%H:%M"),
                "risk_score": record.risk_score,
                "materialization_probability": round(float(record.materialization_probability), 2),
                "confidence_score": round(float(record.confidence_score), 2),
                "priority": record.threat_priority,
                "host_name": alert.host_name if alert else None,
                "source_ip": alert.source_ip if alert else None,
            }
        )

    return {
        "total_alerts": total_alerts,
        "total_predictions": total_predictions,
        "critical_or_high": critical_count,
        "average_risk_score": round(float(avg_risk), 1),
        "average_materialization_probability": round(float(avg_probability), 1),
        "priority_distribution": {name: count for name, count in priority_rows},
        "recommended_actions": {name: count for name, count in action_rows},
        "tactic_distribution": {name: count for name, count in tactic_rows},
        "next_stage_distribution": {name: count for name, count in stage_rows},
        "risk_timeline": timeline,
        "latest_prediction_at": latest.created_at.isoformat() if latest else None,
    }


def get_top_active_threats(db: Session, *, hours: int = 24, limit: int = 5) -> list[dict]:
    since = _utcnow() - timedelta(hours=hours)
    predictions = (
        db.query(ThreatPrediction)
        .options(joinedload(ThreatPrediction.alert))
        .join(WazuhAlert)
        .filter(ThreatPrediction.created_at >= since)
        .order_by(ThreatPrediction.risk_score.desc(), ThreatPrediction.created_at.desc())
        .all()
    )

    grouped: dict[str, dict] = {}
    for item in predictions:
        alert = item.alert
        if alert is None:
            continue

        key = alert.source_ip or alert.mitre_technique_id or alert.host_name or alert.rule_id or f"alert-{alert.id}"
        row = grouped.setdefault(
            key,
            {
                "entity": key,
                "host_name": alert.host_name,
                "source_ip": alert.source_ip,
                "mitre_tactic": alert.mitre_tactic,
                "mitre_technique_id": alert.mitre_technique_id,
                "priority": item.threat_priority,
                "max_risk_score": item.risk_score,
                "max_probability": item.materialization_probability,
                "alert_count": 0,
                "recommended_action": item.recommended_action,
            },
        )
        row["alert_count"] += 1
        row["max_risk_score"] = max(row["max_risk_score"], item.risk_score)
        row["max_probability"] = max(row["max_probability"], item.materialization_probability)

        priorities = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        if priorities.get(item.threat_priority, 0) > priorities.get(row["priority"], 0):
            row["priority"] = item.threat_priority
            row["recommended_action"] = item.recommended_action

    ranked = sorted(
        grouped.values(),
        key=lambda row: (row["max_risk_score"], row["alert_count"], row["max_probability"]),
        reverse=True,
    )
    return ranked[:limit]


def serialize_prediction(record: ThreatPrediction) -> dict:
    alert = record.alert
    return {
        "prediction_id": record.id,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "model_name": record.model_name,
        "model_version": record.model_version,
        "threat_priority": record.threat_priority,
        "risk_score": record.risk_score,
        "materialization_probability": round(record.materialization_probability, 2),
        "confidence_score": round(record.confidence_score, 2),
        "recommended_action": record.recommended_action,
        "predicted_next_attack_stage": record.predicted_next_attack_stage,
        "top_factors": json.loads(record.top_factors or "[]"),
        "feature_snapshot": json.loads(record.feature_snapshot or "{}"),
        "enrichment_summary": json.loads(record.enrichment_summary or "{}"),
        "alert": {
            "id": alert.id if alert else None,
            "wazuh_event_id": alert.wazuh_event_id if alert else None,
            "alert_timestamp": alert.alert_timestamp.isoformat() if alert and alert.alert_timestamp else None,
            "host_name": alert.host_name if alert else None,
            "source_ip": alert.source_ip if alert else None,
            "rule_id": alert.rule_id if alert else None,
            "rule_level": alert.rule_level if alert else None,
            "rule_description": alert.rule_description if alert else None,
            "mitre_tactic": alert.mitre_tactic if alert else None,
            "mitre_technique_id": alert.mitre_technique_id if alert else None,
        },
    }

"""
Feature engineering for Wazuh alert threat prediction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import ipaddress

from sqlalchemy.orm import Session

from app.config import get_config
from app.db import ml_crud


TACTIC_RISK = {
    "reconnaissance": 0.30,
    "resource-development": 0.40,
    "initial-access": 0.80,
    "execution": 0.75,
    "persistence": 0.82,
    "privilege-escalation": 0.90,
    "defense-evasion": 0.88,
    "credential-access": 0.92,
    "discovery": 0.70,
    "lateral-movement": 0.89,
    "collection": 0.78,
    "command-and-control": 0.95,
    "exfiltration": 0.97,
    "impact": 0.99,
}


SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "mshta.exe",
    "regsvr32.exe",
    "wmic.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "bash",
    "sh",
}


@dataclass
class FeatureExtractionResult:
    normalized_alert: dict
    numeric_features: dict
    explanation_signals: dict
    candidate_indicators: list[tuple[str, str]]


def _safe_lower(value: str | None) -> str:
    return (value or "").strip().lower()


def _nested_get(data: dict, *paths, default=None):
    for path in paths:
        current = data
        ok = True
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                ok = False
                break
        if ok and current not in (None, ""):
            return current
    return default


def _first_item(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _derive_event_id(alert_data: dict, timestamp: datetime, rule_id: str | None, agent_id: str | None) -> str:
    if alert_data.get("id"):
        return str(alert_data["id"])
    if alert_data.get("_id"):
        return str(alert_data["_id"])

    raw = f"{timestamp.isoformat()}|{rule_id or 'unknown'}|{agent_id or 'unknown'}|{alert_data.get('location', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _extract_source_ip(alert_data: dict) -> str | None:
    candidates = [
        _nested_get(alert_data, ("data", "srcip")),
        _nested_get(alert_data, ("srcip",)),
        _nested_get(alert_data, ("data", "src_ip")),
        _nested_get(alert_data, ("data", "win", "eventdata", "ipAddress")),
        _nested_get(alert_data, ("data", "aws", "sourceIPAddress")),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


def _extract_destination_ip(alert_data: dict) -> str | None:
    candidates = [
        _nested_get(alert_data, ("data", "dstip")),
        _nested_get(alert_data, ("dstip",)),
        _nested_get(alert_data, ("data", "dest_ip")),
        _nested_get(alert_data, ("data", "destinationIp")),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


def _extract_process_name(alert_data: dict) -> str | None:
    candidates = [
        _nested_get(alert_data, ("data", "process")),
        _nested_get(alert_data, ("data", "win", "eventdata", "processName")),
        _nested_get(alert_data, ("syscheck", "path")),
        _nested_get(alert_data, ("data", "command")),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


def _extract_user_name(alert_data: dict) -> str | None:
    candidates = [
        _nested_get(alert_data, ("data", "srcuser")),
        _nested_get(alert_data, ("data", "dstuser")),
        _nested_get(alert_data, ("data", "win", "eventdata", "targetUserName")),
        _nested_get(alert_data, ("data", "user")),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    return None


def _is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def normalize_alert(alert_data: dict) -> dict:
    timestamp = ml_crud.parse_iso_datetime(
        _nested_get(alert_data, ("timestamp",), ("@timestamp",), default=None)
    )
    rule_id = str(_nested_get(alert_data, ("rule", "id"), default="")) or None
    agent_id = str(_nested_get(alert_data, ("agent", "id"), default="")) or None

    mitre_tactic = _first_item(_nested_get(alert_data, ("rule", "mitre", "tactic"), default=None))
    mitre_technique_id = _first_item(_nested_get(alert_data, ("rule", "mitre", "id"), default=None))
    mitre_technique_name = _first_item(_nested_get(alert_data, ("rule", "mitre", "technique"), default=None))

    host_name = (
        _nested_get(alert_data, ("agent", "name"))
        or _nested_get(alert_data, ("hostname",))
        or _nested_get(alert_data, ("host",))
        or "unknown-host"
    )

    return {
        "wazuh_event_id": _derive_event_id(alert_data, timestamp, rule_id, agent_id),
        "alert_timestamp": timestamp,
        "agent_id": agent_id,
        "host_name": str(host_name),
        "rule_id": rule_id,
        "rule_level": int(_nested_get(alert_data, ("rule", "level"), default=0) or 0),
        "rule_description": str(_nested_get(alert_data, ("rule", "description"), default="")),
        "source_ip": _extract_source_ip(alert_data),
        "destination_ip": _extract_destination_ip(alert_data),
        "user_name": _extract_user_name(alert_data),
        "process_name": _extract_process_name(alert_data),
        "mitre_tactic": str(mitre_tactic) if mitre_tactic else None,
        "mitre_technique_id": str(mitre_technique_id) if mitre_technique_id else None,
        "mitre_technique_name": str(mitre_technique_name) if mitre_technique_name else None,
        "event_category": (
            _nested_get(alert_data, ("decoder", "name"))
            or _nested_get(alert_data, ("location",))
            or "generic"
        ),
        "raw_payload": alert_data,
    }


def extract_features(db: Session, alert_data: dict, host_criticality: int | None = None) -> FeatureExtractionResult:
    normalized = normalize_alert(alert_data)
    config = get_config()
    timestamp = normalized["alert_timestamp"]

    rule_description = _safe_lower(normalized.get("rule_description"))
    process_name = _safe_lower(normalized.get("process_name"))
    mitre_tactic = _safe_lower(normalized.get("mitre_tactic"))

    history = ml_crud.get_alert_history_stats(
        db,
        source_ip=normalized.get("source_ip"),
        host_name=normalized.get("host_name"),
        rule_id=normalized.get("rule_id"),
        process_name=normalized.get("process_name"),
        reference_time=timestamp,
    )

    login_failure_signal = 1 if any(
        needle in rule_description
        for needle in ["failed password", "authentication failed", "invalid user", "login failed", "brute force"]
    ) else 0

    suspicious_process_signal = 1 if any(
        needle in process_name
        for needle in SUSPICIOUS_PROCESSES
    ) else 0

    off_hours_signal = 1 if timestamp.hour < 6 or timestamp.hour >= 20 else 0
    weekend_signal = 1 if timestamp.weekday() >= 5 else 0

    host_profile = ml_crud.get_host_profile_by_name(db, normalized.get("host_name"))
    resolved_host_criticality = host_criticality or (
        host_profile.criticality if host_profile else config.ml.default_host_criticality
    )
    if host_profile and host_profile.crown_jewel:
        resolved_host_criticality = max(resolved_host_criticality, 5)

    candidate_indicators: list[tuple[str, str]] = []
    for key, indicator_type in [
        ("source_ip", "ip"),
        ("destination_ip", "ip"),
    ]:
        value = normalized.get(key)
        if value and _is_public_ip(value):
            candidate_indicators.append((value, indicator_type))

    possible_url = _nested_get(alert_data, ("data", "url"), ("data", "http", "url"))
    if possible_url:
        candidate_indicators.append((str(possible_url), "url"))

    possible_domain = _nested_get(alert_data, ("data", "domain"), ("data", "query"))
    if possible_domain:
        candidate_indicators.append((str(possible_domain), "domain"))

    possible_hash = _nested_get(
        alert_data,
        ("syscheck", "sha256_after"),
        ("data", "sha256"),
        ("data", "hash"),
    )
    if possible_hash:
        candidate_indicators.append((str(possible_hash), "hash"))

    numeric = {
        "rule_level": float(normalized["rule_level"]),
        "rule_severity": min(normalized["rule_level"] / 15.0, 1.0),
        "frequency_1h": float(history["frequency_1h"]),
        "frequency_24h": float(history["frequency_24h"]),
        "same_rule_24h": float(history["same_rule_24h"]),
        "same_host_24h": float(history["same_host_24h"]),
        "same_process_24h": float(history["same_process_24h"]),
        "repeat_behavior_7d": float(history["repeat_behavior_7d"]),
        "host_criticality": float(resolved_host_criticality),
        "login_failures": float(login_failure_signal),
        "suspicious_process_activity": float(suspicious_process_signal),
        "mitre_tactic_risk": TACTIC_RISK.get(mitre_tactic, 0.35),
        "off_hours": float(off_hours_signal),
        "weekend": float(weekend_signal),
        "public_source_ip": float(1 if _is_public_ip(normalized.get("source_ip")) else 0),
        "candidate_indicator_count": float(len(candidate_indicators)),
    }

    explanation = {
        "history": history,
        "host_profile": {
            "criticality": resolved_host_criticality,
            "internet_exposed": host_profile.internet_exposed if host_profile else False,
            "crown_jewel": host_profile.crown_jewel if host_profile else False,
        },
        "signals": {
            "login_failures": bool(login_failure_signal),
            "suspicious_process_activity": bool(suspicious_process_signal),
            "off_hours": bool(off_hours_signal),
            "weekend": bool(weekend_signal),
            "mitre_tactic": normalized.get("mitre_tactic"),
            "mitre_technique_id": normalized.get("mitre_technique_id"),
        },
    }

    return FeatureExtractionResult(
        normalized_alert=normalized,
        numeric_features=numeric,
        explanation_signals=explanation,
        candidate_indicators=candidate_indicators,
    )

"""
Threat prediction orchestration service.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_config
from app.core.ml.features import extract_features
from app.core.ml.model import (
    ThreatPredictionModel,
    build_top_factors,
    predict_next_stage,
    recommended_action,
)
from app.core.ml.reputation import ThreatIntelEnricher
from app.db import ml_crud


class ThreatPredictionService:
    def __init__(self):
        self.config = get_config()
        self.model = ThreatPredictionModel()
        self.enricher = ThreatIntelEnricher()

    def status(self) -> dict:
        return {
            "enabled": self.config.ml.enabled,
            "model_name": self.model.metadata["model_name"],
            "model_version": self.model.metadata["model_version"],
            "trained_at": self.model.metadata.get("trained_at"),
            "live_enrichment_enabled": self.config.ml.live_enrichment_enabled,
            "intel_sources": {
                "otx": bool(self.config.threat_intel.otx_api_key),
                "abuse_ch": bool(self.config.threat_intel.abuse_ch_api_key),
                "abuseipdb": bool(self.config.threat_intel.abuseipdb_api_key),
            },
        }

    def _assemble_prediction(self, db: Session, alert_data: dict) -> tuple[dict, dict]:
        extracted = extract_features(db, alert_data)
        enrichment = self.enricher.enrich(db, extracted.normalized_alert, extracted.candidate_indicators)

        features = deepcopy(extracted.numeric_features)
        features["source_ip_reputation"] = float(enrichment.get("source_ip_reputation", 0))
        features["threat_intel_matches"] = float(enrichment.get("threat_intel_matches", 0))
        features["local_match_count"] = float(enrichment.get("local_match_count", 0))
        features["host_internet_exposed"] = float(
            1 if extracted.explanation_signals["host_profile"].get("internet_exposed") else 0
        )
        features["host_crown_jewel"] = float(
            1 if extracted.explanation_signals["host_profile"].get("crown_jewel") else 0
        )

        model_output = self.model.predict(features)
        prediction = {
            **model_output,
            "recommended_action": recommended_action(
                model_output["threat_priority"],
                model_output["confidence_score"],
            ),
            "predicted_next_attack_stage": predict_next_stage(extracted.normalized_alert.get("mitre_tactic")),
            "top_factors": build_top_factors(features),
            "feature_snapshot": features,
            "enrichment_summary": enrichment,
            "explanation": extracted.explanation_signals,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return extracted.normalized_alert, prediction

    def predict(self, db: Session, alert_data: dict, persist: bool = False) -> dict:
        normalized, prediction = self._assemble_prediction(db, alert_data)

        if not persist:
            return {
                "alert": {
                    **normalized,
                    "alert_timestamp": normalized["alert_timestamp"].isoformat(),
                },
                **prediction,
            }

        existing_alert = ml_crud.get_alert_by_event_id(db, normalized["wazuh_event_id"])
        if existing_alert is None:
            alert_record = ml_crud.create_alert(db, normalized)
        else:
            alert_record = existing_alert

        record = ml_crud.upsert_prediction(db, alert_record.id, prediction)
        record.alert = alert_record
        return ml_crud.serialize_prediction(record)

    def ingest_batch(self, db: Session, alerts: list[dict]) -> dict:
        items = [self.predict(db, alert, persist=True) for alert in alerts]
        return {"count": len(items), "items": items}

    def retrain(self) -> dict:
        return self.model.retrain()

    def seed_demo_alerts(self, db: Session, count: int | None = None) -> dict:
        target = count or self.config.ml.demo_seed_size
        alerts = build_demo_alerts(target)
        return self.ingest_batch(db, alerts)


def build_demo_alerts(count: int) -> list[dict]:
    templates = [
        {
            "rule": {
                "id": "5710",
                "level": 12,
                "description": "sshd: authentication failed",
                "mitre": {"id": ["T1110"], "tactic": ["credential-access"], "technique": ["Brute Force"]},
            },
            "data": {"srcip": "185.220.101.12", "srcuser": "root"},
            "agent": {"id": "001", "name": "prod-auth-01"},
            "decoder": {"name": "sshd"},
        },
        {
            "rule": {
                "id": "61608",
                "level": 14,
                "description": "Suspicious PowerShell execution detected",
                "mitre": {"id": ["T1059.001"], "tactic": ["execution"], "technique": ["PowerShell"]},
            },
            "data": {"srcip": "91.240.118.172", "process": "powershell.exe -enc AAAA", "user": "svc-backup"},
            "agent": {"id": "002", "name": "finance-ws-07"},
            "decoder": {"name": "windows_eventchannel"},
        },
        {
            "rule": {
                "id": "31168",
                "level": 10,
                "description": "Wazuh agent detected outbound connection to known malicious URL",
                "mitre": {"id": ["T1071"], "tactic": ["command-and-control"], "technique": ["Application Layer Protocol"]},
            },
            "data": {"srcip": "103.15.53.231", "url": "http://bad-update.example/dropper", "dstip": "10.10.2.14"},
            "agent": {"id": "003", "name": "hr-laptop-03"},
            "decoder": {"name": "proxy"},
        },
        {
            "rule": {
                "id": "80792",
                "level": 8,
                "description": "Unexpected privileged process spawned",
                "mitre": {"id": ["T1543"], "tactic": ["persistence"], "technique": ["Create or Modify System Process"]},
            },
            "data": {"srcip": "45.95.147.44", "process": "rundll32.exe", "user": "SYSTEM"},
            "agent": {"id": "004", "name": "prod-sql-01"},
            "decoder": {"name": "sysmon_event"},
        },
    ]

    alerts = []
    now = datetime.now(timezone.utc)
    batch_id = now.strftime("%Y%m%d%H%M%S%f")
    for index in range(count):
        template = deepcopy(templates[index % len(templates)])
        template["timestamp"] = now.replace(microsecond=0).isoformat()
        template["id"] = f"demo-{batch_id}-{index + 1}"
        template["data"]["sequence"] = index + 1
        alerts.append(template)
    return alerts


_service: ThreatPredictionService | None = None


def get_threat_prediction_service() -> ThreatPredictionService:
    global _service
    if _service is None:
        _service = ThreatPredictionService()
    return _service

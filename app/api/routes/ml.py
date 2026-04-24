"""
ML threat prediction API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.ml.service import get_threat_prediction_service
from app.core.wazuh_ml_integration import get_wazuh_ml_integration_manager
from app.config import get_config
from app.db import ml_crud

router = APIRouter(prefix="/ml", tags=["Threat Prediction"])


class PredictionRequest(BaseModel):
    alert_data: dict
    persist: bool = False


class BatchIngestRequest(BaseModel):
    alerts: list[dict]


class DemoSeedRequest(BaseModel):
    count: int = Field(default=12, ge=1, le=100)


class HostProfileRequest(BaseModel):
    host_name: str
    criticality: int = Field(default=3, ge=1, le=5)
    internet_exposed: bool = False
    crown_jewel: bool = False
    business_owner: str | None = None
    notes: str | None = None


class WazuhIntegrationInstallRequest(BaseModel):
    hook_url: str | None = None
    level: int = Field(default=3, ge=0, le=16)
    timeout: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=2, ge=0, le=10)


@router.get("/status")
def ml_status():
    return get_threat_prediction_service().status()


@router.post("/predict")
def predict_alert(body: PredictionRequest, db: Session = Depends(get_db)):
    service = get_threat_prediction_service()
    return service.predict(db, body.alert_data, persist=body.persist)


@router.post("/alerts/ingest")
def ingest_alert(body: PredictionRequest, db: Session = Depends(get_db)):
    service = get_threat_prediction_service()
    return service.predict(db, body.alert_data, persist=True)


@router.post("/alerts/ingest/batch")
def ingest_batch(body: BatchIngestRequest, db: Session = Depends(get_db)):
    service = get_threat_prediction_service()
    return service.ingest_batch(db, body.alerts)


@router.get("/predictions")
def get_predictions(
    limit: int = Query(default=25, ge=1, le=200),
    priority: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    records = ml_crud.list_recent_predictions(db, limit=limit, priority=priority)
    return {"items": [ml_crud.serialize_prediction(record) for record in records]}


@router.get("/overview")
def get_overview(db: Session = Depends(get_db)):
    return ml_crud.get_prediction_overview(db)


@router.get("/top-threats")
def get_top_threats(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=5, ge=1, le=25),
    db: Session = Depends(get_db),
):
    return {"items": ml_crud.get_top_active_threats(db, hours=hours, limit=limit)}


@router.post("/retrain")
def retrain_model():
    service = get_threat_prediction_service()
    return {"status": "ok", "model": service.retrain()}


@router.post("/demo/seed")
def seed_demo(body: DemoSeedRequest, db: Session = Depends(get_db)):
    service = get_threat_prediction_service()
    return service.seed_demo_alerts(db, count=body.count)


@router.get("/host-profiles")
def list_host_profiles(db: Session = Depends(get_db)):
    profiles = ml_crud.get_host_profiles(db)
    return {
        "items": [
            {
                "id": profile.id,
                "host_name": profile.host_name,
                "criticality": profile.criticality,
                "internet_exposed": profile.internet_exposed,
                "crown_jewel": profile.crown_jewel,
                "business_owner": profile.business_owner,
                "notes": profile.notes,
            }
            for profile in profiles
        ]
    }


@router.post("/host-profiles")
def create_or_update_host_profile(body: HostProfileRequest, db: Session = Depends(get_db)):
    profile = ml_crud.upsert_host_profile(db, body.model_dump())
    return {
        "id": profile.id,
        "host_name": profile.host_name,
        "criticality": profile.criticality,
        "internet_exposed": profile.internet_exposed,
        "crown_jewel": profile.crown_jewel,
        "business_owner": profile.business_owner,
        "notes": profile.notes,
    }


@router.get("/wazuh/status")
def get_wazuh_integration_status():
    return get_wazuh_ml_integration_manager().status()


@router.post("/wazuh/install")
def install_wazuh_integration(body: WazuhIntegrationInstallRequest):
    config = get_config()
    api_key = config.api.api_key if config.api.api_key_enabled and config.api.api_key else None
    manager = get_wazuh_ml_integration_manager()
    return manager.install(
        hook_url=body.hook_url,
        level=body.level,
        timeout=body.timeout,
        retries=body.retries,
        api_key=api_key,
    )

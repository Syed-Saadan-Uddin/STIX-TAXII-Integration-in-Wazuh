"""
MITRE ATT&CK API routes.

Endpoints:
- GET /mitre                 — All techniques with indicator counts
- GET /mitre/{technique_id}  — Technique detail + linked indicators
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.db import crud

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("")
def list_techniques(db: Session = Depends(get_db)):
    """Return all MITRE ATT&CK techniques with indicator counts."""
    techniques = crud.get_techniques_with_counts(db)
    return techniques


@router.get("/{technique_id}")
def get_technique(technique_id: str, db: Session = Depends(get_db)):
    """
    Return technique detail + all linked indicators.
    technique_id should be in format like T1059, T1071.001
    """
    technique = crud.get_technique_by_id(db, technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")

    # Get linked indicators via the mapping table
    linked_indicators = []
    for mapping in technique.indicator_mappings:
        ind = mapping.indicator
        linked_indicators.append({
            "id": ind.id,
            "value": ind.value,
            "type": ind.type,
            "confidence": ind.confidence,
            "is_active": ind.is_active,
            "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        })

    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactic": technique.tactic,
        "description": technique.description,
        "indicators": linked_indicators,
        "indicator_count": len(linked_indicators),
    }

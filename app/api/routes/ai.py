"""
AI Analyst API routes.

Endpoints:
- POST /ai/enrich/{indicator_id}  — AI-powered IOC enrichment
- POST /ai/chat                    — Natural language threat hunting
- POST /ai/triage                  — Automated alert triage
- GET  /ai/status                  — AI service health check
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db import crud
from app.core.ai_analyst import get_analyst

router = APIRouter(prefix="/ai", tags=["AI Analyst"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    conversation_history: list[dict] | None = None


class TriageRequest(BaseModel):
    alert_data: dict
    indicator_value: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status")
def ai_status():
    """Check if the AI Analyst service is available."""
    analyst = get_analyst()
    return {
        "available": analyst.is_available,
        "model": analyst.model_name if analyst.is_available else None,
        "features": ["enrichment", "chat", "triage"] if analyst.is_available else [],
    }


@router.post("/enrich/{indicator_id}")
async def enrich_indicator(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    """
    Generate an AI-powered threat intelligence briefing for an indicator.
    Caches the result in the database for future lookups.
    """
    analyst = get_analyst()
    if not analyst.is_available:
        raise HTTPException(status_code=503, detail="AI Analyst not configured — set GEMINI_API_KEY")

    # Fetch indicator
    indicator = crud.get_indicator_by_id(db, indicator_id)
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    # Gather MITRE context
    mitre_techniques = []
    for mapping in indicator.mitre_mappings:
        mitre_techniques.append({
            "technique_id": mapping.technique.technique_id,
            "name": mapping.technique.name,
            "tactic": mapping.technique.tactic,
        })

    # Get feed name
    feed_name = None
    if indicator.source_feed:
        feed_name = indicator.source_feed.name

    # Run AI enrichment
    result = await analyst.enrich_indicator(
        indicator_value=indicator.value,
        indicator_type=indicator.type,
        mitre_techniques=mitre_techniques,
        feed_name=feed_name,
    )

    # Cache result in database
    if "error" not in result:
        try:
            indicator.ai_summary = result.get("ai_summary")
            indicator.ai_risk_score = result.get("ai_risk_score")
            db.commit()
        except Exception:
            db.rollback()

    return {
        "indicator_id": indicator.id,
        "indicator_value": indicator.value,
        "indicator_type": indicator.type,
        **result,
    }


@router.post("/chat")
async def chat_with_analyst(
    request: ChatRequest,
    db: Session = Depends(get_db),
):
    """
    Send a natural-language query to the AI Analyst.
    The analyst has access to the current database state for grounded answers.
    """
    analyst = get_analyst()
    if not analyst.is_available:
        raise HTTPException(status_code=503, detail="AI Analyst not configured — set GEMINI_API_KEY")

    # Build database context for grounding
    stats = crud.get_stats(db)
    indicators_raw, _ = crud.get_indicators(db, page=1, per_page=10)
    recent_indicators = [
        {"value": ind.value, "type": ind.type, "confidence": ind.confidence}
        for ind in indicators_raw
    ]
    mitre_data = crud.get_techniques_with_counts(db)

    db_context = {
        "stats": stats,
        "recent_indicators": recent_indicators,
        "mitre_techniques": mitre_data,
    }

    result = await analyst.chat(
        user_message=request.message,
        db_context=db_context,
        conversation_history=request.conversation_history,
    )

    return result


@router.post("/triage")
async def triage_alert(
    request: TriageRequest,
    db: Session = Depends(get_db),
):
    """
    Automatically triage a Wazuh alert using AI analysis.
    Optionally cross-references with known indicators in the database.
    """
    analyst = get_analyst()
    if not analyst.is_available:
        raise HTTPException(status_code=503, detail="AI Analyst not configured — set GEMINI_API_KEY")

    # Look up indicator context if provided
    indicator_context = None
    if request.indicator_value:
        indicators = crud.search_indicators(db, request.indicator_value)
        if indicators:
            ind = indicators[0]
            indicator_context = {
                "value": ind.value,
                "type": ind.type,
                "confidence": ind.confidence,
                "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
                "is_active": ind.is_active,
            }

    result = await analyst.triage_alert(
        alert_data=request.alert_data,
        indicator_context=indicator_context,
    )

    return result

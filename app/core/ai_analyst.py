"""
Gemini AI Analyst — Agentic Threat Intelligence Service.

Provides:
- IOC enrichment: detailed threat briefing for any indicator
- Chat: natural-language threat-hunting queries over the indicator database
- Alert triage: automated severity assessment for Wazuh alerts

Uses Google Gemini API with a specialized cybersecurity system prompt.
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

import google.generativeai as genai
from sqlalchemy.orm import Session

from app.db.models import Indicator, MitreTechnique, IndicatorMitreMap, Feed, SyncLog
from app.db import crud
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

ENRICHMENT_SYSTEM_PROMPT = """You are a senior cybersecurity threat intelligence analyst working inside a SOC (Security Operations Center).

Your role is to analyze Indicators of Compromise (IOCs) and provide actionable intelligence briefings.

When given an IOC (IP address, domain, hash, or URL), you must provide:

1. **Threat Assessment** — A risk rating: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL
2. **Known Associations** — Any known threat actors, malware families, botnets, or campaigns associated with this indicator
3. **MITRE ATT&CK Mapping** — Likely tactics and techniques (use T-numbers)
4. **Recommended Actions** — Specific steps the SOC should take (block, monitor, investigate, etc.)
5. **Context** — Any additional background (geolocation for IPs, registrar info for domains, etc.)

Keep your analysis concise but thorough. Use bullet points. Be direct and actionable.
If you don't have specific intelligence on an indicator, say so honestly but still provide general guidance based on the indicator type and any patterns you can identify."""

CHAT_SYSTEM_PROMPT = """You are an AI-powered threat intelligence analyst embedded in a Wazuh SIEM platform called "Wazuh-TI".

You have access to the organization's threat intelligence database containing IOCs (Indicators of Compromise) including malicious IPs, domains, URLs, and file hashes sourced from STIX/TAXII feeds.

The user is a security analyst who may ask you:
- Questions about specific indicators or threat actors
- To explain MITRE ATT&CK techniques in plain language
- To summarize the current threat landscape based on the data
- To help triage alerts or prioritize investigations
- General cybersecurity questions

You will be given context about the current database state (indicators, MITRE mappings, etc.) to ground your answers.

Be professional, concise, and actionable. Use markdown formatting for readability.
When referencing specific IOCs or techniques from the database, cite them clearly."""

TRIAGE_SYSTEM_PROMPT = """You are an automated alert triage system for a Wazuh SIEM.

Given a Wazuh alert (JSON format) and threat intelligence context, you must:

1. **Verdict**: TRUE_POSITIVE, FALSE_POSITIVE, or NEEDS_INVESTIGATION
2. **Confidence**: 0-100%
3. **Reasoning**: 2-3 sentences explaining your assessment
4. **Priority**: P1 (Critical), P2 (High), P3 (Medium), P4 (Low)
5. **Recommended Actions**: Specific next steps

Be conservative — when in doubt, classify as NEEDS_INVESTIGATION."""


# ---------------------------------------------------------------------------
# Gemini client
# ---------------------------------------------------------------------------

class AIAnalyst:
    """Wrapper around Google Gemini for cybersecurity intelligence."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self._configured = False
        self._model = None

        if self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self._model = genai.GenerativeModel("gemini-2.0-flash")
                self._configured = True
                logger.info("Gemini AI Analyst initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
        else:
            logger.warning("No GEMINI_API_KEY set — AI features disabled")

    @property
    def is_available(self) -> bool:
        return self._configured and self._model is not None

    # ------------------------------------------------------------------
    # IOC Enrichment
    # ------------------------------------------------------------------
    async def enrich_indicator(
        self,
        indicator_value: str,
        indicator_type: str,
        mitre_techniques: list[dict] | None = None,
        feed_name: str | None = None,
    ) -> dict:
        """
        Generate a detailed threat briefing for a single IOC.
        Returns a dict with ai_summary, ai_risk_score, and raw_response.
        """
        if not self.is_available:
            return {
                "ai_summary": "AI analysis unavailable — no Gemini API key configured.",
                "ai_risk_score": None,
                "error": "not_configured",
            }

        # Build context
        context_parts = [
            f"IOC Type: {indicator_type}",
            f"IOC Value: {indicator_value}",
        ]

        if mitre_techniques:
            technique_str = ", ".join(
                f"{t.get('technique_id', '?')} ({t.get('name', 'Unknown')})"
                for t in mitre_techniques
            )
            context_parts.append(f"Associated MITRE Techniques: {technique_str}")

        if feed_name:
            context_parts.append(f"Source Feed: {feed_name}")

        user_prompt = (
            "Analyze this Indicator of Compromise and provide a threat intelligence briefing:\n\n"
            + "\n".join(context_parts)
        )

        try:
            response = self._model.generate_content(
                contents=[
                    {"role": "user", "parts": [{"text": ENRICHMENT_SYSTEM_PROMPT + "\n\n" + user_prompt}]}
                ],
                generation_config=genai.types.GenerationConfig(
                    temperature=0.3,
                    max_output_tokens=1024,
                ),
            )

            summary = response.text

            # Extract risk score from the response
            risk_score = self._extract_risk_score(summary)

            return {
                "ai_summary": summary,
                "ai_risk_score": risk_score,
                "analyzed_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Gemini enrichment failed for {indicator_value}: {e}")
            return {
                "ai_summary": f"Analysis failed: {str(e)}",
                "ai_risk_score": None,
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Chat / Ask the Analyst
    # ------------------------------------------------------------------
    async def chat(
        self,
        user_message: str,
        db_context: dict | None = None,
        conversation_history: list[dict] | None = None,
    ) -> dict:
        """
        Handle a natural-language query from the security analyst.
        db_context provides grounding data from the threat intel database.
        """
        if not self.is_available:
            return {
                "response": "AI Analyst is offline — no Gemini API key configured.",
                "error": "not_configured",
            }

        # Build grounding context from database
        context_block = ""
        if db_context:
            context_block = "\n\n--- CURRENT DATABASE STATE ---\n"
            if "stats" in db_context:
                s = db_context["stats"]
                context_block += (
                    f"Total Indicators: {s.get('total_indicators', 0)}\n"
                    f"Active Indicators: {s.get('active_indicators', 0)}\n"
                    f"IOC Distribution: {json.dumps(s.get('ioc_type_distribution', {}))}\n"
                    f"MITRE Techniques Mapped: {s.get('mitre_techniques_mapped', 0)}\n"
                    f"Total Feeds: {s.get('total_feeds', 0)}\n"
                    f"Last Sync: {s.get('last_sync', 'Never')}\n"
                )
            if "recent_indicators" in db_context:
                context_block += "\nRecent Indicators:\n"
                for ind in db_context["recent_indicators"][:10]:
                    context_block += f"  - [{ind['type']}] {ind['value']} (confidence: {ind.get('confidence', 'N/A')})\n"
            if "mitre_techniques" in db_context:
                context_block += "\nMITRE Techniques in Database:\n"
                for t in db_context["mitre_techniques"][:15]:
                    context_block += f"  - {t['technique_id']}: {t.get('name', 'Unknown')} ({t.get('indicator_count', 0)} indicators)\n"
            context_block += "--- END DATABASE STATE ---\n"

        # Build message contents
        full_prompt = CHAT_SYSTEM_PROMPT + context_block + "\n\nUser Query: " + user_message

        # Include conversation history if provided
        contents = []
        if conversation_history:
            for msg in conversation_history[-6:]:  # Keep last 6 messages for context
                role = "user" if msg["role"] == "user" else "model"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        contents.append({"role": "user", "parts": [{"text": full_prompt}]})

        try:
            response = self._model.generate_content(
                contents=contents,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.4,
                    max_output_tokens=2048,
                ),
            )

            return {
                "response": response.text,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Gemini chat failed: {e}")
            return {
                "response": f"I encountered an error processing your query: {str(e)}",
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Alert Triage
    # ------------------------------------------------------------------
    async def triage_alert(
        self,
        alert_data: dict,
        indicator_context: dict | None = None,
    ) -> dict:
        """
        Analyze a Wazuh alert and provide automated triage.
        """
        if not self.is_available:
            return {
                "verdict": "UNKNOWN",
                "confidence": 0,
                "reasoning": "AI triage unavailable — no API key.",
                "error": "not_configured",
            }

        context = ""
        if indicator_context:
            context = f"\n\nThreat Intel Context:\n{json.dumps(indicator_context, indent=2)}"

        user_prompt = (
            f"Triage this Wazuh SIEM alert:\n\n"
            f"```json\n{json.dumps(alert_data, indent=2)}\n```"
            f"{context}"
        )

        try:
            response = self._model.generate_content(
                contents=[
                    {"role": "user", "parts": [{"text": TRIAGE_SYSTEM_PROMPT + "\n\n" + user_prompt}]}
                ],
                generation_config=genai.types.GenerationConfig(
                    temperature=0.2,
                    max_output_tokens=512,
                ),
            )

            return {
                "triage_report": response.text,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            logger.error(f"Gemini triage failed: {e}")
            return {
                "triage_report": f"Triage failed: {str(e)}",
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_risk_score(summary: str) -> str | None:
        """Extract the risk rating from the AI summary text."""
        summary_upper = summary.upper()
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            if level in summary_upper:
                return level
        return None


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_analyst_instance: AIAnalyst | None = None


def get_analyst() -> AIAnalyst:
    """Return a cached singleton AIAnalyst instance."""
    global _analyst_instance
    if _analyst_instance is None:
        _analyst_instance = AIAnalyst()
    return _analyst_instance

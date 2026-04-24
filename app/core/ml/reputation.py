"""
Live threat-intelligence enrichment used by the ML pipeline.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.config import get_config
from app.core.otx_client import OTXClient
from app.core.threatfox_client import ThreatFoxClient
from app.core.urlhaus_client import URLHausClient
from app.db import ml_crud
from app.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelEnricher:
    def __init__(self):
        config = get_config()
        self.live_enabled = config.ml.live_enrichment_enabled
        self.abuseipdb_key = config.threat_intel.abuseipdb_api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self.otx_client = OTXClient(config.threat_intel.otx_api_key)
        self.threatfox_client = ThreatFoxClient(config.threat_intel.abuse_ch_api_key)
        self.urlhaus_client = URLHausClient(config.threat_intel.abuse_ch_api_key)

    def _abuseipdb_lookup(self, source_ip: str | None) -> dict[str, Any]:
        if not self.live_enabled or not self.abuseipdb_key or not source_ip:
            return {"score": 0, "status": "not_configured"}

        try:
            if not ipaddress.ip_address(source_ip).is_global:
                return {"score": 0, "status": "not_public"}
        except ValueError:
            return {"score": 0, "status": "invalid_ip"}

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": source_ip, "maxAgeInDays": 90, "verbose": True},
                timeout=3,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "score": int(data.get("abuseConfidenceScore", 0) or 0),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports", 0),
                "status": "ok",
            }
        except Exception as exc:
            logger.warning(f"AbuseIPDB lookup failed for {source_ip}: {exc}")
            return {"score": 0, "status": "error", "error": str(exc)}

    def enrich(self, db: Session, normalized_alert: dict, candidate_indicators: list[tuple[str, str]]) -> dict[str, Any]:
        """Return an aggregate intelligence summary used for scoring."""
        local_candidates = [value for value, _ in candidate_indicators]
        local_matches = ml_crud.get_indicator_matches(db, local_candidates)

        summary: dict[str, Any] = {
            "local_match_count": len(local_matches),
            "local_match_values": [match.value for match in local_matches[:10]],
            "indicator_count": len(candidate_indicators),
            "threat_intel_matches": 0,
            "source_ip_reputation": 0,
            "abuseipdb": {"score": 0, "status": "not_checked"},
            "otx": {"hits": 0, "pulse_count": 0, "status": "not_checked"},
            "threatfox": {"hits": 0, "status": "not_checked"},
            "urlhaus": {"hits": 0, "status": "not_checked"},
            "intel_sources": [],
        }

        source_ip = normalized_alert.get("source_ip")
        with ThreadPoolExecutor(max_workers=4) as executor:
            abuseipdb_future = executor.submit(self._abuseipdb_lookup, source_ip)
            abuseipdb = abuseipdb_future.result()
            summary["abuseipdb"] = abuseipdb
            summary["source_ip_reputation"] = abuseipdb.get("score", 0)
            if abuseipdb.get("status") == "ok":
                summary["intel_sources"].append("AbuseIPDB")

            otx_hits = 0
            threatfox_hits = 0
            urlhaus_hits = 0

            for indicator_value, indicator_type in candidate_indicators[:2]:
                otx_future = executor.submit(self.otx_client.lookup_indicator, indicator_value, indicator_type)
                threatfox_future = executor.submit(self.threatfox_client.search_ioc, indicator_value, indicator_type)
                urlhaus_future = executor.submit(self.urlhaus_client.lookup_indicator, indicator_value, indicator_type)

                otx_data = otx_future.result()
                threatfox_data = threatfox_future.result()
                urlhaus_data = urlhaus_future.result()

                otx_hits += int(otx_data.get("pulse_count", 0) or 0)
                threatfox_hits += int(threatfox_data.get("hits", 0) or 0)
                urlhaus_hits += int(urlhaus_data.get("hits", 0) or 0)

                if summary["otx"].get("status") in {"not_checked", "not_found"} and otx_data.get("status") == "ok":
                    summary["otx"] = otx_data
                if summary["threatfox"].get("status") == "not_checked" and threatfox_data.get("status") not in {"not_configured"}:
                    summary["threatfox"] = threatfox_data
                if summary["urlhaus"].get("status") == "not_checked" and urlhaus_data.get("status") not in {"not_configured"}:
                    summary["urlhaus"] = urlhaus_data

        summary["threat_intel_matches"] = len(local_matches) + otx_hits + threatfox_hits + urlhaus_hits

        if otx_hits:
            summary["intel_sources"].append("OTX")
        if threatfox_hits:
            summary["intel_sources"].append("ThreatFox")
        if urlhaus_hits:
            summary["intel_sources"].append("URLhaus")

        return summary

"""
URLhaus direct API client.

Provides lightweight lookups for domains, URLs, and payload hashes so the ML
pipeline can enrich Wazuh alerts with live URLhaus intelligence when an API
key is configured.
"""

from __future__ import annotations

import os
from typing import Any

import requests

from app.env import load_env
from app.utils.logger import get_logger

load_env()

logger = get_logger(__name__)


class URLHausClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("ABUSE_CH_API_KEY", "")
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def lookup_indicator(self, indicator_value: str, indicator_type: str) -> dict[str, Any]:
        """Lookup an indicator and return a compact summary."""
        if not self.is_configured or not indicator_value:
            return {"hits": 0, "status": "not_configured"}

        path = None
        payload = None
        lower_type = (indicator_type or "").lower()

        if lower_type in {"domain", "hostname"}:
            path = "/host/"
            payload = {"host": indicator_value}
        elif lower_type == "url":
            path = "/url/"
            payload = {"url": indicator_value}
        elif lower_type in {"sha256", "md5", "hash"}:
            path = "/payload/"
            payload = {"sha256_hash": indicator_value}

        if not path:
            return {"hits": 0, "status": "unsupported"}

        try:
            response = requests.post(
                f"{self.base_url}{path}",
                headers={"Auth-Key": self.api_key},
                data=payload,
                timeout=2.5,
            )
            response.raise_for_status()
            data = response.json()

            query_status = data.get("query_status", "unknown")
            hits = 1 if query_status not in {"no_results", "invalid_url"} else 0
            tags = data.get("tags") or []

            return {
                "hits": hits,
                "status": query_status,
                "tags": tags[:5],
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
            }
        except Exception as exc:
            logger.warning(f"URLhaus lookup failed for {indicator_value}: {exc}")
            return {"hits": 0, "status": "error", "error": str(exc)}

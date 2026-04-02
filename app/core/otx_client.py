"""
AlienVault OTX Direct API Client
Fetches real threat intelligence from OTX REST API
and converts to the same format as TAXII feeds
"""
import requests
from datetime import datetime, timezone
from app.utils.logger import get_logger

logger = get_logger(__name__)

class OTXClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}

    def fetch_objects(self, added_after=None, limit=10) -> list:
        """Fetch IOCs from OTX and convert to STIX-like format"""
        try:
            logger.info("Fetching pulses from AlienVault OTX...")
            resp = requests.get(
                f"{self.base_url}/pulses/subscribed?limit={limit}&page=1",
                headers=self.headers,
                timeout=30
            )
            resp.raise_for_status()
            pulses = resp.json().get('results', [])
            logger.info(f"Got {len(pulses)} pulses from OTX")

            objects = []
            for pulse in pulses:
                for ind in pulse.get('indicators', []):
                    stix_obj = self._to_stix(ind, pulse)
                    if stix_obj:
                        objects.append(stix_obj)

            logger.info(f"Converted {len(objects)} OTX indicators to STIX format")
            return objects

        except Exception as e:
            logger.error(f"OTX fetch error: {e}")
            return []

    def _to_stix(self, indicator: dict, pulse: dict) -> dict:
        """Convert OTX indicator to STIX 2.1 indicator format"""
        import uuid
        ioc_type = indicator.get('type', '')
        ioc_val = indicator.get('indicator', '')

        pattern_map = {
            'IPv4': f"[ipv4-addr:value = '{ioc_val}']",
            'IPv6': f"[ipv6-addr:value = '{ioc_val}']",
            'domain': f"[domain-name:value = '{ioc_val}']",
            'URL': f"[url:value = '{ioc_val}']",
            'FileHash-MD5': f"[file:hashes.'MD5' = '{ioc_val}']",
            'FileHash-SHA256': f"[file:hashes.'SHA-256' = '{ioc_val}']",
        }

        pattern = pattern_map.get(ioc_type)
        if not pattern:
            return None

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"OTX: {pulse.get('name', 'Unknown')[:50]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "confidence": 75,
            "labels": ["malicious-activity"],
        }

    def test_connection(self) -> bool:
        try:
            resp = requests.get(
                f"{self.base_url}/user/me",
                headers=self.headers,
                timeout=10
            )
            return resp.status_code == 200
        except:
            return False

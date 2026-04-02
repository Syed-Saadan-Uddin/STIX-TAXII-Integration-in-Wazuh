"""
ThreatFox (Abuse.ch) Direct API Client
Fetches real threat intelligence - botnet C2, malware IOCs
"""
import requests
import uuid
from datetime import datetime, timezone
from app.utils.logger import get_logger

logger = get_logger(__name__)

class ThreatFoxClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"

    def fetch_objects(self, days: int = 1) -> list:
        try:
            logger.info("Fetching IOCs from ThreatFox (Abuse.ch)...")
            resp = requests.post(
                self.base_url,
                headers={"Auth-Key": self.api_key, "Content-Type": "application/json"},
                json={"query": "get_iocs", "days": days},
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            if data.get("query_status") != "ok":
                logger.error(f"ThreatFox error: {data}")
                return []

            iocs = data.get("data", [])
            logger.info(f"Got {len(iocs)} IOCs from ThreatFox")

            objects = []
            for ioc in iocs:
                stix_obj = self._to_stix(ioc)
                if stix_obj:
                    objects.append(stix_obj)

            logger.info(f"Converted {len(objects)} ThreatFox IOCs to STIX format")
            return objects

        except Exception as e:
            logger.error(f"ThreatFox fetch error: {e}")
            return []

    def _to_stix(self, ioc: dict) -> dict:
        ioc_type = ioc.get("ioc_type", "")
        ioc_val = ioc.get("ioc", "")
        confidence = ioc.get("confidence_level", 75)

        # Extract IP from ip:port format
        if ioc_type == "ip:port":
            ioc_val = ioc_val.split(":")[0]
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc_val}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{ioc_val}']"
        elif ioc_type in ["md5_hash", "sha256_hash"]:
            hash_type = "MD5" if ioc_type == "md5_hash" else "SHA-256"
            pattern = f"[file:hashes.'{hash_type}' = '{ioc_val}']"
        else:
            return None

        malware = ioc.get("malware_printable", "Unknown")
        threat_type = ioc.get("threat_type_desc", "")

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"ThreatFox: {malware} - {threat_type[:50]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "confidence": confidence,
            "labels": ["malicious-activity", "threat-fox"],
        }

    def test_connection(self) -> bool:
        try:
            resp = requests.post(
                self.base_url,
                headers={"Auth-Key": self.api_key, "Content-Type": "application/json"},
                json={"query": "get_iocs", "days": 1},
                timeout=10
            )
            return resp.json().get("query_status") == "ok"
        except:
            return False

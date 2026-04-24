"""
AlienVault OTX Direct API Client
Fetches real threat intelligence from OTX REST API
and converts to the same format as TAXII feeds
"""
import os
import requests
from urllib.parse import quote
from datetime import datetime, timezone
from app.env import load_env
from app.utils.logger import get_logger

load_env()

logger = get_logger(__name__)

class OTXClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("OTX_API_KEY", "")
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}
        
        # Map OTX tags/keywords to MITRE techniques
        self.mitre_mapping = {
            "c2": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "command and control": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "cobalt strike": {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
            "phishing": {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
            "spearphishing": {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
            "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
            "miner": {"id": "T1496", "name": "Resource Hijacking", "tactic": "impact"},
            "cryptominer": {"id": "T1496", "name": "Resource Hijacking", "tactic": "impact"},
            "credential dumping": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "credential-access"},
            "stealer": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "downloader": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "malware": {"id": "T1204", "name": "User Execution", "tactic": "execution"},
            "backdoor": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "brute force": {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
            "exploit": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "execution"},
            "webshell": {"id": "T1505.003", "name": "Web Shell", "tactic": "persistence"},
            "botnet": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "scanner": {"id": "T1595", "name": "Active Scanning", "tactic": "reconnaissance"},
            "apt": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "trojan": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "spyware": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "emotet": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "trickbot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "qakbot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "agenttesla": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "redline": {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "credential-access"},
            "remcos": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "njrat": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "asyncrat": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "lokibot": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "formbook": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "avemaria": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "warzone": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "brute force": {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
            "sql injection": {"id": "T1190", "name": "Exploitation for Privilege Escalation", "tactic": "privilege-escalation"},
            "xss": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "initial-access"},
            "rce": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "lateral-movement"},
        }
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def fetch_objects(self, added_after=None, limit=10) -> list:
        """Fetch IOCs from OTX and convert to STIX-like format"""
        if not self.is_configured:
            logger.warning("Skipping OTX fetch: no OTX API key configured")
            return []
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
                    stix_objects = self._to_stix(ind, pulse)
                    if stix_objects:
                        objects.extend(stix_objects)

            logger.info(f"Converted OTX indicators to {len(objects)} STIX objects (including mappings)")
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

        objects = []
        indicator_id = f"indicator--{uuid.uuid4()}"

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"OTX: {pulse.get('name', 'Unknown')[:50]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "confidence": 75,
            "labels": ["malicious-activity"],
        }
        objects.append(indicator_obj)

        # Map to MITRE technique if tags match
        tags = [t.lower() for t in pulse.get('tags', [])]
        pulse_name = pulse.get('name', '').lower()
        mapped_technique = None
        
        for key, tech in self.mitre_mapping.items():
            if key in tags or key in pulse_name:
                mapped_technique = tech
                break
                
        if mapped_technique:
            ap_id = f"attack-pattern--{uuid.uuid4()}"
            attack_pattern = {
                "type": "attack-pattern",
                "id": ap_id,
                "name": mapped_technique["name"],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": mapped_technique["id"]
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": mapped_technique["tactic"]
                    }
                ]
            }
            relationship = {
                "type": "relationship",
                "id": f"relationship--{uuid.uuid4()}",
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": ap_id
            }
            objects.append(attack_pattern)
            objects.append(relationship)

        return objects

    def test_connection(self) -> bool:
        if not self.is_configured:
            return False
        try:
            resp = requests.get(
                f"{self.base_url}/user/me",
                headers=self.headers,
                timeout=10
            )
            return resp.status_code == 200
        except:
            return False

    def lookup_indicator(self, indicator_value: str, indicator_type: str) -> dict:
        """Lookup a single IOC in OTX and return a compact summary."""
        if not self.is_configured or not indicator_value:
            return {"hits": 0, "pulse_count": 0, "status": "not_configured"}

        lookup_type = (indicator_type or "").lower()
        encoded = quote(indicator_value, safe="")
        paths: list[str]

        if lookup_type == "ip":
            paths = [f"/indicators/IPv4/{encoded}/general"]
        elif lookup_type == "domain":
            paths = [f"/indicators/hostname/{encoded}/general", f"/indicators/domain/{encoded}/general"]
        elif lookup_type == "url":
            paths = [f"/indicators/url/{encoded}/general"]
        elif lookup_type == "hash":
            paths = [f"/indicators/file/{encoded}/general"]
        else:
            return {"hits": 0, "pulse_count": 0, "status": "unsupported"}

        for path in paths:
            try:
                resp = requests.get(
                    f"{self.base_url}{path}",
                    headers=self.headers,
                    timeout=2.5,
                )
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                data = resp.json()
                pulse_info = data.get("pulse_info") or {}
                count = pulse_info.get("count", 0) or 0
                pulse_names = [
                    pulse.get("name")
                    for pulse in (pulse_info.get("pulses") or [])[:5]
                    if pulse.get("name")
                ]
                return {
                    "hits": 1 if count else 0,
                    "pulse_count": count,
                    "pulse_names": pulse_names,
                    "reputation": data.get("reputation"),
                    "validation": data.get("validation"),
                    "status": "ok",
                }
            except Exception as exc:
                logger.warning(f"OTX lookup failed for {indicator_value}: {exc}")

        return {"hits": 0, "pulse_count": 0, "status": "not_found"}

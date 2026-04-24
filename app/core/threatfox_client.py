"""
ThreatFox (Abuse.ch) Direct API Client
Fetches real threat intelligence - botnet C2, malware IOCs
"""
import os
import requests
import uuid
from datetime import datetime, timezone
from app.env import load_env
from app.utils.logger import get_logger

load_env()

logger = get_logger(__name__)

class ThreatFoxClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("ABUSE_CH_API_KEY", "")
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        
        # Map ThreatFox threat types to MITRE techniques
        self.mitre_mapping = {
            "botnet c2": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "payload delivery": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "information stealer": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
            "cryptominer": {"id": "T1496", "name": "Resource Hijacking", "tactic": "impact"},
            "phishing": {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
            "malware": {"id": "T1204", "name": "User Execution", "tactic": "execution"},
            "backdoor": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "cobalt strike": {"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control"},
            "brute force": {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
            "keylogger": {"id": "T1056.001", "name": "Keylogging", "tactic": "collection"},
            "dropper": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "exploit": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "execution"},
            "webshell": {"id": "T1505.003", "name": "Web Shell", "tactic": "persistence"},
            "scanning": {"id": "T1595", "name": "Active Scanning", "tactic": "reconnaissance"},
            "credential stealer": {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "credential-access"},
            "trojan": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "adware": {"id": "T1204.001", "name": "Malicious Link", "tactic": "execution"},
            "emotet": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "trickbot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "bazarloader": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "icedid": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "qakbot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "agenttesla": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "formbook": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "redline": {"id": "T1555", "name": "Credentials from Password Stores", "tactic": "credential-access"},
            "lokibot": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "ursnif": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "dridex": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "guloader": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "remcos": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "njrat": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "nanocore": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "asyncrat": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "raccoon": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "vidar": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
            "smokeloader": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            "danabot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            "avemaria": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            "warzone": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
        }

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def fetch_objects(self, days: int = 1) -> list:
        if not self.is_configured:
            logger.warning("Skipping ThreatFox fetch: no abuse.ch API key configured")
            return []
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
                stix_objects = self._to_stix(ioc)
                if stix_objects:
                    objects.extend(stix_objects)

            logger.info(f"Converted ThreatFox IOCs to {len(objects)} STIX objects (including mappings)")
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
        
        objects = []
        indicator_id = f"indicator--{uuid.uuid4()}"

        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "modified": datetime.now(timezone.utc).isoformat(),
            "name": f"ThreatFox: {malware} - {threat_type[:50]}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.now(timezone.utc).isoformat(),
            "confidence": confidence,
            "labels": ["malicious-activity", "threat-fox"],
        }
        objects.append(indicator_obj)

        # Map to MITRE technique if threat_type matches
        threat_type_lower = threat_type.lower()
        mapped_technique = None
        
        for key, tech in self.mitre_mapping.items():
            if key in threat_type_lower or key in malware.lower():
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
            resp = requests.post(
                self.base_url,
                headers={"Auth-Key": self.api_key, "Content-Type": "application/json"},
                json={"query": "get_iocs", "days": 1},
                timeout=10
            )
            return resp.json().get("query_status") == "ok"
        except:
            return False

    def search_ioc(self, indicator_value: str, indicator_type: str = "") -> dict:
        """Search a single IOC in ThreatFox and return a compact summary."""
        if not self.is_configured or not indicator_value:
            return {"hits": 0, "status": "not_configured"}

        query = "search_hash" if (indicator_type or "").lower() == "hash" else "search_ioc"
        try:
            resp = requests.post(
                self.base_url,
                headers={"Auth-Key": self.api_key, "Content-Type": "application/json"},
                json={"query": query, "search_term": indicator_value},
                timeout=2.5,
            )
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("data") or []
            if not isinstance(hits, list):
                hits = []
            return {
                "hits": len(hits),
                "status": data.get("query_status", "unknown"),
                "malware": list({
                    hit.get("malware_printable")
                    for hit in hits
                    if hit.get("malware_printable")
                })[:5],
                "threat_types": list({
                    hit.get("threat_type_desc")
                    for hit in hits
                    if hit.get("threat_type_desc")
                })[:5],
            }
        except Exception as exc:
            logger.warning(f"ThreatFox lookup failed for {indicator_value}: {exc}")
            return {"hits": 0, "status": "error", "error": str(exc)}

"""
Seeds the local TAXII mock server with STIX 2.1 objects.

Creates:
- indicator objects for each IOC in ioc_seeds.json
- attack-pattern objects for 5 MITRE ATT&CK techniques
- relationship objects linking indicators to attack-patterns

The resulting STIX bundle is saved to simulation/stix_bundle.json,
which is served by the mock TAXII server.

Run: python simulation/seed_taxii_server.py
"""

import json
import uuid
import os
from datetime import datetime, timezone, timedelta

# Resolve paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SEEDS_PATH = os.path.join(SCRIPT_DIR, "ioc_seeds.json")
OUTPUT_PATH = os.path.join(SCRIPT_DIR, "stix_bundle.json")

# Load seed data
with open(SEEDS_PATH, "r") as f:
    seeds = json.load(f)

# MITRE ATT&CK techniques to seed
TECHNIQUES = [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
    {"id": "T1566", "name": "Phishing", "tactic": "initial-access"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "defense-evasion"},
]

# Helper: generate a STIX ID
def stix_id(obj_type):
    return f"{obj_type}--{uuid.uuid4()}"


def build_indicator(value, ioc_type):
    """Build a STIX 2.1 Indicator object."""
    pattern_map = {
        "ip": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "hash": f"[file:hashes.'SHA-256' = '{value}']",
    }
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id("indicator"),
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": f"Malicious {ioc_type}: {value}",
        "pattern": pattern_map.get(ioc_type, f"[ipv4-addr:value = '{value}']"),
        "pattern_type": "stix",
        "valid_from": datetime.now(timezone.utc).isoformat(),
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        "confidence": 85,
        "labels": ["malicious-activity"],
    }


def build_attack_pattern(technique):
    """Build a STIX 2.1 AttackPattern object for a MITRE technique."""
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": stix_id("attack-pattern"),
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "name": technique["name"],
        "description": f"MITRE ATT&CK technique {technique['id']}: {technique['name']}",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": technique["id"],
                "url": f"https://attack.mitre.org/techniques/{technique['id']}/",
            }
        ],
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": technique["tactic"],
            }
        ],
    }


def build_relationship(source_id, target_id):
    """Build a STIX 2.1 Relationship (indicator -> attack-pattern)."""
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship"),
        "created": datetime.now(timezone.utc).isoformat(),
        "modified": datetime.now(timezone.utc).isoformat(),
        "relationship_type": "indicates",
        "source_ref": source_id,
        "target_ref": target_id,
    }


def main():
    objects = []
    indicator_ids = []

    # Build indicators for malicious IPs
    for ip in seeds["malicious_ips"]:
        ind = build_indicator(ip, "ip")
        objects.append(ind)
        indicator_ids.append(ind["id"])

    # Build indicators for malicious domains
    for domain in seeds["malicious_domains"]:
        ind = build_indicator(domain, "domain")
        objects.append(ind)
        indicator_ids.append(ind["id"])

    # Build indicators for malicious hashes
    for hash_val in seeds["malicious_hashes"]:
        ind = build_indicator(hash_val, "hash")
        objects.append(ind)
        indicator_ids.append(ind["id"])

    # Build attack patterns
    attack_pattern_ids = []
    for technique in TECHNIQUES:
        ap = build_attack_pattern(technique)
        objects.append(ap)
        attack_pattern_ids.append(ap["id"])

    # Build relationships: distribute indicators across attack patterns
    for i, ind_id in enumerate(indicator_ids):
        ap_id = attack_pattern_ids[i % len(attack_pattern_ids)]
        rel = build_relationship(ind_id, ap_id)
        objects.append(rel)

    # Build STIX bundle
    bundle = {
        "type": "bundle",
        "id": stix_id("bundle"),
        "objects": objects,
    }

    # Save to file
    with open(OUTPUT_PATH, "w") as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] STIX bundle created: {OUTPUT_PATH}")
    print(f"    - {len(indicator_ids)} indicators")
    print(f"    - {len(attack_pattern_ids)} attack patterns")
    print(f"    - {len(indicator_ids)} relationships")
    print(f"    - {len(objects)} total objects")


if __name__ == "__main__":
    main()

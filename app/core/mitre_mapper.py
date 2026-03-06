"""
MITRE ATT&CK technique mapper for the Wazuh-TI platform.

Builds mappings between STIX indicators and ATT&CK techniques
by analyzing STIX relationship objects. A relationship of type
"indicates" links an indicator (source_ref) to an attack-pattern
(target_ref).

Input: ParsedAttackPatterns, ParsedRelationships, ParsedIndicators
Output: List of MITREMapping dataclasses
"""

from dataclasses import dataclass
from app.core.stix_parser import ParsedAttackPattern, ParsedRelationship, ParsedIndicator
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MITREMapping:
    """
    Represents a mapping between an indicator and a MITRE ATT&CK technique.

    Attributes:
        indicator_stix_id: STIX ID of the indicator (e.g. "indicator--abc123")
        technique_id: MITRE technique ID (e.g. "T1059")
        technique_name: Human-readable technique name
        tactic: ATT&CK tactic phase (e.g. "execution")
    """
    indicator_stix_id: str
    technique_id: str
    technique_name: str
    tactic: str


class MITREMapper:
    """
    Maps STIX indicators to MITRE ATT&CK techniques via relationships.

    Uses STIX relationship objects where:
    - relationship_type == "indicates"
    - source_ref points to an indicator STIX ID
    - target_ref points to an attack-pattern STIX ID

    The attack-pattern objects contain the MITRE technique metadata
    (technique ID, name, tactic) extracted from external_references.
    """

    def map_techniques(
        self,
        attack_patterns: list[ParsedAttackPattern],
        relationships: list[ParsedRelationship],
        indicators: list[ParsedIndicator],
    ) -> list[MITREMapping]:
        """
        Build indicator-to-technique mappings from STIX data.

        Args:
            attack_patterns: Parsed ATT&CK technique objects
            relationships: Parsed STIX relationships
            indicators: Parsed STIX indicators

        Returns:
            List of MITREMapping objects linking indicators to techniques.
        """
        # Build lookup: stix_id → ParsedAttackPattern
        ap_lookup: dict[str, ParsedAttackPattern] = {
            ap.stix_id: ap for ap in attack_patterns if ap.technique_id
        }

        # Build indicator STIX ID set for validation
        indicator_ids = {ind.stix_id for ind in indicators}

        mappings = []

        for rel in relationships:
            # Only process "indicates" relationships
            if rel.relationship_type != "indicates":
                continue

            # source_ref = indicator, target_ref = attack-pattern
            if rel.source_ref not in indicator_ids:
                continue

            attack_pattern = ap_lookup.get(rel.target_ref)
            if not attack_pattern:
                continue

            mapping = MITREMapping(
                indicator_stix_id=rel.source_ref,
                technique_id=attack_pattern.technique_id,
                technique_name=attack_pattern.name,
                tactic=attack_pattern.tactic or "unknown",
            )
            mappings.append(mapping)

        logger.info(f"Mapped {len(mappings)} indicator-technique relationships")
        return mappings

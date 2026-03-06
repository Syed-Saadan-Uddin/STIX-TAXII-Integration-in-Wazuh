"""
STIX 2.1 bundle parser for the Wazuh-TI platform.

Parses raw STIX object dictionaries into structured dataclasses:
- ParsedIndicator: threat indicators with patterns and confidence
- ParsedAttackPattern: MITRE ATT&CK technique references
- ParsedRelationship: links between indicators and attack patterns

Input: list of raw STIX object dicts (from TAXIIClient.fetch_objects)
Output: ParsedBundle containing categorized, validated objects
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ParsedIndicator:
    """A parsed STIX indicator object."""
    stix_id: str
    pattern: str
    confidence: Optional[int] = None
    valid_until: Optional[datetime] = None


@dataclass
class ParsedAttackPattern:
    """A parsed STIX attack-pattern object (MITRE ATT&CK technique)."""
    stix_id: str
    name: str
    technique_id: Optional[str] = None  # e.g. T1059
    tactic: Optional[str] = None
    description: Optional[str] = None


@dataclass
class ParsedRelationship:
    """A parsed STIX relationship linking two objects."""
    source_ref: str
    target_ref: str
    relationship_type: str


@dataclass
class ParsedBundle:
    """Container for all parsed objects from a STIX bundle."""
    indicators: list[ParsedIndicator] = field(default_factory=list)
    attack_patterns: list[ParsedAttackPattern] = field(default_factory=list)
    relationships: list[ParsedRelationship] = field(default_factory=list)


class STIXParser:
    """
    Parses a list of raw STIX 2.1 objects into structured dataclasses.

    Handles three object types:
    - indicator: threat indicators with STIX patterns
    - attack-pattern: MITRE ATT&CK technique metadata
    - relationship: links between indicators and attack patterns
    """

    def parse_bundle(self, objects: list[dict]) -> ParsedBundle:
        """
        Parse a list of STIX objects into a structured ParsedBundle.

        Args:
            objects: List of raw STIX object dictionaries.

        Returns:
            ParsedBundle with categorized indicators, attack_patterns, and relationships.
        """
        bundle = ParsedBundle()

        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "indicator":
                parsed = self._parse_indicator(obj)
                if parsed:
                    bundle.indicators.append(parsed)

            elif obj_type == "attack-pattern":
                parsed = self._parse_attack_pattern(obj)
                if parsed:
                    bundle.attack_patterns.append(parsed)

            elif obj_type == "relationship":
                parsed = self._parse_relationship(obj)
                if parsed:
                    bundle.relationships.append(parsed)

        logger.info(
            f"Parsed bundle: {len(bundle.indicators)} indicators, "
            f"{len(bundle.attack_patterns)} attack patterns, "
            f"{len(bundle.relationships)} relationships"
        )
        return bundle

    def _parse_indicator(self, obj: dict) -> Optional[ParsedIndicator]:
        """
        Parse a STIX indicator object.

        Extracts: stix_id, pattern, confidence, valid_until.
        Returns None if required fields (id, pattern) are missing.
        """
        stix_id = obj.get("id")
        pattern = obj.get("pattern")

        if not stix_id or not pattern:
            logger.debug(f"Skipping indicator with missing id or pattern: {obj}")
            return None

        # Parse valid_until if present
        valid_until = None
        if obj.get("valid_until"):
            try:
                valid_until_str = obj["valid_until"]
                if isinstance(valid_until_str, str):
                    # Handle various ISO formats
                    valid_until_str = valid_until_str.replace("Z", "+00:00")
                    valid_until = datetime.fromisoformat(valid_until_str)
                elif isinstance(valid_until_str, datetime):
                    valid_until = valid_until_str
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse valid_until for {stix_id}: {e}")

        # Extract confidence (default to None if not present)
        confidence = obj.get("confidence")
        if confidence is not None:
            try:
                confidence = int(confidence)
                confidence = max(0, min(100, confidence))  # Clamp to 0-100
            except (ValueError, TypeError):
                confidence = None

        return ParsedIndicator(
            stix_id=stix_id,
            pattern=pattern,
            confidence=confidence,
            valid_until=valid_until,
        )

    def _parse_attack_pattern(self, obj: dict) -> Optional[ParsedAttackPattern]:
        """
        Parse a STIX attack-pattern object.

        Extracts MITRE technique ID from external_references where
        source_name == "mitre-attack". Extracts tactic from kill_chain_phases.
        """
        stix_id = obj.get("id")
        name = obj.get("name")

        if not stix_id or not name:
            logger.debug(f"Skipping attack-pattern with missing id or name: {obj}")
            return None

        # Extract technique_id from external_references
        technique_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break

        # Extract tactic from kill_chain_phases
        tactic = None
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactic = phase.get("phase_name")
                break

        return ParsedAttackPattern(
            stix_id=stix_id,
            name=name,
            technique_id=technique_id,
            tactic=tactic,
            description=obj.get("description"),
        )

    def _parse_relationship(self, obj: dict) -> Optional[ParsedRelationship]:
        """
        Parse a STIX relationship object.

        Extracts: source_ref, target_ref, relationship_type.
        Returns None if required fields are missing.
        """
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        rel_type = obj.get("relationship_type")

        if not source_ref or not target_ref or not rel_type:
            logger.debug(f"Skipping relationship with missing fields: {obj}")
            return None

        return ParsedRelationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=rel_type,
        )

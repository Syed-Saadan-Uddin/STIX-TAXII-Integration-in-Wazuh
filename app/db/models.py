"""
SQLAlchemy ORM models for the Wazuh-TI platform.

Defines core platform tables for:
- feeds: TAXII feed configurations with encrypted credentials
- indicators: Threat indicators (IPs, domains, URLs, hashes)
- mitre_techniques: MITRE ATT&CK technique records
- indicator_mitre_map: Many-to-many link between indicators and techniques
- sync_log: Audit log for every synchronization attempt
- host_asset_profiles: host criticality metadata for risk scoring
- wazuh_alerts: ingested Wazuh alerts/events
- threat_predictions: ML prediction outputs for each ingested alert
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey,
    UniqueConstraint, PrimaryKeyConstraint, Text, Float,
)
from sqlalchemy.orm import relationship
from app.database import Base


def _utcnow():
    """Return current UTC time (timezone-aware)."""
    return datetime.now(timezone.utc)


class Feed(Base):
    """
    TAXII feed configuration.
    Stores connection details and polling schedule for each threat feed.
    Passwords are stored encrypted via Fernet.
    """
    __tablename__ = "feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    taxii_url = Column(String, nullable=False)
    collection_id = Column(String, nullable=True)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)  # Stored encrypted
    polling_interval = Column(Integer, default=60)
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    # Relationships
    indicators = relationship("Indicator", back_populates="source_feed", cascade="all, delete-orphan")
    sync_logs = relationship("SyncLog", back_populates="feed", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Feed(id={self.id}, name='{self.name}')>"


class Indicator(Base):
    """
    Threat indicator record.
    Represents an IOC extracted from a STIX bundle — can be an IP, domain, URL, or hash.
    Deduplicated by (value, type) unique constraint.
    """
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_indicator_value_type"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String, nullable=False)
    type = Column(String, nullable=False)  # ip, domain, url, hash
    confidence = Column(Integer, nullable=True)  # 0–100
    source_feed_id = Column(Integer, ForeignKey("feeds.id"), nullable=True)
    stix_id = Column(String, nullable=True)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    expires = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    ai_summary = Column(Text, nullable=True)       # Cached Gemini analysis
    ai_risk_score = Column(String, nullable=True)   # CRITICAL/HIGH/MEDIUM/LOW

    # Relationships
    source_feed = relationship("Feed", back_populates="indicators")
    mitre_mappings = relationship(
        "IndicatorMitreMap", back_populates="indicator", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Indicator(id={self.id}, type='{self.type}', value='{self.value}')>"


class MitreTechnique(Base):
    """
    MITRE ATT&CK technique record.
    Stores technique metadata extracted from STIX attack-pattern objects.
    """
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String, unique=True, nullable=False)  # e.g. T1059
    name = Column(String, nullable=True)
    tactic = Column(String, nullable=True)
    description = Column(Text, nullable=True)

    # Relationships
    indicator_mappings = relationship(
        "IndicatorMitreMap", back_populates="technique", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<MitreTechnique(id={self.id}, technique_id='{self.technique_id}')>"


class IndicatorMitreMap(Base):
    """
    Many-to-many association between indicators and MITRE ATT&CK techniques.
    """
    __tablename__ = "indicator_mitre_map"
    __table_args__ = (
        PrimaryKeyConstraint("indicator_id", "mitre_id"),
    )

    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False)
    mitre_id = Column(Integer, ForeignKey("mitre_techniques.id"), nullable=False)

    # Relationships
    indicator = relationship("Indicator", back_populates="mitre_mappings")
    technique = relationship("MitreTechnique", back_populates="indicator_mappings")

    def __repr__(self):
        return f"<IndicatorMitreMap(indicator={self.indicator_id}, mitre={self.mitre_id})>"


class SyncLog(Base):
    """
    Audit log for synchronization attempts.
    Every sync run (success, failure, or partial) is recorded here.
    """
    __tablename__ = "sync_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("feeds.id"), nullable=True)
    started_at = Column(DateTime, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")  # success, failed, partial, running
    indicators_added = Column(Integer, default=0)
    indicators_updated = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Relationships
    feed = relationship("Feed", back_populates="sync_logs")

    def __repr__(self):
        return f"<SyncLog(id={self.id}, feed_id={self.feed_id}, status='{self.status}')>"


class HostAssetProfile(Base):
    """Optional host metadata used by the ML pipeline for criticality scoring."""

    __tablename__ = "host_asset_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_name = Column(String, unique=True, nullable=False, index=True)
    criticality = Column(Integer, default=3)  # 1-5
    internet_exposed = Column(Boolean, default=False)
    crown_jewel = Column(Boolean, default=False)
    business_owner = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    alerts = relationship("WazuhAlert", back_populates="host_profile")

    def __repr__(self):
        return f"<HostAssetProfile(host_name='{self.host_name}', criticality={self.criticality})>"


class WazuhAlert(Base):
    """Normalized Wazuh alert record persisted for prediction and retraining."""

    __tablename__ = "wazuh_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    wazuh_event_id = Column(String, unique=True, nullable=False, index=True)
    alert_timestamp = Column(DateTime, default=_utcnow, index=True)
    agent_id = Column(String, nullable=True, index=True)
    host_name = Column(String, nullable=True, index=True)
    rule_id = Column(String, nullable=True, index=True)
    rule_level = Column(Integer, default=0)
    rule_description = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True, index=True)
    destination_ip = Column(String, nullable=True)
    user_name = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    mitre_tactic = Column(String, nullable=True, index=True)
    mitre_technique_id = Column(String, nullable=True)
    mitre_technique_name = Column(String, nullable=True)
    event_category = Column(String, nullable=True)
    actual_incident = Column(Boolean, nullable=True)
    analyst_label = Column(String, nullable=True)
    raw_payload = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    host_profile_id = Column(Integer, ForeignKey("host_asset_profiles.id"), nullable=True)

    host_profile = relationship("HostAssetProfile", back_populates="alerts")
    prediction = relationship(
        "ThreatPrediction",
        back_populates="alert",
        cascade="all, delete-orphan",
        uselist=False,
    )

    def __repr__(self):
        return f"<WazuhAlert(id={self.id}, rule_id='{self.rule_id}', host='{self.host_name}')>"


class ThreatPrediction(Base):
    """Current ML prediction snapshot for a Wazuh alert."""

    __tablename__ = "threat_predictions"
    __table_args__ = (
        UniqueConstraint("alert_id", name="uq_threat_prediction_alert"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("wazuh_alerts.id"), nullable=False, index=True)
    model_name = Column(String, nullable=False)
    model_version = Column(String, nullable=False)
    threat_priority = Column(String, nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    materialization_probability = Column(Float, nullable=False)
    confidence_score = Column(Float, nullable=False)
    recommended_action = Column(String, nullable=False)
    predicted_next_attack_stage = Column(String, nullable=True)
    top_factors = Column(Text, nullable=True)
    feature_snapshot = Column(Text, nullable=True)
    enrichment_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)

    alert = relationship("WazuhAlert", back_populates="prediction")

    def __repr__(self):
        return (
            f"<ThreatPrediction(alert_id={self.alert_id}, priority='{self.threat_priority}', "
            f"risk_score={self.risk_score})>"
        )

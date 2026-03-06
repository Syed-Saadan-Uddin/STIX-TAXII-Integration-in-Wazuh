"""
SQLAlchemy ORM models for the Wazuh-TI platform.

Defines 5 tables:
- feeds: TAXII feed configurations with encrypted credentials
- indicators: Threat indicators (IPs, domains, URLs, hashes)
- mitre_techniques: MITRE ATT&CK technique records
- indicator_mitre_map: Many-to-many link between indicators and techniques
- sync_log: Audit log for every synchronization attempt
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey,
    UniqueConstraint, PrimaryKeyConstraint, Text,
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

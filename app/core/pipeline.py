"""
Full synchronization pipeline for the Wazuh-TI platform.

Orchestrates the end-to-end flow for syncing threat intelligence:
1. Fetch STIX objects from TAXII feeds
2. Parse STIX bundles into structured data
3. Extract IOCs from STIX patterns
4. Upsert indicators into the database
5. Map and store MITRE ATT&CK techniques
6. Expire old indicators
7. Write updated CDB list for Wazuh
8. Log sync results

Each feed is processed independently — a single failing feed
does not stop others from syncing.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.db import crud
from app.db.models import Feed
from app.core.taxii_client import TAXIIClient, TAXIIAuthError, TAXIICollectionError
from app.core.stix_parser import STIXParser
from app.core.ioc_extractor import IOCExtractor
from app.core.mitre_mapper import MITREMapper
from app.core.cdb_writer import CDBWriter
from app.utils.crypto import decrypt
from app.config import get_config
from app.utils.logger import get_logger

logger = get_logger(__name__)


def run_full_sync(feed_id: int = None) -> dict:
    """
    Run the full sync pipeline for all active feeds (or a specific feed).

    This function creates its own DB session so it can be called from
    the background scheduler without depending on FastAPI's request lifecycle.

    Args:
        feed_id: Optional — sync only this feed. If None, sync all active feeds.

    Returns:
        Summary dict: {feeds_synced, indicators_added, indicators_updated, errors}
    """
    db = SessionLocal()
    try:
        return _run_sync(db, feed_id)
    finally:
        db.close()


def _run_sync(db: Session, feed_id: int = None) -> dict:
    """Internal sync logic with an existing DB session."""
    config = get_config()
    summary = {
        "feeds_synced": 0,
        "indicators_added": 0,
        "indicators_updated": 0,
        "errors": [],
    }

    # Get feeds to sync
    if feed_id:
        feed = crud.get_feed_by_id(db, feed_id)
        feeds = [feed] if feed else []
        if not feed:
            summary["errors"].append(f"Feed {feed_id} not found")
            return summary
    else:
        feeds = [f for f in crud.get_all_feeds(db) if f.is_active]

    if not feeds:
        logger.info("No active feeds to sync")
        return summary

    # Initialize shared components
    stix_parser = STIXParser()
    ioc_extractor = IOCExtractor()
    mitre_mapper = MITREMapper()
    cdb_writer = CDBWriter(
        cdb_path=config.wazuh.cdb_list_path,
        reload_command=config.wazuh.reload_command,
        log_path=config.wazuh.log_path,
    )

    # Process each feed independently
    for feed in feeds:
        _sync_feed(
            db=db,
            feed=feed,
            stix_parser=stix_parser,
            ioc_extractor=ioc_extractor,
            mitre_mapper=mitre_mapper,
            summary=summary,
        )

    # Post-sync: expire old indicators and update CDB list
    try:
        expired = crud.expire_old_indicators(db)
        if expired:
            logger.info(f"Expired {expired} old indicators")
    except Exception as e:
        logger.error(f"Error expiring old indicators: {e}")

    # Write CDB list with all active indicators
    try:
        active_indicators, _ = crud.get_indicators(db, is_active=True, per_page=100000)
        cdb_writer.write(active_indicators)
    except Exception as e:
        logger.error(f"Error writing CDB list: {e}")
        summary["errors"].append(f"CDB write error: {str(e)}")

    logger.info(
        f"Sync complete: {summary['feeds_synced']} feeds, "
        f"{summary['indicators_added']} added, "
        f"{summary['indicators_updated']} updated, "
        f"{len(summary['errors'])} errors"
    )

    return summary


def _sync_feed(
    db: Session,
    feed: Feed,
    stix_parser: STIXParser,
    ioc_extractor: IOCExtractor,
    mitre_mapper: MITREMapper,
    summary: dict,
) -> None:
    """
    Sync a single TAXII feed through the full pipeline.
    Catches all exceptions so one feed failure doesn't stop others.
    """
    sync_log = crud.create_sync_log(db, feed.id)
    added = 0
    updated = 0

    try:
        logger.info(f"Syncing feed: {feed.name} ({feed.taxii_url})")

        # Step 1: Initialize TAXII client with decrypted credentials
        password = decrypt(feed.password) if feed.password else None
        client = TAXIIClient(
            url=feed.taxii_url,
            username=feed.username,
            password=password,
        )

        # Step 2: Fetch STIX objects (incremental since last sync)
        collection_id = feed.collection_id
        if not collection_id:
            # Auto-discover first collection
            collections = client.get_collections()
            if collections:
                collection_id = collections[0]["id"]
            else:
                raise ValueError("No collections found on TAXII server")

        objects = client.fetch_objects(
            collection_id=collection_id,
            added_after=feed.last_sync,
        )

        if not objects:
            logger.info(f"No new objects from feed: {feed.name}")
            crud.complete_sync_log(db, sync_log.id, "success", 0, 0)
            crud.update_last_sync(db, feed.id, datetime.now(timezone.utc))
            summary["feeds_synced"] += 1
            return

        # Step 3: Parse STIX bundle
        bundle = stix_parser.parse_bundle(objects)

        # Step 4: Extract IOCs and upsert indicators
        stix_id_to_indicator_id = {}

        for parsed_ind in bundle.indicators:
            result = ioc_extractor.extract(parsed_ind.pattern)
            if not result:
                continue

            value, ioc_type = result
            indicator, was_created = crud.upsert_indicator(
                db=db,
                value=value,
                type=ioc_type,
                confidence=parsed_ind.confidence,
                feed_id=feed.id,
                stix_id=parsed_ind.stix_id,
                expires=parsed_ind.valid_until,
            )

            stix_id_to_indicator_id[parsed_ind.stix_id] = indicator.id

            if was_created:
                added += 1
            else:
                updated += 1

        # Step 5: Map and store MITRE techniques
        mappings = mitre_mapper.map_techniques(
            attack_patterns=bundle.attack_patterns,
            relationships=bundle.relationships,
            indicators=bundle.indicators,
        )

        for mapping in mappings:
            # Upsert technique
            technique = crud.upsert_technique(
                db=db,
                technique_id=mapping.technique_id,
                name=mapping.technique_name,
                tactic=mapping.tactic,
            )

            # Link indicator to technique
            indicator_db_id = stix_id_to_indicator_id.get(mapping.indicator_stix_id)
            if indicator_db_id:
                crud.link_indicator_technique(db, indicator_db_id, technique.id)

        # Step 6: Update feed last_sync timestamp
        crud.update_last_sync(db, feed.id, datetime.now(timezone.utc))

        # Step 7: Complete sync log
        crud.complete_sync_log(db, sync_log.id, "success", added, updated)
        summary["feeds_synced"] += 1
        summary["indicators_added"] += added
        summary["indicators_updated"] += updated

        logger.info(
            f"Feed '{feed.name}' synced: {added} added, {updated} updated"
        )

    except TAXIIAuthError as e:
        error_msg = f"Auth error for feed '{feed.name}': {e}"
        logger.error(error_msg)
        crud.complete_sync_log(db, sync_log.id, "failed", added, updated, str(e))
        summary["errors"].append(error_msg)

    except TAXIICollectionError as e:
        error_msg = f"Collection error for feed '{feed.name}': {e}"
        logger.error(error_msg)
        crud.complete_sync_log(db, sync_log.id, "failed", added, updated, str(e))
        summary["errors"].append(error_msg)

    except Exception as e:
        error_msg = f"Unexpected error syncing feed '{feed.name}': {e}"
        logger.error(error_msg, exc_info=True)
        status = "partial" if added > 0 else "failed"
        crud.complete_sync_log(db, sync_log.id, status, added, updated, str(e))
        summary["errors"].append(error_msg)

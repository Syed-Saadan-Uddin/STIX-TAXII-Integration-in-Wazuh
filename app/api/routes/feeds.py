"""
Feed management API routes.

Endpoints:
- GET    /feeds          — List all feeds (passwords masked)
- POST   /feeds          — Create a new feed (encrypts password)
- PUT    /feeds/{id}     — Update a feed
- DELETE /feeds/{id}     — Delete a feed
- POST   /feeds/{id}/test — Test TAXII connection without saving
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.db import crud
from app.utils.crypto import encrypt, decrypt
from app.core.taxii_client import TAXIIClient, TAXIIAuthError

router = APIRouter(prefix="/feeds", tags=["Feeds"])


class FeedCreate(BaseModel):
    name: str
    taxii_url: str
    collection_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    polling_interval: int = 60


class FeedUpdate(BaseModel):
    name: Optional[str] = None
    taxii_url: Optional[str] = None
    collection_id: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    polling_interval: Optional[int] = None
    is_active: Optional[bool] = None


class FeedTestRequest(BaseModel):
    taxii_url: str
    username: Optional[str] = None
    password: Optional[str] = None


@router.get("")
def list_feeds(db: Session = Depends(get_db)):
    """Return all feeds. Passwords are always masked in responses."""
    feeds = crud.get_all_feeds(db)
    return [_serialize_feed(f) for f in feeds]


@router.post("")
def create_feed(body: FeedCreate, db: Session = Depends(get_db)):
    """Create a new TAXII feed. Password is encrypted before storage."""
    feed_data = body.model_dump()
    if feed_data.get("password"):
        feed_data["password"] = encrypt(feed_data["password"])
    feed = crud.create_feed(db, feed_data)
    return _serialize_feed(feed)


@router.put("/{feed_id}")
def update_feed(feed_id: int, body: FeedUpdate, db: Session = Depends(get_db)):
    """Update an existing feed. Re-encrypts password if changed."""
    updates = body.model_dump(exclude_unset=True)
    if "password" in updates and updates["password"]:
        updates["password"] = encrypt(updates["password"])
    feed = crud.update_feed(db, feed_id, updates)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return _serialize_feed(feed)


@router.delete("/{feed_id}")
def delete_feed(feed_id: int, db: Session = Depends(get_db)):
    """Delete a feed by ID."""
    deleted = crud.delete_feed(db, feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Feed not found")
    return {"status": "deleted", "feed_id": feed_id}


@router.post("/{feed_id}/test")
def test_feed_connection(feed_id: int, db: Session = Depends(get_db)):
    """Test TAXII connection for an existing feed."""
    feed = crud.get_feed_by_id(db, feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    password = decrypt(feed.password) if feed.password else None
    return _test_connection(feed.taxii_url, feed.username, password)


@router.post("/test")
def test_connection(body: FeedTestRequest):
    """Test a TAXII connection without saving the feed."""
    return _test_connection(body.taxii_url, body.username, body.password)


def _test_connection(url: str, username: str = None, password: str = None) -> dict:
    """Test TAXII connectivity and return result."""
    try:
        client = TAXIIClient(url=url, username=username, password=password)
        success = client.test_connection()
        collections = client.get_collections() if success else []
        return {
            "success": success,
            "message": "Connection successful" if success else "Connection failed",
            "collections": collections,
        }
    except TAXIIAuthError:
        return {
            "success": False,
            "message": "Authentication failed — check username/password",
            "collections": [],
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Connection error: {str(e)}",
            "collections": [],
        }


def _serialize_feed(feed) -> dict:
    """Convert a Feed ORM object to a JSON-serializable dict with masked password."""
    return {
        "id": feed.id,
        "name": feed.name,
        "taxii_url": feed.taxii_url,
        "collection_id": feed.collection_id,
        "username": feed.username,
        "password": "••••••••" if feed.password else None,  # NEVER expose raw password
        "polling_interval": feed.polling_interval,
        "is_active": feed.is_active,
        "last_sync": feed.last_sync.isoformat() if feed.last_sync else None,
        "created_at": feed.created_at.isoformat() if feed.created_at else None,
    }

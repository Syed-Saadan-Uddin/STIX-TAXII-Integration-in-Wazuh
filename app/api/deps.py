"""
FastAPI dependency injection utilities.

Provides:
- get_db: Database session dependency (yields a scoped SQLAlchemy session)
- verify_api_key: Optional API key authentication dependency
"""

import os
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from app.database import get_db as _get_db

# Re-export the database session dependency
get_db = _get_db

# API Key security (optional, configurable)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(_api_key_header)) -> str | None:
    """
    Optional API key verification dependency.

    If API_KEY_ENABLED is set to 'true' in environment, requires a valid
    X-API-Key header. Otherwise, this is a no-op.

    Returns:
        The validated API key, or None if auth is disabled.

    Raises:
        HTTPException 401: If auth is enabled and key is missing/invalid.
    """
    enabled = os.environ.get("API_KEY_ENABLED", "false").lower() == "true"

    if not enabled:
        return None

    expected_key = os.environ.get("API_KEY", "")
    if not api_key or api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

    return api_key

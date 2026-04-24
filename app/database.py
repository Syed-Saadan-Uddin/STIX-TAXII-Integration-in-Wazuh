"""
Database engine, session factory, and declarative base.

Provides:
- SQLAlchemy engine connected to SQLite at the configured path
- SessionLocal factory for creating scoped sessions
- Base class for all ORM models
- get_db() generator for FastAPI dependency injection
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool

from app.env import load_env

load_env()

# Resolve database path — use env var or fallback to local dev path
_db_path = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "..", "data", "wazuh_ti.db"))
_db_dir = os.path.dirname(os.path.abspath(_db_path))
os.makedirs(_db_dir, exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.abspath(_db_path)}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={
        "check_same_thread": False,
        "timeout": 60,  # Increased timeout for I/O heavy environments
    },
    poolclass=StaticPool,
    echo=False,
)

# Enable WAL mode for better concurrency and fewer disk I/O errors (e.g. OneDrive)
from sqlalchemy import event
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


def get_db():
    """
    FastAPI dependency that yields a database session.
    Automatically closes the session when the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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

# Resolve database path — use env var or fallback to local dev path
_db_path = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "..", "data", "wazuh_ti.db"))
_db_dir = os.path.dirname(os.path.abspath(_db_path))
os.makedirs(_db_dir, exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.abspath(_db_path)}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    echo=False,
)

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

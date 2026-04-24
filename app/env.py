"""
Environment bootstrap helpers.

Loads the repository-level `.env` file when python-dotenv is available so
local development and direct script execution behave the same way as Docker.
"""

from pathlib import Path

_loaded = False


def load_env() -> bool:
    """Load the repo `.env` file once. Returns True when dotenv handled it."""
    global _loaded
    if _loaded:
        return True

    try:
        from dotenv import load_dotenv
    except ImportError:
        return False

    env_path = Path(__file__).resolve().parents[1] / ".env"
    load_dotenv(env_path, override=False)
    _loaded = True
    return True

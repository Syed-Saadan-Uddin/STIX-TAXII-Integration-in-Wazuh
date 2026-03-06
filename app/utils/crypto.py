"""
Fernet-based encryption utilities for storing sensitive credentials.

Provides encrypt/decrypt functions used to protect TAXII feed passwords
before storing them in the database.

The encryption key is loaded from the ENCRYPTION_KEY environment variable.
Generate a key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import os
from cryptography.fernet import Fernet, InvalidToken

# Load or generate a key for development
_key = os.environ.get("ENCRYPTION_KEY")
if not _key:
    # Auto-generate a key for development — in production, always set ENCRYPTION_KEY
    _key = Fernet.generate_key().decode()

_fernet = Fernet(_key.encode() if isinstance(_key, str) else _key)


def encrypt(plaintext: str) -> str:
    """
    Encrypt a plaintext string and return the ciphertext as a UTF-8 string.
    Returns empty string if input is None or empty.
    """
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """
    Decrypt a ciphertext string back to plaintext.
    Returns empty string if input is None, empty, or decryption fails.
    """
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        return ""

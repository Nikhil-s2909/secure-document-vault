"""
Encryption Service
==================
Provides per-file encryption/decryption using the Fernet symmetric scheme
(AES-128 in CBC mode with PKCS7 padding + HMAC-SHA256 authentication).

Key Derivation
--------------
A unique 16-byte salt is generated for every uploaded file.
The per-file key is derived with PBKDF2-HMAC-SHA256:
    per_file_key = PBKDF2(master_key, salt, iterations=260_000)

This ensures:
  - Compromise of one file key does NOT expose other files.
  - The master key is never stored; only the salt is persisted.
  - Brute-force resistance via high iteration count (OWASP 2023 minimum).
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# OWASP recommended minimum for PBKDF2-SHA256 (2023)
KDF_ITERATIONS = 260_000


def _derive_key(master_key: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet-compatible key from master key + per-file salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    raw_key = kdf.derive(master_key.encode())
    # Fernet needs a URL-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(raw_key)


def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte random salt."""
    return os.urandom(16)


def encrypt_file(plaintext: bytes, master_key: str) -> tuple[bytes, str]:
    """
    Encrypt file bytes.

    Returns
    -------
    ciphertext : bytes
        The encrypted payload (includes Fernet token).
    salt_hex : str
        Hex-encoded salt to store alongside the document record.
    """
    salt = generate_salt()
    derived_key = _derive_key(master_key, salt)
    f = Fernet(derived_key)
    ciphertext = f.encrypt(plaintext)
    return ciphertext, salt.hex()


def decrypt_file(ciphertext: bytes, master_key: str, salt_hex: str) -> bytes:
    """
    Decrypt file bytes.

    Parameters
    ----------
    ciphertext : bytes
        Raw encrypted payload read from disk.
    master_key : str
        Application master key.
    salt_hex : str
        Hex-encoded salt stored in the database record.

    Returns
    -------
    plaintext : bytes
        Original file contents.

    Raises
    ------
    cryptography.fernet.InvalidToken
        If the ciphertext has been tampered with or the key is wrong.
    """
    salt = bytes.fromhex(salt_hex)
    derived_key = _derive_key(master_key, salt)
    f = Fernet(derived_key)
    return f.decrypt(ciphertext)

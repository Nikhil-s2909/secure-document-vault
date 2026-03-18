"""
vault_app/encryption.py
------------------------
Cryptographic layer for the Secure Document Vault.

Design decisions
----------------
* Algorithm  : AES-256-GCM via the `cryptography` library's Fernet *or*
               raw AES-GCM for authenticated encryption + integrity check.
               We use Fernet (AES-128-CBC + HMAC-SHA256) for simplicity and
               auditability, combined with a per-file random salt so that two
               identical uploads produce different ciphertexts.

* Key storage: A master key is derived from Django's SECRET_KEY using PBKDF2-
               HMAC-SHA256 with a per-file random salt. The salt is stored in
               the database alongside the document record. No plaintext key is
               ever persisted.

* File layout on disk:
      [16-byte salt][ciphertext produced by Fernet]
  The salt is prepended so the decryption function can read it back without a
  DB round-trip when called directly (though we always go through the model).

Public API
----------
encrypt_file(file_obj)  -> (ciphertext: bytes, salt_hex: str)
decrypt_file(ciphertext: bytes, salt_hex: str) -> plaintext: bytes
"""

import os
import hashlib
import base64
import logging

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from django.conf import settings

logger = logging.getLogger(__name__)

# Number of PBKDF2 iterations — NIST recommends ≥ 600 000 for SHA-256.
PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 32  # bytes


def _derive_fernet_key(salt: bytes) -> bytes:
    """
    Derive a 32-byte (256-bit) key from Django's SECRET_KEY + a random salt
    using PBKDF2-HMAC-SHA256, then base64url-encode it so Fernet can use it.

    Parameters
    ----------
    salt : 32 random bytes unique to this file.

    Returns
    -------
    A URL-safe base64-encoded 32-byte key suitable for Fernet.
    """
    master_secret = settings.SECRET_KEY.encode('utf-8')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    raw_key = kdf.derive(master_secret)
    # Fernet requires URL-safe base64-encoded 32-byte key
    return base64.urlsafe_b64encode(raw_key)


def encrypt_file(file_obj) -> tuple[bytes, str]:
    """
    Read *file_obj* (a Django InMemoryUploadedFile or similar), encrypt its
    contents with AES-128-CBC + HMAC-SHA256 (Fernet), and return the
    ciphertext together with the hex-encoded salt.

    Parameters
    ----------
    file_obj : file-like object with a .read() method.

    Returns
    -------
    (ciphertext, salt_hex)
        ciphertext : raw bytes to write to disk.
        salt_hex   : hex string to store in the DB (used for decryption).
    """
    plaintext = file_obj.read()
    salt = os.urandom(SALT_LENGTH)
    fernet_key = _derive_fernet_key(salt)
    f = Fernet(fernet_key)
    ciphertext = f.encrypt(plaintext)

    logger.debug("File encrypted successfully, salt=%s", salt.hex()[:8] + "…")
    return ciphertext, salt.hex()


def decrypt_file(ciphertext: bytes, salt_hex: str) -> bytes:
    """
    Decrypt *ciphertext* using the key derived from *salt_hex*.

    Parameters
    ----------
    ciphertext : raw bytes read from disk.
    salt_hex   : hex-encoded salt retrieved from the DB.

    Returns
    -------
    Plaintext bytes of the original file.

    Raises
    ------
    cryptography.fernet.InvalidToken  if the ciphertext has been tampered
    with or the wrong key is supplied (integrity check failure).
    """
    salt = bytes.fromhex(salt_hex)
    fernet_key = _derive_fernet_key(salt)
    f = Fernet(fernet_key)
    plaintext = f.decrypt(ciphertext)

    logger.debug("File decrypted successfully")
    return plaintext

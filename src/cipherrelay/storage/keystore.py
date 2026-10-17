"""Encrypted local keystore protected by Argon2id password hashing and AEAD.

Provides:
- Argon2id key derivation with high memory and time parameters
- Authenticated encryption (XChaCha20-Poly1305) of private key material
- Safe file persistence with restricted permissions
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from argon2.low_level import Type as ArgonType
from argon2.low_level import hash_secret_raw
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.signing import SigningKey as Ed25519SigningKey

from cipherrelay.crypto.aead import DecryptionError, decrypt_aead, encrypt_aead
from cipherrelay.crypto.identity import IdentityKeyPair

SALT_SIZE = 16
ARGON2_TIME_COST = 3  # iterations
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 2
KEY_LENGTH = 32


class KeystoreError(Exception):
    """Base error for keystore operations."""


class InvalidPassphraseError(KeystoreError):
    """Raised when passphrase verification or AEAD decryption fails."""


def derive_argon2id_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 256-bit symmetric key using Argon2id."""
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LENGTH,
        type=ArgonType.ID,
    )


def save_keystore(path: str | Path, identity: IdentityKeyPair, passphrase: str) -> None:
    """Encrypt and save the user's private keys to disk."""
    salt = os.urandom(SALT_SIZE)
    derived_key = derive_argon2id_key(passphrase, salt)

    payload_dict: dict[str, str] = {
        "signing_key_hex": bytes(identity.signing_key).hex(),
        "dh_private_key_hex": bytes(identity.dh_private_key).hex(),
    }
    raw_payload = json.dumps(payload_dict).encode("utf-8")

    # Associated data binds version and salt
    aad = b"cipherrelay_keystore_v1:" + salt
    encrypted_blob = encrypt_aead(derived_key, raw_payload, associated_data=aad)

    keystore_data = {
        "version": 1,
        "kdf": "Argon2id",
        "salt_hex": salt.hex(),
        "encrypted_blob_hex": encrypted_blob.hex(),
        "verify_key_hex": bytes(identity.verify_key).hex(),
        "dh_public_key_hex": bytes(identity.dh_public_key).hex(),
    }

    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(keystore_data, f, indent=2)

    # Restrict permissions (on POSIX systems; safe fallback on Windows)
    try:
        os.chmod(target_path, 0o600)
    except Exception:
        pass


def load_keystore(path: str | Path, passphrase: str) -> IdentityKeyPair:
    """Load and decrypt identity keys from disk using the passphrase."""
    target_path = Path(path)
    if not target_path.exists():
        raise KeystoreError(f"Keystore file not found: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)

    if data.get("version") != 1:
        raise KeystoreError("Unsupported keystore version")

    salt = bytes.fromhex(data["salt_hex"])
    encrypted_blob = bytes.fromhex(data["encrypted_blob_hex"])

    derived_key = derive_argon2id_key(passphrase, salt)
    aad = b"cipherrelay_keystore_v1:" + salt

    try:
        decrypted_raw = decrypt_aead(derived_key, encrypted_blob, associated_data=aad)
    except DecryptionError as e:
        raise InvalidPassphraseError("Incorrect passphrase or corrupted keystore") from e

    payload = json.loads(decrypted_raw.decode("utf-8"))
    signing_key = Ed25519SigningKey(bytes.fromhex(payload["signing_key_hex"]))
    dh_private_key = X25519PrivateKey(bytes.fromhex(payload["dh_private_key_hex"]))

    return IdentityKeyPair(signing_key=signing_key, dh_private_key=dh_private_key)

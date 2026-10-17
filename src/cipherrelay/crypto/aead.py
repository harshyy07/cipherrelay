"""XChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).

Uses libsodium's crypto_aead_xchacha20poly1305_ietf via PyNaCl bindings.
Non-repeating 192-bit (24-byte) random nonces ensure collision resistance.
"""

from __future__ import annotations

import os

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)

NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24 bytes
KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32 bytes


class DecryptionError(Exception):
    """Raised when ciphertext fails integrity or authenticity check."""


def encrypt_aead(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt plaintext using XChaCha20-Poly1305 with associated data.

    Returns: nonce (24 bytes) + ciphertext_and_tag.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext,
        aad=associated_data,
        nonce=nonce,
        key=key,
    )
    return nonce + ciphertext_and_tag


def decrypt_aead(key: bytes, payload: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt payload (nonce + ciphertext_and_tag) with associated data verification.

    Raises DecryptionError if tampering, reordering, or wrong key/AAD is detected.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be exactly {KEY_SIZE} bytes, got {len(key)}")

    if len(payload) < NONCE_SIZE + 16:
        raise DecryptionError("Ciphertext payload is too short")

    nonce = payload[:NONCE_SIZE]
    ciphertext_and_tag = payload[NONCE_SIZE:]

    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=ciphertext_and_tag,
            aad=associated_data,
            nonce=nonce,
            key=key,
        )
        return plaintext
    except Exception as e:
        raise DecryptionError(f"AEAD authentication failed: {e}") from e

"""Chunked encrypted file transfer using libsodium secretstream (XChaCha20-Poly1305).

Features:
- Streaming authenticated encryption
- Chunks (e.g. 64KB) with per-chunk authentication tags
- Truncation detection via FINAL tag
- Reordering detection
- Zero metadata leakage (filename, mime type sent inside E2EE message, not to server)
"""

from __future__ import annotations

import os

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_KEYBYTES,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
)

CHUNK_SIZE = 64 * 1024  # 64 KB per chunk
KEY_SIZE = crypto_secretstream_xchacha20poly1305_KEYBYTES  # 32 bytes
HEADER_SIZE = crypto_secretstream_xchacha20poly1305_HEADERBYTES  # 24 bytes


class FileCryptoError(Exception):
    """Raised when file chunk verification or secretstream fails."""


def generate_file_key() -> bytes:
    """Generate 256-bit random symmetric key for file encryption."""
    return os.urandom(KEY_SIZE)


def encrypt_file_bytes(plaintext: bytes, key: bytes, chunk_size: int = CHUNK_SIZE) -> bytes:
    """Encrypt byte payload into secretstream ciphertext containing header and tagged chunks."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")

    state = crypto_secretstream_xchacha20poly1305_state()
    header = crypto_secretstream_xchacha20poly1305_init_push(state, key)

    output = bytearray(header)
    offset = 0
    total = len(plaintext)

    if total == 0:
        # Edge case: empty file
        c_chunk = crypto_secretstream_xchacha20poly1305_push(
            state, b"", b"", crypto_secretstream_xchacha20poly1305_TAG_FINAL
        )
        output.extend(c_chunk)
        return bytes(output)

    while offset < total:
        chunk = plaintext[offset : offset + chunk_size]
        offset += len(chunk)
        is_last = (offset >= total)
        tag = (
            crypto_secretstream_xchacha20poly1305_TAG_FINAL
            if is_last
            else crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        )
        c_chunk = crypto_secretstream_xchacha20poly1305_push(state, chunk, b"", tag)
        output.extend(c_chunk)

    return bytes(output)


def decrypt_file_bytes(ciphertext_stream: bytes, key: bytes, chunk_size: int = CHUNK_SIZE) -> bytes:
    """Decrypt secretstream ciphertext, enforcing ordering and final truncation detection."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes")

    if len(ciphertext_stream) < HEADER_SIZE:
        raise FileCryptoError("Ciphertext is too short to contain secretstream header")

    header = ciphertext_stream[:HEADER_SIZE]
    state = crypto_secretstream_xchacha20poly1305_state()
    crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)

    output = bytearray()
    offset = HEADER_SIZE
    total = len(ciphertext_stream)
    encrypted_chunk_size = chunk_size + crypto_secretstream_xchacha20poly1305_ABYTES
    final_seen = False

    while offset < total:
        # Remaining ciphertext chunk
        end = min(offset + encrypted_chunk_size, total)
        chunk = ciphertext_stream[offset:end]
        offset = end

        try:
            decrypted_chunk, tag = crypto_secretstream_xchacha20poly1305_pull(state, chunk, b"")
        except Exception as e:
            raise FileCryptoError(f"Corrupted or tampered file chunk: {e}") from e

        output.extend(decrypted_chunk)
        if tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            final_seen = True
            break

    if not final_seen:
        raise FileCryptoError("File was truncated: missing secretstream FINAL tag")

    if offset < total:
        raise FileCryptoError("Extraneous unverified data found after secretstream FINAL tag")

    return bytes(output)

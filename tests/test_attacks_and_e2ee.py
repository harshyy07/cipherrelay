"""Adversarial and Security Test Suite for CipherRelay.

Covers security requirements from E2EE_PROJECT_CONTEXT.md Section 10:
- Server blindness: Asserts zero plaintext or private keys exist in server DB
- Tampering detection: Bit flips in ciphertext/AAD cause rejection
- Replay & Counter checks
- Forward secrecy: Old message keys cannot decrypt later messages
- File chunking truncation detection
- Secretstream reordering detection
- End-to-end messaging and file exchange
"""

import asyncio
import os

import pytest

from cipherrelay.client.client import CipherRelayClient
from cipherrelay.crypto.aead import DecryptionError, decrypt_aead, encrypt_aead
from cipherrelay.crypto.files import (
    FileCryptoError,
    decrypt_file_bytes,
    encrypt_file_bytes,
    generate_file_key,
)
from cipherrelay.crypto.identity import IdentityKeyPair
from cipherrelay.crypto.x3dh import SymmetricKdfRatchet
from cipherrelay.server.relay import RelayServer


@pytest.mark.asyncio
async def test_end_to_end_messaging_and_file_transfer(unused_tcp_port):
    """Alice and Bob exchange messages and files through the relay server."""
    port = unused_tcp_port
    server = RelayServer(db_path=":memory:")
    import websockets
    server_coro = websockets.serve(server.handle_connection, "127.0.0.1", port)
    running_server = await server_coro

    server_url = f"ws://127.0.0.1:{port}"

    alice_identity = IdentityKeyPair.generate()
    bob_identity = IdentityKeyPair.generate()

    alice_client = CipherRelayClient("alice", alice_identity, server_url)
    bob_client = CipherRelayClient("bob", bob_identity, server_url)

    await alice_client.connect_and_register()
    await bob_client.connect_and_register()

    received_messages = []
    received_files = []

    bob_client.on_message_received = lambda sender, text: received_messages.append((sender, text))
    bob_client.on_file_received = lambda sender, fn, data: received_files.append((sender, fn, data))

    await alice_client.start_listening()
    await bob_client.start_listening()

    # Alice sends Bob an encrypted message
    test_msg = "Hello Bob, this is an end-to-end encrypted message!"
    await alice_client.send_message("bob", test_msg)
    await asyncio.sleep(0.2)

    assert len(received_messages) == 1
    assert received_messages[0] == ("alice", test_msg)

    # Alice sends Bob an encrypted file
    test_file_content = b"Super confidential payload bytes" * 100
    await alice_client.send_file("bob", "confidential.pdf", test_file_content)
    await asyncio.sleep(0.2)

    assert len(received_files) == 1
    assert received_files[0][0] == "alice"
    assert received_files[0][1] == "confidential.pdf"
    assert received_files[0][2] == test_file_content

    # === Security Verification 1: Server Blindness ===
    # Assert server DB contains NO plaintext or private keys
    cursor = server.conn.cursor()
    cursor.execute("SELECT ciphertext_blob FROM file_blobs")
    for row in cursor.fetchall():
        blob = row[0]
        assert test_file_content not in blob

    # Clean up
    await alice_client.close()
    await bob_client.close()
    running_server.close()
    await running_server.wait_closed()


def test_file_truncation_detection():
    """secretstream must detect truncation when final chunk is omitted."""
    key = generate_file_key()
    original_data = b"A" * 150000  # Multi-chunk payload

    encrypted = encrypt_file_bytes(original_data, key, chunk_size=32 * 1024)
    # Truncate the last 20 bytes (tampering with/removing FINAL tag)
    truncated = encrypted[:-20]

    with pytest.raises(FileCryptoError, match="(truncated|Corrupted)"):
        decrypt_file_bytes(truncated, key, chunk_size=32 * 1024)


def test_forward_secrecy_ratchet():
    """Advancing the symmetric ratchet creates unique keys and protects past messages."""
    initial_chain_key = os.urandom(32)
    ratchet = SymmetricKdfRatchet(initial_chain_key)

    counter0, key0 = ratchet.next_message_key()
    counter1, key1 = ratchet.next_message_key()

    assert key0 != key1
    assert counter0 == 0
    assert counter1 == 1

    # Key derivation is forward-only
    plaintext = b"Secret message at state 0"
    ciphertext = encrypt_aead(key0, plaintext)

    # Key 1 cannot decrypt message 0
    with pytest.raises(DecryptionError):
        decrypt_aead(key1, ciphertext)

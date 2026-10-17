"""Tests for identity keys, AEAD encryption, and local encrypted keystore."""

import os

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cipherrelay.crypto.aead import DecryptionError, decrypt_aead, encrypt_aead
from cipherrelay.crypto.identity import IdentityKeyPair, calculate_safety_number, verify_signature
from cipherrelay.storage.keystore import InvalidPassphraseError, load_keystore, save_keystore


def test_identity_keypair_generation_and_signing():
    identity = IdentityKeyPair.generate()
    msg = b"E2EE test message to sign"
    sig = identity.sign(msg)

    assert len(sig) == 64
    assert verify_signature(bytes(identity.verify_key), msg, sig) is True

    # Tampered message must fail signature verification
    assert verify_signature(bytes(identity.verify_key), msg + b"!", sig) is False

    # Wrong public key must fail
    other = IdentityKeyPair.generate()
    assert verify_signature(bytes(other.verify_key), msg, sig) is False


def test_safety_number_symmetry():
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()

    sn_ab = calculate_safety_number(bytes(alice.verify_key), bytes(bob.verify_key))
    sn_ba = calculate_safety_number(bytes(bob.verify_key), bytes(alice.verify_key))

    assert sn_ab == sn_ba
    assert len(sn_ab.replace(" ", "")) == 12

    # Different key changes safety number
    eve = IdentityKeyPair.generate()
    sn_ae = calculate_safety_number(bytes(alice.verify_key), bytes(eve.verify_key))
    assert sn_ab != sn_ae


@given(st.binary(min_size=0, max_size=1024), st.binary(min_size=0, max_size=256))
def test_aead_encrypt_decrypt_roundtrip(data: bytes, aad: bytes):
    key = os.urandom(32)
    ciphertext = encrypt_aead(key, data, associated_data=aad)
    decrypted = decrypt_aead(key, ciphertext, associated_data=aad)
    assert decrypted == data


def test_aead_tamper_detection():
    key = os.urandom(32)
    plaintext = b"Confidential top secret"
    aad = b"context=42"
    ciphertext = bytearray(encrypt_aead(key, plaintext, associated_data=aad))

    # Flip a single bit in the ciphertext/tag
    ciphertext[-1] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_aead(key, bytes(ciphertext), associated_data=aad)

    # Wrong AAD must fail
    with pytest.raises(DecryptionError):
        decrypt_aead(key, encrypt_aead(key, plaintext, associated_data=aad), associated_data=b"context=43")


def test_keystore_save_and_load(tmp_path):
    keystore_path = tmp_path / "alice.keystore"
    identity = IdentityKeyPair.generate()
    passphrase = "correct horse battery staple"

    save_keystore(keystore_path, identity, passphrase)
    assert keystore_path.exists()

    # Load with correct passphrase
    loaded_identity = load_keystore(keystore_path, passphrase)
    assert bytes(loaded_identity.verify_key) == bytes(identity.verify_key)
    assert bytes(loaded_identity.dh_public_key) == bytes(identity.dh_public_key)

    # Load with incorrect passphrase must raise InvalidPassphraseError
    with pytest.raises(InvalidPassphraseError):
        load_keystore(keystore_path, "wrong passphrase")

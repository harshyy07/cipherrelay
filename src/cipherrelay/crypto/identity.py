"""Cryptographic identity and keypair management for CipherRelay.

Primitives used:
- Ed25519 for identity signing and authentication
- X25519 for Diffie-Hellman key agreement
- SHA-256 for safety number fingerprint calculation
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from nacl.public import PrivateKey as X25519PrivateKey
from nacl.public import PublicKey as X25519PublicKey
from nacl.signing import SigningKey as Ed25519SigningKey
from nacl.signing import VerifyKey as Ed25519VerifyKey


@dataclass(frozen=True)
class IdentityKeyPair:
    """Holds long-term Ed25519 signing key and X25519 DH key."""

    signing_key: Ed25519SigningKey
    dh_private_key: X25519PrivateKey

    @property
    def verify_key(self) -> Ed25519VerifyKey:
        return self.signing_key.verify_key

    @property
    def dh_public_key(self) -> X25519PublicKey:
        return self.dh_private_key.public_key

    @classmethod
    def generate(cls) -> IdentityKeyPair:
        """Generate a fresh Ed25519 signing key and X25519 DH key."""
        signing_key = Ed25519SigningKey.generate()
        dh_key = X25519PrivateKey.generate()
        return cls(signing_key=signing_key, dh_private_key=dh_key)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using Ed25519."""
        signed = self.signing_key.sign(message)
        return signed.signature

    @property
    def public_identity_b64(self) -> str:
        return base64.b64encode(bytes(self.verify_key)).decode("ascii")

    @property
    def public_dh_b64(self) -> str:
        return base64.b64encode(bytes(self.dh_public_key)).decode("ascii")


def verify_signature(verify_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""
    try:
        vk = Ed25519VerifyKey(verify_key_bytes)
        vk.verify(message, signature)
        return True
    except Exception:
        return False


def calculate_safety_number(user_a_pubkey: bytes, user_b_pubkey: bytes) -> str:
    """Compute a safety number (fingerprint) between two users' public identity keys.

    Sorted lexicographically so that calculate_safety_number(A, B) == calculate_safety_number(B, A).
    Returns a formatted 12-digit string split into two 6-digit blocks (e.g., '123456 789012').
    """
    ordered = sorted([user_a_pubkey, user_b_pubkey])
    digest = hashlib.sha256(b"".join(ordered)).digest()
    # Convert first 8 bytes into a 12-digit numeric code
    num = int.from_bytes(digest[:8], byteorder="big") % (10**12)
    s = f"{num:012d}"
    return f"{s[:6]} {s[6:]}"

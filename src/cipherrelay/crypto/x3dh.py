"""X3DH key agreement and symmetric ratcheting for forward secrecy.

Follows Signal-style X3DH:
- Identity Key (IK)
- Signed Prekey (SPK) with signature
- One-Time Prekey (OPK)
- Ephemeral Key (EK)
- Symmetric KDF chain (HKDF-based) ratcheting for per-message keys
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.public import Box
from nacl.public import PrivateKey as X25519PrivateKey
from nacl.public import PublicKey as X25519PublicKey

from cipherrelay.crypto.identity import IdentityKeyPair, verify_signature

HKDF_INFO_ROOT = b"CipherRelay_X3DH_Root_v1"
HKDF_INFO_RATCHET = b"CipherRelay_Ratchet_Step_v1"
HKDF_INFO_MSG_KEY = b"CipherRelay_Message_Key_v1"


def hkdf_derive(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 derivation."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else b"\x00" * 32,
        info=info,
    )
    return hkdf.derive(secret)


@dataclass
class PreKeyBundle:
    """Public prekey bundle uploaded by users to the server."""

    user_id: str
    identity_key_b64: str  # Ed25519 verify key
    base_dh_key_b64: str  # X25519 public key
    signed_prekey_b64: str  # X25519 public key
    signed_prekey_sig_b64: str  # Ed25519 signature over signed_prekey bytes
    one_time_prekey_id: int | None = None
    one_time_prekey_b64: str | None = None  # X25519 public key


def generate_signed_prekey(identity_keypair: IdentityKeyPair) -> tuple[X25519PrivateKey, str, str]:
    """Generate a signed prekey and its signature."""
    spk = X25519PrivateKey.generate()
    spk_bytes = bytes(spk.public_key)
    sig = identity_keypair.sign(spk_bytes)
    return (
        spk,
        base64.b64encode(spk_bytes).decode("ascii"),
        base64.b64encode(sig).decode("ascii"),
    )


def generate_one_time_prekeys(count: int = 10) -> dict[int, X25519PrivateKey]:
    """Generate batch of one-time prekeys."""
    return {i: X25519PrivateKey.generate() for i in range(count)}


def x3dh_initiator_handshake(
    sender_identity: IdentityKeyPair,
    recipient_bundle: PreKeyBundle,
) -> tuple[bytes, bytes, dict[str, str]]:
    """Initiator side of X3DH: generates ephemeral key, performs DH calculations, and derives root key."""
    # 1. Verify recipient signed prekey signature
    recipient_ik_bytes = base64.b64decode(recipient_bundle.identity_key_b64)
    spk_bytes = base64.b64decode(recipient_bundle.signed_prekey_b64)
    spk_sig = base64.b64decode(recipient_bundle.signed_prekey_sig_b64)

    if not verify_signature(recipient_ik_bytes, spk_bytes, spk_sig):
        raise ValueError("Invalid signed prekey signature from recipient")

    recipient_ik_dh = X25519PublicKey(base64.b64decode(recipient_bundle.base_dh_key_b64))
    recipient_spk = X25519PublicKey(spk_bytes)

    # 2. Generate Ephemeral Key (EK)
    ephemeral_key = X25519PrivateKey.generate()

    # 3. DH calculations:
    # DH1 = DH(sender_ik, recipient_spk)
    # DH2 = DH(sender_ek, recipient_ik)
    # DH3 = DH(sender_ek, recipient_spk)
    dh1 = Box(sender_identity.dh_private_key, recipient_spk).shared_key()
    dh2 = Box(ephemeral_key, recipient_ik_dh).shared_key()
    dh3 = Box(ephemeral_key, recipient_spk).shared_key()

    dh_inputs = [dh1, dh2, dh3]

    # Optional DH4 with OPK
    header_info: dict[str, str] = {
        "ephemeral_dh_pub": base64.b64encode(bytes(ephemeral_key.public_key)).decode("ascii"),
    }

    if recipient_bundle.one_time_prekey_b64:
        recipient_opk = X25519PublicKey(base64.b64decode(recipient_bundle.one_time_prekey_b64))
        dh4 = Box(ephemeral_key, recipient_opk).shared_key()
        dh_inputs.append(dh4)
        if recipient_bundle.one_time_prekey_id is not None:
            header_info["opk_id"] = str(recipient_bundle.one_time_prekey_id)

    combined_secret = b"".join(dh_inputs)
    root_key = hkdf_derive(combined_secret, salt=b"", info=HKDF_INFO_ROOT, length=32)
    return root_key, bytes(ephemeral_key.public_key), header_info


def x3dh_receiver_handshake(
    receiver_identity: IdentityKeyPair,
    receiver_spk_private: X25519PrivateKey,
    sender_ik_dh_pub: X25519PublicKey,
    sender_ek_pub: X25519PublicKey,
    receiver_opk_private: X25519PrivateKey | None = None,
) -> bytes:
    """Receiver side of X3DH: recomputes the DH secret and derives matching root key."""
    # DH1 = DH(recipient_spk, sender_ik)
    dh1 = Box(receiver_spk_private, sender_ik_dh_pub).shared_key()
    # DH2 = DH(recipient_ik, sender_ek)
    dh2 = Box(receiver_identity.dh_private_key, sender_ek_pub).shared_key()
    # DH3 = DH(recipient_spk, sender_ek)
    dh3 = Box(receiver_spk_private, sender_ek_pub).shared_key()

    dh_inputs = [dh1, dh2, dh3]

    if receiver_opk_private is not None:
        dh4 = Box(receiver_opk_private, sender_ek_pub).shared_key()
        dh_inputs.append(dh4)

    combined_secret = b"".join(dh_inputs)
    return hkdf_derive(combined_secret, salt=b"", info=HKDF_INFO_ROOT, length=32)


class SymmetricKdfRatchet:
    """Symmetric-key KDF chain ratchet providing forward secrecy.

    Each ratchet step produces a unique message key and immediately overwrites
    and advances the chain key. Past keys cannot be recovered.
    """

    def __init__(self, chain_key: bytes):
        if len(chain_key) != 32:
            raise ValueError("Chain key must be 32 bytes")
        self.chain_key = chain_key
        self.step_counter = 0

    def next_message_key(self) -> tuple[int, bytes]:
        """Advance ratchet, return (step_counter, message_key).

        Deletes old chain key and stores newly derived chain key.
        """
        # message_key = HKDF(chain_key, info="CipherRelay_Message_Key_v1")
        msg_key = hkdf_derive(self.chain_key, salt=b"", info=HKDF_INFO_MSG_KEY, length=32)

        # new_chain_key = HKDF(chain_key, info="CipherRelay_Ratchet_Step_v1")
        new_chain_key = hkdf_derive(self.chain_key, salt=b"", info=HKDF_INFO_RATCHET, length=32)

        counter = self.step_counter
        self.step_counter += 1
        self.chain_key = new_chain_key
        return counter, msg_key

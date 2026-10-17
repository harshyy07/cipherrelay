"""Protocol specification, envelope serialization, and verification for CipherRelay.

Wire format rules:
- Versioned envelope (version 1)
- Explicit sender, recipient, message counter, and timestamp
- Cryptographic signature covering all envelope metadata and ciphertext to prevent rerouting and tampering
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from cipherrelay.crypto.identity import verify_signature


class ProtocolError(Exception):
    """Raised when an envelope fails validation, signature check, or schema requirements."""


@dataclass
class Envelope:
    """Wire envelope format for CipherRelay messages."""

    v: int  # Protocol version (1)
    type: str  # 'msg', 'prekey_bundle', 'challenge', 'auth', 'ack', 'file_meta', 'error'
    from_user: str
    to_user: str
    counter: int
    ts: int
    ciphertext_b64: str
    header: dict[str, Any]
    sig_b64: str = ""

    def canonical_aad_bytes(self) -> bytes:
        """Create deterministic Associated Data (AAD) binding sender, recipient, and counter.

        Prevents server from tampering, swapping recipients, or replaying with different headers.
        """
        aad_dict = {
            "v": self.v,
            "type": self.type,
            "from_user": self.from_user,
            "to_user": self.to_user,
            "counter": self.counter,
            "header": self.header,
        }
        return json.dumps(aad_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def canonical_signing_bytes(self) -> bytes:
        """Create deterministic canonical representation for signing.

        Excludes `sig_b64` so the signature covers all other fields including the ciphertext.
        """
        canonical_dict = {
            "v": self.v,
            "type": self.type,
            "from_user": self.from_user,
            "to_user": self.to_user,
            "counter": self.counter,
            "ts": self.ts,
            "header": self.header,
            "ciphertext_b64": self.ciphertext_b64,
        }
        return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self) -> str:
        """Serialize envelope to JSON string."""
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, json_str: str) -> Envelope:
        """Parse and strictly validate JSON envelope."""
        try:
            data = json.loads(json_str)
        except Exception as e:
            raise ProtocolError(f"Malformed JSON: {e}") from e

        required_fields = ["v", "type", "from_user", "to_user", "counter", "ts", "header", "ciphertext_b64", "sig_b64"]
        for field in required_fields:
            if field not in data:
                raise ProtocolError(f"Missing required envelope field: {field}")

        if data["v"] != 1:
            raise ProtocolError(f"Unsupported protocol version: {data['v']}")

        return cls(
            v=data["v"],
            type=data["type"],
            from_user=data["from_user"],
            to_user=data["to_user"],
            counter=data["counter"],
            ts=data["ts"],
            header=data["header"],
            ciphertext_b64=data["ciphertext_b64"],
            sig_b64=data["sig_b64"],
        )

    def verify_envelope_signature(self, sender_verify_key_bytes: bytes) -> bool:
        """Verify the envelope signature against the sender's Ed25519 verify key."""
        if not self.sig_b64:
            return False
        try:
            sig = base64.b64decode(self.sig_b64)
            canonical_bytes = self.canonical_signing_bytes()
            return verify_signature(sender_verify_key_bytes, canonical_bytes, sig)
        except Exception:
            return False


def create_signed_envelope(
    identity_keypair,
    msg_type: str,
    from_user: str,
    to_user: str,
    counter: int,
    ciphertext_bytes: bytes,
    header: dict[str, Any] | None = None,
) -> Envelope:
    """Helper to create an envelope, encode ciphertext, and sign it."""
    envelope = Envelope(
        v=1,
        type=msg_type,
        from_user=from_user,
        to_user=to_user,
        counter=counter,
        ts=int(time.time()),
        header=header or {},
        ciphertext_b64=base64.b64encode(ciphertext_bytes).decode("ascii"),
        sig_b64="",
    )
    sig = identity_keypair.sign(envelope.canonical_signing_bytes())
    envelope.sig_b64 = base64.b64encode(sig).decode("ascii")
    return envelope

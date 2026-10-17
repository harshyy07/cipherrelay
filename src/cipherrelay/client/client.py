"""High-level asynchronous E2EE client for CipherRelay.

Handles:
- Connecting to relay server and authenticating via challenge-response
- Uploading/fetching prekey bundles
- X3DH handshake initiation and reception
- Encrypting and sending messages/files with forward secrecy
- Verifying safety numbers and TOFU contact tracking
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from collections.abc import Callable

import websockets
from nacl.public import PublicKey as X25519PublicKey

from cipherrelay.crypto.aead import decrypt_aead, encrypt_aead
from cipherrelay.crypto.files import decrypt_file_bytes, encrypt_file_bytes, generate_file_key
from cipherrelay.crypto.identity import (
    IdentityKeyPair,
    calculate_safety_number,
)
from cipherrelay.crypto.protocol import Envelope, create_signed_envelope
from cipherrelay.crypto.x3dh import (
    PreKeyBundle,
    SymmetricKdfRatchet,
    generate_one_time_prekeys,
    generate_signed_prekey,
    x3dh_initiator_handshake,
    x3dh_receiver_handshake,
)


class CipherRelayClient:
    """Client implementing the CipherRelay E2EE protocol."""

    def __init__(self, username: str, identity: IdentityKeyPair, server_url: str = "ws://localhost:8765"):
        self.username = username
        self.identity = identity
        self.server_url = server_url
        self.ws: websockets.WebSocketClientProtocol | None = None
        self.known_contacts: dict[str, str] = {}  # contact_username -> identity_key_b64 (TOFU)

        # Prekey state
        self.spk_private, self.spk_b64, self.spk_sig_b64 = generate_signed_prekey(self.identity)
        self.opks = generate_one_time_prekeys(count=10)

        # Active ratchets: peer_username -> SymmetricKdfRatchet
        self.send_ratchets: dict[str, SymmetricKdfRatchet] = {}
        self.recv_ratchets: dict[str, SymmetricKdfRatchet] = {}

        # Message callbacks
        self.on_message_received: Callable[[str, str], None] | None = None
        self.on_file_received: Callable[[str, str, bytes], None] | None = None
        self.on_key_change_warning: Callable[[str, str, str], None] | None = None

        self._listen_task: asyncio.Task | None = None

    async def connect_and_register(self) -> None:
        """Connect to server and register identity public keys."""
        self.ws = await websockets.connect(self.server_url)

        # Receive challenge
        raw = await self.ws.recv()
        challenge_data = json.loads(raw)
        nonce = challenge_data["nonce"]

        # Send register request
        await self.ws.send(json.dumps({
            "type": "register",
            "username": self.username,
            "identity_key_b64": self.identity.public_identity_b64,
            "base_dh_key_b64": self.identity.public_dh_b64,
        }))
        res = json.loads(await self.ws.recv())
        if res.get("type") == "error" and "already exists" not in res.get("message", ""):
            raise RuntimeError(f"Registration failed: {res.get('message')}")

        # Authenticate
        sig = self.identity.sign(nonce.encode("utf-8"))
        await self.ws.send(json.dumps({
            "type": "auth",
            "username": self.username,
            "sig_b64": base64.b64encode(sig).decode("ascii"),
        }))
        auth_res = json.loads(await self.ws.recv())
        if auth_res.get("type") != "auth_ok":
            raise RuntimeError(f"Auth failed: {auth_res.get('message')}")

        # Upload initial prekeys
        await self.upload_prekeys()

    async def connect_and_auth(self) -> None:
        """Connect to server and authenticate existing account."""
        self.ws = await websockets.connect(self.server_url)

        raw = await self.ws.recv()
        challenge_data = json.loads(raw)
        nonce = challenge_data["nonce"]

        sig = self.identity.sign(nonce.encode("utf-8"))
        await self.ws.send(json.dumps({
            "type": "auth",
            "username": self.username,
            "sig_b64": base64.b64encode(sig).decode("ascii"),
        }))
        auth_res = json.loads(await self.ws.recv())
        if auth_res.get("type") != "auth_ok":
            raise RuntimeError(f"Auth failed: {auth_res.get('message')}")

    async def upload_prekeys(self) -> None:
        """Upload signed prekey and one-time prekeys to server."""
        opk_list = [
            {"id": opk_id, "key_b64": base64.b64encode(bytes(priv.public_key)).decode("ascii")}
            for opk_id, priv in self.opks.items()
        ]
        await self.ws.send(json.dumps({
            "type": "upload_prekeys",
            "signed_prekey_b64": self.spk_b64,
            "signed_prekey_sig_b64": self.spk_sig_b64,
            "one_time_prekeys": opk_list,
        }))
        res = json.loads(await self.ws.recv())
        if res.get("type") != "upload_prekeys_ok":
            raise RuntimeError(f"Failed to upload prekeys: {res}")

    async def start_listening(self) -> None:
        """Start background loop to process inbound envelopes."""
        self._response_waiters: dict[str, asyncio.Queue] = {}
        self._listen_task = asyncio.create_task(self._listener_loop())

    async def _wait_for_response(self, response_type: str, timeout: float = 10.0) -> dict:
        """Wait for a response of a specific type from the server."""
        if response_type not in self._response_waiters:
            self._response_waiters[response_type] = asyncio.Queue()
        res = await asyncio.wait_for(self._response_waiters[response_type].get(), timeout=timeout)
        if res.get("type") == "error":
            raise RuntimeError(res.get("message", "Server error"))
        return res

    async def _listener_loop(self) -> None:
        try:
            async for raw in self.ws:
                data = json.loads(raw)
                msg_type = data.get("type")
                if msg_type == "inbound_envelope":
                    asyncio.create_task(self._process_inbound_envelope(data["envelope"]))
                else:
                    if msg_type not in self._response_waiters:
                        self._response_waiters[msg_type] = asyncio.Queue()
                    await self._response_waiters[msg_type].put(data)
        except websockets.exceptions.ConnectionClosed:
            pass

    async def _process_inbound_envelope(self, envelope_dict: dict) -> None:
        envelope = Envelope.from_json(json.dumps(envelope_dict))

        # Check contact identity against TOFU
        sender = envelope.from_user
        sender_ik_b64 = envelope.header.get("sender_ik_b64")

        if sender_ik_b64:
            if sender in self.known_contacts and self.known_contacts[sender] != sender_ik_b64:
                if self.on_key_change_warning:
                    self.on_key_change_warning(sender, self.known_contacts[sender], sender_ik_b64)
                return  # Block processing changed key without explicit verification
            self.known_contacts[sender] = sender_ik_b64

        sender_ik_bytes = base64.b64decode(sender_ik_b64)

        # 1. Verify envelope signature
        if not envelope.verify_envelope_signature(sender_ik_bytes):
            raise ValueError("Envelope signature verification failed! Tampered message.")

        # 2. X3DH handshake if initial message
        if envelope.type in ("init_msg", "init_file"):
            sender_dh_pub = X25519PublicKey(base64.b64decode(envelope.header["sender_dh_b64"]))
            sender_ek_pub = X25519PublicKey(base64.b64decode(envelope.header["ephemeral_dh_pub"]))

            opk_id_str = envelope.header.get("opk_id")
            receiver_opk = None
            if opk_id_str is not None:
                opk_id = int(opk_id_str)
                receiver_opk = self.opks.pop(opk_id, None)

            root_key = x3dh_receiver_handshake(
                receiver_identity=self.identity,
                receiver_spk_private=self.spk_private,
                sender_ik_dh_pub=sender_dh_pub,
                sender_ek_pub=sender_ek_pub,
                receiver_opk_private=receiver_opk,
            )
            self.recv_ratchets[sender] = SymmetricKdfRatchet(root_key)

        # 3. Ratchet step decryption
        ratchet = self.recv_ratchets.get(sender)
        if not ratchet:
            return

        _msg_counter, msg_key = ratchet.next_message_key()
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        aad = envelope.canonical_aad_bytes()

        decrypted_bytes = decrypt_aead(msg_key, ciphertext, associated_data=aad)

        if envelope.type in ("init_msg", "msg"):
            text = decrypted_bytes.decode("utf-8")
            if self.on_message_received:
                self.on_message_received(sender, text)

        elif envelope.type in ("init_file", "file_meta"):
            meta = json.loads(decrypted_bytes.decode("utf-8"))
            file_id = meta["file_id"]
            filename = meta["filename"]
            file_key = bytes.fromhex(meta["file_key_hex"])

            # Download blob from server
            await self.ws.send(json.dumps({
                "type": "download_file_blob",
                "file_id": file_id,
            }))
            res = await self._wait_for_response("download_file_blob_ok")
            blob_bytes = base64.b64decode(res["ciphertext_blob_b64"])
            plain_file_bytes = decrypt_file_bytes(blob_bytes, file_key)

            if self.on_file_received:
                self.on_file_received(sender, filename, plain_file_bytes)

    async def send_message(self, recipient: str, text: str) -> None:
        """Send an end-to-end encrypted message to a recipient."""
        is_initial = recipient not in self.send_ratchets
        header: dict[str, str] = {
            "sender_ik_b64": self.identity.public_identity_b64,
            "sender_dh_b64": self.identity.public_dh_b64,
        }

        if is_initial:
            # Fetch recipient prekey bundle from relay server
            await self.ws.send(json.dumps({
                "type": "get_prekey_bundle",
                "target_user": recipient,
            }))
            bundle_res = await self._wait_for_response("prekey_bundle")
            if bundle_res.get("type") == "error":
                raise RuntimeError(bundle_res.get("message"))

            opk_info = bundle_res.get("one_time_prekey")
            bundle = PreKeyBundle(
                user_id=recipient,
                identity_key_b64=bundle_res["identity_key_b64"],
                base_dh_key_b64=bundle_res["base_dh_key_b64"],
                signed_prekey_b64=bundle_res["signed_prekey_b64"],
                signed_prekey_sig_b64=bundle_res["signed_prekey_sig_b64"],
                one_time_prekey_id=opk_info["id"] if opk_info else None,
                one_time_prekey_b64=opk_info["key_b64"] if opk_info else None,
            )

            root_key, _, x3dh_header = x3dh_initiator_handshake(self.identity, bundle)
            self.send_ratchets[recipient] = SymmetricKdfRatchet(root_key)
            header.update(x3dh_header)
            envelope_type = "init_msg"
        else:
            envelope_type = "msg"

        ratchet = self.send_ratchets[recipient]
        counter, msg_key = ratchet.next_message_key()

        envelope_for_aad = Envelope(
            v=1,
            type=envelope_type,
            from_user=self.username,
            to_user=recipient,
            counter=counter,
            ts=0,
            header=header,
            ciphertext_b64="",
            sig_b64="",
        )
        aad = envelope_for_aad.canonical_aad_bytes()
        ciphertext = encrypt_aead(msg_key, text.encode("utf-8"), associated_data=aad)

        # Create signed final envelope
        final_envelope = create_signed_envelope(
            identity_keypair=self.identity,
            msg_type=envelope_type,
            from_user=self.username,
            to_user=recipient,
            counter=counter,
            ciphertext_bytes=ciphertext,
            header=header,
        )

        await self.ws.send(json.dumps({
            "type": "relay_envelope",
            "envelope": json.loads(final_envelope.to_json()),
        }))

        res = await self._wait_for_response("envelope_relayed")
        if res.get("type") != "envelope_relayed":
            raise RuntimeError(f"Server failed to relay envelope: {res}")

    async def send_file(self, recipient: str, filename: str, file_bytes: bytes) -> str:
        """Encrypt and upload file blob, then send file metadata inside E2EE envelope."""
        file_key = generate_file_key()
        encrypted_blob = encrypt_file_bytes(file_bytes, file_key)
        file_id = os.urandom(16).hex()

        # Upload encrypted blob to server (server knows only opaque file_id and blob)
        await self.ws.send(json.dumps({
            "type": "upload_file_blob",
            "file_id": file_id,
            "ciphertext_blob_b64": base64.b64encode(encrypted_blob).decode("ascii"),
        }))
        upload_res = await self._wait_for_response("upload_file_blob_ok")
        if upload_res.get("type") != "upload_file_blob_ok":
            raise RuntimeError(f"File upload failed: {upload_res}")

        # Send encrypted metadata envelope to recipient
        meta = {
            "file_id": file_id,
            "filename": filename,
            "size": len(file_bytes),
            "file_key_hex": file_key.hex(),
        }
        meta_json = json.dumps(meta)

        # Route through E2EE envelope
        is_initial = recipient not in self.send_ratchets
        header: dict[str, str] = {
            "sender_ik_b64": self.identity.public_identity_b64,
            "sender_dh_b64": self.identity.public_dh_b64,
        }

        if is_initial:
            await self.ws.send(json.dumps({"type": "get_prekey_bundle", "target_user": recipient}))
            bundle_res = await self._wait_for_response("prekey_bundle")
            opk_info = bundle_res.get("one_time_prekey")
            bundle = PreKeyBundle(
                user_id=recipient,
                identity_key_b64=bundle_res["identity_key_b64"],
                base_dh_key_b64=bundle_res["base_dh_key_b64"],
                signed_prekey_b64=bundle_res["signed_prekey_b64"],
                signed_prekey_sig_b64=bundle_res["signed_prekey_sig_b64"],
                one_time_prekey_id=opk_info["id"] if opk_info else None,
                one_time_prekey_b64=opk_info["key_b64"] if opk_info else None,
            )
            root_key, _, x3dh_header = x3dh_initiator_handshake(self.identity, bundle)
            self.send_ratchets[recipient] = SymmetricKdfRatchet(root_key)
            header.update(x3dh_header)
            envelope_type = "init_file"
        else:
            envelope_type = "file_meta"

        ratchet = self.send_ratchets[recipient]
        counter, msg_key = ratchet.next_message_key()

        envelope_for_aad = Envelope(
            v=1,
            type=envelope_type,
            from_user=self.username,
            to_user=recipient,
            counter=counter,
            ts=0,
            header=header,
            ciphertext_b64="",
            sig_b64="",
        )
        aad = envelope_for_aad.canonical_aad_bytes()
        ciphertext = encrypt_aead(msg_key, meta_json.encode("utf-8"), associated_data=aad)

        final_envelope = create_signed_envelope(
            identity_keypair=self.identity,
            msg_type=envelope_type,
            from_user=self.username,
            to_user=recipient,
            counter=counter,
            ciphertext_bytes=ciphertext,
            header=header,
        )

        await self.ws.send(json.dumps({
            "type": "relay_envelope",
            "envelope": json.loads(final_envelope.to_json()),
        }))
        res = await self._wait_for_response("envelope_relayed")
        if res.get("type") != "envelope_relayed":
            raise RuntimeError(f"Server failed to relay file envelope: {res}")
        return file_id

    def get_safety_number(self, contact_identity_b64: str) -> str:
        """Calculate safety number for out-of-band contact verification."""
        contact_pub = base64.b64decode(contact_identity_b64)
        return calculate_safety_number(bytes(self.identity.verify_key), contact_pub)

    async def close(self) -> None:
        if self._listen_task:
            self._listen_task.cancel()
        if self.ws:
            await self.ws.close()

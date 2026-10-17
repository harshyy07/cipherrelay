"""Web bridge server exposing local HTTP & WebSocket API for CipherRelay Web UI."""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
from pathlib import Path
from typing import Any

from aiohttp import web

from cipherrelay.client.client import CipherRelayClient
from cipherrelay.crypto.identity import IdentityKeyPair
from cipherrelay.storage.keystore import InvalidPassphraseError, load_keystore, save_keystore

STATIC_DIR = Path(__file__).parent / "static"


class WebBridge:
    def __init__(self, relay_server_url: str = "ws://localhost:8765"):
        self.relay_server_url = relay_server_url
        self.client: CipherRelayClient | None = None
        self.active_ui_websockets: set[web.WebSocketResponse] = set()
        self.crypto_audit_logs: list[dict[str, Any]] = []

    async def broadcast_ui(self, msg: dict[str, Any]) -> None:
        """Broadcast event to connected browser tabs."""
        dead = set()
        for ws in self.active_ui_websockets:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.add(ws)
        self.active_ui_websockets.difference_update(dead)

    def log_crypto_event(self, event_type: str, details: dict[str, Any]) -> None:
        entry = {
            "type": event_type,
            "ts": os.times().elapsed,
            **details,
        }
        self.crypto_audit_logs.append(entry)
        asyncio.create_task(self.broadcast_ui({"type": "crypto_event", "event": entry}))

    async def handle_login(self, request: web.Request) -> web.Response:
        data = await request.json()
        username = data.get("username", "").strip()
        passphrase = data.get("passphrase", "")

        if not username or not passphrase:
            return web.json_response({"error": "Username and passphrase are required"}, status=400)

        keystore_dir = Path.home() / ".cipherrelay"
        keystore_path = keystore_dir / f"{username}.keystore"

        try:
            if keystore_path.exists():
                identity = load_keystore(keystore_path, passphrase)
                is_new = False
            else:
                identity = IdentityKeyPair.generate()
                save_keystore(keystore_path, identity, passphrase)
                is_new = True
        except InvalidPassphraseError:
            return web.json_response({"error": "Invalid keystore passphrase"}, status=401)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

        # Initialize and connect client
        self.client = CipherRelayClient(username=username, identity=identity, server_url=self.relay_server_url)

        try:
            await self.client.connect_and_register()
        except Exception:
            await self.client.connect_and_auth()

        # Wire callbacks
        self.client.on_message_received = self._on_message_received
        self.client.on_file_received = self._on_file_received
        self.client.on_key_change_warning = self._on_key_warn

        await self.client.start_listening()

        self.log_crypto_event("session_init", {
            "username": username,
            "identity_pubkey": identity.public_identity_b64,
            "dh_pubkey": identity.public_dh_b64,
            "new_account": is_new,
        })

        return web.json_response({
            "status": "ok",
            "username": username,
            "identity_key": identity.public_identity_b64,
            "is_new": is_new,
        })

    def _on_message_received(self, sender: str, text: str) -> None:
        asyncio.create_task(self.broadcast_ui({
            "type": "inbound_msg",
            "sender": sender,
            "text": text,
        }))
        self.log_crypto_event("aead_decrypted", {
            "sender": sender,
            "plaintext_length": len(text),
            "algorithm": "XChaCha20-Poly1305",
        })

    def _on_file_received(self, sender: str, filename: str, data: bytes) -> None:
        asyncio.create_task(self.broadcast_ui({
            "type": "inbound_file",
            "sender": sender,
            "filename": filename,
            "size": len(data),
            "data_b64": base64.b64encode(data).decode("ascii"),
        }))
        self.log_crypto_event("file_secretstream_decrypted", {
            "sender": sender,
            "filename": filename,
            "size": len(data),
            "algorithm": "crypto_secretstream_xchacha20poly1305",
        })

    def _on_key_warn(self, sender: str, old_key: str, new_key: str) -> None:
        asyncio.create_task(self.broadcast_ui({
            "type": "key_change_warning",
            "sender": sender,
            "old_key": old_key,
            "new_key": new_key,
        }))
        self.log_crypto_event("tofu_key_alert", {
            "sender": sender,
            "alert": "Identity key changed! Potential Man-In-The-Middle attack detected.",
        })

    async def handle_send_message(self, request: web.Request) -> web.Response:
        if not self.client:
            return web.json_response({"error": "Not authenticated"}, status=401)
        data = await request.json()
        recipient = data.get("recipient", "").strip()
        text = data.get("text", "")

        if not recipient or not text:
            return web.json_response({"error": "Missing recipient or text"}, status=400)

        try:
            await self.client.send_message(recipient, text)
            ratchet = self.client.send_ratchets.get(recipient)
            step = ratchet.step_counter if ratchet else 0
            self.log_crypto_event("envelope_sent", {
                "recipient": recipient,
                "ratchet_step": step,
                "algorithm": "XChaCha20-Poly1305 + AAD Binding",
                "bytes_encrypted": len(text),
            })
            return web.json_response({"status": "ok"})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_send_file(self, request: web.Request) -> web.Response:
        if not self.client:
            return web.json_response({"error": "Not authenticated"}, status=401)
        data = await request.json()
        recipient = data.get("recipient", "").strip()
        filename = data.get("filename", "")
        file_bytes_b64 = data.get("data_b64", "")

        if not recipient or not filename or not file_bytes_b64:
            return web.json_response({"error": "Missing parameters"}, status=400)

        file_bytes = base64.b64decode(file_bytes_b64)
        try:
            file_id = await self.client.send_file(recipient, filename, file_bytes)
            self.log_crypto_event("file_uploaded", {
                "recipient": recipient,
                "filename": filename,
                "size": len(file_bytes),
                "file_id": file_id,
                "streaming_cipher": "XChaCha20-Poly1305 secretstream",
            })
            return web.json_response({"status": "ok", "file_id": file_id})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_safety_number(self, request: web.Request) -> web.Response:
        if not self.client:
            return web.json_response({"error": "Not authenticated"}, status=401)
        contact_key_b64 = request.query.get("contact_key", "")
        if not contact_key_b64:
            return web.json_response({"error": "Missing contact_key"}, status=400)

        try:
            sn = self.client.get_safety_number(contact_key_b64)
            return web.json_response({"safety_number": sn})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.active_ui_websockets.add(ws)

        # Send current state
        if self.client:
            await ws.send_json({
                "type": "auth_state",
                "authenticated": True,
                "username": self.client.username,
                "identity_key": self.client.identity.public_identity_b64,
            })
        for event in self.crypto_audit_logs[-30:]:
            await ws.send_json({"type": "crypto_event", "event": event})

        try:
            async for _ in ws:
                pass
        finally:
            self.active_ui_websockets.discard(ws)
        return ws


def create_web_app(relay_server_url: str = "ws://localhost:8765") -> web.Application:
    bridge = WebBridge(relay_server_url=relay_server_url)
    app = web.Application()

    app.router.add_post("/api/login", bridge.handle_login)
    app.router.add_post("/api/send_message", bridge.handle_send_message)
    app.router.add_post("/api/send_file", bridge.handle_send_file)
    app.router.add_get("/api/safety_number", bridge.handle_safety_number)
    app.router.add_get("/ws", bridge.handle_ws)

    # Static assets
    app.router.add_static("/static", STATIC_DIR)
    app.router.add_get("/", lambda req: web.FileResponse(STATIC_DIR / "index.html"))

    return app


def main():
    relay_url = os.environ.get("CIPHERRELAY_SERVER", "ws://localhost:8765")
    port = int(os.environ.get("WEB_PORT", "5000"))
    app = create_web_app(relay_server_url=relay_url)
    print("=" * 60)
    print("   [+] CipherRelay Web UI starting")
    print(f"   URL: http://localhost:{port}")
    print(f"   Connecting to relay: {relay_url}")
    print("=" * 60)
    web.run_app(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()

"""Untrusted Zero-Knowledge Relay Server for CipherRelay.

Responsibilities:
- Register users and store public identity keys & prekey bundles
- Authenticate clients via Ed25519 challenge-response (zero passwords on server)
- Route opaque envelopes between online clients
- Store-and-forward offline messages (zero plaintext knowledge)
- Encrypted file blob storage (zero metadata or filename knowledge)
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time

import websockets
from websockets.server import WebSocketServerProtocol

from cipherrelay.crypto.identity import verify_signature
from cipherrelay.crypto.protocol import Envelope, ProtocolError


class RelayServer:
    """Zero-knowledge relay server."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.init_db()
        self.online_clients: dict[str, WebSocketServerProtocol] = {}  # username -> websocket
        self.pending_challenges: dict[WebSocketServerProtocol, dict[str, str]] = {}

    def init_db(self) -> None:
        """Create tables for public keys, prekey bundles, offline messages, and file blobs."""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    identity_key_b64 TEXT NOT NULL,
                    base_dh_key_b64 TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS prekeys (
                    username TEXT PRIMARY KEY,
                    signed_prekey_b64 TEXT NOT NULL,
                    signed_prekey_sig_b64 TEXT NOT NULL,
                    one_time_prekeys_json TEXT NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_user TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS file_blobs (
                    file_id TEXT PRIMARY KEY,
                    uploader TEXT NOT NULL,
                    ciphertext_blob BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)

    async def handle_connection(self, websocket: WebSocketServerProtocol) -> None:
        """Handle incoming client WebSocket connection and dispatch messages."""
        authenticated_user: str | None = None
        try:
            # 1. Send challenge nonce to client
            challenge_nonce = os.urandom(32).hex()
            self.pending_challenges[websocket] = {"nonce": challenge_nonce}
            await websocket.send(json.dumps({
                "type": "challenge",
                "nonce": challenge_nonce,
            }))

            async for raw_msg in websocket:
                try:
                    data = json.loads(raw_msg)
                except Exception:
                    await websocket.send(json.dumps({"type": "error", "message": "Malformed JSON"}))
                    continue

                msg_type = data.get("type")

                # Handle Registration
                if msg_type == "register":
                    res = self._handle_register(data)
                    await websocket.send(json.dumps(res))
                    continue

                # Handle Authentication / Login
                if msg_type == "auth":
                    user = self._handle_auth(websocket, data)
                    if user:
                        authenticated_user = user
                        self.online_clients[authenticated_user] = websocket
                        await websocket.send(json.dumps({"type": "auth_ok", "username": user}))
                        # Deliver any queued offline messages
                        await self._flush_offline_messages(user, websocket)
                    else:
                        await websocket.send(json.dumps({"type": "error", "message": "Auth failed: invalid signature"}))
                    continue

                # For all other operations, client must be authenticated
                if not authenticated_user:
                    await websocket.send(json.dumps({"type": "error", "message": "Unauthorized"}))
                    continue

                # Upload Prekey Bundle
                if msg_type == "upload_prekeys":
                    res = self._handle_upload_prekeys(authenticated_user, data)
                    await websocket.send(json.dumps(res))

                # Fetch Prekey Bundle
                elif msg_type == "get_prekey_bundle":
                    res = self._handle_get_prekey_bundle(data.get("target_user", ""))
                    await websocket.send(json.dumps(res))

                # Route Envelope (1:1 message)
                elif msg_type == "relay_envelope":
                    await self._handle_relay_envelope(authenticated_user, data, websocket)

                # Store File Blob
                elif msg_type == "upload_file_blob":
                    res = self._handle_upload_file_blob(authenticated_user, data)
                    await websocket.send(json.dumps(res))

                # Download File Blob
                elif msg_type == "download_file_blob":
                    res = self._handle_download_file_blob(data)
                    await websocket.send(json.dumps(res))

                else:
                    await websocket.send(json.dumps({"type": "error", "message": f"Unknown type: {msg_type}"}))

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.pending_challenges.pop(websocket, None)
            if authenticated_user and self.online_clients.get(authenticated_user) == websocket:
                del self.online_clients[authenticated_user]

    def _handle_register(self, data: dict) -> dict:
        username = data.get("username", "").strip()
        identity_key_b64 = data.get("identity_key_b64", "")
        base_dh_key_b64 = data.get("base_dh_key_b64", "")

        if not username or not identity_key_b64 or not base_dh_key_b64:
            return {"type": "error", "message": "Missing registration fields"}

        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return {"type": "error", "message": "Username already exists"}

            cursor.execute(
                "INSERT INTO users (username, identity_key_b64, base_dh_key_b64, created_at) VALUES (?, ?, ?, ?)",
                (username, identity_key_b64, base_dh_key_b64, int(time.time())),
            )
        return {"type": "register_ok", "username": username}

    def _handle_auth(self, websocket: WebSocketServerProtocol, data: dict) -> str | None:
        username = data.get("username")
        sig_b64 = data.get("sig_b64")
        challenge_info = self.pending_challenges.get(websocket)

        if not username or not sig_b64 or not challenge_info:
            return None

        cursor = self.conn.cursor()
        cursor.execute("SELECT identity_key_b64 FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return None

        identity_key_bytes = base64.b64decode(row[0])
        nonce_bytes = challenge_info["nonce"].encode("utf-8")
        sig_bytes = base64.b64decode(sig_b64)

        if verify_signature(identity_key_bytes, nonce_bytes, sig_bytes):
            return username
        return None

    def _handle_upload_prekeys(self, user: str, data: dict) -> dict:
        spk_b64 = data.get("signed_prekey_b64")
        spk_sig_b64 = data.get("signed_prekey_sig_b64")
        opk_list = data.get("one_time_prekeys", [])

        if not spk_b64 or not spk_sig_b64:
            return {"type": "error", "message": "Invalid prekey payload"}

        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO prekeys (username, signed_prekey_b64, signed_prekey_sig_b64, one_time_prekeys_json)
                VALUES (?, ?, ?, ?)
            """, (user, spk_b64, spk_sig_b64, json.dumps(opk_list)))
        return {"type": "upload_prekeys_ok"}

    def _handle_get_prekey_bundle(self, target_user: str) -> dict:
        cursor = self.conn.cursor()
        cursor.execute("SELECT identity_key_b64, base_dh_key_b64 FROM users WHERE username = ?", (target_user,))
        user_row = cursor.fetchone()
        if not user_row:
            return {"type": "error", "message": f"User {target_user} not found"}

        cursor.execute("SELECT signed_prekey_b64, signed_prekey_sig_b64, one_time_prekeys_json FROM prekeys WHERE username = ?", (target_user,))
        prekey_row = cursor.fetchone()
        if not prekey_row:
            return {"type": "error", "message": f"No prekeys found for {target_user}"}

        opk_list = json.loads(prekey_row[2])
        one_time_prekey = None
        if opk_list:
            one_time_prekey = opk_list.pop(0)
            # Update remaining one-time prekeys in DB
            with self.conn:
                self.conn.execute("UPDATE prekeys SET one_time_prekeys_json = ? WHERE username = ?", (json.dumps(opk_list), target_user))

        return {
            "type": "prekey_bundle",
            "target_user": target_user,
            "identity_key_b64": user_row[0],
            "base_dh_key_b64": user_row[1],
            "signed_prekey_b64": prekey_row[0],
            "signed_prekey_sig_b64": prekey_row[1],
            "one_time_prekey": one_time_prekey,
        }

    async def _handle_relay_envelope(self, sender: str, data: dict, sender_ws: WebSocketServerProtocol) -> None:
        envelope_data = data.get("envelope")
        if not envelope_data:
            await sender_ws.send(json.dumps({"type": "error", "message": "Missing envelope"}))
            return

        try:
            envelope = Envelope.from_json(json.dumps(envelope_data))
        except ProtocolError as e:
            await sender_ws.send(json.dumps({"type": "error", "message": f"Invalid envelope: {e}"}))
            return

        # Anti-spoofing check: sender in envelope must match authenticated session
        if envelope.from_user != sender:
            await sender_ws.send(json.dumps({"type": "error", "message": "Sender identity spoofing rejected"}))
            return

        recipient_ws = self.online_clients.get(envelope.to_user)
        if recipient_ws:
            # Deliver in real-time
            await recipient_ws.send(json.dumps({
                "type": "inbound_envelope",
                "envelope": json.loads(envelope.to_json()),
            }))
        else:
            # Store offline message
            with self.conn:
                self.conn.execute(
                    "INSERT INTO offline_messages (to_user, envelope_json, created_at) VALUES (?, ?, ?)",
                    (envelope.to_user, envelope.to_json(), int(time.time())),
                )

        await sender_ws.send(json.dumps({"type": "envelope_relayed", "counter": envelope.counter}))

    async def _flush_offline_messages(self, username: str, ws: WebSocketServerProtocol) -> None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, envelope_json FROM offline_messages WHERE to_user = ? ORDER BY id ASC", (username,))
        rows = cursor.fetchall()
        for msg_id, envelope_json in rows:
            await ws.send(json.dumps({
                "type": "inbound_envelope",
                "envelope": json.loads(envelope_json),
            }))
        if rows:
            with self.conn:
                self.conn.execute("DELETE FROM offline_messages WHERE to_user = ?", (username,))

    def _handle_upload_file_blob(self, uploader: str, data: dict) -> dict:
        file_id = data.get("file_id")
        ciphertext_blob_b64 = data.get("ciphertext_blob_b64")
        if not file_id or not ciphertext_blob_b64:
            return {"type": "error", "message": "Invalid file upload payload"}

        blob_bytes = base64.b64decode(ciphertext_blob_b64)
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO file_blobs (file_id, uploader, ciphertext_blob, created_at)
                VALUES (?, ?, ?, ?)
            """, (file_id, uploader, blob_bytes, int(time.time())))
        return {"type": "upload_file_blob_ok", "file_id": file_id}

    def _handle_download_file_blob(self, data: dict) -> dict:
        file_id = data.get("file_id")
        cursor = self.conn.cursor()
        cursor.execute("SELECT ciphertext_blob FROM file_blobs WHERE file_id = ?", (file_id,))
        row = cursor.fetchone()
        if not row:
            return {"type": "error", "message": f"File blob {file_id} not found"}

        return {
            "type": "download_file_blob_ok",
            "file_id": file_id,
            "ciphertext_blob_b64": base64.b64encode(row[0]).decode("ascii"),
        }

"""Server CLI runner for CipherRelay."""

import asyncio
import os

import websockets

from cipherrelay.server.relay import RelayServer


async def main():
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", "0.0.0.0")
    db_path = os.environ.get("CIPHERRELAY_DB", "cipherrelay_server.db")

    server = RelayServer(db_path=db_path)

    print("=" * 60)
    print("   🌐 CipherRelay Zero-Knowledge Relay Server")
    print(f"   Listening on ws://{host}:{port}")
    print(f"   Database: {db_path} (zero plaintext / zero private keys)")
    print("=" * 60)

    async with websockets.serve(server.handle_connection, host, port):
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down.")

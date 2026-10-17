"""Interactive CLI client for CipherRelay."""

import asyncio
import os
from pathlib import Path

from cipherrelay.client.client import CipherRelayClient
from cipherrelay.crypto.identity import IdentityKeyPair
from cipherrelay.storage.keystore import InvalidPassphraseError, load_keystore, save_keystore


def print_banner():
    print("=" * 60)
    print("   🔐 CipherRelay - End-to-End Encrypted Messenger & Files")
    print("   Untrusted Relay Server | X3DH | Ratchet | Libsodium")
    print("=" * 60)


async def main():
    print_banner()
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    keystore_dir = Path.home() / ".cipherrelay"
    keystore_path = keystore_dir / f"{username}.keystore"

    if keystore_path.exists():
        passphrase = input(f"Enter passphrase to unlock keystore for '{username}': ")
        try:
            identity = load_keystore(keystore_path, passphrase)
            print("Keystore unlocked successfully.")
        except InvalidPassphraseError:
            print("Error: Invalid passphrase or corrupted keystore!")
            return
    else:
        print(f"Creating fresh identity keys for '{username}'...")
        identity = IdentityKeyPair.generate()
        passphrase = input("Set a strong passphrase for your local keystore: ")
        save_keystore(keystore_path, identity, passphrase)
        print(f"Keys saved and encrypted in {keystore_path}")

    server_url = os.environ.get("CIPHERRELAY_SERVER", "ws://localhost:8765")
    client = CipherRelayClient(username=username, identity=identity, server_url=server_url)

    print(f"Connecting to relay server at {server_url}...")
    try:
        await client.connect_and_register()
    except Exception:
        # If registration failed because user exists, authenticate
        await client.connect_and_auth()

    print("Connected & Authenticated! Starting listener...")

    def on_msg(sender, text):
        print(f"\n[📩 Message from {sender}]: {text}\n> ", end="", flush=True)

    def on_file(sender, filename, data):
        out_dir = Path("received_files")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"{sender}_{filename}"
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"\n[📁 File received from {sender}]: saved to {out_path} ({len(data)} bytes)\n> ", end="", flush=True)

    def on_key_warn(sender, old_key, new_key):
        print(f"\n⚠️  SECURITY WARNING: Identity key for {sender} has CHANGED! Possible MITM attack!\n> ", end="", flush=True)

    client.on_message_received = on_msg
    client.on_file_received = on_file
    client.on_key_change_warning = on_key_warn

    await client.start_listening()

    print("\nCommands:")
    print("  /msg <user> <text>      - Send encrypted message")
    print("  /file <user> <path>     - Send encrypted file")
    print("  /fingerprint            - View your public identity key")
    print("  /quit                   - Exit")

    loop = asyncio.get_running_loop()
    try:
        while True:
            cmd = await loop.run_in_executor(None, input, "> ")
            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd == "/quit":
                break
            elif cmd == "/fingerprint":
                print(f"Your Identity Key: {identity.public_identity_b64}")
            elif cmd.startswith("/msg "):
                parts = cmd[5:].split(" ", 1)
                if len(parts) == 2:
                    recipient, text = parts
                    await client.send_message(recipient, text)
                    print(f"Encrypted message sent to {recipient}!")
                else:
                    print("Usage: /msg <user> <text>")
            elif cmd.startswith("/file "):
                parts = cmd[6:].split(" ", 1)
                if len(parts) == 2:
                    recipient, file_path_str = parts
                    fpath = Path(file_path_str)
                    if not fpath.exists():
                        print(f"File not found: {fpath}")
                        continue
                    with open(fpath, "rb") as f:
                        data = f.read()
                    fid = await client.send_file(recipient, fpath.name, data)
                    print(f"Encrypted file '{fpath.name}' sent to {recipient} (ID: {fid})!")
                else:
                    print("Usage: /file <user> <path>")
            else:
                print("Unknown command.")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())

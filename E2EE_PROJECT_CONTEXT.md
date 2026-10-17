# Project Context: End-to-End Encrypted Chat & File Sharing App

> Working name: **CipherRelay** (rename freely)
> Purpose: A portfolio-grade cybersecurity project. The goal is NOT to invent cryptography. It is to correctly **compose well-vetted primitives** into a secure protocol, document the threat model, and prove the design with tests.

---

## 1. Golden Rules

1. **Never write your own crypto primitives.** Use libsodium (PyNaCl) or an equivalent audited library.
2. **The server is untrusted.** It only relays ciphertext. If a compromised server can read messages, the design is broken.
3. **Write the threat model first**, then the code. Every design choice should trace back to a threat.
4. **Be honest in the README** about what the project does NOT protect against. This signals maturity to reviewers.
5. This is an educational project. Do not claim it is a replacement for Signal.

---

## 2. Recommended Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | Fast to build, readable, good crypto bindings |
| Crypto | `PyNaCl` (libsodium) | Audited primitives, hard to misuse |
| Password KDF | Argon2id (via `argon2-cffi` or PyNaCl `pwhash`) | Protect local key store |
| Transport | `websockets` (asyncio) over TLS | Simple bidirectional relay |
| Server storage | SQLite (SQLAlchemy optional) | Store only public keys + ciphertext blobs |
| Client UI | CLI first (`prompt_toolkit` or `textual`) | Skip UI work, focus on security |
| Testing | `pytest`, `hypothesis` | Property-based tests suit crypto code |
| Tooling | `bandit`, `semgrep`, `pip-audit`, `ruff` | Show secure-development practice |

**Alternatives:** Go (`x/crypto`, `nacl`), Rust (`libsodium-sys`, `ring`, `orion`). Pick whichever you want to showcase.

---

## 3. Threat Model (starting draft, refine it)

### Assets
- Message and file plaintext
- Users' private keys
- Metadata (who talks to whom, when)

### Adversaries
| Adversary | Capability | In scope? |
|---|---|---|
| Passive network eavesdropper | Reads traffic | Yes (TLS + E2EE) |
| Active network attacker (MITM) | Modifies/injects traffic | Yes |
| Honest-but-curious server | Reads everything it stores | Yes |
| Malicious server | Replays, drops, reorders, swaps public keys | Partially (detect key swaps via safety numbers) |
| Stolen device/disk (offline) | Reads local files | Yes (encrypted key store) |
| Endpoint malware / compromised OS | Reads memory/keystrokes | **No** (document it) |
| Traffic analysis / metadata | Timing, sizes, social graph | **No** / partial (document it) |

### Security Goals
- **Confidentiality:** only sender and recipient read content
- **Integrity & authenticity:** tampering and impersonation are detected
- **Forward secrecy:** compromise of long-term keys does not expose past messages
- **Replay protection:** captured messages cannot be re-sent
- **Key-change detection:** user is warned when a contact's identity key changes

### Explicit Non-Goals
Metadata privacy, anonymity, deniability, post-quantum security, protection against compromised endpoints.

---

## 4. Architecture

```
 ┌──────────┐   TLS/WebSocket   ┌─────────────┐   TLS/WebSocket   ┌──────────┐
 │ Client A │ <───────────────> │ Relay Server│ <───────────────> │ Client B │
 │ (keys    │   ciphertext only │ (public keys│   ciphertext only │ (keys    │
 │  local)  │                   │  + blobs)   │                   │  local)  │
 └──────────┘                   └─────────────┘                   └──────────┘
```

### Server responsibilities (and nothing more)
- Register users and store **public** keys / prekeys
- Authenticate clients (challenge-response using signing key, no passwords on server)
- Queue and forward opaque encrypted envelopes (store-and-forward for offline users)
- Store encrypted file chunks (blob storage)
- Rate-limit and size-limit requests

### Client responsibilities
- Generate and protect all private keys
- Perform key agreement and encryption/decryption
- Verify contacts' key fingerprints (safety numbers)
- Chunk-encrypt files

---

## 5. Cryptographic Design

Build in levels. Ship each level working and tested before moving on.

### Level 1: Identity Keys and Basic Encrypted Messaging
- Each user generates:
  - **Ed25519** signing key (identity, authentication)
  - **X25519** key-exchange key
- Server stores public keys only.
- Message encryption: ephemeral-static Diffie-Hellman
  1. Sender generates fresh ephemeral X25519 keypair per message
  2. Derive shared secret with recipient's public key
  3. Derive symmetric key using HKDF (or libsodium `crypto_kdf` / `crypto_box` which does this internally)
  4. Encrypt with **XChaCha20-Poly1305** (AEAD)
  5. Sign envelope with sender's Ed25519 key
- Gives confidentiality, integrity, and authenticity. Forward secrecy is limited (see Level 3).

### Level 2: Authenticated Sessions and Replay Protection
- Challenge-response login: server sends random nonce, client signs it.
- Every message includes: sender ID, recipient ID, monotonically increasing counter, timestamp.
- Bind metadata into the AEAD **associated data** (sender, recipient, counter) so the server cannot swap or reroute ciphertexts.
- Receiver rejects duplicate or out-of-window counters.

### Level 3: Forward Secrecy (X3DH-style + Ratchet)
- Users upload a signed prekey plus a batch of one-time prekeys to the server.
- Initiator fetches a prekey bundle and runs an **X3DH-style** handshake to derive a shared root key (works even when the recipient is offline).
- Use a **symmetric-key ratchet** (HKDF chain) so each message gets a new key and old keys are deleted.
- Stretch: full **Double Ratchet** (adds DH ratchet for post-compromise security).
- Delete used message keys and one-time prekeys immediately.

> Read the Signal specs (X3DH, Double Ratchet) fully before implementing. Your implementation should follow them, not improvise.

### Level 4: Encrypted File Sharing
- Generate a random 256-bit file key per file.
- Encrypt in chunks (e.g., 64 KB) using libsodium **`secretstream`** (XChaCha20-Poly1305 streaming), which handles chunk ordering and truncation detection.
- Upload ciphertext chunks to the server blob store.
- Send the **file key, file ID, size, filename, and hash** inside a normal E2EE message (never to the server in plaintext).
- Recipient downloads chunks, decrypts, and verifies the final-chunk tag (detects truncation).
- Do not leak filenames or MIME types to the server.

### Level 5: Identity Verification
- Compute a **safety number** from both users' identity public keys (hash, then render as digits or QR).
- Users compare it out-of-band.
- Implement **TOFU** (trust on first use) with loud warnings and blocked sending when a contact's identity key changes.

### Level 6 (Stretch): Group Chat
- Start simple: pairwise fan-out (encrypt separately per member).
- Advanced: **Sender Keys** (as in Signal groups), with rekeying on member removal.

---

## 6. Local Key Storage

- Store private keys in an encrypted file or SQLCipher DB.
- Derive the encryption key from a passphrase with **Argon2id** (tune memory/time cost, store salt and parameters).
- Encrypt with an AEAD. Never store passphrases.
- Zero out sensitive buffers where possible (limited in Python, so document this limitation).
- File permissions `0600`.

---

## 7. Suggested Wire Protocol

Use a versioned envelope so the format can evolve.

```json
{
  "v": 1,
  "type": "msg | file_meta | key_bundle | ack",
  "from": "alice",
  "to": "bob",
  "counter": 42,
  "ts": 1760000000,
  "header": { "eph_pub": "<base64>", "prekey_id": 7 },
  "ciphertext": "<base64>",
  "sig": "<base64>"
}
```

Rules:
- Strict schema validation on server and client (reject unknown or oversized fields).
- Max message size and per-user rate limits.
- Constant-time comparisons for any secret-dependent checks.
- Never log plaintext, keys, or full ciphertext.

---

## 8. Suggested Repo Structure

```
cipherrelay/
├── README.md
├── THREAT_MODEL.md
├── PROTOCOL.md            # wire format + crypto design, diagrams
├── SECURITY.md            # how to report bugs, known limitations
├── pyproject.toml
├── src/cipherrelay/
│   ├── crypto/
│   │   ├── identity.py    # key generation, safety numbers
│   │   ├── x3dh.py        # handshake
│   │   ├── ratchet.py     # symmetric/double ratchet
│   │   ├── aead.py        # thin wrappers around libsodium
│   │   └── files.py       # chunked file encryption
│   ├── storage/keystore.py
│   ├── client/            # CLI, networking, session management
│   └── server/            # relay, auth, queue, blob store
├── tests/
│   ├── test_crypto_*.py
│   ├── test_protocol.py
│   ├── test_server_blindness.py
│   └── test_attacks.py    # tamper, replay, reorder, key-swap tests
├── scripts/demo.sh
└── .github/workflows/ci.yml
```

---

## 9. Build Roadmap

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | Threat model + protocol doc draft | Reviewed by you after a day away |
| 1 | Key generation + encrypted keystore | Keys survive restart, wrong passphrase fails |
| 2 | Relay server + login via signature | Two clients can connect and authenticate |
| 3 | 1:1 encrypted messaging (Level 1+2) | Server DB contains zero plaintext |
| 4 | Prekeys + X3DH + ratchet (Level 3) | Offline delivery works; old keys deleted |
| 5 | File sharing (Level 4) | 1 GB file transfers; truncation detected |
| 6 | Safety numbers + key-change warnings | MITM test is detected |
| 7 | Attack test suite + CI + fuzzing | All attacks in section 10 pass |
| 8 | Polish: README, diagrams, demo GIF, blog post | A stranger can run it in 5 minutes |
| 9 | Stretch: groups, Double Ratchet, TUI, metadata hardening | Optional |

---

## 10. Security Test Plan (this is what makes it impressive)

Write automated tests that **try to break** your own system:

- **Server blindness:** dump the server DB and logs, assert no plaintext or private keys appear.
- **Tampering:** flip a bit in ciphertext/header/AAD; decryption must fail.
- **Replay:** resend a captured envelope; receiver must reject.
- **Reordering/dropping:** out-of-order messages handled correctly within the window.
- **Key substitution MITM:** malicious server swaps Bob's public key; safety number mismatch is detected.
- **Impersonation:** forged sender field or invalid signature is rejected.
- **File truncation / chunk reorder:** detected by `secretstream`.
- **Forward secrecy:** after ratchet advances, leaking current state cannot decrypt older ciphertexts (test using saved ciphertexts).
- **Fuzzing:** fuzz the envelope parser with `hypothesis` or `atheris`.
- **Resource abuse:** oversized messages, connection floods, malformed JSON.

Run `bandit`, `semgrep`, and `pip-audit` in CI and show a clean badge.

---

## 11. Common Mistakes to Avoid

- Reusing a nonce with the same key (use random 24-byte XChaCha nonces or secretstream)
- Encrypting without authentication (always AEAD)
- Using the DH shared secret directly as a key (always run through a KDF)
- Sign-then-forget-context: signatures that do not cover recipient/counter enable replay or redirection
- Trusting server-provided public keys without a verification path
- Comparing MACs/tokens with `==` (use constant-time compare)
- Logging secrets, or leaving debug prints in
- Keeping old message keys or one-time prekeys after use
- Implementing "custom" key exchange or padding schemes
- Overclaiming in the README

---

## 12. Documentation Deliverables

1. **README:** problem statement, features, quick start, demo GIF, security guarantees and limitations.
2. **THREAT_MODEL.md:** assets, adversaries, goals, non-goals, mitigations table.
3. **PROTOCOL.md:** sequence diagrams (Mermaid works on GitHub), message formats, key schedule.
4. **Blog post:** "What I learned building an E2EE messenger" covering one or two mistakes you caught.
5. **Test report:** table of attacks attempted vs. result.

### Resume Bullet Templates
- Designed and implemented an end-to-end encrypted messaging and file-sharing system using X25519/Ed25519 and XChaCha20-Poly1305, with an X3DH-style handshake and ratcheting for forward secrecy.
- Built a zero-knowledge relay server; verified via automated tests that stored data contains no plaintext or private keys.
- Authored a threat model and 25+ adversarial tests (replay, tampering, key substitution, truncation) integrated into CI with SAST and dependency scanning.
- Implemented chunked authenticated encryption for files up to N GB with truncation and reordering detection.

---

## 13. References

- Signal specs: **X3DH**, **Double Ratchet**, **Sesame** (signal.org/docs)
- libsodium docs: `crypto_box`, `crypto_sign`, `crypto_secretstream`, `crypto_kdf`, `pwhash` (doc.libsodium.org)
- PyNaCl docs (pynacl.readthedocs.io)
- RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 9106 (Argon2)
- *Cryptography Engineering* (Ferguson, Schneier, Kohno)
- Cryptopals challenges (to understand how crypto breaks)
- Matrix Olm/Megolm specs (alternative design to compare against)
- OWASP Cryptographic Storage Cheat Sheet

---

## 14. Definition of Done

- [ ] Two clients exchange messages and files through the relay
- [ ] Server DB inspection reveals no plaintext, filenames, or private keys
- [ ] Forward secrecy demonstrated by test
- [ ] Safety-number verification and key-change warnings work
- [ ] Attack test suite passes; CI is green with SAST and dependency audit
- [ ] Threat model and protocol docs are complete and honest about limits
- [ ] A demo GIF or video and a quick-start under 5 minutes
- [ ] Blog post or write-up published

---

## 15. Using This File with an AI Coding Assistant

If you use an assistant while building, paste this file as context and give it focused tasks, for example:

> "Using the design in PROTOCOL.md Level 1, implement `aead.py` using PyNaCl with XChaCha20-Poly1305. Include type hints and pytest tests for tamper detection. Do not implement any custom primitives."

Review every crypto-related line yourself. Understand each construct well enough to explain it in an interview; that understanding is the actual value of the project.

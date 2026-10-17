# CipherRelay

CipherRelay is a portfolio-grade End-to-End Encrypted (E2EE) messaging and chunked file-sharing system designed with audited cryptographic primitives (PyNaCl / libsodium), an untrusted relay server architecture, X3DH prekey exchange, and symmetric ratcheting for forward secrecy.

## Features
- **Zero-Trust Relay Server**: Server only routes opaque ciphertext envelopes and chunked blobs. No plaintext or private keys ever touch the server.
- **Identity & Signatures**: Ed25519 for identity signing and challenge-response authentication.
- **Key Agreement**: X25519 Diffie-Hellman + HKDF key derivation.
- **Authenticated Encryption**: XChaCha20-Poly1305 with Associated Data (AAD) binding (sender, recipient, counter) to eliminate tamper and replay.
- **Encrypted Local Keystore**: Argon2id password-based key derivation protecting local credentials with strict OS file permissions.
- **Chunked File Transfer**: Libsodium `secretstream` streaming encryption with truncation and chunk-reordering detection.
- **Safety Numbers**: Visual/numerical cryptographic fingerprint comparison for MITM prevention (TOFU).

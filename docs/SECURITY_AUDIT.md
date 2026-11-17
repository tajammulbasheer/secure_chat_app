# Security Audit and Remediation

The first working version of this application was audited in June 2026, before it was hardened. This
document records the threat model, each finding, and its current status. Most fixes have an
architecture decision record (ADR) in [`docs/adrs/`](adrs/).

## Threat model

The application aims to protect against:

- **Eavesdropping on direct chats.** Messages and files between peers are end-to-end encrypted with AES-GCM.
- **Man-in-the-middle attacks on key exchange.** Peer certificates must be signed by the central CA and are then pinned (trust on first use).
- **Replay attacks.** Packets outside a 60-second window are rejected, and ratchet counters reject already-consumed messages.
- **Unauthorized registration.** New clients need the administrator's master password.

### Known limitations

1. **No NAT traversal.** Direct chat needs a reachable TCP port on each peer (no STUN/TURN/ICE).
2. **No persistent history.** Chat history is held in memory and lost when the app closes.
3. **No offline messaging.** Messages to offline users are dropped.
4. **Single CA.** If the central server is offline, no new users can register.

## Findings and status

| ID | Severity | Finding in the original version | Resolution | Record |
|----|----------|--------------------------------|------------|--------|
| C-1 | Critical | Group chats used a hardcoded shared key, so group messages had no confidentiality. | The group creator generates a random key and sends it to each member, encrypted to that member's public key. | [ADR 0004](adrs/0004-secure-group-chats.md) |
| C-2 | Critical | Clients pinned peer certificates without checking the CA signature, so a first contact could be intercepted. | Peer certificates are verified against the root CA before pinning. | [ADR 0002](adrs/0002-verify-ca-certs.md) |
| C-3 | Critical | The master password crossed the network in plaintext over raw TCP. | Client-to-server traffic runs over TLS. | [CHANGELOG](../CHANGELOG.md) |
| C-4 | Critical | Client private keys were stored on disk unencrypted. | Keys are encrypted with a user passphrase, and an empty passphrase is refused. | [ADR 0006](adrs/0006-secure-private-key-storage.md) |
| H-1 | High | Session keys were wrapped with long-term RSA keys, so there was no forward secrecy. | Sessions use ephemeral ECDHE (SECP256R1), followed by a Double Ratchet. | [ADR 0003](adrs/0003-ecdhe-perfect-forward-secrecy.md) |
| H-2 | High | AES-GCM was called without associated data, so packet metadata could be altered. | Session ID, sender, counter and timestamp are bound as associated data. | [ADR 0005](adrs/0005-aead-metadata-protection.md) |
| H-3 | High | The master password was checked with a single unsalted SHA-256 hash. | The server uses salted PBKDF2-HMAC-SHA256 with the hash and salt read from configuration, and refuses to start with the default hash outside development mode. A memory-hard hash such as Argon2id would be stronger. | [ADR 0008](adrs/0008-dotenv-and-configurations.md) |
| H-4 | High | A captured message could be replayed repeatedly within the 60-second window. | Ratchet counters reject messages that were already consumed. | [ADR 0003](adrs/0003-ecdhe-perfect-forward-secrecy.md) |
| M-1 | Medium | Message signatures used PKCS#1 v1.5 padding. | Message signatures use RSA-PSS. X.509 certificate verification follows the CA's signature scheme. | [CHANGELOG](../CHANGELOG.md) |
| M-2 | Medium | Server data was kept in plaintext JSON files. | Data moved to SQLite with a one-time JSON migration. Server files rely on OS permissions and are not encrypted at rest. | [`server/database.py`](../server/database.py) |
| M-3 | Medium | Shared server state was read outside the lock in some places. | Not yet re-checked after the refactor. | Open |
| L-1 | Low | Session keys were not cleared from memory when a session ended. | Ratchet key material is zeroized when a session is discarded. Python cannot guarantee that every copy is erased. | [`shared/crypto_utils.py`](../shared/crypto_utils.py) |
| L-2 | Low | The server address and port were hardcoded in the clients. | Configuration is read from environment variables (`.env`). | [ADR 0008](adrs/0008-dotenv-and-configurations.md) |

## Open items

- M-3: confirm that every read of shared server state holds the lock.
- The development CA lacks some RFC 5280 extensions, so the client turns off strict X.509 checking. Regenerating the CA with the correct extensions would allow strict mode again (see the comment in `client/client_engine.py`).
- The server's CA private key is stored unencrypted on the server host.

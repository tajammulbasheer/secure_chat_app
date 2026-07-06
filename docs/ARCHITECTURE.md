# System Architecture & Cryptographic Protocols

This document details the system design, communication protocols, and cryptographic structures used in the Secure Chat Application.

---

## 1. System Topology
The application uses a **hybrid client-server and peer-to-peer (P2P)** architecture. 

```
                ┌───────────────────────────────────┐
                │   Security Token Service (STS)    │
                │        (CA & User Registry)       │
                └──────┬─────────────────────┬──────┘
                       ▲                     ▲
        1. Auth & Registry            1. Auth & Registry
                       │                     │
                       ▼                     ▼
             ┌─────────────────┐    3. P2P   ┌─────────────────┐
             │  Client Alice   │◄==========►│   Client Bob    │
             │ (Peer Port 7000)│    E2EE    │ (Peer Port 7001)│
             └─────────────────┘             └─────────────────┘
```

1. **Security Token Service (STS)**:
   - Coordinates user registrations and authentications.
   - Signs Certificate Signing Requests (CSRs) for client keys.
   - Manages the online user list, mapping usernames to active IP addresses and peer ports.
   - Relays session keys and offline indicators.
2. **Peer Clients**:
   - Each client hosts an internal TCP socket listener (e.g., ports `7000`, `7001`) to accept direct connections from authorized peers.
   - Performs End-to-End Encrypted (E2EE) messaging directly without server relaying once sessions are confirmed.

---

## 2. Framing & Transport Protocol
To exchange structured payloads over TCP streams, the application uses a custom framing protocol:
- **Packet Structure**:
  - `Header`: 4-byte big-endian unsigned integer representing the byte length of the payload.
  - `Payload`: UTF-8 encoded JSON string.

Example representation:
```
┌─────────────────────────┬──────────────────────────────────────────┐
│  Length Prefix (4-byte) │              JSON Payload                │
│    e.g., \x00\x00\x00\x3F│ {"type":"AUTH_INIT","username":"alice"}   │
└─────────────────────────┴──────────────────────────────────────────┘
```

---

## 3. Cryptographic Lifecycle

### Phase 1: Enrollment & Authentication
1. **Enrollment**: 
   - Administrator registers a user with the server by providing a master password.
   - The client generates an RSA-2048 key-pair locally, submits a CSR to the STS, and receives an X.509 certificate signed by the server's Root CA (`rootCA.pem`).
2. **Challenge-Response Authentication**:
   - Client requests challenge via `AUTH_INIT`.
   - STS responds with a cryptographically secure 16-byte random nonce challenge.
   - Client signs the challenge using its RSA private key and returns the signature and X.509 certificate.
   - STS verifies the certificate signature chain, checks validity dates, inspects the certificate revocation status, and verifies the challenge signature. If successful, client is authenticated and registered as online.

### Phase 2: Key Exchange & Session Agreement
To set up a direct secure chat, clients negotiate a symmetric session key with Perfect Forward Secrecy:
1. **Fetch Peer Certificate**: Alice requests Bob's connection metadata and X.509 certificate from the STS.
2. **ECDHE Agreement**: Alice and Bob generate ephemeral EC private keys (using SECP256R1) and compute their public keys.
3. **Signature and Authentication**: Alice signs her ephemeral public key using her RSA private key (with RSA-PSS) to verify origin authenticity.
4. **Relay**: Alice's signed ephemeral public key is sent to Bob, and Bob's is returned to Alice.
5. **Verification & Derivation**: Alice and Bob verify each other's signatures and certificates back to the Root CA. They perform Diffie-Hellman key agreement to derive a shared secret, and use HKDF-SHA256 to generate the symmetric session key.
6. **Direct Handshake**: Bob connects to Alice's peer port. They verify the session key via a secure challenge-response exchange using HMAC-SHA256.

### Phase 3: Encryption & Key Ratcheting
- **Data Encryption**: All chat messages and file transfers use **AES-GCM (256-bit key)** with a random 12-byte initialization vector (IV).
- **Key Ratcheting**:
  - To mitigate risk, session keys are rotated every 10 messages.
  - The active key is derived from the master session key using HKDF-SHA256:
    $$\text{key}_{\text{interval}} = \text{HKDF}(\text{salt}=\text{None}, \text{info}=\text{bytes("chat\_interval\_" } + \text{index}), \text{secret}=\text{session\_key})$$

---

## 4. Current Architecture Limitations & Mitigations
- **Lack of Transport-Level Encryption to STS**: Command/control server communication currently runs over raw TCP sockets.
  * *Mitigation Plan*: Wrap the STS socket in an SSL/TLS context to secure registration and challenge-response metadata in transit. (Work in progress in Milestone 1).
- **In-Memory History**: Message histories are transient.
  * *Mitigation Plan*: Implement secure local SQLite logs encrypted with keys derived from the user passphrase.
- **NAT Traversal (STUN/TURN/ICE)**: Direct P2P assumes both peers are reachable on public/forwarded ports.
  * *Mitigation Plan*: Introduce NAT hole punching or a server-relayed fallback for firewalled clients.

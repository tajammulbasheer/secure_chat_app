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
To set up a direct secure chat, clients must negotiate a symmetric session key:
1. **Fetch Peer Certificate**: Alice requests Bob's connection metadata and X.509 certificate from the STS.
2. **Symmetric Session Key Generation**: Alice generates a random 32-byte master session key and a challenge nonce.
3. **Encapsulation**: Alice encrypts the master session key using Bob's RSA public key (extracted from his certificate) using RSA-OAEP-SHA256.
4. **Signature**: Alice signs the session key using her private key to guarantee origin authenticity.
5. **Relay**: The encrypted session key, signature, challenge nonce, and Alice's certificate are relayed through the STS to Bob.
6. **Verification & Decryption**: Bob decrypts the session key using his private key and verifies Alice's signature using her certificate.
7. **Direct Handshake**: Bob connects to Alice's peer port and computes an HMAC-SHA256 MAC of Alice's challenge nonce using the session key. Alice verifies the MAC. The session is confirmed.

### Phase 3: Encryption & Key Ratcheting
- **Data Encryption**: All chat messages and file transfers use **AES-GCM (256-bit key)** with a random 12-byte initialization vector (IV).
- **Key Ratcheting**:
  - To mitigate risk, session keys are rotated every 10 messages.
  - The active key is derived from the master session key using HKDF-SHA256:
    $$\text{key}_{\text{interval}} = \text{HKDF}(\text{salt}=\text{None}, \text{info}=\text{bytes("chat\_interval\_" } + \text{index}), \text{secret}=\text{session\_key})$$

---

## 4. Current Architecture Limitations & Mitigations
- **Lack of Perfect Forward Secrecy**: Master session keys are encrypted directly via RSA. If a user's long-term private key is leaked, historical session keys can be decrypted. 
  * *Mitigation Plan*: Transition key exchange to Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) signed by RSA keys.
- **Unverified Certificate Authorities**: Peer-to-Peer certificate exchanges verify fingerprints against pinned certificates, but don't verify trust chains back to the Root CA on initial connection.
  * *Mitigation Plan*: Integrate Root CA verification in client validation paths.
- **In-Memory History**: Message histories are transient.
  * *Mitigation Plan*: Implement secure local SQLite logs encrypted with keys derived from the user passphrase.

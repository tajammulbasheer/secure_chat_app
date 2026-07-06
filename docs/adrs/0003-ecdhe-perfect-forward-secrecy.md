# 3. Perfect Forward Secrecy (ECDHE) & RSA-PSS Signatures

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
In the initial security audit, vulnerability **[H-1] (Lack of Perfect Forward Secrecy)** was identified. The current session key exchange relies on RSA encryption: Alice encrypts a session key using Bob's long-term RSA public key. If Bob's long-term private key `client.key` is compromised in the future, all historically recorded ciphertext streams can be decrypted by the attacker.

Additionally, signatures are generated using the outdated **PKCS#1 v1.5** signature padding (**[M-1]**), which is mathematically inferior to modern probabilistic signature padding.

We need a secure key exchange mechanism that ensures future compromise of long-term keys does not compromise past session confidentiality, while modernizing our signature padding.

## Decision Drivers
* Achieve Perfect Forward Secrecy (PFS) for all E2EE chats.
* Protect key negotiations from MITM attacks.
* Deprecate legacy cryptographic padding schemes (PKCS#1 v1.5) in favor of industry standards (RSA-PSS).

## Considered Options
1. **Option A**: Keep RSA key encapsulation but rotate RSA keys frequently. (High overhead, doesn't fully guarantee PFS for short-lived sessions).
2. **Option B (ECDHE with RSA-PSS signatures)**: Perform an Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) key agreement using curve `SECP256R1`. Clients generate temporary EC keypairs for each session, exchange public keys signed with their long-term RSA private keys using RSA-PSS padding, and derive the session key using ECDH.

## Decision Outcome
Chosen Option: **Option B (ECDHE with RSA-PSS signatures)**

### Protocol Flow
1. Alice generates an ephemeral EC private key $d_A$ and public key $Q_A = d_A \cdot G$.
2. Alice signs $Q_A$ using her long-term RSA private key with **RSA-PSS** padding.
3. Alice transmits $Q_A$ and the signature to Bob via the STS.
4. Bob verifies Alice's signature using her RSA certificate.
5. Bob generates an ephemeral EC private key $d_B$ and public key $Q_B = d_B \cdot G$.
6. Bob signs $Q_B$ using his long-term RSA private key with **RSA-PSS** padding.
7. Bob sends $Q_B$ and the signature to Alice.
8. Alice verifies Bob's signature.
9. Both compute the shared secret $S = d_A \cdot Q_B = d_B \cdot Q_A$.
10. The session key is derived from $S$ using HKDF-SHA256.

### Positive Consequences
- **Perfect Forward Secrecy**: The compromise of a client's long-term RSA key does not compromise past session keys, as ephemeral keys $d_A$ and $d_B$ are discarded from memory immediately after key derivation.
- **Robust Signatures**: RSA-PSS padding is used for all signatures, resolving vulnerability **[M-1]**.

### Negative Consequences
- Increases protocol message size and complexity, as clients must relay EC public keys and signatures.
- Slightly higher CPU overhead due to elliptic curve point multiplications.

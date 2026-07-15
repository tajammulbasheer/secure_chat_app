# ADR 0015: Double Ratchet Algorithm & Identity Verification

**Date:** 2026-07-09  
**Status:** Accepted

## Context
While our Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) exchange provided Perfect Forward Secrecy for the *initial* session, the protocol did not provide forward secrecy for individual messages sent within that session, nor did it offer Post-Compromise Security (healing if a session key is temporarily compromised). Furthermore, relying solely on Central Server (STS) signed certificates for identity was insufficient against advanced MITM attacks if the STS itself was fully compromised. We needed an out-of-band identity verification mechanism.

## Decision
We implemented a variant of the Double Ratchet Algorithm (inspired by Signal) alongside Safety Numbers.
1. **Double Ratchet**: Instead of just using a single symmetric session key or a simple KDF counter ratchet, peers continuously execute Diffie-Hellman ratchet steps to update the root chain, sending and receiving keys for every new message. This guarantees full forward and backward (post-compromise) secrecy.
2. **Safety Numbers**: We implemented an out-of-band identity verification feature where users can compare cryptographic fingerprints (Safety Numbers) generated from their public keys to manually verify the authenticity of the E2EE tunnel.

## Consequences
- **Positive**: State-of-the-art cryptographic security for active chat sessions. Complete protection against long-term session key compromise. Stronger identity assurances.
- **Negative**: Considerably increased complexity in the client state machine (managing KDF chains and out-of-order message keys). Slightly larger packet headers to transmit ephemeral public keys.

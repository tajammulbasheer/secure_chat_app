# 2. Verify Client Certificates against Root CA

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
In the initial security audit, vulnerability **[C-2] (Bypassed Certificate Authority Validation)** was identified. During session exchanges (`FETCH_CERT` and `RELAY_SESSION_KEY`), the client engines pinned peer certificates using Trust-On-First-Use (TOFU) check against a local registry file `known_peers.json`, but **never validated the certificate signature** against the Root CA.

This enables a Man-In-The-Middle (MITM) attacker to intercept connections, present a self-signed certificate mimicking a valid user, and negotiate session keys. 

## Decision Drivers
* Enforce cryptographic trust boundaries: only certificates signed by the official server Root CA are trusted.
* Retain the TOFU registry to protect against Root CA compromise/impersonation (hybrid trust model).
* Keep verification fast and robust.

## Considered Options
1. **Option A (Only TOFU)**: Trust any certificate on first connection, pinning the fingerprint. (Vulnerable to first-connection MITM).
2. **Option B (Only CA Signature)**: Trust any certificate signed by the Root CA. (Vulnerable if the CA key is compromised or if someone obtains a certificate signed with a rogue common name).
3. **Option C (Hybrid Trust: CA Validation + Fingerprint TOFU)**: Verify that the certificate is signed by the Root CA *and* is not revoked, then check if the fingerprint matches the pinned fingerprint in `known_peers.json` (if pinned). If not pinned, verify Root CA, extract name, and pin fingerprint.

## Decision Outcome
Chosen Option: **Option C (Hybrid Trust)**

### Positive Consequences
- Mitigates the first-connection MITM vulnerability completely. An attacker cannot present a self-signed certificate, as it won't pass CA chain validation.
- Retains the benefit of TOFU pinning to prevent rogue CA certificate issuance.

### Negative Consequences
- Every client must have local access to `rootCA.pem`.
- Clock synchronization issues between clients can cause validation to fail if certificate validity windows are strictly checked but systems have mismatched times.

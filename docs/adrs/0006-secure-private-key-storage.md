# 6. Secure Local Client Private Key Storage

* Status: **Accepted**
* Date: 2026-07-02
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
In the initial security audit, vulnerability **[C-4] (Plaintext Storage of Client Private Keys)** was identified. Currently, when a user registers, the client engine generates an RSA private key and saves it to disk at `client_<username>/client.key` in plaintext (using `serialization.NoEncryption()`). 

If an attacker gains local access to the device or if another process compromises the user's filesystem space, the client private key can be copied. This allows the attacker to impersonate the user or decrypt past session keys. We need a way to protect the client's long-term RSA private key on disk.

## Decision Drivers
* Prevent local unauthorized extraction of client private keys.
* Maintain a seamless CLI/GUI login experience while prompting for credentials securely.
* Utilize standard, proven key derivation functions (KDFs) and encryption primitives.

## Considered Options
1. **Option A (Passphrase-Encrypted PKCS#8)**: Serialize the private key using `serialization.BestAvailableEncryption(passphrase)` using Python's cryptography library. (Standard format, robust protection, requires password input on app launch).
2. **Option B (Platform Key Store Integration)**: Store the key in system keychains like Windows Credential Manager or macOS Keychain. (Highly secure, but limits project portability and complicates cross-platform deployment for a Python portfolio app).
3. **Option C (Local Key Derivation + Custom AES-GCM Envelope)**: Encrypt the key bytes with AES-GCM using a key derived from the user's local passphrase via PBKDF2.

## Decision Outcome
Chosen Option: **Option A (Passphrase-Encrypted PKCS#8)**

### Implementation
1. **Enrollment / Registration**:
   When registering a user, prompt for a local private key passphrase (distinct from or matching the STS master password).
   Serialize and save the key bytes using:
   ```python
   private_key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
   )
   ```
2. **Load / Authentication**:
   When loading the client engine for authentication:
   - CLI/GUI prompts the user: `Enter your private key passphrase:`.
   - The engine attempts to load the private key using:
     ```python
     load_pem_private_key(key_data, password=passphrase.encode())
     ```
   - If loading fails (due to incorrect passphrase), raise a clean "Incorrect Passphrase" exception and terminate.

### Positive Consequences
- **Local Key Protection**: The private key is never saved in plaintext on disk. Theft of `client.key` alone does not compromise the user's identity. Resolves vulnerability **[C-4]**.
- **Standards Adherence**: Utilizes the industry-standard PKCS#8 format.

### Negative Consequences
- Users must enter their passphrase every time they launch the client, slightly increasing interface friction.
- Forgetfulness results in unrecoverable data loss (the user must delete their profile, register a new key pair with the STS, and redistribute their new certificate).

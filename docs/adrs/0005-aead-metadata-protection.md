# 5. AEAD Associated Data Integration

* Status: **Accepted**
* Date: 2026-07-01
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
In the initial security audit, vulnerability **[H-2] (Unauthenticated Metadata in AES-GCM)** was identified. While the payload of messages and file chunks is encrypted using AES-GCM, the packet metadata headers (such as `session_id`, `sender` name, `counter`, and `timestamp`) are sent outside the ciphertext block. The AES-GCM Associated Data (AD) parameter is set to `None`. 

This enables an active network attacker to alter metadata headers (e.g., changing the sender's username, counter value, or message timestamps) in transit. Since the metadata is not included in the authentication tag generation, the receiver's AES-GCM decryption succeeds, allowing malicious packet tampering or replay attack manipulation.

## Decision Drivers
* Cryptographically authenticate all metadata associated with encrypted message envelopes.
- Prevent spoofing of packet headers (sender, counter, timestamp, session ID).
- Keep serialization clean and identical for both sending and receiving sides.

## Considered Options
1. **Option A (No Associated Data)**: Trust that transport or signature protocols verify identity. (Vulnerable to metadata manipulation and replay attack window bypass).
2. **Option B (JSON Serialized Associated Data)**: Serialize header fields into a standard JSON string and pass it to GCM. (Higher serialization overhead, minor variations in whitespace can fail tag verification).
3. **Option C (Delimited String Associated Data)**: Format headers as a strict, fixed-order delimited byte string (e.g. `session_id:sender:counter:timestamp`). (Low overhead, deterministic, easily formatted).

## Decision Outcome
Chosen Option: **Option C (Delimited String Associated Data)**

### Implementation
1. **Encryption & Decryption Utilities**:
   Update `aes_encrypt` and `aes_decrypt` in `shared/crypto_utils.py` to accept an optional `associated_data` parameter:
   ```python
   def aes_encrypt(key, plaintext: bytes, associated_data: bytes = None):
       aesgcm = AESGCM(key)
       nonce = os.urandom(12)
       ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
       return base64.b64encode(nonce).decode(), base64.b64encode(ciphertext).decode()
   ```
2. **Integration**:
   In `client/client_engine.py` (during `send_message`, `_handle_encrypted_message`, `send_file`, and `_handle_file_chunk`), format the AD string using:
   ```python
   ad_str = f"{session_id}:{sender}:{counter}:{timestamp}".encode()
   ```
   Pass this byte array to the AES encryption and decryption operations.

### Positive Consequences
- **Metadata Integrity**: Any modification of the `session_id`, `sender`, `counter`, or `timestamp` in transit will cause the GCM tag verification to fail during `aes_decrypt`, resulting in packet drop. Resolves vulnerability **[H-2]**.
- **Minimal Overhead**: DELIMITED string formatting consumes negligible CPU cycles.

### Negative Consequences
- Out-of-order fields or minor type changes (e.g., float vs. int timestamp) between sender and receiver will cause decryption to fail. Fields must be strictly synchronized.

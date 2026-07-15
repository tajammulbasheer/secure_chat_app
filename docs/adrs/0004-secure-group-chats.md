# 4. Creator-Distributed Pairwise Group Keys

* Status: **Accepted**
* Date: 2026-06-30
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
In the initial security audit, vulnerability **[C-1] (Lack of Security in Group Chats)** was identified. Group chats are initialized with a static hardcoded symmetric key: `b"static_group_key_32_bytes_shared"`. Consequently, any authenticated client, or any network eavesdropper, can decrypt all group chat traffic instantly. There is no cryptographic isolation between distinct group rooms.

We need a group key distribution protocol that ensures confidentiality and integrity of messages only for the designated group members.

## Decision Drivers
- Secure group chat confidentiality against unauthorized peers and network eavesdroppers.
- Limit changes to the STS server to avoid over-complicating central architecture.
- Maintain simple pairwise cryptography without complex Group Key Management (GKM) trees, suitable for small groups (5–20 users).

## Considered Options
1. **Option A (Central Server Key Distribution)**: The server generates the group key and distributes it. (Server must be trusted with the key, meaning group chats are not truly End-to-End Encrypted from the server's perspective).
2. **Option B (Asymmetrical Pairwise Creator-Distribution)**: The group creator generates a random 32-byte key locally, fetches certificates of all intended members from the STS, encrypts the group key separately for each member using their public RSA keys (RSA-OAEP-SHA256), signs each encrypted key package using their long-term RSA key, and uploads them to the STS. The STS relays the encrypted packages to the corresponding members upon group entry or invitation.

## Decision Outcome
Chosen Option: **Option B (Asymmetrical Pairwise Creator-Distribution)**

### Protocol Flow
1. **Group Creation**:
   - Alice creates a group room named "SecretRoom" and specifies Bob and Charlie as members.
   - Alice generates a random 32-byte `group_key` locally.
   - Alice fetches Bob and Charlie's certificates from the STS.
   - Alice encrypts the `group_key` using Bob's public key ($EK_{Bob}$) and Charlie's public key ($EK_{Charlie}$).
   - Alice signs both payloads using her private key.
   - Alice sends a `CREATE_GROUP` request to the STS containing the room name, the list of members, and the map of encrypted/signed keys.
2. **Group Sync**:
   - The STS registers the group and broadcasts `GROUP_CREATED` to the members, including their individual encrypted key payloads.
   - Bob and Charlie receive the `GROUP_CREATED` payload, verify Alice's signature, decrypt their respective package using their private RSA keys, and initialize the room session locally with the decrypted `group_key`.
3. **Communication**:
   - All messages sent within "SecretRoom" are encrypted using AES-GCM with the derived `group_key` and ratcheted message counters.

### Positive Consequences
- **True End-to-End Encryption**: The server never sees the plaintext `group_key`, preserving group chat confidentiality against server compromises.
- **Relatively low complexity**: Integrates into current client engines with minimal changes to database state on the server.

### Negative Consequences
- Group creation is $O(N)$ where $N$ is the number of members. Alice must perform $N-1$ encryptions and signatures. This is acceptable for typical group chat sizes.
- If a new member joins, the group creator must encrypt the key for them and distribute it.

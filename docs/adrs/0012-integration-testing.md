# 12. Socket-Level Integration Testing

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
We have unit tests in `tests/test_crypto.py` verifying cryptographic primitives, but we do not have tests verifying end-to-end socket operations (KDC registration, challenge-response auth, direct chat session agreements, group creation, message/file transmission over TCP sockets). 

To ensure that the KDC server and Client Engines integrate correctly and communicate over raw TCP sockets without manually launching multiple CLI client instances, we need automated socket-level integration tests.

## Decision Drivers
- Verify full client-server registration and challenge-response authentication.
- Verify peer-to-peer ECDHE handshake and secure message transmission over TCP sockets.
- Ensure clean teardown to prevent thread or socket leaks.

## Considered Options
1. **Option A (Manual Testing only)**: Run client/server terminals manually. (Fails to prevent regression, time-consuming, unsuited for CI pipelines).
2. **Option B (Threaded Socket Integration Testing)**: Implement integration tests under `tests/test_integration.py` that dynamically bind local ports, launch KDC/client loops in background threads, execute assertions, and close sockets.

## Decision Outcome
Chosen Option: **Option B (Threaded Socket Integration Testing)**

### Implementation Details
We will build `tests/test_integration.py` using `pytest` with the following structure:
1. **Fixtures**:
   - `sts_server`: Spawns the STS server on a dynamic port (`0` to let OS pick free port), runs `sts.main()` in a background thread, and stops it cleanly on teardown.
   - `temp_ca`: Sets up a temporary Root CA.
2. **Integration Cases**:
   - `test_client_registration_and_login`: Instantiates a `ClientEngine`, registers a new user with the server, receives CA certificate, and authenticates.
   - `test_direct_e2ee_chat_handshake`: Registers two users (Alice and Bob), initializes their engines, simulates Alice initiating a direct session with Bob, handles ECDHE exchange via server relay, confirms the session, and transmits encrypted direct messages.
   - `test_group_chat_e2ee`: Creates a group chat room, verifies group key distribution, and sends messages.

### Positive Consequences
- **Full Coverage**: Ensures socket transport framing, challenge nonces, and signature chains work in concert.
- **CI Compatible**: Actions runner can execute these integration tests inside the headless Ubuntu runner on push events.

### Negative Consequences
- Threaded socket execution is inherently asynchronous. Tests must use retry/polling helper loops to wait for events (e.g. key confirmation) rather than sleeping fixed amounts of time.
- Clean shutdown is critical; unclosed threads or sockets will cause the pytest process to hang indefinitely.

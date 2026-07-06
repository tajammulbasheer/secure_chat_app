# 7. Automated Test Suite using Pytest

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
The codebase currently has zero automated tests. Making changes to cryptographic modules (`shared/crypto_utils.py`), transport loops (`shared/transport.py`), client engine (`client/client_engine.py`), or STS server (`server/sts.py`) introduces regression risks. Validating integration flows currently requires a developer to manually start a server and multiple terminals to simulate users, which is slow and error-prone.

To verify protocol correctness, detect regressions, and demonstrate professional software engineering standards, we need a robust, automated test suite.

## Decision Drivers
- Support rapid, one-command verification of cryptographic and network operations.
- Isolate test code from production code.
- Minimize external dependencies while testing network sockets.

## Considered Options
1. **Option A (Python's Built-in Unittest)**: Standard library module. (Functional, but requires more boilerplate and is less expressive than pytest).
2. **Option B (Pytest Framework)**: Highly expressive, standard test runner in the Python community. Supports powerful fixtures, parameterized testing, and robust mocking.

## Decision Outcome
Chosen Option: **Option B (Pytest Framework)**

### Testing Architecture
1. **Unit Tests (`tests/test_crypto.py`)**:
   Test individual cryptographic functions in `shared/crypto_utils.py`:
   - Ephemeral EC key generation and PEM serialization.
   - HKDF derivation of PFS keys.
   - RSA-PSS signing and signature verification.
   - Root CA verification of certificate validity periods and signatures.
   - AES-GCM encryption and decryption with/without Associated Data (AD), validating tamper-resistance.
2. **Integration Tests (`tests/test_integration.py`)**:
   Verify network socket exchange loops:
   - Spin up a mock STS server thread on a dynamic local port.
   - Spawn two mock `ClientEngine` instances (e.g., Alice and Bob).
   - Simulate registration with CA signing.
   - Simulate challenge-response authentication.
   - Verify E2EE direct chat setup (PFS key agreement and session confirmation).
   - Verify group chat creation and E2EE message routing.
   - Terminate socket threads cleanly on test teardown.

### Positive Consequences
- **Automated Verification**: Runs in seconds, providing a safety net for future code modifications.
- **Portability**: Test suite can be run on any environment, paving the way for CI/CD container testing.

### Negative Consequences
- Threaded socket tests are prone to race conditions and port collisions if not designed cleanly. Integration tests must dynamically allocate free ports and handle connection timeouts.

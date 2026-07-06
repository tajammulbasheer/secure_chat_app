# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-10

### Added
- Created complete developer playbook and master chat guidelines.
- Bootstrapped project memory directory structure (`docs/`).
- Added system task board (`TODO.md`) and project roadmap (`docs/ROADMAP.md`).
- Prepared Architecture Decision Records (ADRs) layout.
- Added Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) key exchange module in `shared/crypto_utils.py`.
- Added dynamic member-certificate query capabilities on the server (`GET_MEMBER_CERTS`) to support decentralized group key distribution.
- Added private key passphrase inputs and prompts to both the CLI and PyQt6 GUI application registration and startup flows.
- Added automated unit testing package structure and cryptographic module assertions in `tests/test_crypto.py`.
- Added configuration modules `client/config.py` and `server/config.py` leveraging `python-dotenv` for loading environment configurations.
- Added `.env.example` defining external project configuration keys.
- Added a centralized `shared/logger.py` utility utilizing Python's standard `logging` library.
- Added `Dockerfile` and `docker-compose.yml` to support containerized execution of the STS server.
- Added `requirements.txt` listing project runtime dependencies.
- Added GitHub Actions Continuous Integration workflow `.github/workflows/ci.yml` to run test suites on push/PR events.
- Added comprehensive socket-level end-to-end integration tests in `tests/test_integration.py` verifying registration, authentication, ECDHE key agreement, direct messages, and group chat.
- Added final security refactoring and architecture `walkthrough.md` mapping out mitigated vulnerabilities and implementation details.
- Added central server TLS transport wrapping using dedicated certificates signed by the Root CA.
- Added background socket heartbeat ping-pong pings and client auto-reconnection logic.

### Changed
- Restructured code files into packages (`client/`, `server/`, `shared/`, `docs/`) and updated module import structures.
- Upgraded signature padding from PKCS#1 v1.5 to RSA-PSS for authenticating ephemeral EC keys.
- Replaced absolute documentation paths inside project files with relative paths.
- Refactored all console standard output print statements in client and server codebases to use unified logger severity levels.
- Polished root `README.md` to represent package execution commands, configuration instructions, testing, and Docker execution.

### Security
- Completed a comprehensive architecture and security audit (`PROJECT_ANALYSIS.md`) detailing critical, high, and medium vulnerabilities.
- Resolved bypassed certificate authority validation ([C-2]) by enforcing x509 signature verification against `rootCA.pem` before fingerprint pinning.
- Resolved unencrypted command/control STS server communication ([C-3]) by wrapping KDC socket connections in TLS.
- Mitigated Lack of Perfect Forward Secrecy ([H-1]) and legacy signature padding ([M-1]) by replacing RSA session key encapsulation with signed Ephemeral Diffie-Hellman (ECDHE SECP256R1) key agreement.
- Fixed complete lack of security in group chats ([C-1]) by replacing static keys with creator-generated pairwise key distribution encrypted with member certificates.
- Resolved unauthenticated metadata in AES-GCM ([H-2]) by passing serialized message header envelopes (`session_id:sender:counter:timestamp`) as Associated Data.
- Resolved plaintext storage of client private keys ([C-4]) by encrypting `client.key` on disk using standard PKCS#8 serialization with a user-provided passphrase.
- Resolved hardcoded configurations ([L-2]) and weak hashing of master password ([H-3]) by using environment configuration loading and a salted PBKDF2 hash scheme for register user checks.
- Scrubbed plain-text password outputs from log dumps to prevent leakage of credentials.

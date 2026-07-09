# 8. Configuration Management using Dotenv

* Status: **Accepted**
* Date: 2026-07-09
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
Configuration values, such as hosts, ports, database directory paths, and the STS administrator password hash, are currently hardcoded in multiple places across the client and server code (e.g. `127.0.0.1` and port `6000` in client files, and `PORT = 6000` in server files). 

This configuration approach violates the **Twelve-Factor App** methodology and introduces security risks:
1. **Exposure of Secrets**: Sensitive authentication secrets (like the administrative master password hash) are checked into version control.
2. **Lack of Portability**: It is difficult to run the server on a different IP/port or deploy it to a staging/cloud server without manually modifying source code files.

## Decision Drivers
- Decouple code configurations from environment secrets.
- Support easy transition between local development environments, containers (Docker), and cloud deployments.
- Upgrade the master password hash verification using a salted PBKDF2 scheme instead of plain SHA-256.

## Considered Options
1. **Option A (INI / JSON Configuration Files)**: Read settings from a local `.ini` or `.json` file. (Requires parsing libraries, files can accidentally be checked into git if not configured carefully).
2. **Option B (Environment Variables with Dotenv)**: Read settings directly from the system environment, backed by local `.env` files for development using `python-dotenv`.

## Decision Outcome
Chosen Option: **Option B (Environment Variables with Dotenv)**

### Implementation Details
1. **Dependencies**: Add `python-dotenv` to dependencies.
2. **Client Config (`client/config.py`)**:
   Load parameters such as `KDC_IP`, `KDC_PORT`, `PEER_PORT` from environment variables, using default fallback values (e.g., `127.0.0.1` and `6000`) for seamless developer onboarding.
3. **Server Config (`server/config.py`)**:
   Load `STS_IP`, `STS_PORT`, and the administrative `MASTER_PASSWORD_HASH` from environment variables.
4. **PBKDF2 Master Password Verification**:
   - Instead of checking against a hardcoded SHA-256 hash, derive a salted PBKDF2 hash using HMAC-SHA256, 100,000 iterations, and a salt stored in the `.env` configuration file.
5. **Git Protection**:
   Add `.env` to `.gitignore`. Create a `.env.example` file checked into Git showing standard configuration properties without actual secrets.

### Positive Consequences
- **Environment Isolation**: Secrets are kept outside of source code files, satisfying vulnerability audit item **[L-2]** and **[H-3]**.
- **Container Readiness**: Docker and Kubernetes can pass environment variables directly without needing local configurations.

### Negative Consequences
- Developers must copy `.env.example` to `.env` and fill it out when setting up the project locally.

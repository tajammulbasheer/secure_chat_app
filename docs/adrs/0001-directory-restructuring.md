# 1. Directory Restructuring

* Status: **Accepted**
* Date: 2026-07-09
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
The current codebase has code files (like `cli.py`), directories (`client_core/`, `sts/`, `common/`, `gui/`), and dynamic data files (`cert_db.json`, `revoked_serials.json`, `users.json`, `rootCA.key`, `rootCA.pem`, `rootCA.srl`, client folders) all located in the root directory. 

This causes several issues:
1. **Lack of separation of concerns**: Dynamic data and keys generated at runtime clutter the root folder.
2. **Confusing module system**: Imports are highly relative or rely on flat paths, which breaks packaging and modular testing.
3. **Unprofessional presentation**: Recruiters viewing the repo see a flat list of mixed scripts and data.

## Decision Drivers
* Make the codebase modular and exportable as Python packages.
* Separate transient runtime data (like certs and databases) from source code.
* Present a professional structure for code reviews and recruitment portfolios.

## Considered Options
1. **Option A (Status Quo)**: Keep files in the root. 
2. **Option B (Modular Structure)**: Restructure files into logical top-level packages:
   - `client/`: Containing GUI (`client/gui/`), CLI (`client/cli.py`), core client logic (`client/client_engine.py`), and a dedicated folder for client-side generated key-pairs and pinned peer certs (`client/data/`).
   - `server/`: Containing the KDC server (`server/sts.py`) and a dedicated folder for server databases and CA certificates (`server/data/`).
   - `shared/`: Shared crypto and transport wrappers.
   - `tests/`: For unit and integration tests.
   - `docs/`: For project memory, ADRs, and guides.

## Decision Outcome
Chosen Option: **Option B (Modular Structure)**

### Positive Consequences
* Absolute separation between client and server namespaces.
* Clear locations for writing tests and documentation.
* Dynamic runtime files (like databases and client private key directories) are stored under localized `data/` directories, allowing us to ignore them in `.gitignore` cleanly.

### Negative Consequences
* Relative imports between files will temporarily break, requiring a dedicated PR to refactor all `import` statements.
* Execution commands for running client and server scripts will change.

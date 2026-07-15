# ADR 0014: SQLite Database Migration

**Date:** 2026-07-07  
**Status:** Accepted

## Context
The central server originally stored user data, banned lists, revoked serials, and certificate details in plaintext JSON files on the filesystem. This presented a severe security risk; any read access to the server's filesystem would compromise user privacy and the integrity of the registration system. Additionally, JSON files do not scale well and are prone to race conditions or corruption during concurrent writes in our multi-threaded environment.

## Decision
We migrated all data persistence to a SQLite backend running in Write-Ahead Logging (WAL) mode. We designed a new `server/database.py` interface. Crucially, sensitive columns (such as the `cert_pem` data) are encrypted at rest using AES-256-GCM. The encryption key is derived dynamically from the `MASTER_PASSWORD_HASH` using HKDF-SHA256, ensuring that the database remains secure even if the server filesystem is compromised. We implemented an automatic migration routine to transition legacy JSON files to SQLite, backing them up as `.bak` files.

## Consequences
- **Positive**: High security for data at rest. Thread-safe concurrent operations. Better scalability and querying.
- **Negative**: Adds a dependency on SQLite (which is built into Python, mitigating external dependencies). Requires the master password hash to decrypt the database, linking the DB security strictly to the configuration security.

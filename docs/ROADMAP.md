# Product Roadmap

This document outlines the milestones and goals for the Secure Chat Application.

## Milestone 1: Foundation & Directory Restructuring (Active)
*Goal: Restructure code directories to adhere to industry standard package models.*
- [x] Implement new package layout: `client/`, `server/`, `shared/`, `docs/`, `tests/`.
- [x] Fix broken relative imports resulting from move.
- [x] Update execution guides for CLI and GUI apps.

## Milestone 2: Cryptographic Rigor & Security Correctness
*Goal: Fix critical and high vulnerabilities detected in the security audit.*
- [x] Implement peer certificate CA check to prevent MITM.
- [x] Implement Ephemeral ECDHE key exchange for Perfect Forward Secrecy.
- [x] Secure group chats with a randomized key distribution model.
- [x] Add GCM Associated Data integrity protection to prevent package tampering.
- [x] Encrypt client private keys on disk using local passphrase.

## Milestone 3: Software Engineering & Developer Experience
*Goal: Transition the codebase from a raw prototype to a robust production system.*
- [x] Build automated unit and integration tests with `pytest`.
- [x] Clean up configuration variables using environment variables.
- [x] Replace `print` with Python structured `logging`.

## Milestone 4: DevOps & Portfolio Polishing
*Goal: Containerize, deploy, and package the application for recruiter presentation.*
- [x] Containerize server with Docker.
- [x] Set up GitHub Actions CI for automated build validation.
- [x] Polish README and record GIF demo.

## Milestone 5: Advanced Security & Polish (Active)
*Goal: Finalize repository to production-grade portfolio standards.*
- [x] Wrap central STS sockets in TLS and add connection resilience.
- [x] Migrate JSON databases to encrypted SQLite.
- [x] Implement Double Ratchet and Safety Numbers.
- [x] Apply premium global Dark Mode QSS to the GUI.
- [ ] Complete final security audit and cleanup internal files.

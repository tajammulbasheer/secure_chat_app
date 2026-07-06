# Product Roadmap

This document outlines the milestones and goals for the Secure Chat Application.

## Milestone 1: Foundation & Directory Restructuring (Active)
*Goal: Restructure code directories to adhere to industry standard package models.*
- [ ] Implement new package layout: `client/`, `server/`, `shared/`, `docs/`, `tests/`.
- [ ] Fix broken relative imports resulting from move.
- [ ] Update execution guides for CLI and GUI apps.

## Milestone 2: Cryptographic Rigor & Security Correctness
*Goal: Fix critical and high vulnerabilities detected in the security audit.*
- [ ] Implement peer certificate CA check to prevent MITM.
- [ ] Implement Ephemeral ECDHE key exchange for Perfect Forward Secrecy.
- [ ] Secure group chats with a randomized key distribution model.
- [ ] Add GCM Associated Data integrity protection to prevent package tampering.
- [ ] Encrypt client private keys on disk using local passphrase.

## Milestone 3: Software Engineering & Developer Experience
*Goal: Transition the codebase from a raw prototype to a robust production system.*
- [ ] Build automated unit and integration tests with `pytest`.
- [ ] Clean up configuration variables using environment variables.
- [ ] Replace `print` with Python structured `logging`.

## Milestone 4: DevOps & Portfolio Polishing
*Goal: Containerize, deploy, and package the application for recruiter presentation.*
- [ ] Containerize server with Docker.
- [ ] Set up GitHub Actions CI for automated build validation.
- [ ] Polish README and record GIF demo.

# ADR 0013: Central Server TLS Integration & Socket Resilience

**Date:** 2026-07-07  
**Status:** Accepted

## Context
Our Security Token Service (STS) / Key Distribution Center (KDC) was receiving client connections over raw TCP sockets. This meant that client registration data and master passwords were being transmitted in plaintext over the network, leaving the application vulnerable to basic packet sniffing (e.g., Man-In-The-Middle attacks) on the command and control channel.

## Decision
We decided to wrap the central connection sockets in TLS. We provisioned dedicated KDC certificates signed by our Root CA and configured the Client Engine to wrap its KDC sockets in TLS, enforcing server certificate identity validation. Additionally, we implemented background heartbeat keep-alive messages (ping/pong loops) and automatic client reconnect handlers to improve connection resilience.

## Consequences
- **Positive**: Command and control traffic (including registrations and logins) is now fully encrypted in transit. Dropped connections are detected quickly via heartbeats, and clients gracefully attempt to reconnect.
- **Negative**: Adds slight overhead to the initial connection handshake. Requires careful management of the KDC certificate lifecycle.

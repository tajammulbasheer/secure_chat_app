# 10. Server Containerization using Docker

* Status: **Accepted**
* Date: 2026-06-26
* Decided by: Workflow Architect / Developer

## Context and Problem Statement
Running the STS (KDC) server requires installing specific Python dependencies (`cryptography`, `pyOpenSSL`, `python-dotenv`) on the host machine. Onboarding new developers, deploying to staging/production, or running integration tests can encounter configuration conflicts due to variations in operating systems, Python versions, or directory permissions.

We need a consistent, isolated runtime environment for the server to streamline deployment and local integration testing.

## Decision Drivers
- Enable single-command execution of the server environment.
- Isolate server dependencies from the developer's host machine.
- Provide persistence for server certificates and registration JSON databases across container restarts.

## Considered Options
1. **Option A (Host Python Execution)**: Continue running the server directly on the host shell. (Prone to dependencies friction, hard to deploy to standard cloud setups).
2. **Option B (Docker Containerization)**: Create a `Dockerfile` for the server using a lightweight Python image, and a `docker-compose.yml` to define environment settings and volume mounts.

## Decision Outcome
Chosen Option: **Option B (Docker Containerization)**

### Implementation Details
1. **Dockerfile (`Dockerfile`)**:
   Use a slim, multi-stage or standard base image (`python:3.10-slim`). Install dependencies defined in `requirements.txt` and launch the server:
   ```dockerfile
   FROM python:3.10-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY shared/ ./shared/
   COPY server/ ./server/
   ENV PYTHONPATH=/app
   EXPOSE 6000
   CMD ["python", "-m", "server.sts"]
   ```
2. **Docker Compose (`docker-compose.yml`)**:
   Define the STS service, port mapping (`6000:6000`), environment variables file reference (`.env`), and a persistent directory mount mapping the host's `server/data/` folder to the container's `/app/server/data/` directory so that users and databases persist.

### Positive Consequences
- **Environment Isolation**: Absolute isolation of server environments.
- **Portability**: The container can be deployed to any Docker-capable host (AWS ECS, Google Cloud Run, digital ocean droplet) instantly.
- **Ease of Use**: Local testing setup is reduced to `docker compose up --build`.

### Negative Consequences
- Developers must have Docker Desktop or Docker Engine installed to build and run containerized instances.

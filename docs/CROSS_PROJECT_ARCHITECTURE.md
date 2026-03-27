# Cross-Project Architecture

## High-Level View

The workspace is organized around a classic monitoring pattern:

- `server/` acts as the control plane and data store
- `client/` acts as the host-side agent and updater

## Communication Flows

### 1. Discovery

- The client broadcasts `DISCOVER_SERVER` on UDP port `5002`.
- The server listens on the same port in `handle_discovery_requests()` and replies
  with its IP address.
- Both `client/probe.py` and `client/launcher.py` use the discovery flow.

### 2. Authentication

- The server issues JWT tokens from `/api/auth/token`.
- The client launcher and probe authenticate with the admin credentials supplied via
  environment variables.
- The probe verifies JWTs locally for `/reboot`, `/shutdown`, and `/trigger-update`.

### 3. Metrics Ingestion

- The client probe gathers host metrics and posts them to the server `/update`.
- The server stores the payload in SQLite table `pc_info` and emits a Socket.IO event
  named `update_received`.

### 4. Remote Actions

- The server dashboard can request `reboot` or `shutdown` from a client by MAC address.
- The server resolves the client IP from the SQLite inventory and forwards the request
  to the probe on port `5001`.

### 5. Update Distribution

- The client launcher calls `/latest-version` and `/download-probe`.
- The server serves the current probe implementation from `server/probe.py`.
- The launcher replaces the local `probe.py` with the downloaded payload and restarts
  the probe process.

## Cross-Project Dependencies

- Shared environment variables:
  - `JWT_SECRET_KEY`
  - `ADMIN_USERNAME`
  - `ADMIN_PASSWORD`
  - `SERVER_PORT`
  - `SERVER_SCHEME`
  - `SERVER_CA_CERT`
- Shared trust material:
  - `client/server-cert.pem` is used by the client side as a CA certificate reference
    when TLS verification is enabled.
- Shared versioning:
  - `client/version.txt` stores the local probe version.
  - `server/app.py` exposes `LATEST_VERSION`.

## Architectural Risks

- The probe source is duplicated in two paths, which makes drift likely.
- TLS verification is optional on both sides if the expected certificate file is
  absent.
- Discovery relies on broadcast and a single UDP port, so it can fail in segmented or
  restricted networks.
- The server database is a single SQLite file, which is adequate for small deployments
  but becomes a scaling and concurrency constraint.
- The server rate limiter is in-memory, so it does not coordinate across multiple
  server instances.

## Integration Points

- `server/app.py`
- `server/probe.py`
- `client/launcher.py`
- `client/probe.py`
- `docker-compose.yml`
- `server/Dockerfile`
- `client/distribution/windows/probe.spec`
- `client/distribution/windows/innoset.iss`

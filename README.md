# Monitorium Workspace

Monitorium is a multi-project workspace for host monitoring and remote control.
It contains:

- `server/`: central Flask dashboard and API
- `client/`: local probe plus launcher used on monitored hosts

The two projects communicate through HTTP(S) and UDP discovery. The server stores
host state in SQLite and exposes a dashboard, while the client probe collects host
metrics and accepts control requests.

## Workspace Documents

- [`docs/WORKSPACE_OVERVIEW.md`](docs/WORKSPACE_OVERVIEW.md)
- [`docs/CROSS_PROJECT_ARCHITECTURE.md`](docs/CROSS_PROJECT_ARCHITECTURE.md)
- [`docs/MASTER_IMPROVEMENT_ROADMAP.md`](docs/MASTER_IMPROVEMENT_ROADMAP.md)

Project-level documentation is under each project root:

- [`server/docs/`](server/docs)
- [`client/docs/`](client/docs)

## Security Baseline

The workspace requires explicit credentials and secrets via environment variables.
No default admin credentials or fallback JWT secret are used.

Required variables observed in the code:

- `JWT_SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `FLASK_SECRET_KEY`

Use [`.env.example`](.env.example) as the starting point for runtime configuration.

## Ports

- Server dashboard/API: `5454` by default
- Probe API on monitored hosts: `5001`
- UDP discovery: `5002`

## Quick Start

1. Install server dependencies:

```bash
cd server
pip install -r requirements.txt
```

2. Set the required environment variables.

3. Start the server:

```bash
python app.py
```

4. On each monitored machine, start the launcher:

```bash
cd client
python launcher.py
```

## Dashboard Access

Open:

- `https://<server-ip>:5454/`

The dashboard requires login using `ADMIN_USERNAME` and `ADMIN_PASSWORD`.

## Docker

The server can be built and run with Docker:

```bash
cd server
docker build -t server-app .
docker run -d -p 5454:5454 \
  -e JWT_SECRET_KEY=... \
  -e ADMIN_USERNAME=... \
  -e ADMIN_PASSWORD=... \
  -e FLASK_SECRET_KEY=... \
  server-app:latest
```

From the repository root, the provided compose file starts the server and persists
the SQLite database on a named volume:

```bash
cp .env.example .env
docker compose up -d --build
```

The compose setup exposes:

- `5454/tcp` for the dashboard/API
- `5002/udp` for discovery

## Tests

Run the server API tests:

```bash
cd server
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

## Notes

- If TLS certificates are not present, the server starts without TLS and logs a warning.
- The client and server probe implementations are duplicated across `client/probe.py`
  and `server/probe.py`; this is an important maintenance risk.
- Auth endpoints and control endpoints are rate-limited, and actions are written to
  `audit_log` in SQLite.

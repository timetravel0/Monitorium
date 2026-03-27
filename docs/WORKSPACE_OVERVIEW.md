# Workspace Overview

## Scope
This workspace contains two real software projects plus repository-level orchestration
files. The analysis excludes build outputs, caches, dependency folders, and generated
artifacts.

## Project Map

| Project | Path | Type | Stack | Notes |
| --- | --- | --- | --- | --- |
| Monitorium Server | `server/` | Backend / full-stack service | Python, Flask, Flask-SocketIO, SQLite, requests, psutil, PyJWT, cachetools | Central dashboard/API, discovery responder, SQLite persistence |
| Monitorium Client | `client/` | Tool / local service | Python, Flask, requests, psutil, getmac, PyJWT | Local probe plus launcher, self-update flow, remote control endpoints |

## Observed Relationships

- `server/app.py` exposes the dashboard, token API, update ingestion endpoint, and
  UDP discovery responder.
- `client/launcher.py` discovers the server, authenticates to it, and downloads probe
  updates from the server.
- `client/probe.py` runs a local Flask service on port `5001` that reports metrics to
  the server and accepts control actions.
- `server/probe.py` is byte-identical to `client/probe.py` in the current workspace
  snapshot, which indicates duplicated probe source or a distribution copy.
- The root `docker-compose.yml` only orchestrates the server container and mounts the
  client Windows installer output for download.

## Workspace Boundaries

The following folders are not treated as source code for analysis:

- `client/__pycache__/`
- `client/distribution/windows/build/`
- `client/distribution/windows/dist/`
- `client/distribution/windows/output/`
- `server/__pycache__/`
- `server/.pytest_tmp/`
- `server/static/` and `server/templates/` are application assets, not generated
  artifacts, and are considered part of the server project only as supporting files.

Repository-level files used as context:

- `.env.example`
- `docker-compose.yml`
- `README.md`
- `ANALYZE_WORKSPACE.md`

## Notes

- The workspace is clearly multi-project.
- The server is the coordination point for discovery, authentication, persistence, and
  update distribution.
- The client is the execution endpoint on monitored hosts, not a standalone product
  with its own data store.

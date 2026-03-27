# Master Improvement Roadmap

## Cross-Project Tasks

| ID | Title | Area | Priority | Effort | Impact | Depends On |
| --- | --- | --- | --- | --- | --- | --- |
| WS-CROSS-01 | Deduplicate probe source | architecture | High | M | High | None |
| WS-CROSS-02 | Make TLS handling explicit end-to-end | security | High | M | High | WS-CROSS-01 |
| WS-CROSS-03 | Add shared smoke tests for server/client handshake | test | High | M | High | None |
| WS-CROSS-04 | Formalize environment and release docs | documentation | Medium | S | Medium | None |
| WS-CROSS-05 | Improve packaging and release automation | DX | Medium | L | Medium | WS-CROSS-01 |

## Project-Specific Task Groups

### Server

- Harden the SQLite access layer and document schema evolution.
- Replace in-memory rate limiting with a process-safe implementation if horizontal
  scaling is needed.
- Cover `/action`, `/request-update`, discovery, and download flows with tests.

### Client

- Add tests around probe payload generation and update application.
- Replace process shutdown calls with a safer abstraction where possible.
- Reduce repeated broadcast discovery attempts by caching the server location more
  aggressively.

## Suggested Execution Order

1. Deduplicate the probe source and define a single authoritative copy.
2. Tighten TLS and certificate handling across both projects.
3. Add end-to-end smoke tests for auth, update fetch, and metrics upload.
4. Improve packaging/release automation once the runtime contract is stable.

## Note for the Next Coding Agent

- Read `README.md`, `docs/WORKSPACE_OVERVIEW.md`, and the relevant project docs before
  editing code.
- Do not touch build outputs under `client/distribution/windows/build`,
  `client/distribution/windows/dist`, or `client/distribution/windows/output`.
- Validate any change to authentication or update flows against both projects.
- Quick wins:
  - align `client/probe.py` and `server/probe.py`
  - document runtime variables more explicitly
  - add tests for the server routes already covered by `server/tests/test_api.py`
- High-risk areas:
  - TLS defaults
  - remote reboot/shutdown endpoints
  - schema recreation in `server/app.py`

# API Reference - Monitorium Client (Probe API)

Questa reference descrive l'API HTTP esposta dal probe (`probe.py`) su `0.0.0.0:5001` (evidenza).

## Autenticazione (evidenza)

Esistono due meccanismi distinti:

1. `POST /login` (probe) rilascia un JWT con claim `user=admin` firmato con `JWT_SECRET_KEY`. Questo token e' usato per chiamare endpoint sensibili del probe (`/reboot`, `/shutdown`, `/trigger-update`).
2. Il probe usa un JWT ottenuto dal server (`POST /api/auth/token` lato server) per autenticare le chiamate verso `POST /update`.

Il probe verifica i token via `jwt.decode(token, SECRET_KEY, algorithms=["HS256"])` e richiede `user == "admin"` (evidenza: `verify_server_token()`).

## Endpoints esposti dal probe

### `POST /login`

Scopo (evidenza):

- Consente al server di ottenere un token per invocare comandi sul probe.

Request JSON (evidenza):

- `username`
- `password`

Response (evidenza):

- `200`: `{ "token": "<jwt>" }`
- `401`: `{ "message": "Invalid credentials!" }`

### `POST /set-interval`

Scopo (evidenza):

- Imposta un intervallo di reporting fisso, bypassando l'auto-tuning basato su load.

Request JSON (evidenza):

- `interval`: integer

Bounds (evidenza):

- `MIN_INTERVAL = 60`
- `MAX_INTERVAL = 600`

Response (evidenza):

- `200`: `{ "status": "success", "new_interval": <int> }`
- `400`: `{ "status": "error", "message": ... }`

Security note (evidenza):

- Questo endpoint non richiede autenticazione.

### `POST /reboot`

Scopo (evidenza):

- Riavvia la macchina tramite comando OS.

Auth (evidenza):

- Header `Authorization: Bearer <jwt>` dove `<jwt>` e' rilasciato da `POST /login`.

Response (evidenza):

- `200`: `{ "status": "rebooting" }`
- `403`: missing/invalid token.

Note (evidenza):

- Windows: `shutdown /r /t 0`
- non-Windows: `sudo reboot`

### `POST /shutdown`

Scopo (evidenza):

- Spegne la macchina tramite comando OS.

Auth e response: come `/reboot`.

Note (evidenza):

- Windows: `shutdown /s /t 0`
- non-Windows: `sudo shutdown now`

### `POST /trigger-update`

Scopo (evidenza):

- Esegue immediatamente `get_system_info()` e invia un report al server (`send_data_to_server()`).

Auth (evidenza):

- Header `Authorization: Bearer <jwt>` dove `<jwt>` e' rilasciato da `POST /login`.

Response (evidenza):

- `200`: `{ "status": "updated" }`
- `403`: missing/invalid token.

## Endpoint server consumati dal client (evidenza)

Questi non sono implementati nel `client/`, ma sono consumati da `probe.py`/`launcher.py`:

- `POST /api/auth/token` (auth verso server)
- `POST /update` (invio dati host)
- `GET /latest-version` (version check)
- `GET /download-probe` (download nuovo `probe.py`)

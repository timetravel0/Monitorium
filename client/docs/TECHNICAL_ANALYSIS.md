# Technical Analysis - Monitorium Client

## Stack (evidenza)

- Linguaggio: Python.
- Runtime principale:
  - `launcher.py`: processo supervisor + updater.
  - `probe.py`: processo agent + HTTP API (Flask) + loop reporting.
- Networking:
  - HTTP(S) client verso server via `requests`.
  - UDP broadcast discovery su `5002/udp`.
  - HTTP server su `0.0.0.0:5001` (Flask dev server).
- Autenticazione:
  - JWT (libreria `jwt` / PyJWT).

## Moduli e responsabilita'

### `launcher.py`

Evidenza:

- Imposta working directory su `script_dir` (side effect importante per percorsi relativi).
- Determina IP server:
  - prova `server.txt` (se presente e valido),
  - altrimenti discovery UDP broadcast.
- Ottiene token server chiamando `POST /api/auth/token` con `ADMIN_USERNAME`/`ADMIN_PASSWORD`.
- Controlla update via `GET /latest-version` e scarica codice via `GET /download-probe`.
- Applica update:
  - termina `probe.py`,
  - cancella `probe.py`,
  - rinomina `probe_new.py` -> `probe.py`,
  - aggiorna `version.txt`,
  - riavvia `probe.py`.

Osservazioni tecniche (evidenza):

- Non esiste rollback: se la sostituzione fallisce nel mezzo, il probe puo' restare mancante o corrotto.
- Il loop di update dorme 300 secondi fissi (`time.sleep(300)`).
- La verifica TLS puo' essere disabilitata quando manca `SERVER_CA_CERT` e `SERVER_SCHEME=https`.

### `probe.py`

Evidenza:

- Richiede `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` all'avvio.
- Login verso server:
  - discovery server IP via `server.txt` oppure UDP broadcast,
  - `POST /api/auth/token` per ottenere JWT da usare per `POST /update`.
- Raccolta metriche:
  - CPU/RAM via `psutil`.
  - Disco via `psutil.disk_usage('/')`.
  - Processi via `psutil.process_iter`.
  - Porte/connessioni via `psutil.net_connections(kind='inet')`.
  - IP pubblico via chiamata esterna `https://api.ipify.org?format=json`.
  - IP locale via socket UDP verso `8.8.8.8:80` (solo per derivare la local interface).
- Scheduling:
  - loop `run_probe()` con intervallo dinamico basato su load o forzato via `/set-interval`.
- HTTP API esposta (Flask):
  - `POST /login`: emette token JWT "admin" per il server che invoca comandi sul probe.
  - `POST /set-interval`: set intervallo reporting (non autenticato).
  - `POST /reboot`, `POST /shutdown`: comandi OS, autenticati via Bearer token firmato con `JWT_SECRET_KEY`.
  - `POST /trigger-update`: invia immediatamente un report al server (autenticato).

Concorrenza (evidenza):

- Il server HTTP Flask gira in un thread.
- Il loop di reporting gira nel thread principale.
- Variabili globali condivise: `JWT_TOKEN`, `reporting_interval`, `admin_set_interval`.

## Payload verso server `/update` (evidenza)

Il probe costruisce un dizionario con chiavi:

- `hostname`, `public_ip_address`, `local_ip_address`, `platform`, `mac_address`
- `cpu_usage`, `memory_usage`
- `hdd_usage`: `{total, used, free, percent}`
- `running_processes`: lista stringhe
- `used_ports`: lista stringhe
- `last_reboot`, `uptime`, `current_users`
- `disk_io`: `{read_bytes, write_bytes}`
- `network_io`: `{bytes_sent, bytes_recv}`
- `last_updated` (timestamp string)

## Configurazione e file locali (evidenza)

- Environment (probe):
  - richieste: `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`
  - opzionali: `SERVER_PORT`, `SERVER_SCHEME`, `SERVER_CA_CERT`
- File locali:
  - `server.txt` (letto, non creato dal codice)
  - `version.txt`
  - `server-cert.pem`
- Log:
  - `probe.log` (probe)
  - `probe_manager.log` (launcher)

## Debito tecnico e criticita' (evidenza)

- Aggiornamento in-place senza backup/rollback (`launcher.py`).
- `/set-interval` non autenticato (`probe.py`).
- API del probe senza TLS ma con comandi sensibili; protezione demandata a JWT e rete.
- Disabilitazione verifica TLS quando manca `SERVER_CA_CERT` (launcher e probe).

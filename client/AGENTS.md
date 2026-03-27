# Monitorium Client (Probe + Launcher) - Istruzioni per Coding Agent

Questo file descrive come lavorare sul progetto `client/` del workspace Monitorium.

## Scopo del progetto (evidenza)

- `probe.py`: raccoglie metriche host e le invia periodicamente al server; espone anche un piccolo HTTP API per comandi e trigger.
- `launcher.py`: avvia `probe.py` e gestisce l'auto-aggiornamento del file `probe.py` scaricandolo dal server.
- `version.txt`: versione corrente del probe usata dal launcher per decidere se aggiornare.

## Confini

- Non trattare `distribution/`, `__pycache__/` e output build come sorgente applicativa.
- Questa documentazione e le istruzioni qui sono basate solo su: `launcher.py`, `probe.py`, `version.txt`, `server-cert.pem`.

## Entry point e comandi (evidenza)

- Avvio launcher: `python launcher.py`
  - Avvia `probe.py` via `subprocess.Popen([sys.executable, "probe.py"])`.
  - Ogni 300s controlla update con `GET /latest-version` e scarica `GET /download-probe`.
- Avvio probe (senza launcher): `python probe.py`
  - Espone HTTP su `0.0.0.0:5001`.
  - Esegue loop di reporting.

## File runtime e log (evidenza)

- `probe_manager.log` creato da `launcher.py`.
- `probe.log` creato da `probe.py`.
- `server.txt` (non versionato): se presente, contiene IP server usato per saltare la discovery UDP.
- `probe_new.py` usato come staging per aggiornamento e poi rinominato a `probe.py`.

## Porte e rete (evidenza)

- Probe API: `5001/tcp`.
- Server discovery (UDP broadcast): `5002/udp` (client invia `DISCOVER_SERVER` e aspetta risposta con IP server).

## Configurazione via environment (evidenza)

Probe (`probe.py`):

- Obbligatorie: `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` (usate da `env_required()`).
- Opzionali: `SERVER_PORT` (default `5454`), `SERVER_SCHEME` (default `https`), `SERVER_CA_CERT` (default `server-cert.pem`).

Launcher (`launcher.py`):

- Necessarie per update autenticato: `ADMIN_USERNAME`, `ADMIN_PASSWORD` (se mancanti, il launcher non ottiene token e non fa update).
- Opzionali: `SERVER_PORT` (default `5454`), `SERVER_SCHEME` (default `https`), `SERVER_CA_CERT` (default `server-cert.pem`).

## Superfici ad alto rischio

- `probe.py` implementa comandi di reboot/shutdown via `os.system()` (Windows: `shutdown ...`, non-Windows: `sudo ...`).
- Se `SERVER_SCHEME=https` ma `SERVER_CA_CERT` manca, sia launcher che probe disabilitano la verifica TLS (`verify=False` in `requests`).
- L'endpoint `/set-interval` sul probe non richiede autenticazione.

## Regole operative per cambi futuri

- Se cambi la forma del payload inviato al server (`send_data_to_server()`), verificare compatibilita' con l'endpoint server `/update`.
- Se cambi API del probe (porte, path, auth), verificare i punti di chiamata lato server (altro progetto) e aggiornare `docs/API_REFERENCE.md`.
- Evitare dipendenze nuove non necessarie: il probe gira su host monitorati e deve restare leggero.

# Monitorium Client (Probe + Launcher)

## Cosa e' (evidenza)

Il progetto `client/` contiene due componenti Python:

- `launcher.py`: supervisiona l'esecuzione del probe e gestisce l'auto-aggiornamento del file `probe.py` scaricandolo dal server.
- `probe.py`: raccoglie metriche della macchina (CPU, RAM, disco, rete, processi, porte, utenti) e le invia al server su base periodica; espone anche un HTTP API per alcuni comandi (trigger update, reboot, shutdown, set interval).

Versione probe corrente: letta/scritta in `version.txt`.

## Flussi principali (evidenza)

### Reporting periodico

1. `probe.py` calcola `get_system_info()`.
2. Effettua login verso il server (`/api/auth/token`) usando `ADMIN_USERNAME`/`ADMIN_PASSWORD`.
3. Invia il payload a `POST /update` con header `Authorization: Bearer <jwt>`.

### Discovery server (fallback)

Se `server.txt` non esiste o non contiene un IP valido, sia probe sia launcher tentano discovery via UDP broadcast su `5002/udp` inviando il messaggio `DISCOVER_SERVER` e usando l'IP della risposta come server (`discover_server_ip()` in `probe.py` e `launcher.py`).

### Auto-update del probe

1. `launcher.py` avvia `probe.py`.
2. Ogni 300s chiede `GET /latest-version`.
3. Se la versione differisce da `version.txt`, scarica `GET /download-probe`, scrive `probe_new.py`, sostituisce `probe.py` e aggiorna `version.txt`.

## Dipendenze principali (evidenza da import)

Il client utilizza librerie Python importate direttamente in codice:

- `requests`
- `Flask`
- `psutil`
- `PyJWT` (`jwt`)
- `getmac`

## File importanti

- `launcher.py`: update e gestione processo.
- `probe.py`: raccolta metriche e API del probe.
- `version.txt`: versione locale del probe.
- `server-cert.pem`: CA/cert usato per verificare TLS verso il server quando `SERVER_SCHEME=https` (se configurato).

## Documentazione correlata

- `AGENTS.md` (root di `client/`)
- `docs/FUNCTIONAL_ANALYSIS.md`
- `docs/TECHNICAL_ANALYSIS.md`
- `docs/DEPLOYMENT.md`
- `docs/API_REFERENCE.md`
- `docs/SECURITY_NOTES.md`
- `docs/TESTING_STRATEGY.md`
- `docs/IMPROVEMENT_ROADMAP.md`

## Limiti dell'analisi

- Questa documentazione si basa solo su: `launcher.py`, `probe.py`, `version.txt`, `server-cert.pem`.
- Il comportamento lato server (validazioni e persistenza) e' descritto solo per quanto necessario a comprendere il client.

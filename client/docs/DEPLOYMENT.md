# Deployment - Monitorium Client

Questo documento descrive come eseguire il client (probe + launcher) sulla macchina monitorata.

## Prerequisiti (evidenza)

- Python disponibile sulla macchina.
- Librerie Python richieste dal codice (evidenza da import in `probe.py`/`launcher.py`):
  - `requests`
  - `flask`
  - `psutil`
  - `PyJWT` (import `jwt`)
  - `getmac`

Nota (evidenza):

- In `client/` non esiste un `requirements.txt`. L'installazione delle dipendenze va gestita esternamente (es. provisioning/packaging), fuori perimetro di questa documentazione.

## Configurazione via environment

### Probe (`probe.py`) - obbligatoria

Evidenza: `env_required()` su queste variabili.

| Variabile | Scopo |
| --- | --- |
| `JWT_SECRET_KEY` | firma/verifica JWT tra server e probe |
| `ADMIN_USERNAME` | credenziale usata per ottenere token dal server e per `/login` sul probe |
| `ADMIN_PASSWORD` | credenziale usata per ottenere token dal server e per `/login` sul probe |

### Probe e Launcher - opzionali

| Variabile | Default | Scopo |
| --- | --- | --- |
| `SERVER_PORT` | `5454` | porta HTTP(S) del server Monitorium |
| `SERVER_SCHEME` | `https` | schema usato verso il server (`http` o `https`) |
| `SERVER_CA_CERT` | `server-cert.pem` | path CA da usare per verificare TLS (requests `verify=<path>`) |

Launcher (`launcher.py`) richiede anche `ADMIN_USERNAME`/`ADMIN_PASSWORD` per fare update autenticati. Se assenti, non ottiene token e non procede.

## File runtime locali (evidenza)

- `version.txt`: versione corrente del probe.
- `server.txt`: (opzionale) IP server; se presente bypassa discovery UDP.
- `probe_manager.log` e `probe.log`: log dei processi.
- `probe_new.py`: staging file durante un aggiornamento applicato dal launcher.

## Run (manuale)

Avvio consigliato:

```bash
cd client
python launcher.py
```

Avvio diretto del probe (senza auto-update):

```bash
cd client
python probe.py
```

## Rete e firewall (evidenza)

- Inbound sulla macchina monitorata:
  - `5001/tcp` (Flask server del probe).
- Outbound dalla macchina monitorata:
  - verso il server: `SERVER_SCHEME://<server-ip>:SERVER_PORT` per `/api/auth/token`, `/latest-version`, `/download-probe`, `/update`.
  - UDP broadcast per discovery su `5002/udp`.
  - verso `api.ipify.org` per ottenere l'IP pubblico.

## TLS verso server (evidenza)

- Se `SERVER_SCHEME=https` e il file `SERVER_CA_CERT` non esiste, il codice disabilita la verifica TLS (`requests` con `verify=False`) e logga un warning.

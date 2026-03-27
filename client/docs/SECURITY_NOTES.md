# Security Notes - Monitorium Client

Questo documento evidenzia rischi e superfici di attacco osservabili nel solo `client/`.

## Livello di certezza

- Evidenza: direttamente in `probe.py`/`launcher.py`.
- Inferenza: rischio ragionevole dato il comportamento osservato.

## Autenticazione e segreti

Evidenza:

- `probe.py` richiede `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`.
- I token JWT sono firmati/verificati con `JWT_SECRET_KEY`.
- Le credenziali admin sono riutilizzate:
  - dal probe per ottenere token dal server (`/api/auth/token`),
  - dal server per ottenere token dal probe (`POST /login` del probe),
  - dal launcher per update autenticato.

Inferenza:

- Compromissione di `JWT_SECRET_KEY` o delle credenziali admin permette comandi sul probe e accesso alle API server correlate.

## Transport security (TLS) verso server

Evidenza:

- Se `SERVER_SCHEME=https` ma `SERVER_CA_CERT` non esiste, probe e launcher disabilitano la verifica TLS (`requests` con `verify=False`).

Inferenza:

- Apre a MITM in reti non affidabili.

## Probe API esposta su rete

Evidenza:

- `probe.py` avvia Flask su `0.0.0.0:5001` senza TLS.
- Endpoints sensibili:
  - `/reboot`, `/shutdown`: impattano direttamente lo stato della macchina.
  - `/trigger-update`: forza comunicazione e puo' aumentare leak di info.

Inferenza:

- Il rischio dipende dalla segmentazione rete e da chi puo' raggiungere `5001/tcp`.

## Endpoint non autenticato

Evidenza:

- `POST /set-interval` non richiede autenticazione e consente di variare l'intervallo del loop.

Inferenza:

- Puo' essere abusato per aumentare carico o ridurre visibilita' (entro bounds 60..600s).

## Esecuzione comandi OS

Evidenza:

- `probe.py` usa `os.system()` per `shutdown`/`reboot`.
- Su Linux usa `sudo ...` senza gestione credenziali.

Inferenza:

- Richiede configurazione `sudoers` passwordless oppure fallira'.

## Dipendenze e richieste verso terze parti

Evidenza:

- `probe.py` chiama `https://api.ipify.org` per ottenere IP pubblico.
- Usa un socket verso `8.8.8.8:80` per derivare IP locale.

Inferenza:

- In ambienti offline/regolati queste chiamate possono fallire e generare log rumorosi.

## Logging e dati sensibili

Evidenza:

- Log su file (`probe.log`, `probe_manager.log`).

Inferenza:

- Verificare che nei log non finiscano token o credenziali (oggi non sembrano loggati esplicitamente, ma eccezioni possono includere contesto).

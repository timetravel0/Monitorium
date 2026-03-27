# Functional Analysis - Monitorium Client

## Livelli di certezza usati

- Evidenza: supportato direttamente da `launcher.py`, `probe.py`, `version.txt`, `server-cert.pem`.
- Inferenza: deduzione ragionevole dal comportamento osservato.
- Ipotesi: da validare (non determinabile con certezza dal solo `client/`).

## Attori

Evidenza:

- Admin: configura credenziali via environment e usa la dashboard server (fuori perimetro) per comandare/consultare.
- Probe agent: processo Python in esecuzione sulla macchina monitorata (`probe.py`).
- Probe launcher: processo Python che gestisce lifecycle e update del probe (`launcher.py`).

Inferenza:

- Server Monitorium: servizio remoto che espone endpoint consumati dal client e che invoca l'API esposta dal probe.

## Use case principali

### UC-CLIENT-01: Monitoraggio host

Evidenza:

- Il probe raccoglie metriche e inventario e le invia al server (`get_system_info()`, `send_data_to_server()` in `probe.py`).

### UC-CLIENT-02: Discovery automatica del server

Evidenza:

- Se `server.txt` non esiste o non contiene un IP valido, probe e launcher provano discovery su LAN via UDP broadcast (`discover_server_ip()`).

### UC-CLIENT-03: Aggiornamento automatico del probe

Evidenza:

- `launcher.py` verifica periodicamente la versione disponibile (`GET /latest-version`), scarica il codice (`GET /download-probe`) e sostituisce `probe.py`, aggiornando `version.txt`.

Ipotesi:

- Il server distribuisce una copia "canonica" di `probe.py` e mantiene una versione coerente con `version.txt`.

### UC-CLIENT-04: Controllo remoto (reboot/shutdown)

Evidenza:

- `probe.py` espone endpoint `POST /reboot` e `POST /shutdown` che eseguono rispettivamente reboot e shutdown tramite comandi OS.

Inferenza:

- La richiesta parte dal server: prima ottiene un token via `POST /login` sul probe e poi invoca `/reboot` o `/shutdown`.

### UC-CLIENT-05: Modifica intervallo reporting

Evidenza:

- Il probe adatta l'intervallo in base a CPU/RAM (`adjust_interval_based_on_load()`).
- Il probe consente un intervallo manuale via `POST /set-interval` tra `60` e `600` secondi.

Nota (evidenza):

- `/set-interval` non richiede autenticazione.

### UC-CLIENT-06: Trigger update on-demand

Evidenza:

- `probe.py` espone `POST /trigger-update` che forza una raccolta e invio immediato di `get_system_info()`.

## Requisiti funzionali impliciti

Evidenza:

- Il probe richiede `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD` all'avvio.
- Il client deve poter raggiungere il server su `SERVER_SCHEME://<server-ip>:SERVER_PORT`.
- Il client assume una rete che consenta UDP broadcast per discovery (almeno in fallback).

## Ambiguita' e punti da validare

Evidenza:

- `server.txt` viene letto ma non viene creato dal codice client.

Ipotesi:

- `server-cert.pem` e' una CA/cert self-signed usata per TLS verso server, ma l'effettivo uso dipende da `SERVER_CA_CERT` e dall'ambiente.

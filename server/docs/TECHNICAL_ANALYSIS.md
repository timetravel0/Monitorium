# Technical Analysis

## Stack tecnologico

- Flask come web framework
- Flask-SocketIO per notifiche al dashboard
- SQLite come persistenza locale
- PyJWT per token JWT
- requests per le chiamate verso i client
- psutil per il collector distribuito nel probe
- cachetools per caching dei token dei probe

## Entrypoint applicativi

- `app.py`

## Moduli principali

- autenticazione e autorizzazione
- rate limiting in memoria
- persistence layer SQLite
- discovery UDP
- dashboard HTML
- distribuzione probe e client installer

## Pattern architetturali osservati

- monolite Flask con route, persistence e integrazioni nello stesso file
- thread dedicato alla discovery UDP
- schema SQLite creato/validato all'avvio
- token-based auth per le API tecniche

## Flussi interni principali

- all'avvio il server verifica o ricrea lo schema
- il server ascolta discovery request su UDP 5002
- il dashboard usa sessioni Flask
- l'API tecnica usa JWT Bearer token
- `socketio.emit("update_received")` segnala nuovi update

## Integrazioni esterne

- il probe client su porta `5001`
- file installer client allineato al path configurato da `CLIENT_INSTALLER_PATH`
- certi flussi HTTPS dipendono da certificato e chiave locali

## Gestione configurazione

- variabili obbligatorie:
  - `JWT_SECRET_KEY`
  - `ADMIN_USERNAME`
  - `ADMIN_PASSWORD`
  - `FLASK_SECRET_KEY`
- variabili operative osservate:
  - `LATEST_VERSION`
  - `DATABASE_PATH`
  - `CLIENT_PORT`
  - `PROBE_SCHEME`
  - `PROBE_CA_CERT`
  - `SERVER_PORT`
  - `RATE_LIMIT_WINDOW_SECONDS`
  - `RATE_LIMIT_MAX_REQUESTS`
  - `AUTH_RATE_LIMIT_MAX_REQUESTS`
  - `CLIENT_INSTALLER_PATH`
  - `FLASK_DEBUG`
  - `TLS_CERT_PATH`
  - `TLS_KEY_PATH`

## Stato qualita del codice

- il server e piu strutturato del client ma resta concentrato in un unico file
- esiste un set di test API di base
- i warning osservati nei test indicano uso di `datetime.utcnow()`
- il database viene ricreato automaticamente in caso di mismatch schema

## Debito tecnico

- schema recreation distruttiva in caso di mismatch
- rate limiting solo in memoria
- uso di `datetime.utcnow()` deprecato nei warning del test run
- duplicazione del probe con `server/probe.py`

## Criticita tecniche

- il server dipende da un file SQLite singolo
- il flusso discovery presume networking broadcast funzionante
- l'endpoint `/download-probe` serve il codice sorgente direttamente
- gli endpoint che comandano i client dipendono da IP risolvibili correttamente

## Scalabilita e manutenibilita

- il design e adatto a installazioni piccole o medie
- la manutenibilita soffre per il monolite `app.py`
- la separazione di responsabilita andrebbe migliorata prima di estendere il sistema

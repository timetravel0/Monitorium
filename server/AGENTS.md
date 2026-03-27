# AGENTS.md

## Scopo
Server centrale del workspace Monitorium: dashboard Flask, API di autenticazione,
persistenza SQLite, discovery UDP e distribuzione della versione del probe.

## Identita del progetto
- Nome: Monitorium Server
- Path root: `C:\Code\github\Monitorium\server`
- Tipo: backend / full-stack service
- Stack principale: Python, Flask, Flask-SocketIO, SQLite, requests, psutil,
  PyJWT, cachetools

## Cartelle rilevanti
- `app.py` - entrypoint principale, routing, auth, persistence e discovery
- `probe.py` - sorgente del probe distribuito al client
- `tests/` - test API
- `static/` - asset del dashboard
- `templates/` - template HTML del dashboard
- `requirements.txt` e `requirements-dev.txt`
- `Dockerfile`

## Cartelle da ignorare
- `__pycache__/`
- `.pytest_tmp/`

## Convenzioni osservate
- Il server carica le variabili obbligatorie all'import.
- La persistenza usa SQLite con schema creato in avvio.
- La discovery avviene in un thread UDP in background.
- L'API usa JWT per le route tecniche e sessione Flask per la dashboard.
- Le azioni verso i client sono tracciate su `audit_log`.

## Comandi utili
```bash
# installazione
pip install -r requirements.txt
pip install -r requirements.txt -r requirements-dev.txt

# avvio locale
python app.py

# test
pytest -q

# lint / type-check
non presente nel repository

# build
docker build -t server-app .
```

## Guardrail
- Leggi prima `..\README.md` e `docs\*.md` del workspace.
- Non modificare file in `static/`, `templates/` o `.pytest_tmp/` come se fossero
  sorgente applicativo.
- Non cambiare schema SQLite senza aggiornare anche documentazione e test.
- Se modifichi `probe.py`, verifica la coerenza con il client.

## Output attesi da futuri coding agent
1. identificare i file coinvolti
2. proporre modifiche minime e coerenti
3. aggiornare i test se il comportamento cambia
4. aggiornare la documentazione collegata

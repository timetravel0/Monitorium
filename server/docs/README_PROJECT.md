# Monitorium Server

## Scopo
Il server ospita la dashboard centrale e le API usate dai probe per autenticazione,
invio metriche e distribuzione degli aggiornamenti.

## Funzionalita principali

- login dashboard per l'amministratore
- issue di token JWT per probe e client
- ricezione e persistenza dei dati di host in SQLite
- discovery UDP del server sulla rete locale
- richiesta di reboot/shutdown verso i client
- distribuzione della sorgente del probe e dell'installer client

## Stack

- Python
- Flask
- Flask-SocketIO
- SQLite
- requests
- psutil
- PyJWT
- cachetools

## Struttura

- `app.py`: applicazione principale
- `probe.py`: payload distribuito al client
- `tests/`: test API
- `templates/`: dashboard HTML
- `static/`: asset statici
- `Dockerfile`: immagine server

## Setup rapido

```bash
cd server
pip install -r requirements.txt -r requirements-dev.txt
python app.py
```

## Comandi principali

- `python app.py`
- `pytest -q`
- `docker build -t server-app .`

## Documentazione correlata

- [`AGENTS.md`](../AGENTS.md)
- [`FUNCTIONAL_ANALYSIS.md`](FUNCTIONAL_ANALYSIS.md)
- [`TECHNICAL_ANALYSIS.md`](TECHNICAL_ANALYSIS.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
- [`API_REFERENCE.md`](API_REFERENCE.md)
- [`DATA_MODEL.md`](DATA_MODEL.md)
- [`SECURITY_NOTES.md`](SECURITY_NOTES.md)
- [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md)
- [`IMPROVEMENT_ROADMAP.md`](IMPROVEMENT_ROADMAP.md)

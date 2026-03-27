# Deployment

## Prerequisiti

- Python 3.x
- dipendenze da `requirements.txt`
- credenziali amministrative
- `JWT_SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `FLASK_SECRET_KEY`
- opzionalmente certificato e chiave TLS per avvio HTTPS

## Variabili di ambiente osservate

- `JWT_SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `FLASK_SECRET_KEY`
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

## Build e run

```bash
cd server
pip install -r requirements.txt -r requirements-dev.txt
python app.py
```

Docker:

```bash
cd server
docker build -t server-app .
docker run -d -p 5454:5454 server-app:latest
```

Compose dal root del workspace:

```bash
cp .env.example .env
docker compose up -d --build
```

## Ambienti

- sviluppo locale con Flask
- container Docker
- compose con volume persistente per SQLite

## Note operative

- se `TLS_CERT_PATH` e `TLS_KEY_PATH` non esistono, il server parte senza TLS
- la base dati SQLite e ricreata se lo schema atteso non coincide
- l'installer client viene servito da un path configurabile via ambiente

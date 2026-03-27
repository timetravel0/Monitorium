# API Reference

## Overview

Il server espone route per autenticazione, dashboard, ingestione dati e comandi verso
i probe/client.

## Endpoints

### `POST /api/auth/token`

- funzione: `issue_token()`
- input: JSON con `username` e `password`
- output: JWT per il probe
- auth: nessuna, ma rate limited

### `GET /latest-version`

- funzione: `get_latest_version()`
- auth: Bearer token
- output: `latest_version`

### `GET /download-probe`

- funzione: `download_probe()`
- auth: Bearer token
- output: sorgente del probe come JSON `probe_code`

### `GET /download-client`

- funzione: `download_client()`
- auth: sessione dashboard
- output: installer client come file scaricato

### `GET /`

- funzione: `dashboard()`
- auth: sessione dashboard
- output: dashboard HTML con i record `pc_info`

### `POST /action`

- funzione: `perform_action()`
- auth: sessione dashboard
- input: JSON con `mac_address` e `action`
- output: esito di reboot/shutdown su client

### `POST /update`

- funzione: `update_data()`
- auth: Bearer token
- input: payload metriche del probe
- output: `success` o errore di validazione/persistenza

### `POST /request-update`

- funzione: `request_update()`
- auth: sessione dashboard
- input: JSON con `mac_address`
- output: trigger di refresh dati sul client

### `GET|POST /login`

- funzione: `login_page()`
- auth: none
- output: login form o sessione autenticata

### `POST /logout`

- funzione: `logout()`
- auth: sessione dashboard

## Auth Pattern

- la dashboard usa sessione Flask
- le route tecniche usano JWT Bearer token
- il token viene emesso con claim `user` e scadenza temporale

## Limiti dell'analisi

- non esiste un file OpenAPI
- i dettagli completi dei template HTML non sono documentati qui

# Testing Strategy

## Test presenti

- esiste `server/tests/test_api.py`
- il test run osservato ha prodotto `5 passed`

## Livelli di test rilevati

- test API di integrazione leggera con Flask test client
- verifica di auth token
- verifica di update con token valido
- verifica rate limiting sull'endpoint di auth
- verifica della scrittura su `audit_log`

## Copertura percepita

- buona copertura dei casi base di auth e ingestione
- copertura assente o debole per:
  - `/action`
  - `/request-update`
  - `/download-client`
  - `/download-probe`
  - discovery UDP
  - TLS fallback
  - schema recreation

## Gap principali

- nessun test per i flussi verso i client remoti
- nessun test per il thread di discovery
- nessun test di regressione per il modello dati SQLite

## Suggerimenti

- aggiungere fixture per simulare client e discovery
- coprire i casi di errore dei payload `update`
- controllare i warning su `datetime.utcnow()` durante i test

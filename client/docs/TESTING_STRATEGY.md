# Testing Strategy - Monitorium Client

## Stato attuale (evidenza)

- Nel perimetro `client/` non sono presenti test automatizzati (nessuna cartella `tests/`, nessun framework di test referenziato).

## Rischi principali senza test (inferenza)

- Regressioni sul contratto del payload verso server (`/update`).
- Regressioni su discovery UDP e gestione `server.txt`.
- Regressioni sulla logica di auto-update (sostituzione file e restart processo).
- Regressioni su API del probe (auth e comandi sensibili).

## Strategia consigliata (inferenza)

### Livello 1: Unit test (rapidi)

- Testare funzioni in `probe.py` con mocking:
  - parsing e bounds di `/set-interval`
  - `verify_server_token()` con token valido/scaduto/non valido
  - `get_system_info()` con mocking di `psutil` e `requests.get` (ipify)
- Testare `launcher.py`:
  - `get_current_version()` / `set_current_version()`
  - refresh token dopo `403`

### Livello 2: Integration test (simulati)

- Avviare un finto server HTTP locale che implementi `/api/auth/token`, `/latest-version`, `/download-probe`, `/update`.
- Verificare:
  - che il probe invii il payload atteso
  - che il launcher scarichi e sostituisca `probe.py` correttamente

### Livello 3: E2E (manuale/CI opzionale)

- Esecuzione controllata su Windows e Linux (idealmente VM) per verificare:
  - reachability porte e firewall
  - reboot/shutdown in ambiente sicuro

## Nota operativa

- Per testare in modo sicuro `reboot`/`shutdown`, introdurre in futuro un layer che consenta di stubbare l'esecuzione del comando OS.

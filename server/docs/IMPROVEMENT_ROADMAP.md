# Improvement Roadmap: Monitorium Server

Roadmap basata su evidenze nel codice in [`server/app.py`](../app.py), template in [`server/templates/`](../templates), test in [`server/tests/test_api.py`](../tests/test_api.py), e file di deploy in [`server/Dockerfile`](../Dockerfile).

## Task

### SRV-ARCH-01: Modularizzare `app.py` in package con blueprint

| Campo | Valore |
| --- | --- |
| Descrizione | Estrarre DB layer, auth, rate limiting, routes in moduli separati e registrare blueprint Flask. |
| Problema osservato | `server/app.py` contiene tutto (DB, auth, rate limit, discovery, routes) rendendo test e manutenzione difficili. |
| Beneficio atteso | Maggiore testabilita, isolamento responsabilita, evoluzione piu sicura. |
| Priorita | Media |
| Effort | L |
| Impatto | Medio |
| Area | architettura |
| File/cartelle coinvolte | `server/app.py` (refactor), nuova cartella `server/monitorium_server/` (o simile). |
| Dipendenze | SRV-DATA-01 (consigliata prima di cambiare schema/DB). |
| Rischi | Regressioni su routing/import order (DB check a import-time). |
| Criterio completamento | Stesse route/behavior, test esistenti verdi, nessun side-effect inatteso su import. |
| Istruzioni per futuri agent | Introdurre prima test per route critiche, poi refactor incrementale con piccoli PR logici. |

### SRV-DATA-01: Eliminare la ricreazione distruttiva del DB e introdurre migrazioni

| Campo | Valore |
| --- | --- |
| Descrizione | Sostituire `check_and_recreate_db()` con una strategia safe: migrazioni (es. Alembic) o migrazioni manuali, con backup del file SQLite. |
| Problema osservato | Se lo schema non coincide, il server elimina `DATABASE_PATH` (`os.remove`) e ricrea: rischio data loss. |
| Beneficio atteso | Upgrade/downgrade sicuri e preservazione dati. |
| Priorita | Alta |
| Effort | L |
| Impatto | Alto |
| Area | architettura |
| File/cartelle coinvolte | `server/app.py`, eventuale `migrations/`, docs aggiornate. |
| Dipendenze | Nessuna, ma va coordinata con SRV-ARCH-01. |
| Rischi | Migrazioni incomplete possono bloccare avvio. |
| Criterio completamento | Nessuna cancellazione automatica DB; migrazione testata su DB con dati; rollback documentato. |
| Istruzioni per futuri agent | Aggiungere test che crea un DB "vecchio" e verifica la migrazione senza perdita di righe `pc_info`. |

### SRV-SEC-01: Protezione CSRF per endpoint dashboard

| Campo | Valore |
| --- | --- |
| Descrizione | Aggiungere CSRF token per POST `/action`, `/request-update`, `/logout` (e in generale per le form/session routes). |
| Problema osservato | Endpoint POST protetti da session cookie senza CSRF (evidenza in `server/app.py`). |
| Beneficio atteso | Riduzione rischio CSRF con sessione admin attiva. |
| Priorita | Alta |
| Effort | M |
| Impatto | Alto |
| Area | sicurezza |
| File/cartelle coinvolte | `server/app.py`, `server/templates/dashboard.html`, `server/templates/login.html`. |
| Dipendenze | Nessuna. |
| Rischi | Rottura chiamate fetch JS se non aggiornate. |
| Criterio completamento | Tutti i POST da UI includono CSRF token; test coprono failure senza token. |
| Istruzioni per futuri agent | Introdurre prima una libreria (es. Flask-WTF) o implementazione minimale, poi aggiornare fetch JS. |

### SRV-SEC-02: Hardening cookie/session e enforcement HTTPS

| Campo | Valore |
| --- | --- |
| Descrizione | Impostare `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, e raccomandare HTTPS end-to-end; opzionalmente HSTS. |
| Problema osservato | Il server puo partire senza TLS e non imposta esplicitamente cookie flags. |
| Beneficio atteso | Riduzione rischio session hijack e CSRF (in combinazione con SRV-SEC-01). |
| Priorita | Media |
| Effort | S |
| Impatto | Medio |
| Area | sicurezza |
| File/cartelle coinvolte | `server/app.py`, `server/docs/DEPLOYMENT.md`, `server/docs/SECURITY_NOTES.md`. |
| Dipendenze | SRV-SEC-01 consigliata. |
| Rischi | Necessita di TLS in ambienti dove oggi non e configurato. |
| Criterio completamento | Config documentata e applicata; comportamento verificato su HTTP vs HTTPS. |
| Istruzioni per futuri agent | Non rompere dev setup: usare flag configurabili via env e default ragionevoli. |

### SRV-SEC-03: Separare credenziali UI da credenziali API/probe

| Campo | Valore |
| --- | --- |
| Descrizione | Introdurre credenziali/secret separati per: admin UI, token issuance per probe/launcher, e (opzionale) per-probe credentials. |
| Problema osservato | Stesse credenziali admin (`ADMIN_USERNAME`/`ADMIN_PASSWORD`) usate per UI e per token API (`/api/auth/token`). |
| Beneficio atteso | Compromissione di un canale non implica compromissione totale. |
| Priorita | Alta |
| Effort | L |
| Impatto | Alto |
| Area | sicurezza |
| File/cartelle coinvolte | `server/app.py`, contract con probe/launcher, documentazione. |
| Dipendenze | SRV-DOC-01 (contratto) consigliata. |
| Rischi | Richiede coordinamento con codice client/launcher (fuori da `server/`). |
| Criterio completamento | Token API non ottenibile con credenziali UI; migrazione configurazioni documentata. |
| Istruzioni per futuri agent | Progettare una fase di transizione con supporto temporaneo a entrambi i metodi. |

### SRV-SEC-04: TLS robusto verso probe (evitare `verify=False` in produzione)

| Campo | Valore |
| --- | --- |
| Descrizione | Quando `PROBE_SCHEME=https`, richiedere `PROBE_CA_CERT` (o un truststore) e fallire in modo esplicito se manca; opzionale supporto mTLS. |
| Problema osservato | `PROBE_SCHEME=https` senza `PROBE_CA_CERT` porta a TLS non verificato (`verify=False`). |
| Beneficio atteso | Riduzione MITM e spoofing delle probe. |
| Priorita | Alta |
| Effort | M |
| Impatto | Alto |
| Area | sicurezza |
| File/cartelle coinvolte | `server/app.py`, docs. |
| Dipendenze | Coordinamento con distribuzione certificati lato probe (fuori scope). |
| Rischi | Rottura ambienti dove oggi TLS e self-signed senza CA configurata. |
| Criterio completamento | In modalita production: nessuna chiamata verso probe con `verify=False`; documentazione aggiornata. |
| Istruzioni per futuri agent | Introdurre env `ALLOW_INSECURE_PROBE_TLS=false` e default sicuro in production. |

### SRV-SCALE-01: Rate limiting persistente e reverse proxy correctness

| Campo | Valore |
| --- | --- |
| Descrizione | Sostituire rate limiting in-memory con store condiviso (Redis) o middleware dedicato; configurare `ProxyFix` per `remote_addr`/header affidabili. |
| Problema osservato | Rate limit basato su `request.remote_addr` e stato in memoria (`RATE_LIMIT_STATE`). |
| Beneficio atteso | Protezione consistente in produzione (multi-worker, reverse proxy). |
| Priorita | Media |
| Effort | M |
| Impatto | Medio |
| Area | performance |
| File/cartelle coinvolte | `server/app.py`, deployment docs. |
| Dipendenze | Potrebbe richiedere infrastruttura (Redis). |
| Rischi | Config errata puo bloccare utenti legittimi. |
| Criterio completamento | Rate limit consistente su piu processi; test di base; documentazione. |
| Istruzioni per futuri agent | Rendere la feature opzionale e configurabile, con fallback per dev. |

### SRV-DEP-01: Production server per Flask-SocketIO e dipendenze pinned

| Campo | Valore |
| --- | --- |
| Descrizione | Definire runtime production (es. gunicorn + eventlet/gevent) compatibile con Socket.IO; pin versioni dipendenze e documentare. |
| Problema osservato | Deploy attuale usa `python app.py` e requirements senza versioni. |
| Beneficio atteso | Stabilita deploy, riproducibilita, meno sorprese da upgrade impliciti. |
| Priorita | Media |
| Effort | M |
| Impatto | Medio |
| Area | DX |
| File/cartelle coinvolte | `server/requirements.txt`, `server/Dockerfile`, `server/docs/DEPLOYMENT.md`. |
| Dipendenze | Scelta di server ASGI/WSGI e async mode Socket.IO (da validare). |
| Rischi | Introduzione di eventlet/gevent cambia comportamento threading. |
| Criterio completamento | Docker image avvia con server production; smoke test websocket ok. |
| Istruzioni per futuri agent | Validare con un test manuale della dashboard che riceve update senza reload completo (se SRV-UX-01 implementata). |

### SRV-UX-01: Aggiornamento dashboard senza reload completo

| Campo | Valore |
| --- | --- |
| Descrizione | Sostituire `location.reload()` su evento `update_received` con update incrementale (fetch dati o push solo delta). |
| Problema osservato | Reload totale pagina ad ogni update (`server/templates/dashboard.html`). |
| Beneficio atteso | Migliore UX e riduzione carico su server/browser. |
| Priorita | Bassa |
| Effort | M |
| Impatto | Basso |
| Area | funzionalita |
| File/cartelle coinvolte | `server/templates/dashboard.html`, nuove API (opzionale). |
| Dipendenze | Potrebbe richiedere API per fetch per-host. |
| Rischi | Maggiore complessita JS. |
| Criterio completamento | Dashboard aggiorna metriche senza full reload; test manuale documentato. |
| Istruzioni per futuri agent | Implementare prima un endpoint JSON `GET /api/pc-info` protetto e rate-limited. |

### SRV-TEST-01: Ampliare test coverage e mocking chiamate verso probe

| Campo | Valore |
| --- | --- |
| Descrizione | Aggiungere test per `/login`, `/action`, `/request-update`, `/download-probe`, `/download-client`; mock `requests` per simulare probe. |
| Problema osservato | Test attuali coprono solo token e update (`server/tests/test_api.py`). |
| Beneficio atteso | Riduzione regressioni su funzionalita critiche (azioni remote). |
| Priorita | Alta |
| Effort | M |
| Impatto | Medio |
| Area | test |
| File/cartelle coinvolte | `server/tests/`, `server/app.py`. |
| Dipendenze | SRV-ARCH-01 facilita mocking e separazione. |
| Rischi | Test flakey se non si mockano correttamente time/rate-limit. |
| Criterio completamento | Suite test copre happy path e error path per azioni; execution time stabile. |
| Istruzioni per futuri agent | Introdurre fixture per inizializzare DB con righe `pc_info` e usare monkeypatch su `requests.post`. |

### SRV-OBS-01: Health endpoint e logging strutturato

| Campo | Valore |
| --- | --- |
| Descrizione | Aggiungere `GET /healthz` (no-auth o token) e standardizzare logging (request id, livelli, formati). |
| Problema osservato | Non esiste un endpoint di health; logging e basico (`logging.basicConfig(level=INFO)`). |
| Beneficio atteso | Migliore operativita (monitoring, readiness/liveness). |
| Priorita | Media |
| Effort | S |
| Impatto | Medio |
| Area | DX |
| File/cartelle coinvolte | `server/app.py`, docs. |
| Dipendenze | Nessuna. |
| Rischi | Esporre info sensibili se health include dettagli. |
| Criterio completamento | Endpoint risponde 200 e verifica connessione DB; documentato in DEPLOYMENT. |
| Istruzioni per futuri agent | Health deve essere cheap e non esporre segreti; usare un check minimale. |

### SRV-DOC-01: Versionare e testare il contratto `/update` e probe distribution

| Campo | Valore |
| --- | --- |
| Descrizione | Definire schema versionato per payload `/update` e meccanismo di compatibilita; aggiungere contract tests. |
| Problema osservato | Schema payload e "implicito" nel codice; `server/probe.py` e distribuito via API e deve restare compatibile con insert/upsert (`server/app.py`). |
| Beneficio atteso | Upgrade sicuri e riduzione rotture tra server e probe. |
| Priorita | Alta |
| Effort | M |
| Impatto | Alto |
| Area | documentazione |
| File/cartelle coinvolte | `server/app.py`, `server/probe.py`, `server/tests/`, docs. |
| Dipendenze | SRV-DATA-01 se lo schema DB cambia con nuove chiavi. |
| Rischi | Introduzione versione richiede coordinamento con launcher/client. |
| Criterio completamento | Schema documentato, test che validano payload minimo e payload esteso. |
| Istruzioni per futuri agent | Aggiungere un campo `schema_version` nel payload e gestire default lato server. |

## Note per il Prossimo Coding Agent

Ordine suggerito:
1. SRV-DATA-01 (evitare data loss prima di evolvere schema)
2. SRV-SEC-01 e SRV-SEC-02 (hardening UI)
3. SRV-TEST-01 (stabilizzare cambi con test)
4. SRV-ARCH-01 (refactor in moduli)
5. SRV-SEC-03 e SRV-SEC-04 (separazione credenziali e TLS probe)
6. SRV-DEP-01 e SRV-SCALE-01 (production hardening)
7. SRV-DOC-01 e SRV-UX-01 (contratto e UX)

Prerequisiti:
- Comprendere schema DB e flusso `/update` (leggere `DATA_MODEL.md` e `API_REFERENCE.md`).
- Validare l'ambiente di rete per discovery UDP e indirizzi IP.

Documenti da leggere prima di intervenire:
- [`server/docs/TECHNICAL_ANALYSIS.md`](TECHNICAL_ANALYSIS.md)
- [`server/docs/API_REFERENCE.md`](API_REFERENCE.md)
- [`server/docs/SECURITY_NOTES.md`](SECURITY_NOTES.md)
- [`server/docs/DATA_MODEL.md`](DATA_MODEL.md)

Aree da non toccare senza validazione:
- `check_and_recreate_db()` e gestione schema (rischio data loss).
- Contratto payload `/update` e distribuzione `server/probe.py` (impatti cross-project).

Quick wins:
- Aggiungere `/healthz` (SRV-OBS-01).
- Pin dipendenze e documentare runtime (parte di SRV-DEP-01).

Attivita ad alto rischio:
- Cambiare auth/token model (SRV-SEC-03) senza coordinamento con client/launcher.
- Cambiare schema DB senza migrazioni (SRV-DATA-01).


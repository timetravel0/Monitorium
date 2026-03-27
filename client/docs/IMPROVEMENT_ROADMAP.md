# Improvement Roadmap - Monitorium Client

Questa roadmap trasforma osservazioni su `client/` in task implementabili.

Legenda:

- Priorita: Alta / Media / Bassa
- Effort: S / M / L / XL
- Impatto: Alto / Medio / Basso
- Area: architettura / funzionalita / sicurezza / performance / DX / test / documentazione

## Task

### CLIENT-SEC-01: Autenticare `/set-interval` e aggiungere rate limiting

Descrizione: rendere `/set-interval` accessibile solo con token valido e aggiungere un rate limit base.
Problema osservato: endpoint non autenticato che modifica comportamento runtime (`probe.py`).
Beneficio atteso: riduzione superficie di attacco e prevenzione abuso.
Priorita: Alta
Effort stimato: S
Impatto: Alto
Area: sicurezza
File o cartelle coinvolte: `probe.py`
Dipendenze tra task: nessuna
Rischi: rottura compatibilita con eventuali chiamanti non autenticati (da verificare).
Criterio di completamento: richieste senza `Authorization: Bearer` ricevono 403; richieste con token valido funzionano; test aggiunti.
Istruzioni per futuri coding agent: riusare `verify_server_token()`; aggiornare `docs/API_REFERENCE.md`.

### CLIENT-SEC-02: Ridurre esposizione rete del probe (binding configurabile)

Descrizione: permettere configurazione del bind address del server Flask (es. `PROBE_BIND_HOST`) e documentare l'uso con firewall.
Problema osservato: probe ascolta su `0.0.0.0:5001` senza TLS, con endpoint sensibili.
Beneficio atteso: contenimento rischio in reti non fidate.
Priorita: Alta
Effort stimato: M
Impatto: Alto
Area: sicurezza
File o cartelle coinvolte: `probe.py`
Dipendenze tra task: nessuna (ma va verificata la compatibilita con chiamate server->probe, fuori perimetro).
Rischi: un binding restrittivo puo' rompere funzionalita se il server chiama direttamente il probe.
Criterio di completamento: variabile env introdotta; default esplicitato; doc aggiornata.
Istruzioni per futuri coding agent: prima di cambiare default, verificare il flusso server->probe nel progetto `server/`.

### CLIENT-SEC-03: Hardening TLS verso server (no `verify=False` silenzioso)

Descrizione: rendere esplicito il comportamento TLS, ad esempio fallendo se `SERVER_SCHEME=https` e CA mancante in modalita production.
Problema osservato: se CA mancante, il codice disabilita la verifica TLS.
Beneficio atteso: evita downgrade silenzioso della sicurezza.
Priorita: Media
Effort stimato: M
Impatto: Alto
Area: sicurezza
File o cartelle coinvolte: `probe.py`, `launcher.py`
Dipendenze tra task: nessuna
Rischi: installazioni esistenti che si affidano al fallback non verificato.
Criterio di completamento: comportamento configurabile (es. `TLS_INSECURE_ALLOW=true`), default sicuro e doc aggiornata.
Istruzioni per futuri coding agent: mantenere backward-compat con un flag esplicito.

### CLIENT-ARCH-01: Rendere l'auto-update atomico e con rollback

Descrizione: applicare update in modo atomico (backup del vecchio `probe.py`, rename sicuro, recovery su failure).
Problema osservato: `launcher.py` cancella `probe.py` prima del rename e non gestisce rollback.
Beneficio atteso: riduzione downtime e rischio corruzione installazione.
Priorita: Alta
Effort stimato: M
Impatto: Alto
Area: architettura
File o cartelle coinvolte: `launcher.py`
Dipendenze tra task: nessuna
Rischi: gestione permessi file su Windows; file lock se `probe.py` e' ancora in esecuzione.
Criterio di completamento: update non lascia mai il sistema senza `probe.py`; su failure ripristina versione precedente e logga chiaramente.
Istruzioni per futuri coding agent: aggiungere backup (es. `probe.py.bak`) e usare rename atomici dove possibile.

### CLIENT-ARCH-02: Separare configurazione e stato (path configurabili)

Descrizione: rendere configurabili i path di `version.txt`, `server.txt`, log file, per supportare installazioni come servizio.
Problema osservato: path relativi e working directory forzata.
Beneficio atteso: facilita deploy e gestione multi-istanza.
Priorita: Media
Effort stimato: M
Impatto: Medio
Area: architettura
File o cartelle coinvolte: `launcher.py`, `probe.py`
Dipendenze tra task: nessuna
Rischi: rottura installazioni che si aspettano i file nella directory corrente.
Criterio di completamento: variabili env (es. `STATE_DIR`) supportate; retro-compat mantenuta con default attuale.
Istruzioni per futuri coding agent: introdurre configurazione graduale, iniziando dai log e `server.txt`.

### CLIENT-FUNC-01: Migliorare resilienza discovery server

Descrizione: supportare fallback manuale via env (es. `SERVER_HOST`) e caching robusto dell'IP server.
Problema osservato: discovery UDP puo' fallire; `server.txt` e' letto ma non gestito/creato dal client.
Beneficio atteso: onboarding e operativita' piu' affidabili.
Priorita: Media
Effort stimato: S
Impatto: Medio
Area: funzionalita
File o cartelle coinvolte: `probe.py`, `launcher.py`
Dipendenze tra task: nessuna
Rischi: configurazioni conflittuali (env vs file vs discovery).
Criterio di completamento: priorita' di scelta definita e documentata; fallback chiaro.
Istruzioni per futuri coding agent: definire ordine consigliato (env > file > discovery) e loggare la scelta.

### CLIENT-TEST-01: Aggiungere test automatizzati per probe e launcher

Descrizione: introdurre una suite di test (unit + integration) con mocking di `psutil` e server fake.
Problema osservato: assenza test nel progetto `client/`.
Beneficio atteso: prevenire regressioni e rendere evoluzioni piu' sicure.
Priorita: Media
Effort stimato: L
Impatto: Medio
Area: test
File o cartelle coinvolte: `probe.py`, `launcher.py`, nuova cartella `tests/`
Dipendenze tra task: nessuna (ma serve scegliere framework di test e come installarlo).
Rischi: flakiness se test dipendono dal sistema reale; mitigare con mocking.
Criterio di completamento: test eseguibili offline e deterministici.
Istruzioni per futuri coding agent: iniziare dai test di parsing e auth, poi passare a integrazione update.

### CLIENT-DOC-01: Chiarire in doc il doppio uso di JWT

Descrizione: consolidare doc su doppio uso JWT (server->probe e probe->server) e su variabili env.
Problema osservato: due token distinti con stessa secret key; facile confondere flussi.
Beneficio atteso: onboarding e troubleshooting piu' rapidi.
Priorita: Bassa
Effort stimato: S
Impatto: Basso
Area: documentazione
File o cartelle coinvolte: `docs/API_REFERENCE.md`, `docs/DEPLOYMENT.md`, `docs/TECHNICAL_ANALYSIS.md`
Dipendenze tra task: nessuna
Rischi: nessuno
Criterio di completamento: doc con flussi descritti senza ambiguita'.
Istruzioni per futuri coding agent: mantenere la distinzione tra token "admin" (probe) e token "probe" (server).

## Note per il Prossimo Coding Agent

Ordine suggerito:

1. `CLIENT-SEC-01` (protezione endpoint non autenticato).
2. `CLIENT-ARCH-01` (update atomico/rollback).
3. `CLIENT-FUNC-01` (discovery/config esplicita).
4. `CLIENT-TEST-01` (test per stabilizzare evoluzione).
5. `CLIENT-SEC-02` e `CLIENT-SEC-03` (hardening rete/TLS, con attenzione alla compatibilita).

Prerequisiti:

- Leggere `client/AGENTS.md` e `client/docs/API_REFERENCE.md`.
- Capire come il server invoca il probe (progetto `server/`) prima di cambiare porte, path o binding.

Documenti da leggere prima di intervenire:

- `client/docs/TECHNICAL_ANALYSIS.md`
- `client/docs/SECURITY_NOTES.md`
- `client/docs/DEPLOYMENT.md`

Aree da non toccare senza validazione:

- Contratto payload verso `/update` (server potrebbe essere rigido).
- Logica di update (rischio di brick del probe).

Quick wins:

- Autenticare `/set-interval`.
- Aggiungere una variabile `SERVER_HOST` per evitare dipendenza dal broadcast UDP.

Attivita ad alto rischio:

- Cambiare i comandi OS per reboot/shutdown o il binding di rete del probe.
- Cambiare la gestione TLS/verify senza flag di compatibilita.

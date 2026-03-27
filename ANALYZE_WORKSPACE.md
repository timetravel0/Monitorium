# ANALYZE_WORKSPACE_AND_DOCUMENT

Agisci come un sistema multi-agentico specializzato nell’analisi di codebase e nella produzione di documentazione tecnica e funzionale di alta qualità.

Il tuo compito è analizzare la cartella corrente, che potrebbe contenere uno o più progetti software, documentarne architettura e funzionalità, produrre la documentazione necessaria per comprenderli e mantenerli, e generare artefatti utili per future evoluzioni del software.

---

## OBIETTIVO GENERALE

Devi:

1. analizzare il workspace corrente
2. identificare tutti i progetti reali contenuti al suo interno
3. escludere cartelle irrilevanti, generate o contenenti dipendenze esterne
4. produrre documentazione tecnica e funzionale utile e concreta
5. creare, se assente, un file `AGENTS.md` per ciascun progetto
6. generare una roadmap di migliorie future utilizzabile da futuri coding agent
7. non inventare informazioni non supportate dal codice reale

---

## MODALITÀ DI LAVORO

Lavora con approccio rigoroso, analitico, conservativo e basato esclusivamente su evidenze presenti nella codebase.

Se un’informazione non è determinabile con sufficiente certezza:
- dichiaralo esplicitamente
- distingui sempre tra:
  - evidenza certa
  - inferenza ragionevole
  - ipotesi da validare

Non produrre documentazione generica o da template se non contestualizzata al progetto reale.

---

## APPROCCIO MULTI-AGENTICO OBBLIGATORIO

Non affrontare il task come un’unica analisi monolitica. Suddividi il lavoro in agenti logici specializzati, coordinati tra loro.

### Agent 1 — Workspace Discovery Agent
Responsabilità:
- mappare il workspace
- identificare i progetti reali
- distinguere progetti, librerie interne, servizi e materiale non rilevante
- classificare ogni progetto
- creare `docs/WORKSPACE_OVERVIEW.md`

### Agent 2 — Functional Analyst Agent
Responsabilità:
- analizzare funzionalità, attori, casi d’uso, processi, regole di business
- identificare funzionalità implementate, incomplete o implicite
- creare la documentazione funzionale per ciascun progetto

### Agent 3 — Technical Architect Agent
Responsabilità:
- analizzare stack, moduli, pattern architetturali, dipendenze, integrazioni, flussi applicativi
- descrivere la struttura tecnica effettiva
- creare la documentazione tecnica per ciascun progetto

### Agent 4 — Security & Quality Agent
Responsabilità:
- analizzare rischi tecnici, sicurezza, qualità del codice, test, debito tecnico, criticità operative
- contribuire alla roadmap e ai documenti tecnici

### Agent 5 — Documentation Editor Agent
Responsabilità:
- consolidare i risultati degli altri agenti
- eliminare duplicazioni
- uniformare terminologia e struttura
- scrivere documenti finali leggibili, coerenti e utili

### Agent 6 — Future Improvements Agent
Responsabilità:
- generare roadmap concrete di miglioramento
- trasformare le osservazioni in task implementabili in futuro
- produrre documenti che possano essere usati da futuri coding agent per evolvere il progetto

### Regole di coordinamento
- ogni agente deve usare solo evidenze reali della codebase
- ogni agente deve citare file e path relativi concreti quando possibile
- nessun agente deve trattare codice generato o dipendenze esterne come business logic del progetto
- la sintesi finale deve mantenere distinzione chiara tra fatto, inferenza e ipotesi

---

## CONTESTO DEL WORKSPACE

La cartella corrente potrebbe contenere:
- un solo progetto
- più sottocartelle, ciascuna contenente un progetto distinto
- un monorepo
- servizi backend + frontend + librerie interne + strumenti + documentazione

### Fase iniziale obbligatoria: discovery del workspace

Prima di produrre qualsiasi documentazione dettagliata, devi:

1. esplorare la struttura del workspace
2. identificare tutte le sottocartelle che rappresentano veri progetti software
3. classificare ciascun progetto in una delle seguenti categorie:
   - frontend
   - backend
   - full-stack
   - libreria/package
   - microservizio
   - tool/CLI
   - infrastruttura/devops
   - documentazione
4. identificare relazioni tra progetti, se presenti
5. distinguere chiaramente codice sorgente da dipendenze, build output e file generati

### Criteri per riconoscere un progetto

Considera come possibile progetto una cartella che contiene uno o più segnali come:
- `package.json`
- `pnpm-workspace.yaml`
- `turbo.json`
- `requirements.txt`
- `pyproject.toml`
- `Pipfile`
- `go.mod`
- `Cargo.toml`
- `pom.xml`
- `build.gradle`
- `settings.gradle`
- `*.csproj`
- `Dockerfile`
- `docker-compose.yml`
- `Makefile`
- cartelle `src/`, `app/`, `server/`, `client/`, `cmd/`
- test o file di bootstrap applicativo

### Regola di biforcazione

Se il workspace contiene più progetti:
- prima crea una mappa globale del workspace
- poi analizza ogni progetto separatamente
- infine crea una sintesi trasversale e una roadmap master

Se il workspace contiene un solo progetto:
- applica comunque la discovery iniziale
- poi esegui il flusso standard su quel singolo progetto

---

## ESCLUSIONI OBBLIGATORIE DALL’ANALISI

NON analizzare come codice di progetto o business logic le seguenti cartelle e file, salvo usarli solo marginalmente per riconoscere il contesto tecnico:

- `node_modules/`
- `.git/`
- `.next/`
- `.nuxt/`
- `.output/`
- `dist/`
- `build/`
- `out/`
- `coverage/`
- `.cache/`
- `.turbo/`
- `.parcel-cache/`
- `target/`
- `bin/`
- `obj/`
- `vendor/`
- `.venv/`
- `venv/`
- `__pycache__/`
- `.pytest_cache/`
- `.mypy_cache/`
- `.idea/`
- `.vscode/`
- `tmp/`
- `temp/`
- file minificati `*.min.js`, `*.min.css`
- file lock (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, ecc.) come fonte di analisi funzionale

### Regola fondamentale
Queste cartelle/file NON devono essere trattati come sorgente architetturale o funzionale del progetto.

### Priorità delle fonti per comprendere il software
Ordine di priorità:
1. README e documentazione esistente
2. file di configurazione e manifest
3. entrypoint e bootstrap applicativi
4. moduli core, servizi, controller, componenti, model, repository
5. test
6. pipeline CI/CD e deployment
7. dipendenze solo per capire stack e contesto, non per documentare il comportamento del prodotto

---

## CREAZIONE DI AGENTS.md PER OGNI PROGETTO

Per ogni progetto rilevato:

- verifica se esiste già un file `AGENTS.md` nella root del progetto
- se esiste, leggilo e rispettalo
- se non esiste, crealo automaticamente
- non sovrascrivere un `AGENTS.md` già esistente, salvo esplicita necessità motivata
- ogni `AGENTS.md` deve essere specifico del progetto reale, non generico

### Scopo di AGENTS.md
Il file deve aiutare futuri coding agent a:
- capire rapidamente il progetto
- conoscere stack, cartelle importanti e convenzioni
- sapere quali cartelle ignorare
- usare i comandi corretti
- evitare modifiche fuori scope
- sapere quali documenti leggere prima di intervenire

### Contenuto minimo obbligatorio di ogni AGENTS.md
Ogni `AGENTS.md` creato deve includere, se determinabili dal progetto reale:

1. scopo del progetto
2. path root del progetto
3. tipo di progetto
4. stack principale
5. cartelle rilevanti
6. cartelle da ignorare
7. convenzioni di sviluppo osservate
8. comandi reali per:
   - installazione
   - avvio
   - test
   - lint
   - build
9. guardrail per futuri agent
10. riferimenti alla documentazione del progetto

### Template da adattare al progetto reale

Usa questo schema, ma riempilo solo con dati effettivamente osservati:

```md
# AGENTS.md

## Scopo
Breve descrizione del progetto.

## Identità del progetto
- Nome:
- Path root:
- Tipo:
- Stack principale:

## Cartelle rilevanti
- `...` — ...
- `...` — ...

## Cartelle da ignorare
- `node_modules/`
- `dist/`
- `build/`
- `.next/`
- `coverage/`
- `.git/`
- altre cartelle non rilevanti osservate nel progetto

## Convenzioni osservate
- naming convention
- pattern architetturali
- organizzazione moduli
- stile test
- eventuali convenzioni API/UI

## Comandi utili
```bash
# installazione
...

# avvio locale
...

# test
...

# lint / type-check
...

# build
...
```

## Guardrail
- leggi prima `README.md`
- leggi `docs/TECHNICAL_ANALYSIS.md` e `docs/IMPROVEMENT_ROADMAP.md` se presenti
- evita modifiche fuori scope
- non modificare file generati automaticamente
- aggiorna documentazione se cambi comportamento o architettura

## Output attesi da futuri coding agent
1. identificare i file coinvolti
2. proporre modifiche minime e coerenti
3. aggiornare test se necessario
4. aggiornare documentazione correlata
```

### Regola di qualità per AGENTS.md
Il contenuto deve essere:
- specifico
- sintetico
- concreto
- aderente al progetto reale
- privo di istruzioni inventate o comandi non verificabili

---

## DOCUMENTAZIONE DA PRODURRE

### Documenti globali del workspace
Crea nella root o nella cartella `docs/` del workspace:

1. `docs/WORKSPACE_OVERVIEW.md`
2. `docs/CROSS_PROJECT_ARCHITECTURE.md` (se ci sono più progetti)
3. `docs/MASTER_IMPROVEMENT_ROADMAP.md` (se ci sono più progetti)
4. aggiornamento o creazione del `README.md` principale della root workspace

### Documenti per ciascun progetto
Per ogni progetto rilevato, crea una cartella `docs/` nella root del progetto, se non esiste, e genera:

1. `README_PROJECT.md`
2. `FUNCTIONAL_ANALYSIS.md`
3. `TECHNICAL_ANALYSIS.md`
4. `DEPLOYMENT.md`
5. `IMPROVEMENT_ROADMAP.md`

Genera inoltre, solo se applicabili:
6. `API_REFERENCE.md`
7. `DATA_MODEL.md`
8. `SECURITY_NOTES.md`
9. `TESTING_STRATEGY.md`

---

## CONTENUTO MINIMO DEI DOCUMENTI

### 1. WORKSPACE_OVERVIEW.md
Deve contenere:
- mappa dei progetti rilevati
- path di ciascun progetto
- tipologia di ciascun progetto
- stack presunto/reale
- eventuali dipendenze o relazioni tra progetti
- note sui confini del workspace
- elenco delle cartelle escluse dall’analisi

### 2. CROSS_PROJECT_ARCHITECTURE.md
Se ci sono più progetti, descrivi:
- relazioni tra frontend/backend/librerie/servizi
- flussi di comunicazione
- dipendenze tra componenti del sistema
- punti di integrazione
- rischi architetturali cross-project
- eventuali duplicazioni o accoppiamenti forti

### 3. README.md della root
Deve spiegare:
- cos’è il workspace
- quali progetti contiene
- come orientarsi
- dove si trovano i documenti principali
- come partire per analizzare o modificare il sistema

### 4. README_PROJECT.md
Deve spiegare:
- scopo del progetto
- funzionalità principali
- stack
- struttura cartelle
- setup rapido
- comandi principali
- collegamenti agli altri documenti del progetto

### 5. FUNCTIONAL_ANALYSIS.md
Deve contenere:
- scopo funzionale del progetto
- attori principali
- casi d’uso identificabili
- flussi principali
- regole di business deducibili
- funzionalità complete
- funzionalità parziali/incomplete
- punti oscuri o da validare

### 6. TECHNICAL_ANALYSIS.md
Deve contenere:
- stack tecnologico
- entrypoint applicativi
- moduli principali
- pattern architetturali osservati
- flussi interni principali
- integrazioni esterne
- gestione configurazione
- stato qualità del codice
- debito tecnico
- criticità tecniche
- osservazioni su scalabilità e manutenibilità

### 7. DEPLOYMENT.md
Deve contenere, se determinabile:
- prerequisiti
- variabili d’ambiente rilevate
- build
- run
- deployment
- ambienti
- note su migrazioni, rollback, dipendenze infrastrutturali

### 8. API_REFERENCE.md
Se esistono API:
- endpoint o controller individuati
- responsabilità
- pattern request/response
- autenticazione/autorizzazione osservata
- dipendenze da servizi esterni
- limiti dell’analisi se le API non sono completamente inferibili

### 9. DATA_MODEL.md
Se esistono modelli dati:
- entità principali
- relazioni tra entità
- modelli applicativi
- repository/ORM/schema rilevati
- dubbi o incompletezze del modello

### 10. SECURITY_NOTES.md
Se rilevante:
- autenticazione
- autorizzazione
- gestione segreti/config
- validazione input
- criticità potenziali
- superfici di rischio

### 11. TESTING_STRATEGY.md
Se rilevante:
- test presenti
- livelli di test rilevati
- copertura percepita
- gap principali
- suggerimenti di miglioramento

### 12. IMPROVEMENT_ROADMAP.md
Questo è uno degli output più importanti.

Per ogni progetto deve contenere una roadmap con task concreti, ciascuno con:

- ID univoco (es. `PRJ-ARCH-01`, `PRJ-FUNC-02`)
- titolo
- descrizione
- problema osservato
- beneficio atteso
- priorità: Alta / Media / Bassa
- effort stimato: S / M / L / XL
- impatto: Alto / Medio / Basso
- area: architettura / funzionalità / sicurezza / performance / DX / test / documentazione
- file o cartelle coinvolte, se identificabili
- dipendenze tra task
- rischi
- criterio di completamento
- istruzioni per futuri coding agent

### Sezione obbligatoria finale in ogni roadmap
Aggiungi una sezione chiamata:

`## Note per il Prossimo Coding Agent`

con:
- ordine suggerito di esecuzione
- prerequisiti
- documenti da leggere prima di intervenire
- aree da non toccare senza validazione
- quick wins
- attività ad alto rischio

### MASTER_IMPROVEMENT_ROADMAP.md
Se ci sono più progetti, crea una roadmap master che:
- unisca i principali task trasversali
- distingua task per progetto da task cross-project
- evidenzi dipendenze tra progetti
- identifichi il miglior ordine di evoluzione del workspace

---

## REGOLE DI ANALISI

### Regola 1 — Basati sul codice reale
Non inventare feature, pattern o comportamenti non supportati da file reali.

### Regola 2 — Cita sempre i path
Quando descrivi un modulo, una responsabilità o un problema, cita i path relativi concreti se disponibili.

### Regola 3 — Distingui i livelli di certezza
Usa formulazioni che distinguano:
- evidenza osservata
- inferenza ragionevole
- ipotesi da validare

### Regola 4 — Non sporcare la documentazione
Niente frasi vaghe come:
- “soluzione moderna e scalabile”
- “architettura ben strutturata”
- “codice pulito”
se non supportate da osservazioni specifiche

### Regola 5 — Non modificare il codice applicativo
Il compito principale è analizzare e documentare.
Non introdurre modifiche al codice sorgente del progetto salvo minima creazione/aggiornamento dei file documentali richiesti e dei file `AGENTS.md`.

### Regola 6 — Rispettare la documentazione esistente
Se esiste già documentazione utile:
- riusala
- integrala
- correggila se necessario
- evita duplicazioni inutili

### Regola 7 — Gerarchia di coerenza
Per ogni progetto:
1. leggi `AGENTS.md` se presente
2. leggi `README.md` esistente se presente
3. analizza il codice reale
4. genera documentazione coerente con quanto osservato

---

## CRITERI DI QUALITÀ

La documentazione prodotta deve essere:

- specifica del progetto reale
- leggibile da umani
- utile per onboarding tecnico
- utile per futuri agent
- strutturata
- non ridondante
- concreta
- navigabile
- priva di riempitivi
- orientata a manutenzione ed evoluzione

---

## DONE WHEN

Il lavoro è completo solo se tutte le condizioni seguenti sono soddisfatte:

- [ ] È stata fatta la discovery iniziale del workspace
- [ ] Sono stati identificati i progetti reali
- [ ] Le cartelle irrilevanti (`node_modules`, `dist`, `build`, ecc.) non sono state trattate come codice progetto
- [ ] È stato creato `docs/WORKSPACE_OVERVIEW.md`
- [ ] Se ci sono più progetti, è stato creato `docs/CROSS_PROJECT_ARCHITECTURE.md`
- [ ] Se ci sono più progetti, è stato creato `docs/MASTER_IMPROVEMENT_ROADMAP.md`
- [ ] Il `README.md` della root è stato creato o aggiornato
- [ ] Per ogni progetto è stata creata o aggiornata la cartella `docs/`
- [ ] Per ogni progetto sono stati creati i documenti fondamentali
- [ ] Per ogni progetto esiste un file `AGENTS.md`
- [ ] Nessun `AGENTS.md` esistente è stato sovrascritto inutilmente
- [ ] Ogni `AGENTS.md` contiene istruzioni specifiche e reali del progetto
- [ ] Ogni roadmap contiene task implementabili in futuro
- [ ] Ogni roadmap contiene la sezione `Note per il Prossimo Coding Agent`
- [ ] La documentazione distingue fatti, inferenze e ipotesi
- [ ] Non sono state inventate informazioni non supportate dal codice

---

## FORMATO ATTESO DEGLI OUTPUT

Produci file Markdown ben formattati, con:
- titoli chiari
- sezioni coerenti
- tabelle dove utili
- bullet list dove opportune
- linguaggio chiaro e professionale
- contenuti sintetici ma completi

Se trovi ambiguità forti nel codice, documentale esplicitamente nei file finali invece di nasconderle.
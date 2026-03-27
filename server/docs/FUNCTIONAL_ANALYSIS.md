# Functional Analysis

## Scopo funzionale

Il server fornisce il centro di controllo per Monitorium: autentica operatori e probe,
riceve metriche, consente azioni remote e distribuisce aggiornamenti.

## Attori principali

- amministratore umano
- probe/client registrato
- server Monitorium stesso come coordinatore di discovery e update

## Casi d'uso identificati

- login alla dashboard
- issue di token per probe
- aggiornamento inventario host con metriche periodiche
- richiesta di reboot o shutdown di un host
- richiesta di aggiornamento immediato del probe
- download del probe e dell'installer client

## Flussi principali

1. L'amministratore effettua login e accede alla dashboard.
2. Il probe ottiene un token e invia i dati host a `/update`.
3. Il server salva o aggiorna la riga in `pc_info`.
4. L'amministratore puo richiedere reboot/shutdown o refresh del client.
5. Il server risponde alla discovery UDP con il proprio indirizzo IP.

## Regole di business deducibili

- le credenziali amministrative sono l'unica base per login e token issue
- ogni host e identificato dal `mac_address`
- i payload di update devono contenere un set completo di campi attesi
- l'endpoint `request-update` e `action` dipendono dalla risoluzione dell'IP del client
- gli eventi rilevanti vengono tracciati in `audit_log`

## Funzionalita complete

- dashboard base
- auth e token issue
- ingestione metriche
- audit log
- discovery UDP
- download del probe e dell'installer

## Funzionalita parziali o incomplete

- la scala orizzontale non e supportata dal rate limiting in memoria
- non c'e una migrazione schema esplicita
- l'aggiornamento del probe dipende da un file servito direttamente

## Punti oscuri da validare

- non e documentato un processo formale di deployment per ambienti multipli
- il ruolo di `Flask-SocketIO` e limitato a un evento osservato, quindi la sua
  finalita potrebbe essere ampliabile

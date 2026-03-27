# Security Notes

## Osservazioni

- Segreti e credenziali sono richiesti via environment variables.
- Le route tecniche principali richiedono JWT Bearer token.
- La dashboard usa sessione Flask e login esplicito.
- Le azioni inviate ai probe vengono tracciate su `audit_log`.
- Il rate limiting e presente ma solo in memoria.

## Superfici di rischio

- endpoint di reboot/shutdown verso i client
- download del probe come sorgente direttamente servito dal server
- eventuale disabilitazione TLS se i certificati non esistono
- ricostruzione del database in caso di mismatch schema

## Osservazioni specifiche

- `token_required()` controlla firma e scadenza, ma non introduce un modello di ruoli
  complesso
- `login_required()` protegge la dashboard, ma la protezione e basata su sessione
- il server accetta richieste di discovery via UDP broadcast sulla rete locale

## Rischi prioritari

1. protezione dei comandi remoti ai client
2. gestione TLS e certificati
3. tenuta dei segreti e delle credenziali
4. limitazione della superficie esposta dal download del probe

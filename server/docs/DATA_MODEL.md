# Data Model

## Persistence Layer

Il server usa SQLite tramite `sqlite3` e crea lo schema in `ensure_table_exists()`.

## Entita principali

### `pc_info`

Rappresenta lo stato dell'host monitorato.

Campi osservati:

- `id`
- `mac_address` unique
- `hostname`
- `local_ip_address`
- `public_ip_address`
- `platform`
- `cpu_usage`
- `memory_usage`
- `hdd_total`
- `hdd_used`
- `hdd_free`
- `hdd_percent`
- `running_processes`
- `used_ports`
- `last_reboot`
- `uptime`
- `current_users`
- `disk_io_read_bytes`
- `disk_io_write_bytes`
- `net_io_bytes_sent`
- `net_io_bytes_recv`
- `last_updated`

### `audit_log`

Registra gli eventi di sicurezza e operativi.

Campi osservati:

- `id`
- `created_at`
- `event_type`
- `actor`
- `target`
- `outcome`
- `details`

## Relazioni

- non esistono foreign key esplicite nel codice osservato
- `pc_info.mac_address` viene usato come chiave logica per l'upsert e la risoluzione
  dell'IP client

## Modelli applicativi

- i campi `running_processes`, `used_ports` e `current_users` vengono serializzati come
  JSON text
- il payload `update` del probe deve fornire gli oggetti annidati `hdd_usage`,
  `disk_io` e `network_io`

## Dubbi o incompletezze

- il controllo di schema confronta solo l'insieme dei campi, non la semantica o i
  vincoli aggiuntivi
- non ci sono migrazioni versionate

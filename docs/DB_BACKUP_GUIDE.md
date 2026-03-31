# DB Backup & Restore Feature — Integration Guide

## Overview

This feature adds a **Database Backup / Restore** modal to the Admin Settings menu.
- The server generates a raw gzip dump (pg_dump for Postgres, file-copy for SQLite).
- The browser **encrypts** the dump with AES-256-GCM + PBKDF2 (200 000 iterations) **before** saving it to disk — the server never sees the backup password or the plaintext dump at rest.
- On restore, the browser **decrypts** locally and uploads only the raw gzip to the server.

Works on both **local SQLite** and **production PostgreSQL (Render)**.

---

## How it works end-to-end

### Download (Dump)

```
Admin clicks "Download"
  → Browser sends POST /api/admin/db/dump { username, auth_hash }
    Server verifies admin + auth hash
    Server runs pg_dump (Postgres) or reads .db file (SQLite)
    Server gzips the output in memory
    Server streams gzip bytes back (never written to disk)
  ← Browser receives gzip bytes
  ← Browser encrypts: PBKDF2(backup_password) → AES-GCM key → encrypt(gzip)
  ← File downloaded as: securechat_*_dump_YYYYMMDD_HHMMSS.sql.gz.enc
                         (or .db.gz.enc for SQLite)
```

### Upload (Restore)

```
Admin selects .enc file, enters backup password, clicks "Restore"
  → Browser decrypts: PBKDF2(backup_password) → AES-GCM key → decrypt → gzip bytes
  → Browser uploads gzip bytes via multipart POST /api/admin/db/restore
    Server verifies admin + auth hash
    Server decompresses gzip
    Postgres: pipes SQL into psql
    SQLite:   backs up current .db → writes restored bytes
    Server returns { status, steps[] } with per-step detail
  ← Browser renders step-by-step log in the terminal panel
```

### File format (.enc)

| Offset | Length | Content |
|--------|--------|---------|
| 0      | 4 B    | Magic: `SCDB` |
| 4      | 16 B   | PBKDF2 salt (random) |
| 20     | 12 B   | AES-GCM IV (random) |
| 32     | rest   | AES-256-GCM ciphertext (of the gzip dump) |

---

## Render.com notes

- `pg_dump` / `psql` are available on Render's Python runtime (postgresql-client is pre-installed).
- The `DATABASE_URL` env var is automatically used by `_is_postgres()`.
- No additional Render environment variables are needed.
- Large dumps on the free plan may time out (120 s limit in the code); upgrade the plan or reduce DB size if needed.

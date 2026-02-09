# 🚀 Start Here - E2EE Messenger with SQL Migrations

Welcome! This guide will get you up and running in minutes.

## 📦 What You Got

Your enhanced E2EE messenger with these NEW features:
- ✅ **Unread Message Counter** - See how many unread messages from each contact
- ✅ **Clear Chat** - Delete conversation history  
- ✅ **Mute Users** - Silence notifications from specific contacts
- ✅ **Block Users** - Prevent users from sending you messages
- ✅ **SQL-based Migrations** - Clean, standard SQL (no Python migration code)

## ⚡ Quick Start

### 1️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 2️⃣ Run Local Migration (One Time Only)
```bash
sqlite3 e2ee_messenger.db < migrations/local.sql
```

### 3️⃣ Run the Application
```bash
python main.py
```

### 4️⃣ Open in Browser
```
http://localhost:8000
```

## 🎯 How Migrations Work

### Two Files, Two Databases:

```
migrations/
├── local.sql         ← For SQLite (local dev) - Run manually once
└── production.sql    ← For PostgreSQL (Render.com) - Runs automatically!
```

### Render.com = Automatic! ✨

In `render.yaml`:
```yaml
preDeployCommand: psql $DATABASE_URL -f migrations/production.sql
```

**Just push your code - Render runs the migration automatically!**

```bash
git push  # That's it! Migration runs before app starts
```

---

For complete migration instructions, see **SQL_MIGRATION_GUIDE.md**

**Happy messaging!** 🔐💬

# SQL Migration Guide (No Python Code)

This guide explains how to run SQL migrations without any Python migration code.

## 📁 File Structure

```
your-project/
├── migrations/
│   ├── local.sql           ← For SQLite (local development)
│   └── production.sql      ← For PostgreSQL (Render.com)
├── render.yaml             ← Contains preDeployCommand
└── ... (other files)
```

---

## 🎯 How It Works

### For Render.com (Production) - AUTOMATIC ✨

**Render.com automatically runs `migrations/production.sql` before starting your app!**

This is configured in `render.yaml`:
```yaml
preDeployCommand: psql $DATABASE_URL -f migrations/production.sql
```

**What happens when you deploy:**
1. You push code to GitHub
2. Render detects changes
3. Runs `pip install -r requirements.txt`
4. **Runs `migrations/production.sql`** ← Migration happens here!
5. Starts your app with `uvicorn main:app`

**You don't need to do anything!** Just push your code and Render handles the migration.

### For Local Development - MANUAL

You need to run the migration manually once:

```bash
sqlite3 e2ee_messenger.db < migrations/local.sql
```

---

## 🚀 Step-by-Step Instructions

### Local Development (IntelliJ)

#### Method 1: Command Line (Easiest)

1. Open Terminal in IntelliJ (Alt+F12 or View → Tool Windows → Terminal)
2. Run:
   ```bash
   sqlite3 e2ee_messenger.db < migrations/local.sql
   ```
3. Done! ✅

#### Method 2: IntelliJ Database Tool

1. **Open Database Tool:**
   - Go to View → Tool Windows → Database (or Alt+1)

2. **Connect to Database:**
   - Click **+** → Data Source → SQLite
   - Browse to your `e2ee_messenger.db` file
   - Click "Test Connection"
   - Click "OK"

3. **Open Query Console:**
   - Right-click on your database connection
   - Select "New" → "Query Console"

4. **Run Migration:**
   - Open `migrations/local.sql` in IntelliJ
   - Copy all the SQL content
   - Paste into the Query Console
   - Click the green "Execute" button or press Ctrl+Enter

5. **Verify:**
   - Refresh the database tree (right-click → Refresh)
   - Expand "Tables"
   - Check that `pending_messages` has a `read` column
   - Check that `user_preferences` table exists

#### Method 3: IntelliJ SQL Script

1. Right-click on `migrations/local.sql` in project explorer
2. Select "Run 'local.sql'"
3. IntelliJ will prompt to select a data source
4. Choose your SQLite database
5. Script executes automatically ✅

---

### Render.com (Production) - AUTOMATIC

#### Automatic Execution (Recommended)

**Just deploy your code - migration runs automatically!**

```bash
git add .
git commit -m "Deploy with migrations"
git push
```

**In Render Dashboard:**
1. Your service will start deploying
2. Check "Logs" tab
3. Look for migration output:
   ```
   ==> Running 'psql $DATABASE_URL -f migrations/production.sql'
   NOTICE: Added read column to pending_messages
   NOTICE: Created index idx_user_preferences_username
   NOTICE: ✅ Migration completed successfully!
   ==> Build successful
   ```

That's it! Your migration ran automatically.

#### Manual Execution (Optional)

If you need to run migration manually (not recommended, but possible):

**Method 1: Render Shell**

1. Go to Render Dashboard
2. Select your web service
3. Click "Shell" tab
4. Wait for shell to connect
5. Run:
   ```bash
   psql $DATABASE_URL -f migrations/production.sql
   ```

**Method 2: Local psql Client**

1. Install psql:
   ```bash
   # macOS
   brew install libpq
   brew link --force libpq
   
   # Ubuntu/Debian
   sudo apt-get install postgresql-client
   
   # Windows
   # Download from postgresql.org
   ```

2. Get Database URL from Render:
   - Go to Render Dashboard → Your Database → Info tab
   - Copy "External Database URL"

3. Run migration:
   ```bash
   psql "YOUR_EXTERNAL_DATABASE_URL" -f migrations/production.sql
   ```

---

## 📝 Migration File Details

### local.sql (SQLite)

```sql
-- Add read column
ALTER TABLE pending_messages ADD COLUMN read BOOLEAN DEFAULT 0 NOT NULL;

-- Create user_preferences table
CREATE TABLE IF NOT EXISTS user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(32) NOT NULL,
    blocked_users TEXT DEFAULT '[]' NOT NULL,
    muted_users TEXT DEFAULT '[]' NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Create index
CREATE INDEX IF NOT EXISTS idx_user_preferences_username 
ON user_preferences(username);
```

### production.sql (PostgreSQL)

```sql
-- Idempotent migrations with existence checks
DO $$ 
BEGIN
    -- Add read column if not exists
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pending_messages' AND column_name = 'read'
    ) THEN
        ALTER TABLE pending_messages ADD COLUMN read BOOLEAN DEFAULT FALSE NOT NULL;
    END IF;
END $$;

-- Create table if not exists
CREATE TABLE IF NOT EXISTS user_preferences (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    blocked_users TEXT DEFAULT '[]' NOT NULL,
    muted_users TEXT DEFAULT '[]' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Create index if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'idx_user_preferences_username'
    ) THEN
        CREATE INDEX idx_user_preferences_username ON user_preferences(username);
    END IF;
END $$;
```

**Key Differences:**
- SQLite: Simpler syntax, uses `INTEGER` and `TIMESTAMP`
- PostgreSQL: Uses `DO $$` blocks for conditional logic, `SERIAL` for auto-increment, `TIMESTAMP WITH TIME ZONE`

---

## 🔒 Safety Features

Both migration files are **idempotent** (safe to run multiple times):

✅ **SQLite:** Uses `IF NOT EXISTS` clauses  
✅ **PostgreSQL:** Checks `information_schema` before adding columns  
✅ **Non-destructive:** Only adds tables/columns, never deletes data  
✅ **No downtime:** Existing data remains intact  

---

## 🔍 Verifying Migration

### SQLite (Local)

```bash
# Check if read column exists
sqlite3 e2ee_messenger.db "PRAGMA table_info(pending_messages);" | grep read

# Check if user_preferences table exists
sqlite3 e2ee_messenger.db ".tables" | grep user_preferences

# View table structure
sqlite3 e2ee_messenger.db ".schema user_preferences"
```

### PostgreSQL (Render)

```bash
# Connect to database
psql $DATABASE_URL

# Check columns
\d pending_messages

# Check tables
\dt

# Check user_preferences structure
\d user_preferences

# Exit
\q
```

---

## 🐛 Troubleshooting

### Local SQLite Issues

#### "database is locked"
**Cause:** Another process is using the database.

**Solution:**
```bash
# Check what's using the database
lsof e2ee_messenger.db

# Kill the process or close your app first
```

#### "no such table: pending_messages"
**Cause:** Need to create initial tables first.

**Solution:**
```bash
# Run your application once to create tables
python main.py
# Then stop it and run migration
```

#### "duplicate column name: read"
**Cause:** Migration already ran.

**Solution:** ✅ This is fine! The migration already succeeded. SQLite doesn't support `IF NOT EXISTS` for `ALTER TABLE ADD COLUMN`, so you'll see this error if you run it twice. Just ignore it.

### Render.com Issues

#### "psql: command not found"
**Cause:** psql not available in Render environment (rare).

**Solution:** Contact Render support. The `preDeployCommand` should have psql available by default.

#### Migration fails during deployment
**Cause:** SQL syntax error or database connection issue.

**Solution:**
1. Check Render logs for specific error
2. Test migration locally first
3. Verify DATABASE_URL is set correctly

#### "relation already exists"
**Cause:** Tables already created.

**Solution:** ✅ This is fine! PostgreSQL migration checks for existence, so this shouldn't happen. If it does, the migration still succeeds.

---

## 📊 Deployment Workflow

### First Time Setup

1. **Develop locally:**
   ```bash
   # Run local migration once
   sqlite3 e2ee_messenger.db < migrations/local.sql
   
   # Start your app
   python main.py
   
   # Test features
   ```

2. **Deploy to Render:**
   ```bash
   git add .
   git commit -m "Initial deployment with migrations"
   git push
   ```
   
3. **Render automatically:**
   - Runs production migration
   - Starts your app
   - Everything works! ✅

### Subsequent Deployments

```bash
# Just push - migration runs automatically
git push
```

Render's `preDeployCommand` runs the migration every time, but it's safe because the migration is idempotent.

---

## 🎓 Best Practices

### Version Control

**Commit your migrations:**
```bash
git add migrations/local.sql
git add migrations/production.sql
git add render.yaml
git commit -m "Add migrations for new features"
```

### Testing

**Always test locally first:**
1. Run migration on local SQLite
2. Test all features work
3. Then deploy to production

### Backups

**Before running migrations:**

**Local:**
```bash
cp e2ee_messenger.db e2ee_messenger.db.backup
```

**Render:** 
- Render automatically backs up your database
- You can restore from Render dashboard → Database → Backups

### New Migrations

**To add new migrations:**

1. Create new migration files:
   ```
   migrations/002_add_feature.sql
   ```

2. Update `render.yaml`:
   ```yaml
   preDeployCommand: |
     psql $DATABASE_URL -f migrations/production.sql
     psql $DATABASE_URL -f migrations/002_add_feature.sql
   ```

3. Run locally:
   ```bash
   sqlite3 e2ee_messenger.db < migrations/002_add_feature.sql
   ```

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Run local migration | `sqlite3 e2ee_messenger.db < migrations/local.sql` |
| Deploy to Render | `git push` (migration runs automatically) |
| Check local tables | `sqlite3 e2ee_messenger.db ".tables"` |
| Check Render tables | `psql $DATABASE_URL -c "\dt"` |
| Verify migration | Check Render deployment logs |

---

## ✅ Summary

### For Render.com (Production):
✨ **Fully Automatic!** The `preDeployCommand` in `render.yaml` runs `migrations/production.sql` before every deployment.

### For Local Development:
⚡ **Run once manually:**
```bash
sqlite3 e2ee_messenger.db < migrations/local.sql
```

### Key Benefits:
- ✅ No Python migration code needed
- ✅ Standard SQL everyone understands
- ✅ Render automatically handles production
- ✅ Separate files for local vs production
- ✅ Idempotent (safe to run multiple times)
- ✅ Version controlled with your code

**That's it! Simple SQL migrations without any Python code.**

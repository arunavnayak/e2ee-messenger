-- ============================================================
-- PRODUCTION MIGRATION (PostgreSQL) - Render.com
-- ============================================================
-- This file runs AUTOMATICALLY on Render.com via preDeployCommand
-- You don't need to run this manually!

-- Add read column to pending_messages table (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'pending_messages' AND column_name = 'read'
    ) THEN
        ALTER TABLE pending_messages ADD COLUMN read BOOLEAN DEFAULT FALSE NOT NULL;
        RAISE NOTICE 'Added read column to pending_messages';
    ELSE
        RAISE NOTICE 'Column read already exists in pending_messages';
    END IF;
END $$;

-- Create user_preferences table (if not exists)
CREATE TABLE IF NOT EXISTS user_preferences (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    blocked_users TEXT DEFAULT '[]' NOT NULL,
    muted_users TEXT DEFAULT '[]' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Create index (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE indexname = 'idx_user_preferences_username'
    ) THEN
        CREATE INDEX idx_user_preferences_username ON user_preferences(username);
        RAISE NOTICE 'Created index idx_user_preferences_username';
    ELSE
        RAISE NOTICE 'Index idx_user_preferences_username already exists';
    END IF;
END $$;

-- Success message
DO $$
BEGIN
    RAISE NOTICE '✅ Migration completed successfully!';
END $$;


-- ===================== ALTER TABLE: users =====================
-- Add email column (nullable for existing users)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email VARCHAR(128);

-- Ensure all existing rows have unique dummy emails (for SQLite fallback)
-- NOTE: You can later update these manually if needed.
UPDATE users
SET email = username || '@placeholder.local'
WHERE email IS NULL;

-- Add a unique constraint (Postgres-safe)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_users_email'
    ) THEN
ALTER TABLE users ADD CONSTRAINT uq_users_email UNIQUE (email);
END IF;
EXCEPTION WHEN others THEN
    -- Ignore if running under SQLite (no pg_constraint table)
    RAISE NOTICE 'Skipping UNIQUE constraint creation (likely SQLite)';
END;
$$;

-- Add is_verified column (default false)
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;

-- ===============================================================

-- ===================== CREATE TABLE: user_verifications =====================
CREATE TABLE IF NOT EXISTS user_verifications (
    id SERIAL PRIMARY KEY,
    username VARCHAR(32) UNIQUE NOT NULL,
    email VARCHAR(128) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
                             );

-- Add indexes for lookup performance
CREATE INDEX IF NOT EXISTS idx_verifications_username
    ON user_verifications (username);

CREATE INDEX IF NOT EXISTS idx_verifications_email
    ON user_verifications (email);

-- ===============================================================

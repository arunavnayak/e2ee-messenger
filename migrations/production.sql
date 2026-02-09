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

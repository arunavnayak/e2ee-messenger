-- ============================================================
-- LOCAL DEVELOPMENT MIGRATION (SQLite)
-- ============================================================
-- Run this manually for local SQLite database
-- Command: sqlite3 e2ee_messenger.db < migrations/local.sql

-- Add read column to pending_messages table
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

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_preferences_username ON user_preferences(username);

-- Verification queries (optional - comment out after first run)
-- SELECT sql FROM sqlite_master WHERE name = 'pending_messages';
-- SELECT sql FROM sqlite_master WHERE name = 'user_preferences';

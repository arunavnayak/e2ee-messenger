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

ALTER TABLE users ADD COLUMN email VARCHAR(128);
ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS user_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(32) UNIQUE NOT NULL,
    email VARCHAR(128) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
    );

CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    emoji TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (message_id) REFERENCES pending_messages(id)
    );

CREATE INDEX IF NOT EXISTS idx_reactions_message_id
    ON message_reactions(message_id);


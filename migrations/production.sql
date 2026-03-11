-- ============================================================
-- PRODUCTION MIGRATION (PostgreSQL / Neon)
-- ============================================================
-- This file is safe to run multiple times (idempotent)
-- It creates all tables and indexes required by SQLAlchemy models
-- ============================================================


-- ===================== TABLE: users =====================
CREATE TABLE IF NOT EXISTS users (
                                     id SERIAL PRIMARY KEY,
                                     username VARCHAR(32) UNIQUE NOT NULL,
    email VARCHAR(128) UNIQUE NOT NULL,
    auth_hash VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_authorized BOOLEAN DEFAULT FALSE NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


-- ===================== TABLE: encrypted_vaults =====================
CREATE TABLE IF NOT EXISTS encrypted_vaults (
                                                id SERIAL PRIMARY KEY,
                                                username VARCHAR(32) UNIQUE NOT NULL,
    encrypted_vault_blob TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ
    );

CREATE INDEX IF NOT EXISTS idx_encrypted_vaults_username ON encrypted_vaults(username);


-- ===================== TABLE: pending_messages =====================
CREATE TABLE IF NOT EXISTS pending_messages (
                                                id SERIAL PRIMARY KEY,
                                                from_username VARCHAR(32) NOT NULL,
    to_username VARCHAR(32) NOT NULL,
    encrypted_payload TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    read BOOLEAN DEFAULT FALSE NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_pending_to_username ON pending_messages(to_username);
CREATE INDEX IF NOT EXISTS idx_pending_from_username ON pending_messages(from_username);


-- ===================== TABLE: session_tokens =====================
CREATE TABLE IF NOT EXISTS session_tokens (
                                              id SERIAL PRIMARY KEY,
                                              username VARCHAR(32) NOT NULL,
    token_hash VARCHAR(128) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_token_hash_expires ON session_tokens(token_hash, expires_at);


-- ===================== TABLE: user_preferences =====================
CREATE TABLE IF NOT EXISTS user_preferences (
                                                id SERIAL PRIMARY KEY,
                                                username VARCHAR(32) NOT NULL,
    blocked_users TEXT DEFAULT '[]' NOT NULL,
    muted_users TEXT DEFAULT '[]' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ
    );

CREATE INDEX IF NOT EXISTS idx_user_preferences_username ON user_preferences(username);


-- ===================== TABLE: user_verifications =====================
CREATE TABLE IF NOT EXISTS user_verifications (
                                                  id SERIAL PRIMARY KEY,
                                                  username VARCHAR(32) UNIQUE NOT NULL,
    email VARCHAR(128) NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
    );


-- ===================== TABLE: attachment_config =====================
CREATE TABLE IF NOT EXISTS attachment_config (
                                                 id SERIAL PRIMARY KEY,
                                                 max_image_size_mb INTEGER DEFAULT 5 NOT NULL,
                                                 max_file_size_mb INTEGER DEFAULT 10 NOT NULL,
                                                 updated_by VARCHAR(32),
    updated_at TIMESTAMPTZ
    );


-- ===================== TABLE: message_reactions =====================
CREATE TABLE IF NOT EXISTS message_reactions (
                                                 id SERIAL PRIMARY KEY,
                                                 message_id INTEGER NOT NULL REFERENCES pending_messages(id) ON DELETE CASCADE,
    username VARCHAR(32) NOT NULL,
    emoji VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
    );

CREATE INDEX IF NOT EXISTS idx_message_reactions_message_id ON message_reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_message_reactions_username ON message_reactions(username);


-- ===================== SUCCESS MESSAGE =====================
DO $$
BEGIN
    RAISE NOTICE '✅ Neon migration completed successfully!';
END $$;

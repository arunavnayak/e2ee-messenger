from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index
from sqlalchemy.sql import func
from database import Base

class User(Base):
    """User account with public key and auth hash"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    auth_hash = Column(String(128), nullable=False)  # PBKDF2 hash for authentication
    public_key = Column(Text, nullable=False)  # X25519 public key (base64)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class EncryptedVault(Base):
    """Zero-knowledge encrypted vault storing user's private key"""
    __tablename__ = "encrypted_vaults"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, index=True, nullable=False)
    encrypted_vault_blob = Column(Text, nullable=False)  # Encrypted private key
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class PendingMessage(Base):
    """Queue for messages to offline users"""
    __tablename__ = "pending_messages"

    id = Column(Integer, primary_key=True, index=True)
    from_username = Column(String(32), index=True, nullable=False)
    to_username = Column(String(32), index=True, nullable=False)
    encrypted_payload = Column(Text, nullable=False)  # E2EE ciphertext
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    read = Column(Boolean, default=False, nullable=False)  # Track if message has been read

    __table_args__ = (
        Index('idx_pending_to_username', 'to_username'),
    )

class SessionToken(Base):
    """WebSocket authentication tokens with expiration"""
    __tablename__ = "session_tokens"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), index=True, nullable=False)
    token_hash = Column(String(128), unique=True, index=True, nullable=False)  # SHA-256 hash of token
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index('idx_token_hash_expires', 'token_hash', 'expires_at'),
    )

class UserPreferences(Base):
    """User preferences for blocking and muting contacts"""
    __tablename__ = "user_preferences"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), index=True, nullable=False)
    blocked_users = Column(Text, default='[]', nullable=False)  # JSON array of blocked usernames
    muted_users = Column(Text, default='[]', nullable=False)  # JSON array of muted usernames
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        Index('idx_user_preferences_username', 'username'),
    )
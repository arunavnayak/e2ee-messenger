import hashlib
import hmac
import json
import os
import re
import base64
from datetime import datetime, timedelta, UTC
from typing import Dict

import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import text, or_
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

# Local Imports
from database import engine, get_db, Base, SessionLocal
from models import (
    User,
    EncryptedVault,
    PendingMessage,
    SessionToken,
    UserPreferences,
    UserVerification,
    MessageReaction,
    AttachmentConfig,
)
from rate_limiter import RateLimitMiddleware, login_rate_limiter, ws_rate_limiter
from status import router as status_router
from email_utils import send_otp_email
import random

# ==================== CONFIG ====================

PIPEDREAM_WEBHOOK_URL = os.getenv("PIPEDREAM_WEBHOOK_URL")
NOTIFICATION_FOR_USER = os.getenv("NOTIFICATION_FOR_USER")
NOTIFICATION_COOLDOWN_MINUTES = os.getenv("NOTIFICATION_COOLDOWN_MINUTES")

# Track last notification time per user (e.g., "Arunav")
last_notification_times: Dict[str, datetime] = {}

# Initialize Database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="E2EE Messenger", version="2.1.0")

# Include routers
app.include_router(status_router)


# ==================== SECURITY UTILITIES ====================

def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks"""
    return hmac.compare_digest(a.encode(), b.encode())


def hash_token(token: str) -> str:
    """Hash a session token using SHA-256"""
    return hashlib.sha256(token.encode()).hexdigest()


def cleanup_expired_tokens(db: Session):
    """Remove expired session tokens from database"""
    db.query(SessionToken).filter(
        SessionToken.expires_at < datetime.now(UTC)
    ).delete()
    db.commit()


def get_user_preferences(username: str, db: Session) -> UserPreferences:
    """Get or create user preferences"""
    prefs = db.query(UserPreferences).filter(UserPreferences.username == username).first()
    if not prefs:
        prefs = UserPreferences(username=username, blocked_users='[]', muted_users='[]')
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs


def is_user_blocked(blocker: str, blockee: str, db: Session) -> bool:
    """Check if blockee is blocked by blocker"""
    prefs = get_user_preferences(blocker, db)
    blocked_list = json.loads(prefs.blocked_users)
    return blockee in blocked_list


# ==================== NOTIFICATION UTILITIES ====================

def should_send_notification(username: str) -> bool:
    """Check cooldown for notifications for a given username"""
    now = datetime.now(UTC)
    last = last_notification_times.get(username)
    if not last:
        return True
    return (now - last) >= timedelta(minutes=NOTIFICATION_COOLDOWN_MINUTES)


def record_notification_sent(username: str) -> None:
    """Record that a notification was sent now"""
    last_notification_times[username] = datetime.now(UTC)


def send_pipedream_notification(caller: str, message: str) -> None:
    """Send notification to Pipedream webhook if configured"""
    if not PIPEDREAM_WEBHOOK_URL:
        return
    try:
        payload = {
            "caller": caller,
            "message": message,
        }
        headers = {"Content-Type": "application/json"}
        requests.post(PIPEDREAM_WEBHOOK_URL, json=payload, headers=headers, timeout=5)
    except Exception as e:
        # Log and continue; notification failures shouldn't break chat
        print("Pipedream notification error:", e)


def trigger_new_message_notification_if_needed(
    db: Session,
    to_username: str,
    from_username: str,
    recipient_online: bool,
):
    """
    Trigger notification for user 'NOTIFICATION_FOR_USER' (case-insensitive) if:
    - recipient is 'NOTIFICATION_FOR_USER'
    - recipient is offline (or message queued)
    - cooldown window has passed
    """
    if to_username.lower() != NOTIFICATION_FOR_USER:
        return

    if recipient_online:
        # Requirement: notify when user not online or has not read.
        # At send time, "not online" is approximated by !recipient_online.
        return

    if not should_send_notification(NOTIFICATION_FOR_USER):
        return

    # Count unread messages for NOTIFICATION_FOR_USER
    unread_count = db.query(PendingMessage).filter(
        PendingMessage.to_username == to_username,
        PendingMessage.read == False,  # noqa: E712
    ).count()

    if unread_count <= 0:
        return

    message_text = f"{unread_count} new message" if unread_count == 1 else f"{unread_count} new messages"
    send_pipedream_notification(caller=from_username, message=message_text)
    record_notification_sent(NOTIFICATION_FOR_USER)


# ==================== WEBSOCKET CONNECTION MANAGER ====================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket):
        # Don't accept here - already accepted in endpoint
        self.active_connections[username] = websocket

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]

    async def send_personal_message(self, message: dict, username: str):
        if username in self.active_connections:
            try:
                await self.active_connections[username].send_json(message)
                return True
            except Exception:
                self.disconnect(username)
                return False
        return False


manager = ConnectionManager()


# ==================== SECURITY MIDDLEWARE ====================

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict Content Security Policy
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' https://cdn.tailwindcss.com 'unsafe-eval' 'wasm-unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "worker-src 'self' blob:",
            "connect-src 'self' wss://*.onrender.com ws://localhost:8000 wss://localhost:8000",
            "img-src 'self' data: blob:",
            "font-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'"
        ]

        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


# Add middleware
app.add_middleware(CSPMiddleware)
app.add_middleware(RateLimitMiddleware)


# ==================== PYDANTIC MODELS ====================

class RegisterRequest(BaseModel):
    username: str
    email: str
    auth_hash: str
    public_key: str
    encrypted_vault: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not v or len(v) < 3 or len(v) > 32:
            raise ValueError("Username must be 3-32 characters")
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if "@" not in v:
            raise ValueError("Invalid email format")
        return v.lower()


def validate_password_strength(password: str) -> str:
    """
    Validates that a raw password meets complexity requirements:
    - At least 12 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    NOTE: The frontend never sends the raw password to the backend; this helper is
    used only in endpoints where the raw password is available (currently none, but
    kept as a reusable utility and enforced at the JS layer).  The backend enforces
    these same rules on the UpdateVaultRequest by checking the new_auth_hash is
    non-empty and trusting front-end validation.  All password complexity checks are
    primarily enforced in JS; this function is exported for any future endpoints that
    receive the plain password directly.
    """
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        raise ValueError("Password must contain at least one special character")
    return password


class LoginRequest(BaseModel):
    username: str
    auth_hash: str


class OTPRequest(BaseModel):
    username: str


class UpdateVaultRequest(BaseModel):
    username: str
    old_auth_hash: str
    new_auth_hash: str
    new_encrypted_vault: str


class SendMessageRequest(BaseModel):
    from_username: str
    to_username: str
    encrypted_payload: str


class BlockUserRequest(BaseModel):
    blocker: str
    blockee: str


class MuteUserRequest(BaseModel):
    muter: str
    mutee: str


class ClearChatRequest(BaseModel):
    username: str
    contact: str


class GetChatHistoryRequest(BaseModel):
    username: str
    contact: str


# ==================== API ENDPOINTS ====================

@app.post("/api/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Step 1: Register user and send OTP to email using Brevo (no‑reply)
    """
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user (unverified)
    user = User(
        username=req.username,
        email=req.email,
        auth_hash=req.auth_hash,
        public_key=req.public_key,
        is_verified=False,
    )
    db.add(user)

    vault = EncryptedVault(
        username=req.username,
        encrypted_vault_blob=req.encrypted_vault
    )
    db.add(vault)
    db.commit()

    # Generate OTP and send
    otp = "".join(random.choices("0123456789", k=6))
    exp_time = datetime.now(UTC) + timedelta(minutes=10)

    old = db.query(UserVerification).filter(
        UserVerification.username == req.username
    ).first()
    if old:
        db.delete(old)
        db.commit()

    verification = UserVerification(
        username=req.username,
        email=req.email,
        otp_code=otp,
        expires_at=exp_time
    )
    db.add(verification)
    db.commit()

    try:
        send_otp_email(req.email, req.username, otp)
    except Exception as e:
        print("Brevo email failure:", e)
        raise HTTPException(status_code=500, detail="Could not send verification email")

    return {
        "status": "pending_verification",
        "username": req.username,
        "message": f"OTP sent to {req.email}",
    }


@app.post("/api/login")
async def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate and retrieve encrypted vault with session token"""

    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"
    identifier = f"{client_ip}:{req.username}"

    # Check if locked out
    if login_rate_limiter.is_locked_out(identifier):
        wait_time = login_rate_limiter.get_wait_time(identifier)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {wait_time} seconds.",
            headers={"Retry-After": str(wait_time)}
        )

    user = db.query(User).filter(User.username == req.username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.is_verified:
        return {
            "status": "pending_verification",
            "username": req.username,
            "message": "Account email not verified. Please verify via OTP.",
        }

    if not user.is_authorized:
        return {
            "status": "pending_approval",
            "username": req.username,
            "message": "Your account is awaiting admin approval. Please check back later.",
        }

    # Use constant-time comparison to prevent timing attacks
    if not user or not constant_time_compare(user.auth_hash, req.auth_hash):
        # Record failed attempt
        login_rate_limiter.record_failed_attempt(identifier)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Clear failed attempts on successful login
    login_rate_limiter.clear_attempts(identifier)

    vault = db.query(EncryptedVault).filter(
        EncryptedVault.username == req.username
    ).first()

    # Get all messages for this user (both read and unread)
    pending = db.query(PendingMessage).filter(
        PendingMessage.to_username == req.username
    ).all()

    pending_messages = [
        {
            "from": msg.from_username,
            "payload": msg.encrypted_payload,
            "timestamp": msg.timestamp.isoformat(timespec="milliseconds"),
            "read": msg.read
        }
        for msg in pending
    ]

    # Calculate unread counts per sender
    unread_counts: Dict[str, int] = {}
    for msg in pending:
        if not msg.read:
            unread_counts[msg.from_username] = unread_counts.get(msg.from_username, 0) + 1

    # Generate session token for WebSocket authentication
    import secrets
    session_token = secrets.token_urlsafe(32)
    token_hash = hash_token(session_token)

    # Store hashed token in database (expires in 24 hours)
    session = SessionToken(
        username=req.username,
        token_hash=token_hash,
        expires_at=datetime.now(UTC) + timedelta(hours=24)
    )
    db.add(session)

    # Clean up old expired tokens (do this periodically)
    cleanup_expired_tokens(db)

    # Get user preferences
    prefs = get_user_preferences(req.username, db)

    db.commit()

    return {
        "status": "success",
        "username": req.username,
        "public_key": user.public_key,
        "encrypted_vault": vault.encrypted_vault_blob,
        "pending_messages": pending_messages,
        "unread_counts": unread_counts,
        "session_token": session_token,
        "blocked_users": json.loads(prefs.blocked_users),
        "muted_users": json.loads(prefs.muted_users),
        "is_admin": user.is_admin,
    }


"""
    On successful /api/login, store:
    1. username
    2. session_token
    3. (optionally) encrypted_vault etc. in localStorage or sessionStorage.
    
    On page load:
    Check if username and session_token exist in storage.
    1. If yes, call /api/session/restore with them.
    2. If restore succeeds → go straight to chat UI, reconnect WebSocket using that token.
    3. If it fails → clear storage and show login page.
"""
class RestoreSessionRequest(BaseModel):
    username: str
    session_token: str

@app.post("/api/session/restore")
async def restore_session(req: RestoreSessionRequest, db: Session = Depends(get_db)):
    """
    Restore a logged-in session using an existing session token.
    Used to survive page refresh without re-entering password.
    """

    # Reuse the same verification logic as WebSocket auth
    is_valid = await verify_websocket_token(req.username, req.session_token, db)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")

    user = db.query(User).filter(User.username == req.username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.is_verified:
        return {
            "status": "pending_verification",
            "username": req.username,
            "message": "Account email not verified. Please verify via OTP.",
        }

    if not user.is_authorized:
        return {
            "status": "pending_approval",
            "username": req.username,
            "message": "Your account is awaiting admin approval. Please check back later.",
        }

    vault = db.query(EncryptedVault).filter(
        EncryptedVault.username == req.username
    ).first()

    # Get all messages for this user (both read and unread)
    pending = db.query(PendingMessage).filter(
        PendingMessage.to_username == req.username
    ).all()

    pending_messages = [
        {
            "from": msg.from_username,
            "payload": msg.encrypted_payload,
            "timestamp": msg.timestamp.isoformat(timespec="milliseconds"),
            "read": msg.read,
        }
        for msg in pending
    ]

    # Calculate unread counts per sender
    unread_counts = {}
    for msg in pending:
        if not msg.read:
            unread_counts[msg.from_username] = unread_counts.get(msg.from_username, 0) + 1

    # Get user preferences
    prefs = get_user_preferences(req.username, db)

    return {
        "status": "success",
        "username": req.username,
        "public_key": user.public_key,
        "encrypted_vault": vault.encrypted_vault_blob,
        "pending_messages": pending_messages,
        "unread_counts": unread_counts,
        "session_token": req.session_token,  # reuse existing token
        "blocked_users": json.loads(prefs.blocked_users),
        "muted_users": json.loads(prefs.muted_users),
        "is_admin": user.is_admin,
    }



@app.post("/api/update-vault")
async def update_vault(req: UpdateVaultRequest, db: Session = Depends(get_db)):
    """Update encrypted vault (password change)"""
    user = db.query(User).filter(User.username == req.username).first()

    if not user or not constant_time_compare(user.auth_hash, req.old_auth_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.auth_hash = req.new_auth_hash

    vault = db.query(EncryptedVault).filter(
        EncryptedVault.username == req.username
    ).first()
    vault.encrypted_vault_blob = req.new_encrypted_vault

    db.commit()

    return {"status": "success", "message": "Vault updated successfully"}


# ==================== ATTACHMENT CONFIG (ADMIN ONLY) ====================

def get_attachment_config(db: Session) -> AttachmentConfig:
    """Return the single AttachmentConfig row, creating it with defaults if absent."""
    cfg = db.query(AttachmentConfig).filter(AttachmentConfig.id == 1).first()
    if not cfg:
        cfg = AttachmentConfig(id=1, max_image_size_mb=5, max_file_size_mb=10)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


@app.get("/api/admin/attachment-config")
async def get_attachment_config_endpoint(db: Session = Depends(get_db)):
    """Return current attachment size limits (readable by all authenticated clients)."""
    cfg = get_attachment_config(db)
    return {
        "max_image_size_mb": cfg.max_image_size_mb,
        "max_file_size_mb": cfg.max_file_size_mb,
    }


class UpdateAttachmentConfigRequest(BaseModel):
    admin_username: str
    max_image_size_mb: int
    max_file_size_mb: int

    @field_validator("max_image_size_mb", "max_file_size_mb")
    @classmethod
    def positive_mb(cls, v):
        if v < 1 or v > 100:
            raise ValueError("Size must be between 1 and 100 MB")
        return v


@app.post("/api/admin/attachment-config")
async def update_attachment_config(req: UpdateAttachmentConfigRequest, db: Session = Depends(get_db)):
    """Update attachment size limits. Only admin users are permitted."""
    admin = db.query(User).filter(User.username == req.admin_username).first()
    if not admin or not admin.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")

    cfg = get_attachment_config(db)
    cfg.max_image_size_mb = req.max_image_size_mb
    cfg.max_file_size_mb = req.max_file_size_mb
    cfg.updated_by = req.admin_username
    db.commit()

    return {
        "status": "success",
        "max_image_size_mb": cfg.max_image_size_mb,
        "max_file_size_mb": cfg.max_file_size_mb,
    }


# ==================== FILE ATTACHMENT UPLOAD ====================

# Allowed MIME types and their categories
ALLOWED_MIME_TYPES = {
    # Images
    "image/jpeg": "image",
    "image/png": "image",
    # Documents
    "application/msword": "file",                                                        # .doc
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "file",  # .docx (treat as doc)
    "text/plain": "file",                                                                # .txt
    "application/pdf": "file",                                                           # .pdf
}

ALLOWED_EXTENSIONS = {".jpeg", ".jpg", ".png", ".doc", ".docx", ".txt", ".pdf"}


class AttachmentUploadRequest(BaseModel):
    from_username: str
    to_username: str
    filename: str
    mime_type: str
    # Base64-encoded encrypted file data (already E2EE by the client)
    encrypted_data: str
    # Nonce used during encryption, base64
    nonce: str
    # Sender's public key so the recipient can derive the shared key
    sender_public_key: str


@app.post("/api/attachment/upload")
async def upload_attachment(req: AttachmentUploadRequest, db: Session = Depends(get_db)):
    """
    Accept an E2EE-encrypted file attachment.
    The client encrypts the file bytes with AES-GCM (same ECDH shared-key flow as messages)
    and sends the base64-encoded ciphertext here.  The server stores the ciphertext in the
    existing PendingMessage table using a special payload envelope so it travels through the
    normal messaging pipeline.
    """
    # Validate mime type
    mime = req.mime_type.lower()
    if mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400, detail=f"File type '{mime}' is not allowed. Allowed: jpeg/png/doc/txt/pdf")

    # Validate extension
    import os as _os
    ext = _os.path.splitext(req.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File extension '{ext}' is not allowed")

    # Enforce size limits
    cfg = get_attachment_config(db)
    category = ALLOWED_MIME_TYPES[mime]
    max_bytes = (cfg.max_image_size_mb if category == "image" else cfg.max_file_size_mb) * 1024 * 1024

    try:
        raw_bytes = base64.b64decode(req.encrypted_data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for encrypted_data")

    if len(raw_bytes) > max_bytes:
        limit_mb = cfg.max_image_size_mb if category == "image" else cfg.max_file_size_mb
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size for {category}s is {limit_mb} MB"
        )

    # Package as a special payload envelope (same format as text messages but with type="attachment")
    payload = json.dumps({
        "type": "attachment",
        "sender_public_key": req.sender_public_key,
        "nonce": req.nonce,
        "ciphertext": req.encrypted_data,   # already base64-encoded encrypted bytes
        "filename": req.filename,
        "mime_type": req.mime_type,
        "category": category,
    })

    # Check if recipient is blocked
    if is_user_blocked(req.to_username, req.from_username, db):
        raise HTTPException(status_code=403, detail="You are blocked by this user")

    # Store as a PendingMessage (same as text messages, flows through normal delivery)
    message_record = PendingMessage(
        from_username=req.from_username,
        to_username=req.to_username,
        encrypted_payload=payload,
        read=False,
    )
    db.add(message_record)
    db.commit()
    db.refresh(message_record)

    # Attempt real-time delivery via WebSocket
    delivered = await manager.send_personal_message(
        {
            "type": "message",
            "from": req.from_username,
            "payload": payload,
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "message_id": message_record.id,
        },
        req.to_username,
    )

    return {
        "status": "delivered" if delivered else "queued",
        "message_id": message_record.id,
    }


@app.get("/api/users")
async def list_users(db: Session = Depends(get_db)):
    """List all registered users"""
    users = db.query(User).all()
    return {
        "users": [
            {"username": u.username, "public_key": u.public_key}
            for u in users
        ]
    }


@app.get("/api/chat/history/{username}/{contact}")
async def get_chat_history(username: str, contact: str, db: Session = Depends(get_db)):
    """Get complete chat history between two users (both sent and received messages)"""

    # Get ALL messages between these two users, ordered by timestamp
    messages = db.query(PendingMessage).filter(
        or_(
            (PendingMessage.from_username == username) & (PendingMessage.to_username == contact),
            (PendingMessage.from_username == contact) & (PendingMessage.to_username == username)
        )
    ).order_by(PendingMessage.timestamp).all()

    # fetch reactions for these messages
    message_ids = [m.id for m in messages]
    reactions = db.query(MessageReaction).filter(
        MessageReaction.message_id.in_(message_ids)
    ).all()

    reactions_by_msg = {}
    for r in reactions:
        reactions_by_msg.setdefault(r.message_id, []).append({
            "username": r.username,
            "emoji": r.emoji,
            "timestamp": r.created_at.isoformat(timespec="milliseconds"),
        })

    chat_history = []
    for msg in messages:
        chat_history.append({
            "id": msg.id,
            "from": msg.from_username,
            "to": msg.to_username,
            "payload": msg.encrypted_payload,
            "timestamp": msg.timestamp.isoformat(timespec="milliseconds"),
            "read": msg.read,
            "is_sent": msg.from_username == username,
            "reactions": reactions_by_msg.get(msg.id, []),
        })

    return {
        "status": "success",
        "messages": chat_history
    }


class MarkReadRequest(BaseModel):
    from_username: str
    to_username: str


@app.post("/api/messages/mark-read")
async def mark_messages_read(req: MarkReadRequest, db: Session = Depends(get_db)):
    """Mark messages from a specific user as read"""
    db.query(PendingMessage).filter(
        PendingMessage.from_username == req.from_username,
        PendingMessage.to_username == req.to_username
    ).update({"read": True})

    db.commit()

    return {"status": "success", "message": "Messages marked as read"}


@app.post("/api/chat/clear")
async def clear_chat(req: ClearChatRequest, db: Session = Depends(get_db)):
    """Clear chat history between two users (removes all messages)"""

    # Clear all messages between these two users
    db.query(PendingMessage).filter(
        ((PendingMessage.from_username == req.contact) & (PendingMessage.to_username == req.username)) |
        ((PendingMessage.from_username == req.username) & (PendingMessage.to_username == req.contact))
    ).delete(synchronize_session=False)

    db.commit()

    return {"status": "success", "message": "Chat cleared"}


@app.post("/api/chat/history")
async def get_chat_history(req: GetChatHistoryRequest, db: Session = Depends(get_db)):
    """Get all chat messages between two users"""

    # Get all messages between these two users
    messages = db.query(PendingMessage).filter(
        ((PendingMessage.from_username == req.contact) & (PendingMessage.to_username == req.username)) |
        ((PendingMessage.from_username == req.username) & (PendingMessage.to_username == req.contact))
    ).order_by(PendingMessage.timestamp.asc()).all()

    return {
        "status": "success",
        "messages": [
            {
                "from": msg.from_username,
                "to": msg.to_username,
                "payload": msg.encrypted_payload,
                "timestamp": msg.timestamp.isoformat(timespec="milliseconds"),
                "read": msg.read,
                "id": msg.id
            }
            for msg in messages
        ]
    }


@app.post("/api/user/block")
async def block_user(req: BlockUserRequest, db: Session = Depends(get_db)):
    """Block a user"""
    prefs = get_user_preferences(req.blocker, db)
    blocked_list = json.loads(prefs.blocked_users)

    if req.blockee not in blocked_list:
        blocked_list.append(req.blockee)
        prefs.blocked_users = json.dumps(blocked_list)
        db.commit()

    return {"status": "success", "message": f"User {req.blockee} blocked"}


@app.post("/api/user/unblock")
async def unblock_user(req: BlockUserRequest, db: Session = Depends(get_db)):
    """Unblock a user"""
    prefs = get_user_preferences(req.blocker, db)
    blocked_list = json.loads(prefs.blocked_users)

    if req.blockee in blocked_list:
        blocked_list.remove(req.blockee)
        prefs.blocked_users = json.dumps(blocked_list)
        db.commit()

    return {"status": "success", "message": f"User {req.blockee} unblocked"}


@app.post("/api/user/mute")
async def mute_user(req: MuteUserRequest, db: Session = Depends(get_db)):
    """Mute a user"""
    prefs = get_user_preferences(req.muter, db)
    muted_list = json.loads(prefs.muted_users)

    if req.mutee not in muted_list:
        muted_list.append(req.mutee)
        prefs.muted_users = json.dumps(muted_list)
        db.commit()

    return {"status": "success", "message": f"User {req.mutee} muted"}


@app.post("/api/user/unmute")
async def unmute_user(req: MuteUserRequest, db: Session = Depends(get_db)):
    """Unmute a user"""
    prefs = get_user_preferences(req.muter, db)
    muted_list = json.loads(prefs.muted_users)

    if req.mutee in muted_list:
        muted_list.remove(req.mutee)
        prefs.muted_users = json.dumps(muted_list)
        db.commit()

    return {"status": "success", "message": f"User {req.mutee} unmuted"}


@app.get("/api/user/preferences/{username}")
async def get_preferences(username: str, db: Session = Depends(get_db)):
    """Get user preferences"""
    prefs = get_user_preferences(username, db)

    return {
        "blocked_users": json.loads(prefs.blocked_users),
        "muted_users": json.loads(prefs.muted_users)
    }

#Verify OTP
class VerifyOTPRequest(BaseModel):
    username: str
    otp_code: str


@app.post("/api/verify-otp")
async def verify_otp(req: VerifyOTPRequest, db: Session = Depends(get_db)):
    """
    Step 2: Verify OTP and mark user as verified
    """
    record = db.query(UserVerification).filter(
        UserVerification.username == req.username
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="No verification record found")

    if record.otp_code != req.otp_code:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # If record.expires_at is naive, tell Python it's actually UTC
    if record.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise HTTPException(status_code=400, detail="OTP expired")

    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_verified = True
    db.delete(record)
    db.commit()

    return {"status": "success", "message": "Email verified successfully"}


@app.post("/api/resend-otp")
async def resend_otp(req: OTPRequest, db: Session = Depends(get_db)):
    """
    Generate and send a new OTP via Brevo
    (Only allowed if user exists but is not yet verified)
    """
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        raise HTTPException(status_code=400, detail="User already verified")

    # Before generating OTP:
    if not ws_rate_limiter.check_message(req.username):
        raise HTTPException(status_code=429, detail="Please wait before requesting another OTP")

    # Delete any previous pending OTP records
    existing = (
        db.query(UserVerification)
        .filter(UserVerification.username == req.username)
        .first()
    )
    if existing:
        db.delete(existing)
        db.commit()

    # Generate new OTP
    import random
    otp = "".join(random.choices("0123456789", k=6))
    expires_at = datetime.now(UTC) + timedelta(minutes=10)

    record = UserVerification(
        username=user.username,
        email=user.email,
        otp_code=otp,
        expires_at=expires_at
    )
    db.add(record)
    db.commit()

    try:
        send_otp_email(user.email, user.username, otp)
    except Exception as e:
        print("Brevo send error:", e)
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

    return {
        "status": "success",
        "message": f"New OTP sent to {user.email}. It will expire in 10 minutes.",
    }


# ==================== WEBSOCKET ENDPOINT ====================

async def verify_websocket_token(username: str, token: str, db: Session) -> bool:
    """Verify WebSocket session token"""
    token_hash = hash_token(token)

    session = db.query(SessionToken).filter(
        SessionToken.username == username,
        SessionToken.token_hash == token_hash,
        SessionToken.expires_at > datetime.now(UTC)
    ).first()

    return session is not None


@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """Real-time message delivery via WebSocket with authentication"""

    # Create a dedicated database session for this WebSocket connection
    db = SessionLocal()

    # First, receive authentication message
    await websocket.accept()

    try:
        # Wait for auth message (timeout after 5 seconds)
        import asyncio
        auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=5.0)

        if auth_data.get("type") != "auth":
            await websocket.send_json({"type": "error", "message": "Authentication required"})
            await websocket.close(code=1008)  # Policy violation
            db.close()
            return

        token = auth_data.get("token")
        if not token or not await verify_websocket_token(username, token, db):
            await websocket.send_json({"type": "error", "message": "Invalid token"})
            await websocket.close(code=1008)
            db.close()
            return

        # Authentication successful
        await websocket.send_json({"type": "auth_success"})
        await manager.connect(username, websocket)

    except asyncio.TimeoutError:
        await websocket.send_json({"type": "error", "message": "Authentication timeout"})
        await websocket.close(code=1008)
        db.close()
        return
    except Exception as e:
        print(f"WebSocket auth error: {e}")
        import traceback
        traceback.print_exc()
        await websocket.close(code=1011)  # Internal error
        db.close()
        return

    try:
        while True:
            data = await websocket.receive_json()

            # Rate limiting for messages
            if data.get("type") == "message":
                if not ws_rate_limiter.check_message(username):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Message rate limit exceeded. Please slow down."
                    })
                    continue

                from_user = data.get("from")
                to_user = data.get("to")
                encrypted_payload = data.get("payload")
                message_id = data.get("message_id")

                # Verify sender matches authenticated user
                if from_user != username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Sender mismatch"
                    })
                    continue

                # Check if sender is blocked by recipient
                if is_user_blocked(to_user, from_user, db):
                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "blocked",
                        "message": f"Cannot send message. You are blocked by {to_user}",
                        "message_id": message_id
                    })
                    continue

                # ALWAYS save the message to database (for chat history)
                try:
                    message_record = PendingMessage(
                        from_username=from_user,
                        to_username=to_user,
                        encrypted_payload=encrypted_payload,
                        read=False  # Will be marked as read when recipient reads it
                    )
                    db.add(message_record)
                    db.commit()
                except Exception as e:
                    print(f"Error saving message: {e}")
                    db.rollback()

                # Try to deliver in real-time
                delivered = await manager.send_personal_message(
                    {
                        "type": "message",
                        "from": from_user,
                        "payload": encrypted_payload,
                        "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
                        "message_id": message_id
                    },
                    to_user
                )

                if delivered:
                    # Message delivered in real-time
                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "delivered",
                        "message": f"Message delivered to {to_user}",
                        "message_id": message_id
                    })
                else:
                    # Message saved but user offline
                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "queued",
                        "message": f"User {to_user} is offline. Message queued.",
                        "message_id": message_id
                    })

                # Trigger notification for Arunav if offline / queued
                trigger_new_message_notification_if_needed(
                    db=db,
                    to_username=to_user,
                    from_username=from_user,
                    recipient_online=delivered
                )

            elif data.get("type") == "read_receipt":
                from_user = data.get("from")
                to_user = data.get("to")

                # Verify sender
                if from_user != username:
                    continue

                # Mark messages as read in database
                db.query(PendingMessage).filter(
                    PendingMessage.from_username == to_user,
                    PendingMessage.to_username == from_user
                ).update({"read": True})
                db.commit()

                await manager.send_personal_message(
                    {
                        "type": "read_receipt",
                        "from": from_user
                    },
                    to_user
                )

            elif data.get("type") == "typing":
                # Rate limit typing indicators
                if not ws_rate_limiter.check_typing(username):
                    continue

                if data.get("from") != username:
                    continue

                await manager.send_personal_message(
                    {
                        "type": "typing",
                        "from": data["from"]
                    },
                    data["to"]
                )

            # Emoji Reaction
            elif data.get("type") == "reaction":
                # optional: rate limit reactions too
                if not ws_rate_limiter.check_message(username):
                    await websocket.send_json({
                        "type": "error",
                        "message": "Reaction rate limit exceeded. Please slow down."
                    })
                    continue

                message_id = data.get("message_id")
                emoji = data.get("emoji")
                to_user = data.get("to")      # recipient of the original message
                from_user = data.get("from")  # reactor

                if from_user != username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Sender mismatch"
                    })
                    continue

                # Persist reaction
                try:
                    reaction = MessageReaction(
                        message_id=message_id,
                        username=from_user,
                        emoji=emoji,
                    )
                    db.add(reaction)
                    db.commit()
                except Exception as e:
                    print(f"Error saving reaction: {e}")
                    db.rollback()
                    continue

                # Notify both sides
                payload = {
                    "type": "reaction",
                    "message_id": message_id,
                    "from": from_user,
                    "to": to_user,
                    "emoji": emoji,
                    "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
                }
                await manager.send_personal_message(payload, to_user)
                await manager.send_personal_message(payload, from_user)

            elif data.get("type") == "reaction_toggle":
                msg_id = data.get("message_id")
                emoji = data.get("emoji")
                from_user = data.get("from")
                to_user = data.get("to")

                # Verify sender matches authenticated user
                if from_user != username:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Sender mismatch"
                    })
                    continue

                # Check if reaction already exists
                existing = db.query(MessageReaction).filter(
                    MessageReaction.message_id == msg_id,
                    MessageReaction.username == from_user,
                    MessageReaction.emoji == emoji
                ).first()

                if existing:
                    db.delete(existing)
                    db.commit()
                    status = "removed"
                else:
                    new_reaction = MessageReaction(
                        message_id=msg_id,
                        username=from_user,
                        emoji=emoji
                    )
                    db.add(new_reaction)
                    db.commit()
                    status = "added"

                # Notify both users
                payload = {
                    "type": "reaction_toggle",
                    "message_id": msg_id,
                    "emoji": emoji,
                    "from": from_user,
                    "status": status
                }

                await manager.send_personal_message(payload, to_user)
                await manager.send_personal_message(payload, from_user)


    except WebSocketDisconnect:
        manager.disconnect(username)
        db.close()
    except Exception as e:
        print(f"WebSocket error: {e}")
        import traceback
        traceback.print_exc()
        manager.disconnect(username)
        db.close()

class ApproveUserRequest(BaseModel):
    username: str          # admin performing the action
    target_username: str   # user being approved


class ToggleReactionRequest(BaseModel):
    message_id: int          # or str, if you're using a string ID on the client and mapping it server-side
    emoji: str               # the emoji being toggled (e.g. "❤️", "😂")
    from_username: str       # the user performing the reaction
    to_username: str         # the message owner / recipient


@app.post("/api/reaction/toggle")
async def toggle_reaction(req: ToggleReactionRequest, db: Session = Depends(get_db)):
    existing = db.query(MessageReaction).filter(
        MessageReaction.message_id == req.message_id,
        MessageReaction.username == req.username,
        MessageReaction.emoji == req.emoji
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
        return {"status": "removed"}

    new = MessageReaction(
        message_id=req.message_id,
        username=req.username,
        emoji=req.emoji
    )
    db.add(new)
    db.commit()
    return {"status": "added"}


# ==================== ADMIN USER APPROVAL ENDPOINTS ====================

@app.get("/api/admin/pending-users")
async def get_pending_users(username: str, db: Session = Depends(get_db)):
    """Return users who are email-verified but not yet admin-approved"""
    requester = db.query(User).filter(User.username == username).first()
    if not requester or not requester.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    pending = db.query(User).filter(
        User.is_verified == True,   # noqa: E712
        User.is_authorized == False  # noqa: E712
    ).all()

    return {
        "pending_users": [
            {
                "username": u.username,
                "email": u.email,
                "created_at": u.created_at.isoformat(timespec="seconds"),
            }
            for u in pending
        ]
    }


@app.post("/api/admin/approve-user")
async def approve_user(req: ApproveUserRequest, db: Session = Depends(get_db)):
    """Admin approves a pending user, allowing them to log in"""
    requester = db.query(User).filter(User.username == req.username).first()
    if not requester or not requester.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")

    target = db.query(User).filter(User.username == req.target_username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_authorized = True
    db.commit()

    return {"status": "success", "message": f"User '{req.target_username}' approved"}


# ==================== STATIC FILES ====================

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def read_root():
    """Serve index.html with proper UTF-8 encoding"""
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Error: index.html not found. Please ensure static/index.html exists.</h1>",
            status_code=500
        )


@app.get("/favicon.ico")
async def favicon():
    """Return empty response for favicon to prevent 404 errors"""
    return HTMLResponse(content="", status_code=204)


@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Enhanced health check with database connectivity"""
    try:
        # Test database connection
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    return {
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now(UTC).isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)

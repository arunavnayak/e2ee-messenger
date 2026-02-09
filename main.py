import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta
from typing import Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

# Local Imports
from database import engine, get_db, Base, SessionLocal
from models import User, EncryptedVault, PendingMessage, SessionToken, UserPreferences
from rate_limiter import RateLimitMiddleware, login_rate_limiter, ws_rate_limiter
from status import router as status_router

# Initialize Database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="E2EE Messenger", version="2.0.0")

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
        SessionToken.expires_at < datetime.utcnow()
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
            except:
                # Connection might be dead, remove it
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
            "img-src 'self' data:",
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
    auth_hash: str
    public_key: str
    encrypted_vault: str

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not v or len(v) < 3 or len(v) > 32:
            raise ValueError('Username must be 3-32 characters')
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v.lower()


class LoginRequest(BaseModel):
    username: str
    auth_hash: str


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


# ==================== API ENDPOINTS ====================

@app.post("/api/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register new user with zero-knowledge vault"""

    existing_user = db.query(User).filter(User.username == req.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=req.username,
        auth_hash=req.auth_hash,
        public_key=req.public_key
    )
    db.add(user)

    vault = EncryptedVault(
        username=req.username,
        encrypted_vault_blob=req.encrypted_vault
    )
    db.add(vault)

    # Create default preferences
    prefs = UserPreferences(username=req.username, blocked_users='[]', muted_users='[]')
    db.add(prefs)

    db.commit()

    return {"status": "success", "message": "User registered successfully"}


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

    # Use constant-time comparison to prevent timing attacks
    if not user or not constant_time_compare(user.auth_hash, req.auth_hash):
        # Record failed attempt
        login_rate_limiter.record_failed_attempt(identifier)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Clear failed attempts on successful login
    login_rate_limiter.clear_attempts(identifier)

    vault = db.query(EncryptedVault).filter(EncryptedVault.username == req.username).first()

    # Get pending messages with unread status
    pending = db.query(PendingMessage).filter(
        PendingMessage.to_username == req.username
    ).all()

    pending_messages = [
        {
            "from": msg.from_username,
            "payload": msg.encrypted_payload,
            "timestamp": msg.timestamp.isoformat(timespec="milliseconds") + "Z",
            "read": msg.read
        }
        for msg in pending
    ]

    # Calculate unread counts per sender
    unread_counts = {}
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
        expires_at=datetime.utcnow() + timedelta(hours=24)
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
        "muted_users": json.loads(prefs.muted_users)
    }


@app.post("/api/update-vault")
async def update_vault(req: UpdateVaultRequest, db: Session = Depends(get_db)):
    """Update encrypted vault (password change)"""

    user = db.query(User).filter(User.username == req.username).first()

    if not user or not constant_time_compare(user.auth_hash, req.old_auth_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.auth_hash = req.new_auth_hash

    vault = db.query(EncryptedVault).filter(EncryptedVault.username == req.username).first()
    vault.encrypted_vault_blob = req.new_encrypted_vault

    db.commit()

    return {"status": "success", "message": "Vault updated successfully"}


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


@app.delete("/api/messages/clear/{username}")
async def clear_messages(username: str, db: Session = Depends(get_db)):
    """Clear pending messages after delivery"""

    db.query(PendingMessage).filter(PendingMessage.to_username == username).delete()
    db.commit()

    return {"status": "success", "message": "Messages cleared"}


@app.post("/api/messages/mark-read")
async def mark_messages_read(from_username: str, to_username: str, db: Session = Depends(get_db)):
    """Mark messages from a specific user as read"""

    db.query(PendingMessage).filter(
        PendingMessage.from_username == from_username,
        PendingMessage.to_username == to_username
    ).update({"read": True})

    db.commit()

    return {"status": "success", "message": "Messages marked as read"}


@app.post("/api/chat/clear")
async def clear_chat(username: str, contact: str, db: Session = Depends(get_db)):
    """Clear chat history between two users (removes pending messages)"""

    # Clear pending messages from contact to user
    db.query(PendingMessage).filter(
        PendingMessage.from_username == contact,
        PendingMessage.to_username == username
    ).delete()

    # Clear pending messages from user to contact
    db.query(PendingMessage).filter(
        PendingMessage.from_username == username,
        PendingMessage.to_username == contact
    ).delete()

    db.commit()

    return {"status": "success", "message": "Chat cleared"}


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


# ==================== WEBSOCKET ENDPOINT ====================

async def verify_websocket_token(username: str, token: str, db: Session) -> bool:
    """Verify WebSocket session token"""
    token_hash = hash_token(token)

    session = db.query(SessionToken).filter(
        SessionToken.username == username,
        SessionToken.token_hash == token_hash,
        SessionToken.expires_at > datetime.utcnow()
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

                delivered = await manager.send_personal_message(
                    {
                        "type": "message",
                        "from": from_user,
                        "payload": encrypted_payload,
                        "timestamp": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
                        "message_id": message_id
                    },
                    to_user
                )

                if not delivered:
                    try:
                        pending_msg = PendingMessage(
                            from_username=from_user,
                            to_username=to_user,
                            encrypted_payload=encrypted_payload,
                            read=False
                        )
                        db.add(pending_msg)
                        db.commit()

                        await websocket.send_json({
                            "type": "delivery_status",
                            "status": "queued",
                            "message": f"User {to_user} is offline. Message queued."
                        })
                    except Exception as e:
                        print(f"Error saving pending message: {e}")
                        db.rollback()
                        await websocket.send_json({
                            "type": "delivery_status",
                            "status": "failed",
                            "message": "Failed to queue message"
                        })
                else:
                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "delivered",
                        "message": f"Message delivered to {to_user}",
                        "message_id": message_id
                    })

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

    except WebSocketDisconnect:
        manager.disconnect(username)
        db.close()
    except Exception as e:
        print(f"WebSocket error: {e}")
        import traceback
        traceback.print_exc()
        manager.disconnect(username)
        db.close()


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
        "timestamp": datetime.utcnow().isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from typing import Dict, List
import json
import asyncio
from datetime import datetime
import os

from database import engine, get_db, Base
from models import User, EncryptedVault, PendingMessage
from pydantic import BaseModel, field_validator  # Changed from validator
import hashlib

# Initialize Database
Base.metadata.create_all(bind=engine)

app = FastAPI(title="E2EE Messenger", version="1.0.0")

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[username] = websocket

    def disconnect(self, username: str):
        if username in self.active_connections:
            del self.active_connections[username]

    async def send_personal_message(self, message: dict, username: str):
        if username in self.active_connections:
            await self.active_connections[username].send_json(message)
            return True
        return False

manager = ConnectionManager()

# ==================== SECURITY MIDDLEWARE ====================

class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict Content Security Policy - LOCAL ONLY
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' https://cdn.tailwindcss.com 'unsafe-eval' 'wasm-unsafe-eval'",  # unsafe-eval needed for some libsodium builds
            "style-src 'self' 'unsafe-inline'",
            "worker-src 'self' blob:",  # Allow web workers for libsodium
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



app.add_middleware(CSPMiddleware)

# ==================== PYDANTIC MODELS ====================

class RegisterRequest(BaseModel):
    username: str
    auth_hash: str
    public_key: str
    encrypted_vault: str

    @field_validator('username')  # Fixed: Changed from @validator
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

    db.commit()

    return {"status": "success", "message": "User registered successfully"}

@app.post("/api/login")
async def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate and retrieve encrypted vault"""

    user = db.query(User).filter(User.username == req.username).first()

    if not user or user.auth_hash != req.auth_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    vault = db.query(EncryptedVault).filter(EncryptedVault.username == req.username).first()

    pending = db.query(PendingMessage).filter(
        PendingMessage.to_username == req.username
    ).all()

    pending_messages = [
        {
            "from": msg.from_username,
            "payload": msg.encrypted_payload,
            # "timestamp": msg.timestamp.isoformat()
            "timestamp": msg.timestamp.isoformat(timespec="milliseconds") + "Z"
        }
        for msg in pending
    ]

    return {
        "status": "success",
        "public_key": user.public_key,
        "encrypted_vault": vault.encrypted_vault_blob if vault else None,
        "pending_messages": pending_messages
    }

@app.post("/api/update-vault")
async def update_vault(req: UpdateVaultRequest, db: Session = Depends(get_db)):
    """Update vault after password change"""

    user = db.query(User).filter(User.username == req.username).first()

    if not user or user.auth_hash != req.old_auth_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.auth_hash = req.new_auth_hash

    vault = db.query(EncryptedVault).filter(EncryptedVault.username == req.username).first()
    if vault:
        vault.encrypted_vault_blob = req.new_encrypted_vault
        vault.updated_at = datetime.utcnow()

    db.commit()

    return {"status": "success", "message": "Password updated successfully"}

@app.get("/api/user/{username}/public-key")
async def get_public_key(username: str, db: Session = Depends(get_db)):
    """Retrieve user's public key for E2EE"""

    user = db.query(User).filter(User.username == username.lower()).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"username": user.username, "public_key": user.public_key}

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

# ==================== WEBSOCKET ENDPOINT ====================

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, db: Session = Depends(get_db)):
    """Real-time message delivery via WebSocket"""

    await manager.connect(username, websocket)

    try:
        while True:
            data = await websocket.receive_json()

            if data.get("type") == "message":
                from_user = data.get("from")
                to_user = data.get("to")
                encrypted_payload = data.get("payload")
                message_id = data.get("message_id") # required for delivery receipt

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
                    pending_msg = PendingMessage(
                        from_username=from_user,
                        to_username=to_user,
                        encrypted_payload=encrypted_payload
                    )
                    db.add(pending_msg)
                    db.commit()

                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "queued",
                        "message": f"User {to_user} is offline. Message queued."
                    })
                else:
                    await websocket.send_json({
                        "type": "delivery_status",
                        "status": "delivered",
                        "message": f"Message delivered to {to_user}",
                        "message_id": message_id
                    })

            if data.get("type") == "read_receipt":
                from_user = data["from"]
                to_user = data["to"]
                await manager.send_personal_message(
                    {
                        "type": "read_receipt",
                        "from": from_user
                    },
                    to_user
                )
                continue

            if data.get("type") == "typing":
                await manager.send_personal_message(
                    {
                        "type": "typing",
                        "from": data["from"]
                    },
                    data["to"]
                )
                continue

    except WebSocketDisconnect:
        manager.disconnect(username)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(username)

# ==================== STATIC FILES ====================

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def read_root():
    """Serve index.html with proper UTF-8 encoding"""
    # Fixed: Use UTF-8 encoding explicitly for Windows compatibility
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Error: index.html not found. Please ensure static/index.html exists.</h1>",
            status_code=500
        )

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
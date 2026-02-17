# ==================== email_utils.py ====================
import os
import requests

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_URL = "https://api.brevo.com/v3/smtp/email"


def send_otp_email(to_email: str, username: str, otp: str) -> None:
    """
    Send OTP using Brevo transactional email API
    """
    if not BREVO_API_KEY:
        raise ValueError("BREVO_API_KEY not set in environment variables")

    html = f"""
    <div style='font-family: Arial, padding: 20px'>
        <h2>Welcome to SecureChat, {username}</h2>
        <p>Your one-time verification code is:</p>
        <h1 style='letter-spacing:3px;color:#007bff'>{otp}</h1>
        <p>This OTP will expire in 10 minutes.</p>
        <p style="color:gray;">Do not reply to this automated message.</p>
    </div>
    """

    payload = {
        "sender": {"name": "SecureChat No‑Reply", "email": "no-reply@bitsbloc.com"},
        "to": [{"email": to_email}],
        "subject": "Verify your SecureChat account",
        "htmlContent": html,
    }

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }

    response = requests.post(BREVO_URL, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

/************************************************************
 *  SecureChat - Updated app.js
 *  Option B2: Private key encrypted in sessionStorage
 *  using PBKDF2(username + password + random salt)
 ************************************************************/
// ==================== GLOBAL STATE ====================
let currentUser = null;
let currentRecipient = null;
let websocket = null;
let sessionToken = null;
let isAdmin = false;  // Set after login; controls Admin Settings menu item visibility

let userKeys = {
    publicKey: null,
    privateKey: null // decrypted in memory only
};

let contacts = [];
let chatHistory = {};
let pendingMessagesStore = {};
let unreadCounts = {};
let blockedUsers = [];
let mutedUsers = [];
let typingTimeout = null;

// ==================== SESSION RESTORE CRYPTO HELPERS (ADDED) ====================

// Convert base64 <-> ArrayBuffer
// IMPORTANT: Do NOT use spread operator (String.fromCharCode(...bytes)) — it blows the
// call stack for large files (e.g. PDFs).  Use a chunked loop instead.
function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    const CHUNK = 8192;
    let binary = '';
    for (let i = 0; i < bytes.length; i += CHUNK) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary);
}
function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Derive AES key for encrypting private key in sessionStorage
async function deriveSessionKey(username, password, saltB64) {
    const salt = base64ToArrayBuffer(saltB64);
    const material = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(username.toLowerCase() + password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 150000,
            hash: "SHA-256"
        },
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt private key for session restore
async function encryptPrivateKeyForSession(privateKey, username, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = arrayBufferToBase64(salt.buffer);
    const key = await deriveSessionKey(username, password, saltB64);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        new TextEncoder().encode(privateKey)
    );

    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return {
        encrypted: arrayBufferToBase64(combined.buffer),
        salt: saltB64
    };
}

// Decrypt private key from sessionStorage
async function decryptPrivateKeyFromSession(username, password, encryptedB64, saltB64) {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedB64));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const key = await deriveSessionKey(username, password, saltB64);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}


// ==================== UTILITY FUNCTIONS ====================
function getInitials(name) {
    return name.slice(0, 2).toUpperCase();
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    });
}

function formatDate(timestamp) {
    const date = new Date(timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    if (date.toDateString() === today.toDateString()) {
        return 'Today';
    } else if (date.toDateString() === yesterday.toDateString()) {
        return 'Yesterday';
    } else {
        return date.toLocaleDateString('en-US', {month: 'short', day: 'numeric', year: 'numeric'});
    }
}

function showStatus(elementId, message, isError = false) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.className = isError ? 'status-message error' : 'status-message success';
}

function clearStatus(elementId) {
    const el = document.getElementById(elementId);
    el.className = 'status-message';
    el.textContent = '';
}

function linkify(text) {
    const urlRegex = /(https?:\/\/[^\s]+)/g;

    return text.replace(urlRegex, (url) => {
        // Escape HTML entities inside URL text
        const safeUrl = url.replace(/"/g, "&quot;");
        return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
    });
}


// ==================== TAB SWITCHING ====================
function switchTab(tab) {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const tabBtns = document.querySelectorAll('.tab-btn');

    clearStatus('authStatus');

    if (tab === 'login') {
        loginForm.classList.add('active');
        registerForm.classList.remove('active');
        tabBtns[0].classList.add('active');
        tabBtns[1].classList.remove('active');
    } else {
        loginForm.classList.remove('active');
        registerForm.classList.add('active');
        tabBtns[0].classList.remove('active');
        tabBtns[1].classList.add('active');
    }
}

// ==================== AUTHENTICATION ====================
async function handleRegister() {
    const username = document.getElementById('registerUsername').value.trim();
    const password = document.getElementById('registerPassword').value;
    const confirm = document.getElementById('registerConfirm').value;
    const email = document.getElementById('registerEmail').value.trim();

    if (!email || !email.includes('@')) {
        showStatus('authStatus', 'Please provide a valid email address', true);
        return;
    }

    if (!username || !password || !confirm) {
        showStatus('authStatus', 'Please fill all fields', true);
        return;
    }

    if (password !== confirm) {
        showStatus('authStatus', 'Passwords do not match', true);
        return;
    }

    if (password.length < 12) {
        showStatus('authStatus', 'Password must be at least 12 characters', true);
        return;
    }

    // Password strength: must contain uppercase, lowercase, digit, and special character
    if (!/[A-Z]/.test(password)) {
        showStatus('authStatus', 'Password must contain at least one uppercase letter', true);
        return;
    }
    if (!/[a-z]/.test(password)) {
        showStatus('authStatus', 'Password must contain at least one lowercase letter', true);
        return;
    }
    if (!/\d/.test(password)) {
        showStatus('authStatus', 'Password must contain at least one number', true);
        return;
    }
    if (!/[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>\/?`~]/.test(password)) {
        showStatus('authStatus', 'Password must contain at least one special character (e.g. !@#$%)', true);
        return;
    }

    try {
        showStatus('authStatus', 'Generating encryption keys...', false);

        const keyPair = await CryptoManager.generateKeyPair();
        const authHash = await CryptoManager.deriveAuthHash(username, password);
        const storageKey = await CryptoManager.deriveStorageKey(username, password);
        const encryptedVault = await CryptoManager.encryptVault(keyPair.privateKey, storageKey);

        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: username,
                email: email,
                auth_hash: authHash,
                public_key: keyPair.publicKey,
                encrypted_vault: encryptedVault
            })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.status === 'pending_verification') {
                showStatus('authStatus', 'Check your email for OTP verification', false);
                // Redirect to verification page or modal
                openOTPVerification(username);
            } else {
                showStatus('authStatus', 'Registration successful! Logging in...', false);
                setTimeout(() => {
                    document.getElementById('loginUsername').value = username;
                    document.getElementById('loginPassword').value = password;
                    switchTab('login');
                    handleLogin();
                }, 1000);
            }
        } else {
            showStatus('authStatus', data.detail || 'Registration failed', true);
        }
    } catch (error) {
        showStatus('authStatus', 'Error: ' + error.message, true);
    }
}

function disableResendButton(seconds) {
    const btn = document.getElementById('resendOtpBtn');
    btn.disabled = true;
    btn.classList.add('opacity-50', 'cursor-not-allowed');
    let remaining = seconds;
    btn.textContent = `Resend Code (${remaining}s)`;
    const timer = setInterval(() => {
        remaining -= 1;
        if (remaining <= 0) {
            clearInterval(timer);
            btn.disabled = false;
            btn.classList.remove('opacity-50', 'cursor-not-allowed');
            btn.textContent = 'Resend Code';
        } else {
            btn.textContent = `Resend Code (${remaining}s)`;
        }
    }, 1000);
}

function openOTPVerification(username) {
    document.getElementById('authScreen').style.display = 'none';
    const otpPage = document.getElementById('otpPage');
    otpPage.style.display = 'flex';

    let otpExpireTimer = null;

    // --- start timer (10 minutes) ---
    startOtpExpirationTimer();

    document.getElementById('verifyOtpBtn').onclick = async () => {
        const otp = document.getElementById('otpInput').value.trim();
        const res = await fetch('/api/verify-otp', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, otp_code: otp})
        });
        const data = await res.json();

        if (res.ok) {
            showStatus('otpStatus', '✅ Email Verified! You can now log in.', false);
            clearTimeout(otpExpireTimer);
            setTimeout(() => {
                otpPage.style.display = 'none';
                document.getElementById('authScreen').style.display = 'flex';
                switchTab('login');
            }, 1200);
        } else {
            showStatus('otpStatus', data.detail || 'Invalid or expired OTP', true);
        }
    };

    // ------------------ resend OTP logic ------------------
    document.getElementById('resendOtpBtn').onclick = async () => {
        showStatus('otpStatus', 'Sending new OTP...', false);
        disableResendButton(60);
        try {
            const res = await fetch('/api/resend-otp', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: username})
            });
            const data = await res.json();
            if (res.ok) {
                showStatus('otpStatus', 'New OTP sent! Please check your email.', false);
                clearTimeout(otpExpireTimer);
                startOtpExpirationTimer(); // restart 10‑min window
            } else {
                showStatus('otpStatus', data.detail || 'Could not resend OTP', true);
            }
        } catch (err) {
            showStatus('otpStatus', 'Error contacting server', true);
        }
    };

    // ------------------ expiration handler ------------------
    function startOtpExpirationTimer() {
        const expiryMinutes = 10;
        let remaining = expiryMinutes * 60; // seconds

        otpExpireTimer = setInterval(() => {
            remaining--;
            // optional live countdown
            // console.log('OTP expires in', remaining, 'seconds');
            if (remaining <= 0) {
                clearInterval(otpExpireTimer);
                showStatus(
                    'otpStatus',
                    '⚠️ Your code has expired. Please click "Resend Code" to get a new one.',
                    true
                );
            }
        }, 1000);
    }
}


async function handleLogin() {
    const username = document.getElementById("loginUsername").value.trim();
    const password = document.getElementById("loginPassword").value;

    if (!username || !password) {
        showStatus("authStatus", "Please enter username and password", true);
        return;
    }

    try {
        showStatus("authStatus", "Authenticating...", false);

        const authHash = await CryptoManager.deriveAuthHash(username, password);

        const response = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                auth_hash: authHash
            })
        });

        const data = await response.json();

        if (response.ok) {
            if (data.status === 'pending_verification') {
                showStatus('authStatus', data.message, false);
                // Redirect to verification page or modal
                openOTPVerification(username);
            } else if (data.status === 'pending_approval') {
                showStatus('authStatus', '', false);
                showPendingApprovalModal();
            } else {
                showStatus('authStatus', 'Decrypting vault...', false);

                const storageKey = await CryptoManager.deriveStorageKey(username, password);
                const privateKey = await CryptoManager.decryptVault(data.encrypted_vault, storageKey);
                // --- ADDED: encrypt private key for session restore ---
                const encrypted = await encryptPrivateKeyForSession(privateKey, username, password);
                sessionStorage.setItem("encryptedPrivateKey", encrypted.encrypted);
                sessionStorage.setItem("privateKeySalt", encrypted.salt);
                sessionStorage.setItem("currentUser", username);
                sessionStorage.setItem("sessionToken", data.session_token);


                currentUser = username;
                userKeys.publicKey = data.public_key;
                userKeys.privateKey = privateKey;
                sessionToken = data.session_token;
                isAdmin = data.is_admin || false;

                sessionStorage.setItem('encryptedVault', data.encrypted_vault);

                // Show Admin Settings menu item for admin users
                const adminMenuBtn = document.getElementById('adminMenuBtn');
                if (adminMenuBtn) adminMenuBtn.style.display = isAdmin ? 'block' : 'none';

                // Store unread counts from server
                unreadCounts = data.unread_counts || {};

                // Store blocked and muted users
                blockedUsers = data.blocked_users || [];
                mutedUsers = data.muted_users || [];

                // Store pending messages
                if (data.pending_messages && data.pending_messages.length > 0) {
                    for (const msg of data.pending_messages) {
                        if (!pendingMessagesStore[msg.from]) {
                            pendingMessagesStore[msg.from] = [];
                        }
                        pendingMessagesStore[msg.from].push(msg);
                    }
                }

                // Switch to chat interface
                document.getElementById('authScreen').style.display = 'none';
                document.getElementById('chatContainer').style.display = 'block';
                document.getElementById('userListPage').style.display = 'flex';

                connectWebSocket();
                await loadContacts();

                // Clear password
                document.getElementById('loginPassword').value = '';

                clearStatus('authStatus');
            }
        } else {
            showStatus('authStatus', data.detail || 'Login failed', true);
        }
    } catch (error) {
        showStatus("authStatus", "Error: " + error.message, true);
    }
}

// ==================== SESSION RESTORE (ADDED) ====================
async function restoreSessionFromServer(username, token, password) {
    try {
        const response = await fetch("/api/session/restore", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, session_token: token })
        });

        const data = await response.json();
        if (!response.ok || data.status !== "success") {
            // Handle special statuses before giving up
            if (data.status === 'pending_approval') {
                showPendingApprovalModal();
                return;
            }
            if (data.status === 'pending_verification') {
                openOTPVerification(username);
                return;
            }
            console.warn("Session restore failed:", data.detail || data.message);
            sessionStorage.clear();
            return;
        }

        // Decrypt private key from sessionStorage
        const encrypted = sessionStorage.getItem("encryptedPrivateKey");
        const salt = sessionStorage.getItem("privateKeySalt");
        const privateKey = await decryptPrivateKeyFromSession(username, password, encrypted, salt);

        // Restore global state
        currentUser = username;
        sessionToken = token;
        userKeys.publicKey = data.public_key;
        userKeys.privateKey = privateKey;
        isAdmin = data.is_admin || false;

        // Show Admin Settings menu item for admin users
        const adminMenuBtn = document.getElementById('adminMenuBtn');
        if (adminMenuBtn) adminMenuBtn.style.display = isAdmin ? 'block' : 'none';

        unreadCounts = data.unread_counts || {};
        blockedUsers = data.blocked_users || [];
        mutedUsers = data.muted_users || [];

        // Restore pending messages
        pendingMessagesStore = {};
        if (data.pending_messages) {
            for (const msg of data.pending_messages) {
                if (!pendingMessagesStore[msg.from]) pendingMessagesStore[msg.from] = [];
                pendingMessagesStore[msg.from].push(msg);
            }
        }

        // Switch UI
        document.getElementById("authScreen").style.display = "none";
        document.getElementById("chatContainer").style.display = "block";
        document.getElementById("userListPage").style.display = "flex";

        connectWebSocket();
        await loadContacts();

    } catch (err) {
        console.warn('Error restoring session::', err);

        sessionStorage.clear();
        const restoreSession = document.getElementById('restoreSessionModal');
        restoreSession.style.display = 'none';
        location.reload();
    }
}

// ==================== SESSION RESTORE PASSWORD MODAL ====================

function openRestoreSessionModal(username, token) {
    document.getElementById('authScreen').style.display = 'none';
    const restoreSession = document.getElementById('restoreSessionModal');
    restoreSession.style.display = 'flex';

    document.getElementById("restoreSessionSubmitBtn").onclick = () => {
        const password = document.getElementById("restoreSessionPasswordInput").value.trim();
        if (!password) {
            showStatus("restoreSessionStatus", "Password required", true);
            return;
        }
        restoreSession.style.display = 'none';
        document.getElementById("restoreSessionPasswordInput").value = "";
        clearStatus("restoreSessionStatus");

        restoreSessionFromServer(username, token, password);
    };

    document.getElementById("restoreSessionCancelBtn").onclick = () => {
        restoreSession.style.display = 'none';
        sessionStorage.clear();
        location.reload();
    };
}


function handleLogout() {
    if (websocket) {
        websocket.close();
    }

    currentUser = null;
    currentRecipient = null;
    sessionToken = null;
    userKeys = {publicKey: null, privateKey: null};
    contacts = [];
    chatHistory = {};
    pendingMessagesStore = {};
    unreadCounts = {};
    sessionStorage.clear();

    document.getElementById('authScreen').style.display = 'flex';
    document.getElementById('chatContainer').style.display = 'none';
    document.getElementById('loginPassword').value = '';

    closeSettings();
}

// ==================== SETTINGS MENU ====================
function toggleSettings() {
    const menu = document.getElementById('settingsMenu');
    menu.classList.toggle('show');
}

function closeSettings() {
    const menu = document.getElementById('settingsMenu');
    menu.classList.remove('show');
}

// Click outside to close settings
document.addEventListener('click', (e) => {
    const settingsMenu = document.getElementById('settingsMenu');
    const settingsBtn = e.target.closest('.header-icons button');

    if (!settingsBtn && !e.target.closest('.settings-menu')) {
        closeSettings();
    }
});

// ==================== PASSWORD CHANGE ====================
function showProfileModal() {
    document.getElementById('profileModal').classList.add('show');
    closeSettings();
}

function showSettingsModal() {
    document.getElementById('settingsModal').classList.add('show');
    closeSettings();
}

function showChangePasswordModal() {
    document.getElementById('passwordModal').classList.add('show');
    closeSettings();
}

function hidePasswordModal() {
    document.getElementById('passwordModal').classList.remove('show');
    document.getElementById('oldPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmNewPassword').value = '';
    clearStatus('passwordStatus');
}

async function handlePasswordChange() {
    const oldPassword = document.getElementById('oldPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmNewPassword').value;

    if (!oldPassword || !newPassword || !confirmPassword) {
        showStatus('passwordStatus', 'Please fill all fields', true);
        return;
    }

    if (newPassword !== confirmPassword) {
        showStatus('passwordStatus', 'New passwords do not match', true);
        return;
    }

    if (newPassword.length < 12) {
        showStatus('passwordStatus', 'Password must be at least 12 characters', true);
        return;
    }

    // Password strength: must contain uppercase, lowercase, digit, and special character
    if (!/[A-Z]/.test(newPassword)) {
        showStatus('passwordStatus', 'New password must contain at least one uppercase letter', true);
        return;
    }
    if (!/[a-z]/.test(newPassword)) {
        showStatus('passwordStatus', 'New password must contain at least one lowercase letter', true);
        return;
    }
    if (!/\d/.test(newPassword)) {
        showStatus('passwordStatus', 'New password must contain at least one number', true);
        return;
    }
    if (!/[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>\/?`~]/.test(newPassword)) {
        showStatus('passwordStatus', 'New password must contain at least one special character (e.g. !@#$%)', true);
        return;
    }

    try {
        showStatus('passwordStatus', 'Re-encrypting vault...', false);

        const encryptedVault = sessionStorage.getItem('encryptedVault');
        const result = await CryptoManager.changePassword(
            currentUser,
            oldPassword,
            newPassword,
            encryptedVault
        );

        const response = await fetch('/api/update-vault', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: currentUser,
                old_auth_hash: result.oldAuthHash,
                new_auth_hash: result.newAuthHash,
                new_encrypted_vault: result.newEncryptedVault
            })
        });

        const data = await response.json();

        if (response.ok) {
            sessionStorage.setItem('encryptedVault', result.newEncryptedVault);
            showStatus('passwordStatus', 'Password updated successfully!', false);
            setTimeout(() => {
                hidePasswordModal();
            }, 2000);
        } else {
            showStatus('passwordStatus', data.detail || 'Update failed', true);
        }
    } catch (error) {
        showStatus('passwordStatus', 'Error: ' + error.message, true);
    }
}

// ==================== WEBSOCKET ====================
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${currentUser}`;

    websocket = new WebSocket(wsUrl);

    websocket.onopen = async () => {
        console.log('WebSocket connected - sending authentication');

        websocket.send(JSON.stringify({
            type: 'auth',
            token: sessionToken
        }));
    };

    websocket.onmessage = async (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'auth_success') {
            console.log('WebSocket authenticated successfully');
        } else if (data.type === 'error') {
            console.error('WebSocket error:', data.message);
            if (data.message.includes('Authentication') || data.message.includes('Invalid token')) {
                alert('Session expired. Please login again.');
                handleLogout();
            }
        } else if (data.type === 'message') {
            await handleIncomingMessage(data);
        } else if (data.type === 'reaction') {
            applyIncomingReaction(data);
        } else if (data.type === 'delivery_status') {
            updateMessageStatus(data.message_id, data.status);
        } else if (data.type === 'read_receipt') {
            markMessagesAsRead(data.from);
        } else if (data.type === 'typing') {
            showTypingIndicator(data.from);
        } else if (data.type === 'reaction_toggle') {
            applyReactionToggle(data);
        } else if (data.type === 'signal') {
            // WebRTC signaling relay
            handleCallSignal(data.signal);
        }
    };

    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    websocket.onclose = (event) => {
        console.log('WebSocket disconnected', event.code, event.reason);

        if (event.code === 1008) {
            console.log('WebSocket closed due to authentication failure');
            return;
        }

        if (currentUser && sessionToken) {
            setTimeout(() => {
                console.log('Attempting to reconnect WebSocket...');
                connectWebSocket();
            }, 3000);
        }
    };
}

function applyIncomingReaction(data) {
    const { message_id, emoji, from } = data;
    const chat = chatHistory[currentRecipient] || chatHistory[from] || [];
    const msg = chat.find(m => m.messageId === message_id);
    if (!msg) return;

    msg.reactions = msg.reactions || [];
    msg.reactions.push({ username: from, emoji });

    // Update DOM
    const messagesArea = document.getElementById('messagesArea');
    const el = messagesArea.querySelector(`[data-message-id="${message_id}"]`);
    if (!el) return;

    const bubble = el.querySelector('.message-bubble');
    let reactionsDiv = bubble.querySelector('.message-reactions');
    if (!reactionsDiv) {
        reactionsDiv = document.createElement('div');
        reactionsDiv.className = 'message-reactions';
        bubble.insertBefore(reactionsDiv, bubble.querySelector('.message-footer'));
    }
    const span = document.createElement('span');
    span.className = 'reaction-emoji';
    span.textContent = emoji;
    reactionsDiv.appendChild(span);
}


// ====== EMOJI PICKER =====
// const EMOJI_SET = ['😀','😁','😂','🤣','😊','😍','😎','😢','😡','👍','🙏','🔥','🎉','❤️'];
const EMOJI_SET = [
    // 😀 Smileys & Emotion
    "😀","😄","😁","😆","😂","🤣","😊","😇","🙂","🙃",
    "😍","🥰","😘","🤓","😎","😞","☹️","🥺","😢","😭",
    "😤","😠","😡","🤬","🤯","🥶","😱","😥","😵‍💫","🤧",
    "😷","🤑","👿","👹","👺","💀","☠️","👻","👽","🤖",

    // 👍 Gestures
    "👍","👎","👌","✌️","🤞","👋","🤚","🤲","🙏","💪",

    // ❤️ Hearts & Love
    "❤️","💔","❣️","💕","💞","💓","💖","💘","💝","💟",

    // 🐶 Animals
    "🐶","🐱","🐰","🐻","🐼","🐨","🐯","🦁","🐷","🐸",
    "🐵","🐔","🐧","🐤","🦉","🐺","🐟","🐬","🐳","🐋",

    // 🍔 Food & Drink
    "🍏","🍎","🍐","🍋","🍌","🍉","🍇","🍓","🍒","🍆",
    "🥑","🥦","🥕","🌽","🥨","🥯","🍔","🍟","🍕","🥪",
    "🍩","🍪","🎂","🍰","🍬","🍭","🍺","🍷","🥂","🍸",

    // ⚽ Activities
    "⚽","🏀","🏈","⚾","🏏","🚴","🚗","🚕","🚒","✈️",
    "🚀","🛸","⛵","🚢","🚤","🗽","🗼","🏰","🎡","🎠",

    // 🔣 Symbols
    "✨","⭐","🌟","💫","🔥","💥","🌈","☀️","🌤️","🌧️",
    "❄️","☃️","💦","🌊","🌙","🌛","🌜","⭐","⚡","💤",
];

let emojiPickerEl = null;

document.getElementById('emojiBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    toggleEmojiPicker();
});

function toggleEmojiPicker() {
    if (emojiPickerEl) {
        emojiPickerEl.remove();
        emojiPickerEl = null;
        return;
    }
    const picker = document.createElement('div');
    picker.className = 'emoji-picker';
    picker.innerHTML = EMOJI_SET.map(e => `<span>${e}</span>`).join('');
    picker.addEventListener('click', (e) => {
        if (e.target.tagName === 'SPAN') {
            insertEmoji(e.target.textContent);
        }
    });
    document.body.appendChild(picker);
    emojiPickerEl = picker;
    document.addEventListener('click', closeEmojiPickerOnce, { once: true });
}

function closeEmojiPickerOnce() {
    if (emojiPickerEl) {
        emojiPickerEl.remove();
        emojiPickerEl = null;
    }
}

function insertEmoji(emoji) {
    const input = document.getElementById('messageInput');
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const value = input.value;
    input.value = value.slice(0, start) + emoji + value.slice(end);
    input.focus();
    const pos = start + emoji.length;
    input.setSelectionRange(pos, pos);
}

function addLongPressListener(el, callback) {
    let timer = null;

    el.addEventListener('touchstart', () => {
        timer = setTimeout(() => {
            if (navigator.vibrate) navigator.vibrate(10);  // 🔥 HAPTIC FEEDBACK HERE
            callback();
        }, 350); // long‑press threshold
    });

    el.addEventListener('touchend', () => clearTimeout(timer));
    el.addEventListener('touchmove', () => clearTimeout(timer));
}





// ==================== CONTACTS ====================
async function loadContacts() {
    try {
        const response = await fetch('/api/users');
        const data = await response.json();

        contacts = data.users.filter(u => u.username !== currentUser);

        renderUsersList();
    } catch (error) {
        console.error('Error loading contacts:', error);
    }
}

function renderUsersList() {
    const usersList = document.getElementById('usersList');
    usersList.innerHTML = '';

    const sortedContacts = contacts.sort((a, b) => {
        const aHistory = chatHistory[a.username];
        const bHistory = chatHistory[b.username];

        if (!aHistory && !bHistory) return 0;
        if (!aHistory) return 1;
        if (!bHistory) return -1;

        const aLast = aHistory[aHistory.length - 1].timestamp;
        const bLast = bHistory[bHistory.length - 1].timestamp;

        return bLast - aLast;
    });

    sortedContacts.forEach(contact => {
        const userItem = document.createElement('div');
        userItem.className = 'user-item';

        // Add event listener instead of onclick
        userItem.addEventListener('click', () => openChat(contact.username));

        const history = chatHistory[contact.username];
        const lastMsg = history && history.length > 0 ? history[history.length - 1] : null;
        const unreadCount = unreadCounts[contact.username] || 0;

        userItem.innerHTML = `
            <div class="user-avatar">${getInitials(contact.username)}</div>
            <div class="user-info">
                <div class="user-name">${contact.username}</div>
                <div class="user-last-message">
                    ${lastMsg ? (lastMsg.type === 'sent' ? 'You: ' : '') + lastMsg.text.substring(0, 30) + (lastMsg.text.length > 30 ? '...' : '') : 'No messages yet'}
                </div>
            </div>
            <div class="user-meta">
                <div class="message-time">${lastMsg ? formatTime(lastMsg.timestamp) : ''}</div>
                ${unreadCount > 0 ? `<div class="unread-badge">${unreadCount}</div>` : ''}
            </div>
        `;

        usersList.appendChild(userItem);
    });
}

function filterUsers() {
    const search = document.getElementById('userSearch').value;
    const userItems = document.querySelectorAll('.user-item');

    userItems.forEach(item => {
        const name = item.querySelector('.user-name').textContent;
        item.style.display = name.includes(search) ? 'flex' : 'none';
    });
}

// ==================== CHAT PAGE ====================
async function openChat(username) {
    currentRecipient = username;

    // Clear unread count
    unreadCounts[username] = 0;
    renderUsersList();

    // Update UI
    document.getElementById('userListPage').style.display = 'none';
    document.getElementById('chatPage').style.display = 'flex';
    document.getElementById('chatUserAvatar').textContent = getInitials(username);
    document.getElementById('chatUserName').textContent = username;

    // Update chat settings menu state
    updateChatSettingsMenu();

    // Load messages
    const messagesArea = document.getElementById('messagesArea');
    messagesArea.innerHTML = '';

    // IMPORTANT: Clear pending messages for this user BEFORE fetching from server
    // because the server will return ALL messages including these pending ones
    delete pendingMessagesStore[username];

    // Fetch complete chat history from server
    try {
        const response = await fetch(`/api/chat/history/${currentUser}/${username}`);
        if (response.ok) {
            const data = await response.json();

            // Clear and rebuild chat history for this user
            chatHistory[username] = [];

            // Process all messages from server
            for (const msg of data.messages) {
                const serverTimestamp = new Date(msg.timestamp).getTime();
                const payload = JSON.parse(msg.payload);

                try {
                    // Check if this is a location message
                    if (payload.type === 'location_message') {
                        const senderPub = msg.is_sent
                            ? contacts.find(c => c.username === username)?.public_key
                            : payload.sender_public_key;
                        if (senderPub) {
                            try {
                                const decrypted = await CryptoManager.decryptMessage(
                                    payload.ciphertext, payload.nonce, senderPub, userKeys.privateKey
                                );
                                const locData = JSON.parse(decrypted);
                                chatHistory[username].push({
                                    text: '📍 Location',
                                    type: msg.is_sent ? 'sent' : 'received',
                                    timestamp: serverTimestamp,
                                    messageId: msg.id,
                                    status: msg.is_sent ? 'delivered' : null,
                                    isLocation: true,
                                    locationMeta: { lat: locData.lat, lng: locData.lng },
                                });
                            } catch(e) { console.error('Location history decrypt error:', e); }
                        }
                        continue;
                    }

                    // Check if this is an attachment message
                    if (payload.type === 'attachment') {
                        const isImage = payload.category === 'image';
                        const messageType = msg.is_sent ? 'sent' : 'received';
                        chatHistory[username].push({
                            text: `📎 ${payload.filename}`,
                            type: messageType,
                            timestamp: serverTimestamp,
                            messageId: msg.id,
                            status: msg.is_sent ? 'delivered' : null,
                            reactions: msg.reactions || [],
                            isAttachment: true,
                            attachmentMeta: { filename: payload.filename, mimeType: payload.mime_type, isImage, payload, isSent: msg.is_sent },
                        });
                        continue;
                    }

                    // Decrypt the message
                    const senderPublicKey = msg.is_sent ?
                        contacts.find(c => c.username === username)?.public_key :
                        payload.sender_public_key;

                    if (!senderPublicKey) {
                        console.error('Cannot find sender public key');
                        continue;
                    }

                    const decrypted = await CryptoManager.decryptMessage(
                        payload.ciphertext,
                        payload.nonce,
                        senderPublicKey,
                        userKeys.privateKey
                    );

                    // Add to chat history
                    const messageType = msg.is_sent ? 'sent' : 'received';
                    chatHistory[username].push({
                        text: decrypted,
                        type: messageType,
                        timestamp: serverTimestamp,
                        // messageId: `server_${msg.timestamp}`,
                        messageId: msg.id, // use DB id
                        status: msg.is_sent ? 'delivered' : null,
                        reactions: msg.reactions || [], // new
                    });

                } catch (error) {
                    console.error('Error decrypting message:', error);
                    // Add encrypted message as fallback
                    const messageType = msg.is_sent ? 'sent' : 'received';
                    chatHistory[username].push({
                        text: '[Decryption failed]',
                        type: messageType,
                        timestamp: serverTimestamp,
                        messageId: `server_${msg.timestamp}`,
                        status: null
                    });
                }
            }
        }
    } catch (error) {
        console.error('Error fetching chat history:', error);
    }

    // Now render all messages
    const history = chatHistory[username] || [];
    let lastDate = null;

    history.forEach(msg => {
        const msgDate = formatDate(msg.timestamp);

        if (msgDate !== lastDate) {
            const dateDivider = document.createElement('div');
            dateDivider.className = 'date-divider';
            dateDivider.innerHTML = `<span>${msgDate}</span>`;
            messagesArea.appendChild(dateDivider);
            lastDate = msgDate;
        }

        if (msg.isLocation) {
            const { lat, lng } = msg.locationMeta;
            const el = createLocationElement({ lat, lng, type: msg.type, timestamp: msg.timestamp, messageId: msg.messageId, status: msg.status });
            messagesArea.appendChild(el);
        } else if (msg.isAttachment) {
            const { filename, mimeType, isImage, payload, isSent } = msg.attachmentMeta;
            const el = createAttachmentElement({
                filename, mimeType, isImage,
                type: msg.type,
                timestamp: msg.timestamp,
                messageId: msg.messageId,
                status: msg.status,
                blobUrl: null,
            });
            messagesArea.appendChild(el);

            // Decrypt for both sender and receiver.
            // ECDH shared key is symmetric — the same secret is produced whether
            // you call ECDH(mySenderPrivKey, recipientPubKey) or
            // ECDH(myReceiverPrivKey, senderPubKey).
            (async () => {
                const blobUrl = await handleIncomingAttachment(payload, { from: username, isSent });
                if (blobUrl) updateAttachmentInUI(msg.messageId, filename, mimeType, isImage, blobUrl);
            })();
        } else {
            const messageEl = createMessageElement(msg);
            messagesArea.appendChild(messageEl);
        }
    });

    // NO LONGER PROCESSING pendingMessagesStore here!
    // It's already included in the server response above

    // Scroll to bottom — use rAF to ensure DOM has painted first
    requestAnimationFrame(() => {
        messagesArea.scrollTop = messagesArea.scrollHeight;
        // Double rAF for async decryption updates
        requestAnimationFrame(() => { messagesArea.scrollTop = messagesArea.scrollHeight; });
    });

    // Send read receipt
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
            type: 'read_receipt',
            from: currentUser,
            to: username
        }));
    }
}

function backToUserList() {
    currentRecipient = null;
    document.getElementById('chatPage').style.display = 'none';
    document.getElementById('userListPage').style.display = 'flex';
    hideTypingIndicator();
}

function createMessageElement(msg) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${msg.type}`;
    messageDiv.dataset.messageId = msg.messageId;

    const statusIcon = getStatusIcon(msg.status);

    // --- UPDATED: convert URLs to clickable links ---
    const safeText = linkify(msg.text);

    // --- UPDATED: group reactions by emoji + count ---
    let reactionsHtml = '';
    if (msg.reactions && msg.reactions.length > 0) {
        const counts = {};
        msg.reactions.forEach(r => {
            counts[r.emoji] = (counts[r.emoji] || 0) + 1;
        });

        const grouped = Object.entries(counts)
            .map(([emoji, count]) =>
                `<span class="reaction-emoji">${emoji}${count > 1 ? ' ' + count : ''}</span>`
            )
            .join('');

        reactionsHtml = `
            <div class="message-reactions">
                ${grouped}
            </div>
        `;
    }

    // --- ORIGINAL STRUCTURE PRESERVED ---
    messageDiv.innerHTML = `
    <div class="message-bubble"> 
        <div class="message-text ${msg.text.includes('...') ? 'encrypted' : ''}">
            ${safeText}
        </div>
        ${reactionsHtml}
        <div class="message-footer">
            <span>${formatTime(msg.timestamp)}</span>
            ${msg.type === 'sent' ? `<span class="message-status">${statusIcon}</span>` : ''}
        </div>
    </div>
    `;

    // --- UPDATED: long‑press + right‑click reaction picker ---
    if (msg.type === 'received') {
        // Mobile long‑press
        addLongPressListener(messageDiv, () => openReactionPicker(messageDiv));

        // Desktop right‑click
        messageDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            if (navigator.vibrate) navigator.vibrate(5); // subtle
            openReactionPicker(messageDiv);
        });

    }

    return messageDiv;
}


// ============= Message Reactions =============
const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🔥'];
let currentReactionPicker = null;

function openReactionPicker(messageEl) {
    if (currentReactionPicker) {
        currentReactionPicker.remove();
        currentReactionPicker = null;
    }

    const picker = document.createElement('div');
    picker.className = 'reaction-picker';
    picker.innerHTML = QUICK_REACTIONS.map(e => `<span>${e}</span>`).join('');

    picker.addEventListener('click', (e) => {
        if (e.target.tagName === 'SPAN') {
            const emoji = e.target.textContent;
            sendReactionToggle(messageEl.dataset.messageId, emoji);
            // Close picker after selection
            picker.remove();
            currentReactionPicker = null;
        }
    });

    document.body.appendChild(picker);
    const rect = messageEl.getBoundingClientRect();
    picker.style.left = `${rect.left + rect.width / 2 - picker.offsetWidth / 2}px`;
    picker.style.top = `${rect.top - 40}px`;

    currentReactionPicker = picker;
    setTimeout(() => {
        document.addEventListener('click', closeReactionPickerOnce, { once: true });
    }, 0);
}

function closeReactionPickerOnce() {
    if (currentReactionPicker) {
        currentReactionPicker.remove();
        currentReactionPicker = null;
    }
}

function sendReaction(messageId, emoji) {
    if (!websocket || websocket.readyState !== WebSocket.OPEN || !currentRecipient) return;

    websocket.send(JSON.stringify({
        type: 'reaction',
        from: currentUser,
        to: currentRecipient,
        message_id: Number(messageId),
        emoji,
    }));
}

function renderReactions(msg, bubble) {
    const counts = {};

    msg.reactions.forEach(r => {
        counts[r.emoji] = (counts[r.emoji] || 0) + 1;
    });

    const reactionsDiv = document.createElement('div');
    reactionsDiv.className = 'message-reactions';

    Object.entries(counts).forEach(([emoji, count]) => {
        const span = document.createElement('span');
        span.className = 'reaction-emoji';
        span.textContent = count > 1 ? `${emoji} ${count}` : emoji;
        reactionsDiv.appendChild(span);
    });

    bubble.insertBefore(reactionsDiv, bubble.querySelector('.message-footer'));
}

function sendReactionToggle(messageId, emoji) {
    websocket.send(JSON.stringify({
        type: "reaction_toggle",
        from: currentUser,
        to: currentRecipient,
        message_id: Number(messageId),
        emoji
    }));
}


function applyReactionToggle(data) {
    const { message_id, emoji, from, status } = data;

    const chat = chatHistory[currentRecipient] || [];
    const msg = chat.find(m => m.messageId === message_id);
    if (!msg) return;

    if (status === "added") {
        msg.reactions.push({ username: from, emoji });
    } else {
        msg.reactions = msg.reactions.filter(r => !(r.username === from && r.emoji === emoji));
    }

    // Re-render the reaction bar
    const el = document.querySelector(`[data-message-id="${message_id}"]`);
    const bubble = el.querySelector('.message-bubble');
    const old = bubble.querySelector('.message-reactions');
    if (old) old.remove();
    if (msg.reactions.length) renderReactions(msg, bubble);
}


function getStatusIcon(status) {
    switch (status) {
        case 'sent':
            return '<span class="status-sent">✓</span>';
        case 'delivered':
            return '<span class="status-delivered">✓✓</span>';
        case 'read':
            return '<span class="status-read">✓✓</span>';
        case 'failed':
            return '<span class="status-failed">❌</span>';
        default:
            return '';
    }
}

// ==================== MESSAGING ====================
async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();

    if (!message || !currentRecipient) {
        return;
    }

    const messageId = crypto.randomUUID();
    const timestamp = Date.now();

    if (!websocket || websocket.readyState !== WebSocket.OPEN) {
        addMessageToUI(message, 'sent', timestamp, messageId, 'failed');
        saveToHistory(currentRecipient, message, 'sent', timestamp, messageId, 'failed');
        return;
    }

    try {
        const recipientContact = contacts.find(c => c.username === currentRecipient);
        if (!recipientContact) {
            alert('Recipient not found');
            return;
        }

        const encrypted = await CryptoManager.encryptMessage(
            message,
            recipientContact.public_key,
            userKeys.privateKey
        );

        const payload = JSON.stringify({
            sender_public_key: userKeys.publicKey,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce
        });

        websocket.send(JSON.stringify({
            type: 'message',
            from: currentUser,
            to: currentRecipient,
            payload: payload,
            message_id: messageId
        }));

        addMessageToUI(message, 'sent', timestamp, messageId, 'sent');
        saveToHistory(currentRecipient, message, 'sent', timestamp, messageId, 'sent');

        input.value = '';
        input.style.height = 'auto';

    } catch (error) {
        console.error('Error sending message:', error);
        addMessageToUI(message, 'sent', timestamp, messageId, 'failed');
        saveToHistory(currentRecipient, message, 'sent', timestamp, messageId, 'failed');
    }
}

function addMessageToUI(text, type, timestamp, messageId, status) {
    const messagesArea = document.getElementById('messagesArea');
    const msgDate = formatDate(timestamp);

    // Check if we need a date divider
    const lastDivider = messagesArea.querySelector('.date-divider:last-of-type');
    const lastDividerText = lastDivider ? lastDivider.querySelector('span').textContent : null;

    if (msgDate !== lastDividerText) {
        const dateDivider = document.createElement('div');
        dateDivider.className = 'date-divider';
        dateDivider.innerHTML = `<span>${msgDate}</span>`;
        messagesArea.appendChild(dateDivider);
    }

    const msgEl = createMessageElement({text, type, timestamp, messageId, status});
    messagesArea.appendChild(msgEl);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function saveToHistory(username, text, type, timestamp, messageId, status) {
    if (!chatHistory[username]) {
        chatHistory[username] = [];
    }

    chatHistory[username].push({text, type, timestamp, messageId, status});

    // Update user list if not in chat with this user
    if (currentRecipient !== username) {
        renderUsersList();
    }
}

async function handleIncomingMessage(data) {
    try {
        const payload = JSON.parse(data.payload);
        const serverTimestamp = new Date(data.timestamp).getTime();

        // ---- Location message ----
        if (payload.type === 'location_message') {
            // Decrypt to get lat/lng
            try {
                const decrypted = await CryptoManager.decryptMessage(
                    payload.ciphertext, payload.nonce, payload.sender_public_key, userKeys.privateKey
                );
                const locData = JSON.parse(decrypted);
                if (data.from !== currentRecipient) {
                    if (!unreadCounts[data.from]) unreadCounts[data.from] = 0;
                    unreadCounts[data.from]++;
                    saveToHistory(data.from, '📍 Location', 'received', serverTimestamp, data.message_id, null);
                    renderUsersList();
                    return;
                }
                addLocationMessageToUI(locData.lat, locData.lng, 'received', serverTimestamp, data.message_id, null);
                saveToHistory(data.from, '📍 Location', 'received', serverTimestamp, data.message_id, null);
            } catch(e) { console.error('Location decrypt failed:', e); }
            return;
        }

        // ---- Attachment message ----
        if (payload.type === 'attachment') {
            const isImage = payload.category === 'image';
            const displayText = `📎 ${payload.filename}`;

            if (data.from !== currentRecipient) {
                if (!unreadCounts[data.from]) unreadCounts[data.from] = 0;
                unreadCounts[data.from]++;
                saveToHistory(data.from, displayText, 'received', serverTimestamp, data.message_id, null);
                renderUsersList();
                return;
            }

            // Show placeholder immediately
            addAttachmentMessageToUI(payload.filename, payload.mime_type, isImage, 'received', serverTimestamp, data.message_id, null, null);
            saveToHistory(data.from, displayText, 'received', serverTimestamp, data.message_id, null);

            // Decrypt and update
            setTimeout(async () => {
                const blobUrl = await handleIncomingAttachment(payload, data);
                if (blobUrl) updateAttachmentInUI(data.message_id, payload.filename, payload.mime_type, isImage, blobUrl);
            }, 100);
            return;
        }

        // If not in chat with sender, increment unread and store
        if (data.from !== currentRecipient) {
            if (!unreadCounts[data.from]) unreadCounts[data.from] = 0;
            unreadCounts[data.from]++;
            renderUsersList();

            const encryptedPreview = payload.ciphertext.slice(0, 30) + '...';
            saveToHistory(data.from, encryptedPreview, 'received', serverTimestamp, data.message_id, null);

            // Decrypt in background
            setTimeout(async () => {
                try {
                    const decrypted = await CryptoManager.decryptMessage(
                        payload.ciphertext,
                        payload.nonce,
                        payload.sender_public_key,
                        userKeys.privateKey
                    );
                    updateHistoryMessage(data.from, serverTimestamp, decrypted);
                    renderUsersList();
                } catch (e) {
                    console.error('Decryption failed:', e);
                }
            }, 100);

            return;
        }

        // Show encrypted preview
        const encryptedPreview = payload.ciphertext.slice(0, 30) + '...';
        addMessageToUI(encryptedPreview, 'received', serverTimestamp, data.message_id, null);
        saveToHistory(data.from, encryptedPreview, 'received', serverTimestamp, data.message_id, null);

        // Decrypt and update
        setTimeout(async () => {
            try {
                const decrypted = await CryptoManager.decryptMessage(
                    payload.ciphertext,
                    payload.nonce,
                    payload.sender_public_key,
                    userKeys.privateKey
                );

                updateMessageInUI(serverTimestamp, decrypted);
                updateHistoryMessage(data.from, serverTimestamp, decrypted);
            } catch (e) {
                console.error('Decryption failed:', e);
                updateMessageInUI(serverTimestamp, '[Decryption failed]');
            }
        }, 300);

    } catch (error) {
        console.error('Error handling message:', error);
    }
}

async function processPendingMessage(msg) {
    try {
        const payload = JSON.parse(msg.payload);
        const serverTimestamp = new Date(msg.timestamp).getTime();

        const encryptedPreview = payload.ciphertext.slice(0, 30) + '...';
        addMessageToUI(encryptedPreview, 'received', serverTimestamp, msg.message_id, null);
        saveToHistory(msg.from, encryptedPreview, 'received', serverTimestamp, msg.message_id, null);

        setTimeout(async () => {
            try {
                const decrypted = await CryptoManager.decryptMessage(
                    payload.ciphertext,
                    payload.nonce,
                    payload.sender_public_key,
                    userKeys.privateKey
                );

                updateMessageInUI(serverTimestamp, decrypted);
                updateHistoryMessage(msg.from, serverTimestamp, decrypted);
            } catch (e) {
                console.error('Decryption failed:', e);
            }
        }, 300);

    } catch (error) {
        console.error('Error processing pending message:', error);
    }
}

function updateMessageInUI(timestamp, newText) {
    const messages = document.querySelectorAll('.message');
    messages.forEach(msg => {
        const textEl = msg.querySelector('.message-text');
        const timeEl = msg.querySelector('.message-footer span');

        if (timeEl && formatTime(timestamp) === timeEl.textContent.trim()) {
            textEl.textContent = newText;
            textEl.classList.remove('encrypted');
        }
    });
}

function updateAttachmentInUI(messageId, filename, mimeType, isImage, blobUrl) {
    const el = document.querySelector(`[data-message-id="${messageId}"]`);
    if (!el || el.dataset.attachmentType !== 'attachment') return;
    const bubble = el.querySelector('.message-bubble');
    if (!bubble) return;
    const isSent = el.classList.contains('sent');

    // Grab existing footer to reuse timestamp
    const existingFooter = bubble.querySelector('.attach-footer');

    const displayName = filename.length > 28 ? filename.slice(0, 24) + '…' + filename.slice(filename.lastIndexOf('.')) : filename;
    const iconSvg = getAttachmentIcon(mimeType, isImage);

    // Clear bubble, rebuild
    bubble.innerHTML = '';

    let newCard;
    if (isImage) {
        newCard = document.createElement('div');
        newCard.className = `attach-card attach-card-image ${isSent ? 'sent' : 'received'}`;
        newCard.dataset.msgid = messageId;
        const img = document.createElement('img');
        img.className = 'attach-thumb';
        img.src = blobUrl;
        img.alt = displayName;
        const cardFoot = document.createElement('div');
        cardFoot.className = 'attach-card-footer';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'attach-name';
        nameSpan.textContent = displayName;
        cardFoot.appendChild(nameSpan);
        newCard.appendChild(img);
        newCard.appendChild(cardFoot);
        newCard.addEventListener('click', () => openImageLightbox(blobUrl, filename));
    } else {
        newCard = document.createElement('div');
        newCard.className = `attach-card attach-card-file ${isSent ? 'sent' : 'received'}`;
        newCard.dataset.msgid = messageId;
        newCard._blobUrl = blobUrl;
        newCard._filename = filename;

        // Top row: icon + meta
        const topRow = document.createElement('div');
        topRow.className = 'attach-card-top';

        const iconWrap = document.createElement('div');
        iconWrap.className = 'attach-icon-wrap';
        iconWrap.innerHTML = iconSvg;

        const body = document.createElement('div');
        body.className = 'attach-card-body';

        const meta = document.createElement('div');
        meta.className = 'attach-meta';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'attach-name';
        nameSpan.textContent = displayName;

        const dlBtn = document.createElement('button');
        dlBtn.className = 'attach-download-btn';
        dlBtn.textContent = '⬇ Download';
        dlBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            doDownload(blobUrl, filename);
        });

        meta.appendChild(nameSpan);
        meta.appendChild(dlBtn);
        body.appendChild(meta);
        topRow.appendChild(iconWrap);
        topRow.appendChild(body);
        newCard.appendChild(topRow);
    }

    // Re-attach the existing footer INSIDE the card at the bottom
    if (existingFooter) newCard.appendChild(existingFooter);
    bubble.appendChild(newCard);
}

/** Per-type SVG icons for attachment cards */
function getAttachmentIcon(mimeType, isImage) {
    if (isImage) {
        return `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="4" y="8" width="40" height="32" rx="4" fill="#667eea" opacity="0.18"/>
            <rect x="4" y="8" width="40" height="32" rx="4" stroke="#667eea" stroke-width="2.5" fill="none"/>
            <circle cx="16" cy="19" r="4" fill="#667eea"/>
            <path d="M4 34l10-10 8 8 6-6 16 14" stroke="#667eea" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
        </svg>`;
    }
    if (mimeType === 'application/pdf') {
        return `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="6" y="2" width="28" height="40" rx="3" fill="#fee2e2"/>
            <rect x="6" y="2" width="28" height="40" rx="3" stroke="#ef4444" stroke-width="2" fill="none"/>
            <path d="M28 2v10h10" stroke="#ef4444" stroke-width="2" stroke-linejoin="round" fill="none"/>
            <path d="M28 2l10 10H28V2z" fill="#fca5a5"/>
            <text x="9" y="35" font-family="Arial,sans-serif" font-weight="800" font-size="9" fill="#ef4444">PDF</text>
        </svg>`;
    }
    if (mimeType === 'text/plain') {
        return `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="6" y="2" width="28" height="40" rx="3" fill="#dcfce7"/>
            <rect x="6" y="2" width="28" height="40" rx="3" stroke="#22c55e" stroke-width="2" fill="none"/>
            <path d="M28 2v10h10" stroke="#22c55e" stroke-width="2" stroke-linejoin="round" fill="none"/>
            <path d="M28 2l10 10H28V2z" fill="#86efac"/>
            <text x="9" y="35" font-family="Arial,sans-serif" font-weight="800" font-size="9" fill="#22c55e">TXT</text>
        </svg>`;
    }
    // DOC / DOCX
    return `<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="6" y="2" width="28" height="40" rx="3" fill="#dbeafe"/>
        <rect x="6" y="2" width="28" height="40" rx="3" stroke="#2563eb" stroke-width="2" fill="none"/>
        <path d="M28 2v10h10" stroke="#2563eb" stroke-width="2" stroke-linejoin="round" fill="none"/>
        <path d="M28 2l10 10H28V2z" fill="#93c5fd"/>
        <text x="6" y="35" font-family="Arial,sans-serif" font-weight="800" font-size="9" fill="#2563eb">DOC</text>
    </svg>`;
}

/** CSP-safe download — called only via addEventListener, never from inline onclick */
function doDownload(blobUrl, filename) {
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

/** Legacy entry point kept for any remaining callers — delegates to doDownload */
function triggerAttachmentDownload(messageId) {
    const el = document.querySelector(`[data-message-id="${messageId}"]`);
    if (!el) return;
    const card = el.querySelector('.attach-card-file');
    if (!card) return;
    // Try JS property first (set by updateAttachmentInUI), fall back to dataset
    const blobUrl = card._blobUrl || card.dataset.bloburl;
    const filename = card._filename || card.dataset.filename;
    if (blobUrl && filename) doDownload(blobUrl, filename);
}

// ==================== IMAGE LIGHTBOX (in-app, no new tab, no exposed URL) ====================
let _lightboxBlobUrl = null;

function openImageLightbox(blobUrl, filename) {
    _lightboxBlobUrl = blobUrl;
    const lb = document.getElementById('imageLightbox');
    const img = document.getElementById('lightboxImg');
    img.src = blobUrl;
    img.alt = filename;
    document.getElementById('lightboxFilename').textContent = filename;
    lb.style.display = 'flex';
    document.body.style.overflow = 'hidden';
}

function closeImageLightbox() {
    document.getElementById('imageLightbox').style.display = 'none';
    document.getElementById('lightboxImg').src = '';
    document.body.style.overflow = '';
}

function downloadLightboxImage() {
    if (!_lightboxBlobUrl) return;
    const filename = document.getElementById('lightboxFilename').textContent || 'image';
    const a = document.createElement('a');
    a.href = _lightboxBlobUrl;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}



function updateHistoryMessage(username, timestamp, newText) {
    if (!chatHistory[username]) return;

    const entry = chatHistory[username].find(m => m.timestamp === timestamp);
    if (entry) {
        entry.text = newText;
    }
}

function updateMessageStatus(messageId, status) {
    const messageEl = document.querySelector(`[data-message-id="${messageId}"]`);
    if (messageEl) {
        const statusEl = messageEl.querySelector('.message-status');
        if (statusEl) {
            statusEl.innerHTML = getStatusIcon(status);
        }
    }

    // Update in history
    for (const username in chatHistory) {
        const msg = chatHistory[username].find(m => m.messageId === messageId);
        if (msg) {
            msg.status = status;
            break;
        }
    }
}

function markMessagesAsRead(fromUser) {
    if (currentRecipient !== fromUser) return;

    const messages = document.querySelectorAll('.message.sent');
    messages.forEach(msg => {
        const statusEl = msg.querySelector('.message-status');
        if (statusEl) {
            statusEl.innerHTML = getStatusIcon('read');
        }
    });

    // Update history
    if (chatHistory[fromUser]) {
        chatHistory[fromUser].forEach(msg => {
            if (msg.type === 'sent') {
                msg.status = 'read';
            }
        });
    }
}

// ==================== TYPING INDICATOR ====================
function handleTyping() {
    if (!currentRecipient || !websocket || websocket.readyState !== WebSocket.OPEN) return;

    // Auto-resize textarea
    const input = document.getElementById('messageInput');
    input.style.height = 'auto';
    input.style.height = input.scrollHeight + 'px';

    clearTimeout(typingTimeout);

    websocket.send(JSON.stringify({
        type: 'typing',
        from: currentUser,
        to: currentRecipient
    }));

    typingTimeout = setTimeout(() => {
        // Stop typing
    }, 3000);
}

function showTypingIndicator(fromUser) {
    if (currentRecipient !== fromUser) return;

    const indicator = document.getElementById('typingIndicator');
    const userSpan = document.getElementById('typingUser');

    userSpan.textContent = fromUser;
    indicator.classList.add('show');

    clearTimeout(window.typingHideTimer);
    window.typingHideTimer = setTimeout(() => {
        hideTypingIndicator();
    }, 3000);
}

function hideTypingIndicator() {
    document.getElementById('typingIndicator').classList.remove('show');
}

function handleMessageKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
}

// ==================== CHAT SETTINGS ====================

// ==================== VIDEO CALL ====================
// WebRTC state
let localStream = null;
let peerConnection = null;
let callRingtone = null;
let callTimerInterval = null;
let callSeconds = 0;
let isMuted = false;
let isVideoOff = false;
let pendingOffer = null;   // store offer from incoming call
let callPeer = null;       // who we're calling / being called by

const RTC_CONFIG = { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };

function startVideoCall() {
    if (!currentRecipient) return;
    callPeer = currentRecipient;

    // Show outgoing modal
    document.getElementById('outgoingCallAvatar').textContent = getInitials(callPeer);
    document.getElementById('outgoingCallName').textContent = callPeer;
    document.getElementById('outgoingCallModal').style.display = 'flex';

    // Play ringtone on caller side
    playRingtone();

    // Init WebRTC and send offer
    initCallAsInitiator();
}

async function initCallAsInitiator() {
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });

        peerConnection = new RTCPeerConnection(RTC_CONFIG);
        localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));

        peerConnection.onicecandidate = (e) => {
            if (e.candidate) {
                sendSignal({ type: 'ice_candidate', candidate: e.candidate, to: callPeer, from: currentUser });
            }
        };

        peerConnection.ontrack = (e) => {
            const remoteVideo = document.getElementById('remoteVideo');
            if (remoteVideo) remoteVideo.srcObject = e.streams[0];
        };

        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        sendSignal({ type: 'call_offer', offer, to: callPeer, from: currentUser });
    } catch (err) {
        console.error('Video init error:', err);
        alert('Could not access camera/microphone: ' + err.message);
        cancelOutgoingCall();
    }
}

function cancelOutgoingCall() {
    stopRingtone();
    sendSignal({ type: 'call_cancel', to: callPeer, from: currentUser });
    closePeerConnection();
    document.getElementById('outgoingCallModal').style.display = 'none';
    callPeer = null;
}

function declineCall() {
    stopRingtone();
    sendSignal({ type: 'call_declined', to: callPeer, from: currentUser });
    closePeerConnection();
    document.getElementById('incomingCallModal').style.display = 'none';
    pendingOffer = null;
    callPeer = null;
}

async function acceptCall() {
    stopRingtone();
    document.getElementById('incomingCallModal').style.display = 'none';

    try {
        localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });

        peerConnection = new RTCPeerConnection(RTC_CONFIG);
        localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));

        peerConnection.onicecandidate = (e) => {
            if (e.candidate) {
                sendSignal({ type: 'ice_candidate', candidate: e.candidate, to: callPeer, from: currentUser });
            }
        };

        peerConnection.ontrack = (e) => {
            const remoteVideo = document.getElementById('remoteVideo');
            if (remoteVideo) remoteVideo.srcObject = e.streams[0];
        };

        await peerConnection.setRemoteDescription(new RTCSessionDescription(pendingOffer));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);

        sendSignal({ type: 'call_answer', answer, to: callPeer, from: currentUser });

        showActiveCallUI();
    } catch (err) {
        console.error('Accept call error:', err);
        alert('Could not access camera/microphone: ' + err.message);
        declineCall();
    }
}

function showActiveCallUI() {
    const localVideo = document.getElementById('localVideo');
    if (localStream && localVideo) localVideo.srcObject = localStream;

    document.getElementById('outgoingCallModal').style.display = 'none';
    document.getElementById('incomingCallModal').style.display = 'none';
    document.getElementById('activeCallModal').style.display = 'flex';

    // Start timer
    callSeconds = 0;
    document.getElementById('callTimer').style.display = 'block';
    document.getElementById('callStatusText').style.display = 'none';
    callTimerInterval = setInterval(() => {
        callSeconds++;
        const m = String(Math.floor(callSeconds / 60)).padStart(2, '0');
        const s = String(callSeconds % 60).padStart(2, '0');
        document.getElementById('callTimer').textContent = `${m}:${s}`;
    }, 1000);
}

function endCall() {
    sendSignal({ type: 'call_end', to: callPeer, from: currentUser });
    closeCallUI();
}

function closeCallUI() {
    stopRingtone();
    clearInterval(callTimerInterval);
    callTimerInterval = null;
    document.getElementById('callTimer').style.display = 'none';
    document.getElementById('callStatusText').style.display = 'block';
    document.getElementById('callStatusText').textContent = 'Connecting…';
    document.getElementById('activeCallModal').style.display = 'none';
    document.getElementById('outgoingCallModal').style.display = 'none';
    document.getElementById('incomingCallModal').style.display = 'none';
    closePeerConnection();
    callPeer = null;
    pendingOffer = null;
    isMuted = false;
    isVideoOff = false;
    document.getElementById('muteAudioBtn').textContent = '🎙️';
    document.getElementById('toggleVideoBtn').textContent = '📹';
}

function closePeerConnection() {
    if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
    if (peerConnection) { peerConnection.close(); peerConnection = null; }
    const rv = document.getElementById('remoteVideo');
    const lv = document.getElementById('localVideo');
    if (rv) rv.srcObject = null;
    if (lv) lv.srcObject = null;
}

function toggleCallAudio() {
    if (!localStream) return;
    isMuted = !isMuted;
    localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
    document.getElementById('muteAudioBtn').textContent = isMuted ? '🔇' : '🎙️';
    document.getElementById('muteAudioBtn').style.background = isMuted ? 'rgba(229,62,62,0.7)' : 'rgba(255,255,255,0.2)';
}

function toggleCallVideo() {
    if (!localStream) return;
    isVideoOff = !isVideoOff;
    localStream.getVideoTracks().forEach(t => t.enabled = !isVideoOff);
    document.getElementById('toggleVideoBtn').textContent = isVideoOff ? '🚫' : '📹';
    document.getElementById('toggleVideoBtn').style.background = isVideoOff ? 'rgba(229,62,62,0.7)' : 'rgba(255,255,255,0.2)';
}

function sendSignal(data) {
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({ type: 'signal', signal: data, to: data.to, from: currentUser }));
    }
}

async function handleCallSignal(signal) {
    switch (signal.type) {
        case 'call_offer':
            callPeer = signal.from;
            pendingOffer = signal.offer;
            document.getElementById('incomingCallAvatar').textContent = getInitials(signal.from);
            document.getElementById('incomingCallName').textContent = signal.from;
            document.getElementById('incomingCallModal').style.display = 'flex';
            playRingtone();
            break;

        case 'call_answer':
            if (peerConnection) {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(signal.answer));
                showActiveCallUI();
            }
            break;

        case 'ice_candidate':
            if (peerConnection && signal.candidate) {
                try { await peerConnection.addIceCandidate(new RTCIceCandidate(signal.candidate)); } catch(e) {}
            }
            break;

        case 'call_declined':
            stopRingtone();
            document.getElementById('outgoingCallModal').style.display = 'none';
            closePeerConnection();
            callPeer = null;
            alert(`${signal.from} declined the call.`);
            break;

        case 'call_cancel':
            stopRingtone();
            document.getElementById('incomingCallModal').style.display = 'none';
            closePeerConnection();
            callPeer = null;
            pendingOffer = null;
            break;

        case 'call_end':
            closeCallUI();
            break;
    }
}

function playRingtone() {
    try {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (!AudioContext) return;
        const ctx = new AudioContext();
        function beep() {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain); gain.connect(ctx.destination);
            osc.frequency.setValueAtTime(480, ctx.currentTime);
            osc.frequency.setValueAtTime(620, ctx.currentTime + 0.3);
            gain.gain.setValueAtTime(0.4, ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);
            osc.start(ctx.currentTime); osc.stop(ctx.currentTime + 0.65);
        }
        beep();
        callRingtone = setInterval(beep, 1200);
        // store ctx so we can stop it
        callRingtone._ctx = ctx;
    } catch(e) { console.warn('Ringtone error:', e); }
}

function stopRingtone() {
    if (callRingtone) {
        clearInterval(callRingtone);
        try { if (callRingtone._ctx) callRingtone._ctx.close(); } catch(e) {}
        callRingtone = null;
    }
}

function toggleChatSettings() {
    const menu = document.getElementById('chatSettingsMenu');
    menu.classList.toggle('show');

    // Update button text based on current state
    updateChatSettingsMenu();

    // Close menu when clicking outside
    if (menu.classList.contains('show')) {
        setTimeout(() => {
            document.addEventListener('click', closeChatSettingsOnClickOutside);
        }, 0);
    }
}

function closeChatSettingsOnClickOutside(event) {
    const menu = document.getElementById('chatSettingsMenu');
    const btn = document.getElementById('chatSettingsBtn');

    if (!menu.contains(event.target) && !btn.contains(event.target)) {
        menu.classList.remove('show');
        document.removeEventListener('click', closeChatSettingsOnClickOutside);
    }
}

function updateChatSettingsMenu() {
    if (!currentRecipient) return;

    const muteBtn = document.getElementById('muteBtn');
    const blockBtn = document.getElementById('blockBtn');

    // Update mute button
    if (mutedUsers.includes(currentRecipient)) {
        muteBtn.textContent = 'Unmute';
    } else {
        muteBtn.textContent = 'Mute';
    }

    // Update block button
    if (blockedUsers.includes(currentRecipient)) {
        blockBtn.textContent = 'Unblock';
    } else {
        blockBtn.textContent = 'Block';
    }
}

async function clearChat() {
    if (!currentRecipient) return;

    const confirmed = confirm(`Clear all messages with ${currentRecipient}? This cannot be undone.`);
    if (!confirmed) return;

    try {
        // Clear from local storage
        chatHistory[currentRecipient] = [];

        // Clear from server
        const response = await fetch('/api/chat/clear', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: currentUser,
                contact: currentRecipient
            })
        });

        if (response.ok) {
            // Clear messages UI
            const messagesArea = document.getElementById('messagesArea');
            messagesArea.innerHTML = '';

            // Update user list
            renderUsersList();

            // Close settings menu
            document.getElementById('chatSettingsMenu').classList.remove('show');

            console.log(`Chat with ${currentRecipient} cleared`);
        } else {
            alert('Failed to clear chat on server');
        }
    } catch (error) {
        console.error('Error clearing chat:', error);
        alert('Error clearing chat');
    }
}

async function showContactInfoModal() {
    document.getElementById('settingsModal').classList.add('show');
    closeSettings();
}


async function toggleMute() {
    if (!currentRecipient) return;

    const isMuted = mutedUsers.includes(currentRecipient);

    try {
        const endpoint = isMuted ? '/api/user/unmute' : '/api/user/mute';

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                muter: currentUser,
                mutee: currentRecipient
            })
        });

        if (response.ok) {
            if (isMuted) {
                mutedUsers = mutedUsers.filter(u => u !== currentRecipient);
                console.log(`Unmuted ${currentRecipient}`);
            } else {
                mutedUsers.push(currentRecipient);
                console.log(`Muted ${currentRecipient}`);
            }

            // Update menu
            updateChatSettingsMenu();

            // Close settings menu
            document.getElementById('chatSettingsMenu').classList.remove('show');
        } else {
            alert('Failed to update mute status');
        }
    } catch (error) {
        console.error('Error toggling mute:', error);
        alert('Error updating mute status');
    }
}

async function toggleBlock() {
    if (!currentRecipient) return;

    const isBlocked = blockedUsers.includes(currentRecipient);

    const action = isBlocked ? 'unblock' : 'block';
    const confirmed = confirm(`Are you sure you want to ${action} ${currentRecipient}?`);
    if (!confirmed) return;

    try {
        const endpoint = isBlocked ? '/api/user/unblock' : '/api/user/block';

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                blocker: currentUser,
                blockee: currentRecipient
            })
        });

        if (response.ok) {
            if (isBlocked) {
                blockedUsers = blockedUsers.filter(u => u !== currentRecipient);
                console.log(`Unblocked ${currentRecipient}`);
            } else {
                blockedUsers.push(currentRecipient);
                console.log(`Blocked ${currentRecipient}`);
            }

            // Update menu
            updateChatSettingsMenu();

            // Close settings menu and go back to user list
            document.getElementById('chatSettingsMenu').classList.remove('show');
            backToUserList();
        } else {
            alert('Failed to update block status');
        }
    } catch (error) {
        console.error('Error toggling block:', error);
        alert('Error updating block status');
    }
}


// Toggle attachment menu
function attachDoc() {
    document.getElementById('attachmentMenu').classList.remove('show');
    openFilePicker(['application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain', 'application/pdf'], '.doc,.docx,.txt,.pdf');
}

function attachCamera() {
    // Camera capture — open image picker with capture attribute
    document.getElementById('attachmentMenu').classList.remove('show');
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/jpeg,image/png';
    input.capture = 'environment';
    input.onchange = (e) => handleFileSelected(e.target.files[0]);
    input.click();
}

function attachGallery() {
    document.getElementById('attachmentMenu').classList.remove('show');
    openFilePicker(['image/jpeg', 'image/png'], '.jpg,.jpeg,.png');
}

async function attachLocation() {
    document.getElementById('attachmentMenu').classList.remove('show');

    if (!navigator.geolocation) {
        alert('Geolocation is not supported by your browser.');
        return;
    }

    navigator.geolocation.getCurrentPosition(
        async (pos) => {
            const lat = pos.coords.latitude.toFixed(6);
            const lng = pos.coords.longitude.toFixed(6);

            const locationPayload = JSON.stringify({
                type: 'location',
                lat: parseFloat(lat),
                lng: parseFloat(lng),
            });

            // Encrypt like a normal message
            try {
                const recipientContact = contacts.find(c => c.username === currentRecipient);
                if (!recipientContact) { alert('Could not find recipient.'); return; }

                const encrypted = await CryptoManager.encryptMessage(
                    locationPayload,
                    recipientContact.public_key,
                    userKeys.privateKey
                );

                const envelope = JSON.stringify({
                    type: 'location_message',
                    ciphertext: encrypted.ciphertext,
                    nonce: encrypted.nonce,
                    sender_public_key: userKeys.publicKey,
                });

                const timestamp = Date.now();
                const messageId = `loc_${timestamp}`;

                // Show in own chat
                addLocationMessageToUI(parseFloat(lat), parseFloat(lng), 'sent', timestamp, messageId, 'sent');
                saveToHistory(currentRecipient, `📍 Location`, 'sent', timestamp, messageId, 'sent');

                // Send via WebSocket
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    websocket.send(JSON.stringify({
                        type: 'message',
                        from: currentUser,
                        to: currentRecipient,
                        payload: envelope,
                        message_id: messageId,
                    }));
                }
            } catch(e) {
                alert('Failed to send location: ' + e.message);
            }
        },
        (err) => {
            alert('Could not get your location: ' + err.message);
        },
        { timeout: 10000, enableHighAccuracy: true }
    );
}

function addLocationMessageToUI(lat, lng, type, timestamp, messageId, status) {
    const messagesArea = document.getElementById('messagesArea');
    const msgDate = formatDate(timestamp);

    const lastDivider = messagesArea.querySelector('.date-divider:last-of-type');
    const lastDividerText = lastDivider ? lastDivider.querySelector('span').textContent : null;
    if (msgDate !== lastDividerText) {
        const dd = document.createElement('div');
        dd.className = 'date-divider';
        dd.innerHTML = `<span>${msgDate}</span>`;
        messagesArea.appendChild(dd);
    }

    const el = createLocationElement({ lat, lng, type, timestamp, messageId, status });
    messagesArea.appendChild(el);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function createLocationElement({ lat, lng, type, timestamp, messageId, status }) {
    const isSent = type === 'sent';
    const mapsUrl = `https://www.google.com/maps?q=${lat},${lng}`;

    const wrapper = document.createElement('div');
    wrapper.className = `message ${isSent ? 'sent' : 'received'}`;
    wrapper.dataset.messageId = messageId;

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    bubble.style.padding = '4px 4px 4px';

    // Build card using DOM (CSP-safe, no onclick)
    const card = document.createElement('a');
    card.href = mapsUrl;
    card.target = '_blank';
    card.rel = 'noopener noreferrer';
    card.className = 'location-card';

    // Green placeholder area — no pin emoji, just coords
    const placeholder = document.createElement('div');
    placeholder.className = 'location-map-placeholder';
    const coords = document.createElement('span');
    coords.className = 'loc-coords';
    coords.textContent = `${lat}, ${lng}`;
    placeholder.appendChild(coords);

    // Footer row: pin icon + label
    const footer = document.createElement('div');
    footer.className = 'location-card-footer';
    const icon = document.createElement('span');
    icon.className = 'loc-icon';
    icon.textContent = '📍';
    const label = document.createElement('span');
    label.textContent = 'My Location · Tap to open';
    footer.appendChild(icon);
    footer.appendChild(label);

    card.appendChild(placeholder);
    card.appendChild(footer);
    bubble.appendChild(card);

    // Time row — right-aligned, outside card but inside bubble
    const timeRow = document.createElement('div');
    timeRow.className = 'location-time-row';
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.style.cssText = 'margin:0; padding:0 2px;';
    timeSpan.textContent = formatTime(timestamp);
    timeRow.appendChild(timeSpan);
    if (isSent) {
        const statusSpan = document.createElement('span');
        statusSpan.className = 'message-status';
        statusSpan.innerHTML = getStatusIcon(status);
        timeRow.appendChild(statusSpan);
    }
    bubble.appendChild(timeRow);

    wrapper.appendChild(bubble);
    return wrapper;
}

function openFilePicker(mimeTypes, extensions) {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = extensions;
    input.onchange = (e) => handleFileSelected(e.target.files[0]);
    input.click();
}

// Attachment size config — fetched once on chat open and cached
let attachmentConfig = null;

async function fetchAttachmentConfig() {
    try {
        const res = await fetch('/api/admin/attachment-config');
        if (res.ok) attachmentConfig = await res.json();
    } catch (e) {
        console.warn('Could not fetch attachment config:', e);
    }
}

async function handleFileSelected(file) {
    if (!file || !currentRecipient) return;

    // Ensure config is loaded
    if (!attachmentConfig) await fetchAttachmentConfig();

    const mime = file.type.toLowerCase();
    const allowed = ['image/jpeg', 'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain', 'application/pdf'];

    if (!allowed.includes(mime)) {
        alert('Unsupported file type. Allowed: JPEG, PNG, DOC, TXT, PDF');
        return;
    }

    const isImage = mime === 'image/jpeg' || mime === 'image/png';
    const maxMb = attachmentConfig
        ? (isImage ? attachmentConfig.max_image_size_mb : attachmentConfig.max_file_size_mb)
        : (isImage ? 5 : 10);

    if (file.size > maxMb * 1024 * 1024) {
        alert(`File too large. Maximum size for ${isImage ? 'images' : 'documents'} is ${maxMb} MB.`);
        return;
    }

    try {
        // Read file as ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();

        // Find recipient's public key
        const recipientContact = contacts.find(c => c.username === currentRecipient);
        if (!recipientContact) { alert('Recipient not found'); return; }

        // Encrypt using same ECDH/AES-GCM flow as text messages
        const encoder = new TextEncoder();
        // We encrypt the raw bytes directly (not a string), so we convert to Uint8Array
        const fileBytes = new Uint8Array(arrayBuffer);

        const pub = await crypto.subtle.importKey(
            'raw', base64ToArrayBuffer(recipientContact.public_key),
            {name: 'ECDH', namedCurve: 'P-256'}, false, []
        );
        const priv = await crypto.subtle.importKey(
            'pkcs8', base64ToArrayBuffer(userKeys.privateKey),
            {name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveKey']
        );
        const sharedKey = await crypto.subtle.deriveKey(
            {name: 'ECDH', public: pub}, priv,
            {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, sharedKey, fileBytes);

        const encryptedB64 = arrayBufferToBase64(ciphertext);
        const nonceB64 = arrayBufferToBase64(iv.buffer);

        // Create a local blob URL from the ORIGINAL (unencrypted) file bytes
        // so the sender immediately sees the correct image/file card — no "Decrypting…"
        const localBlob = new Blob([fileBytes], {type: mime});
        const localBlobUrl = URL.createObjectURL(localBlob);

        // Show the card with the blob URL already resolved
        const tempId = crypto.randomUUID();
        const ts = Date.now();
        addAttachmentMessageToUI(file.name, mime, isImage, 'sent', ts, tempId, 'sent', localBlobUrl);

        // Upload to server
        const res = await fetch('/api/attachment/upload', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                from_username: currentUser,
                to_username: currentRecipient,
                filename: file.name,
                mime_type: mime,
                encrypted_data: encryptedB64,
                nonce: nonceB64,
                sender_public_key: userKeys.publicKey,
            })
        });

        const data = await res.json();
        if (!res.ok) {
            alert('Upload failed: ' + (data.detail || 'Unknown error'));
            return;
        }

        // Save to local history as an attachment message
        saveToHistory(currentRecipient, `📎 ${file.name}`, 'sent', ts, tempId, data.status === 'delivered' ? 'delivered' : 'sent');

    } catch (err) {
        console.error('Attachment error:', err);
        alert('Error sending attachment: ' + err.message);
    }
}

// ==================== ADMIN SETTINGS ====================
function showAdminSettingsModal() {
    closeSettings();
    fetchAttachmentConfig().then(() => {
        if (attachmentConfig) {
            document.getElementById('adminMaxImageSize').value = attachmentConfig.max_image_size_mb;
            document.getElementById('adminMaxFileSize').value = attachmentConfig.max_file_size_mb;
        }
        document.getElementById('adminSettingsModal').classList.add('show');
        loadPendingUsers();
    });
}

function hideAdminSettingsModal() {
    document.getElementById('adminSettingsModal').classList.remove('show');
    clearStatus('adminSettingsStatus');
}

// ==================== PENDING APPROVAL MODAL ====================
function showPendingApprovalModal() {
    document.getElementById('pendingApprovalModal').classList.add('show');
}

function hidePendingApprovalModal() {
    document.getElementById('pendingApprovalModal').classList.remove('show');
}

// ==================== ADMIN: PENDING USER APPROVALS ====================
async function loadPendingUsers() {
    const list = document.getElementById('pendingUsersList');
    if (!list) return;
    list.innerHTML = '<p class="no-pending-msg">Loading...</p>';

    try {
        const res = await fetch(`/api/admin/pending-users?username=${encodeURIComponent(currentUser)}`);
        if (!res.ok) { list.innerHTML = '<p class="no-pending-msg">Could not load pending users.</p>'; return; }
        const data = await res.json();

        if (!data.pending_users || data.pending_users.length === 0) {
            list.innerHTML = '<p class="no-pending-msg">No pending approvals.</p>';
            return;
        }

        list.innerHTML = '';
        data.pending_users.forEach(u => {
            const row = document.createElement('div');
            row.className = 'pending-user-row';
            row.dataset.username = u.username;

            const info = document.createElement('div');
            info.className = 'pending-user-info';

            const nameEl = document.createElement('span');
            nameEl.className = 'pending-user-name';
            nameEl.textContent = u.username;

            const emailEl = document.createElement('span');
            emailEl.className = 'pending-user-email';
            emailEl.textContent = u.email;

            info.appendChild(nameEl);
            info.appendChild(emailEl);

            const btn = document.createElement('button');
            btn.className = 'approve-btn';
            btn.textContent = 'Approve';
            btn.addEventListener('click', () => approveUser(u.username, btn));

            row.appendChild(info);
            row.appendChild(btn);
            list.appendChild(row);
        });
    } catch (e) {
        list.innerHTML = '<p class="no-pending-msg">Error loading pending users.</p>';
        console.error('loadPendingUsers error:', e);
    }
}

async function approveUser(targetUsername, btn) {
    btn.disabled = true;
    btn.textContent = 'Approving...';
    try {
        const res = await fetch('/api/admin/approve-user', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username: currentUser, target_username: targetUsername })
        });
        const data = await res.json();
        if (res.ok) {
            btn.textContent = '✓ Approved';
            btn.style.background = '#d1fae5';
            btn.style.color = '#065f46';
            // Remove row after a short delay
            setTimeout(() => {
                const row = document.querySelector(`.pending-user-row[data-username="${targetUsername}"]`);
                if (row) row.remove();
                // If no more rows, show empty message
                const list = document.getElementById('pendingUsersList');
                if (list && list.children.length === 0) {
                    list.innerHTML = '<p class="no-pending-msg">No pending approvals.</p>';
                }
            }, 1200);
        } else {
            btn.textContent = 'Approve';
            btn.disabled = false;
            alert(data.detail || 'Approval failed');
        }
    } catch (e) {
        btn.textContent = 'Approve';
        btn.disabled = false;
        console.error('approveUser error:', e);
    }
}

async function handleSaveAdminSettings() {
    const maxImage = parseInt(document.getElementById('adminMaxImageSize').value, 10);
    const maxFile = parseInt(document.getElementById('adminMaxFileSize').value, 10);

    if (!maxImage || !maxFile || maxImage < 1 || maxFile < 1 || maxImage > 100 || maxFile > 100) {
        showStatus('adminSettingsStatus', 'Sizes must be between 1 and 100 MB', true);
        return;
    }

    try {
        const res = await fetch('/api/admin/attachment-config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                admin_username: currentUser,
                max_image_size_mb: maxImage,
                max_file_size_mb: maxFile,
            })
        });
        const data = await res.json();
        if (res.ok) {
            attachmentConfig = { max_image_size_mb: maxImage, max_file_size_mb: maxFile };
            showStatus('adminSettingsStatus', 'Saved successfully!', false);
            setTimeout(hideAdminSettingsModal, 1500);
        } else {
            showStatus('adminSettingsStatus', data.detail || 'Save failed', true);
        }
    } catch (err) {
        showStatus('adminSettingsStatus', 'Error: ' + err.message, true);
    }
}

// ==================== ATTACHMENT MESSAGE UI ====================
function addAttachmentMessageToUI(filename, mimeType, isImage, type, timestamp, messageId, status, blobUrl) {
    const messagesArea = document.getElementById('messagesArea');
    const msgDate = formatDate(timestamp);

    const lastDivider = messagesArea.querySelector('.date-divider:last-of-type');
    const lastDividerText = lastDivider ? lastDivider.querySelector('span').textContent : null;
    if (msgDate !== lastDividerText) {
        const dateDivider = document.createElement('div');
        dateDivider.className = 'date-divider';
        dateDivider.innerHTML = `<span>${msgDate}</span>`;
        messagesArea.appendChild(dateDivider);
    }

    const el = createAttachmentElement({filename, mimeType, isImage, type, timestamp, messageId, status, blobUrl});
    messagesArea.appendChild(el);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function createAttachmentElement({filename, mimeType, isImage, type, timestamp, messageId, status, blobUrl}) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.dataset.messageId = messageId;
    messageDiv.dataset.attachmentType = 'attachment';
    messageDiv.dataset.isImage = isImage ? '1' : '0';
    messageDiv.dataset.filename = filename;
    messageDiv.dataset.mimeType = mimeType;

    const isSent = type === 'sent';
    const displayName = filename.length > 28
        ? filename.slice(0, 24) + '…' + filename.slice(filename.lastIndexOf('.'))
        : filename;
    const iconSvg = getAttachmentIcon(mimeType, isImage);

    let card;

    if (isImage && blobUrl) {
        card = document.createElement('div');
        card.className = `attach-card attach-card-image ${isSent ? 'sent' : 'received'}`;
        card.dataset.msgid = messageId;

        const img = document.createElement('img');
        img.className = 'attach-thumb';
        img.src = blobUrl;
        img.alt = displayName;

        const cardFoot = document.createElement('div');
        cardFoot.className = 'attach-card-footer';
        const nameSpan = document.createElement('span');
        nameSpan.className = 'attach-name';
        nameSpan.textContent = displayName;
        cardFoot.appendChild(nameSpan);

        card.appendChild(img);
        card.appendChild(cardFoot);
        card.addEventListener('click', () => openImageLightbox(blobUrl, filename));

    } else if (!isImage && blobUrl) {
        card = document.createElement('div');
        card.className = `attach-card attach-card-file ${isSent ? 'sent' : 'received'}`;
        card.dataset.msgid = messageId;
        card._blobUrl = blobUrl;
        card._filename = filename;

        // Top row: icon + meta
        const topRow = document.createElement('div');
        topRow.className = 'attach-card-top';

        const iconWrap = document.createElement('div');
        iconWrap.className = 'attach-icon-wrap';
        iconWrap.innerHTML = iconSvg;

        const body = document.createElement('div');
        body.className = 'attach-card-body';

        const meta = document.createElement('div');
        meta.className = 'attach-meta';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'attach-name';
        nameSpan.textContent = displayName;

        const dlBtn = document.createElement('button');
        dlBtn.className = 'attach-download-btn';
        dlBtn.textContent = '⬇ Download';
        dlBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            doDownload(blobUrl, filename);
        });

        meta.appendChild(nameSpan);
        meta.appendChild(dlBtn);
        body.appendChild(meta);
        topRow.appendChild(iconWrap);
        topRow.appendChild(body);
        card.appendChild(topRow);

    } else {
        // Loading placeholder — blobUrl not ready yet
        card = document.createElement('div');
        card.className = `attach-card attach-card-file ${isSent ? 'sent' : 'received'}`;

        // Top row: icon + meta
        const topRow = document.createElement('div');
        topRow.className = 'attach-card-top';

        const iconWrap = document.createElement('div');
        iconWrap.className = 'attach-icon-wrap';
        iconWrap.innerHTML = iconSvg;

        const body = document.createElement('div');
        body.className = 'attach-card-body';

        const meta = document.createElement('div');
        meta.className = 'attach-meta';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'attach-name';
        nameSpan.textContent = displayName;

        const statusTxt = document.createElement('span');
        statusTxt.className = 'attach-status-text';
        statusTxt.textContent = 'Decrypting…';

        meta.appendChild(nameSpan);
        meta.appendChild(statusTxt);
        body.appendChild(meta);
        topRow.appendChild(iconWrap);
        topRow.appendChild(body);
        card.appendChild(topRow);
    }

    // Time/tick footer — INSIDE the card at the bottom-right
    const footer = document.createElement('div');
    footer.className = 'message-footer attach-footer';
    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = formatTime(timestamp);
    footer.appendChild(timeSpan);
    if (isSent) {
        const statusSpan = document.createElement('span');
        statusSpan.className = 'message-status';
        statusSpan.innerHTML = getStatusIcon(status);
        footer.appendChild(statusSpan);
    }
    card.appendChild(footer);

    // Bubble wraps only the card — footer is inside it
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble attach-bubble';
    bubble.appendChild(card);
    messageDiv.appendChild(bubble);
    return messageDiv;
}

// Handle attachment payload in incoming messages.
// data.isSent = true  → I am the original sender viewing my own history
//               false/undefined → I am the receiver
//
// ECDH shared secret = ECDH(myPrivateKey, otherPartyPublicKey)
// • As receiver : otherParty = sender   → use payload.sender_public_key
// • As sender   : otherParty = recipient → use recipient's public key from contacts
async function handleIncomingAttachment(payload, data) {
    try {
        let otherPartyPublicKeyB64;
        if (data.isSent) {
            // I sent this — derive key with the recipient's public key
            const recipientContact = contacts.find(c => c.username === currentRecipient);
            if (!recipientContact) {
                console.error('Attachment decrypt: recipient contact not found');
                return null;
            }
            otherPartyPublicKeyB64 = recipientContact.public_key;
        } else {
            // I received this — derive key with the sender's public key (stored in payload)
            otherPartyPublicKeyB64 = payload.sender_public_key;
        }

        const pub = await crypto.subtle.importKey(
            'raw', base64ToArrayBuffer(otherPartyPublicKeyB64),
            {name: 'ECDH', namedCurve: 'P-256'}, false, []
        );
        const priv = await crypto.subtle.importKey(
            'pkcs8', base64ToArrayBuffer(userKeys.privateKey),
            {name: 'ECDH', namedCurve: 'P-256'}, false, ['deriveKey']
        );
        const sharedKey = await crypto.subtle.deriveKey(
            {name: 'ECDH', public: pub}, priv,
            {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']
        );

        const iv = new Uint8Array(base64ToArrayBuffer(payload.nonce));
        const ct = base64ToArrayBuffer(payload.ciphertext);
        const decrypted = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, sharedKey, ct);

        const blob = new Blob([decrypted], {type: payload.mime_type});
        return URL.createObjectURL(blob);
    } catch (e) {
        console.error('Attachment decryption failed:', e);
        return null;
    }
}



function toggleAttachmentMenu() {
    const attachmentMenu = document.getElementById('attachmentMenu');
    attachmentMenu.classList.toggle('show');

    if (attachmentMenu.classList.contains('show')) {
        setTimeout(() => {
            document.addEventListener('click', closeAttachmentOnClickOutside);
        }, 0);
    }
}

// Close attachment menu on click outside
function closeAttachmentOnClickOutside(event) {
    const attachmentMenu = document.getElementById('attachmentMenu');
    if (!event.target.closest('.attach-btn') && !event.target.closest('.attachment-menu')) {
        attachmentMenu.classList.remove('show');
        document.removeEventListener('click', closeAttachmentOnClickOutside);
    }
}

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    console.log('SecureChat E2EE Messenger Loaded');

    // ===== AUTH SCREEN EVENT LISTENERS =====

    // Tab switching
    document.getElementById('loginTab').addEventListener('click', () => switchTab('login'));
    document.getElementById('registerTab').addEventListener('click', () => switchTab('register'));

    // Login button
    document.getElementById('loginBtn').addEventListener('click', handleLogin);

    // Register button
    document.getElementById('registerBtn').addEventListener('click', handleRegister);

    // Enter key for login
    document.getElementById('loginPassword').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });

    // Enter key for register
    document.getElementById('registerConfirm').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleRegister();
    });

    // ===== USER LIST EVENT LISTENERS =====

    // Settings button
    document.getElementById('settingsBtn').addEventListener('click', toggleSettings);

    // Settings menu items
    document.getElementById('profileMenuBtn').addEventListener('click', showProfileModal);
    document.getElementById('settingsMenuBtn').addEventListener('click', showSettingsModal);
    document.getElementById('changePasswordMenuBtn').addEventListener('click', showChangePasswordModal);
    document.getElementById('adminMenuBtn').addEventListener('click', showAdminSettingsModal);
    document.getElementById('logoutMenuBtn').addEventListener('click', handleLogout);

    // Search input
    document.getElementById('userSearch').addEventListener('input', filterUsers);

    // ===== CHAT PAGE EVENT LISTENERS =====

    // Back button
    document.getElementById('backBtn').addEventListener('click', backToUserList);

    // Chat settings button
    document.getElementById('startVideoCallBtn').addEventListener('click', startVideoCall);

    // Video call modal buttons — wired here (CSP-safe, no inline onclick)
    document.getElementById('cancelOutgoingCallBtn').addEventListener('click', cancelOutgoingCall);
    document.getElementById('declineCallBtn').addEventListener('click', declineCall);
    document.getElementById('acceptCallBtn').addEventListener('click', acceptCall);
    document.getElementById('endCallBtn').addEventListener('click', endCall);
    document.getElementById('muteAudioBtn').addEventListener('click', toggleCallAudio);
    document.getElementById('toggleVideoBtn').addEventListener('click', toggleCallVideo);
    document.getElementById('chatSettingsBtn').addEventListener('click', toggleChatSettings);

    // Chat settings menu items
    document.getElementById('contactInfoBtn').addEventListener('click', showContactInfoModal);
    document.getElementById('muteBtn').addEventListener('click', toggleMute);
    document.getElementById('clearChatBtn').addEventListener('click', clearChat);
    document.getElementById('blockBtn').addEventListener('click', toggleBlock);

    // Attach button
    document.getElementById('attachBtn').addEventListener('click', toggleAttachmentMenu);

    document.getElementById('attachDoc').addEventListener('click', attachDoc);
    document.getElementById('attachCamera').addEventListener('click', attachCamera);
    document.getElementById('attachGallery').addEventListener('click', attachGallery);
    document.getElementById('attachLocation').addEventListener('click', attachLocation);
    // Send button
    document.getElementById('sendBtn').addEventListener('click', sendMessage);

    // Message input
    const messageInput = document.getElementById('messageInput');

    messageInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            sendMessage();
        }
    });

    messageInput.addEventListener('input', () => {
        // Auto-resize textarea
        messageInput.style.height = 'auto';
        messageInput.style.height = messageInput.scrollHeight + 'px';

        // Handle typing indicator
        handleTyping();
    });

    // ===== PASSWORD MODAL EVENT LISTENERS =====

    // Update password button
    document.getElementById('updatePasswordBtn').addEventListener('click', handlePasswordChange);

    // Cancel button
    document.getElementById('cancelPasswordBtn').addEventListener('click', hidePasswordModal);

    // Close modal on outside click
    document.getElementById('passwordModal').addEventListener('click', (e) => {
        if (e.target.id === 'passwordModal') {
            hidePasswordModal();
        }
    });

    // ===== ADMIN SETTINGS MODAL LISTENERS =====
    document.getElementById('saveAdminSettingsBtn').addEventListener('click', handleSaveAdminSettings);
    document.getElementById('cancelAdminSettingsBtn').addEventListener('click', hideAdminSettingsModal);
    document.getElementById('adminSettingsModal').addEventListener('click', (e) => {
        if (e.target.id === 'adminSettingsModal') hideAdminSettingsModal();
    });

    // ===== PENDING APPROVAL MODAL =====
    document.getElementById('pendingApprovalOkBtn').addEventListener('click', hidePendingApprovalModal);
    document.getElementById('pendingApprovalModal').addEventListener('click', (e) => {
        if (e.target.id === 'pendingApprovalModal') hidePendingApprovalModal();
    });

    // ===== IMAGE LIGHTBOX — close on backdrop click + Save/Close buttons =====
    document.getElementById('imageLightbox').addEventListener('click', (e) => {
        if (e.target.id === 'imageLightbox') closeImageLightbox();
    });
    document.getElementById('lightboxSaveBtn').addEventListener('click', downloadLightboxImage);
    document.getElementById('lightboxCloseBtn').addEventListener('click', closeImageLightbox);

    // ===== MOBILE VIEWPORT HEIGHT =====
    function setVH() {
        let vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    }

    setVH();
    window.addEventListener('resize', setVH);

    // --- ADDED: auto session restore ---
    const storedUser = sessionStorage.getItem("currentUser");
    const storedToken = sessionStorage.getItem("sessionToken");
    const storedEncryptedKey = sessionStorage.getItem("encryptedPrivateKey");
    const storedSalt = sessionStorage.getItem("privateKeySalt");

    if (storedUser && storedToken && storedEncryptedKey && storedSalt) {
        openRestoreSessionModal(storedUser, storedToken);
    }


});
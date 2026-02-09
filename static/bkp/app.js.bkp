// ==================== GLOBAL STATE ====================
let currentUser = null;
let currentRecipient = null;
let websocket = null;
let sessionToken = null;  // Store session token for WebSocket auth
let userKeys = {
    publicKey: null,
    privateKey: null
};
let contacts = [];
let chatHistory = {}; // { username: [ {text, type, timestamp, messageId, status} ] }
let pendingMessagesStore = {}; // { "alice": [msg1, msg2], "bob": [msg3] }
let unreadCounts = {}; // { "alice": 3, "bob": 1 }

//====================== DATE TIME HELPER ===================
function formatDateLabel(date) {
    const d = new Date(date);
    const today = new Date();

    const isToday = d.toDateString() === today.toDateString();

    const yesterday = new Date();
    yesterday.setDate(today.getDate() - 1);
    const isYesterday = d.toDateString() === yesterday.toDateString();

    if (isToday) return "Today";
    if (isYesterday) return "Yesterday";

    return d.toLocaleDateString();
}

function formatTime(date) {
    return new Date(date).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });
}


// ==================== UI HELPERS ====================
function showStatus(elementId, message, isError = false) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.className = isError ? 'mt-4 text-center text-sm text-red-400' : 'mt-4 text-center text-sm text-green-400';
}

function showLogin() {
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('register-form').classList.add('hidden');
}

function showRegister() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
}

function showChangePassword() {
    document.getElementById('change-password-modal').classList.remove('hidden');
}

function hideChangePassword() {
    document.getElementById('change-password-modal').classList.add('hidden');
    document.getElementById('old-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-new-password').value = '';
    document.getElementById('password-change-status').textContent = '';
}

// ==================== AUTHENTICATION ====================
async function register() {
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;

    if (!username || !password) {
        showStatus('auth-status', 'Please fill all fields', true);
        return;
    }

    if (password !== confirm) {
        showStatus('auth-status', 'Passwords do not match', true);
        return;
    }

    if (password.length < 12) {
        showStatus('auth-status', 'Password must be at least 12 characters', true);
        return;
    }

    try {
        showStatus('auth-status', 'Generating encryption keys...', false);

        // Generate key pair
        const keyPair = await CryptoManager.generateKeyPair();

        // Derive authentication hash
        const authHash = await CryptoManager.deriveAuthHash(username, password);

        // Derive storage key
        const storageKey = await CryptoManager.deriveStorageKey(username, password);

        // Encrypt private key into vault
        const encryptedVault = await CryptoManager.encryptVault(keyPair.privateKey, storageKey);

        // Register with server
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username.toLowerCase(),
                auth_hash: authHash,
                public_key: keyPair.publicKey,
                encrypted_vault: encryptedVault
            })
        });

        const data = await response.json();

        if (response.ok) {
            showStatus('auth-status', 'Registration successful! Logging in...', false);
            setTimeout(() => {
                document.getElementById('login-username').value = username;
                document.getElementById('login-password').value = password;
                showLogin();
                login();
            }, 1000);
        } else {
            showStatus('auth-status', data.detail || 'Registration failed', true);
        }
    } catch (error) {
        showStatus('auth-status', 'Error: ' + error.message, true);
    }
}

async function login() {
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    if (!username || !password) {
        showStatus('auth-status', 'Please enter username and password', true);
        return;
    }

    try {
        showStatus('auth-status', 'Authenticating...', false);

        // Derive authentication hash
        const authHash = await CryptoManager.deriveAuthHash(username, password);

        // Login to server
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username.toLowerCase(),
                auth_hash: authHash
            })
        });

        const data = await response.json();

        if (response.ok) {
            showStatus('auth-status', 'Decrypting vault...', false);

            // Derive storage key and decrypt vault
            const storageKey = await CryptoManager.deriveStorageKey(username, password);
            const privateKey = await CryptoManager.decryptVault(data.encrypted_vault, storageKey);

            // Store keys IN MEMORY ONLY
            currentUser = username.toLowerCase();
            userKeys.publicKey = data.public_key;
            userKeys.privateKey = privateKey;

            // Store session token for WebSocket authentication
            sessionToken = data.session_token;

            // Store only encrypted vault (NOT password)
            sessionStorage.setItem('encryptedVault', data.encrypted_vault);

            // Switch to messenger
            document.getElementById('auth-screen').classList.add('hidden');
            document.getElementById('messenger-screen').classList.remove('hidden');
            document.getElementById('current-user').textContent = currentUser;

            // Connect WebSocket with authentication
            connectWebSocket();

            // Load contacts
            await loadContacts();

            // Store pending messages
            if (data.pending_messages && data.pending_messages.length > 0) {
                for (const msg of data.pending_messages) {
                    const from = msg.from;

                    if (!pendingMessagesStore[from]) {
                        pendingMessagesStore[from] = [];
                    }

                    pendingMessagesStore[from].push(msg);
                }
            }

            showStatus('auth-status', 'Login successful!', false);

            // Clear password from input field
            document.getElementById('login-password').value = '';

        } else {
            showStatus('auth-status', data.detail || 'Login failed', true);
        }
    } catch (error) {
        showStatus('auth-status', 'Error: ' + error.message, true);
    }
}

function logout() {
    if (websocket) {
        websocket.close();
    }

    // Clear all sensitive data
    currentUser = null;
    currentRecipient = null;
    sessionToken = null;
    userKeys = { publicKey: null, privateKey: null };
    contacts = [];
    chatHistory = {};
    pendingMessagesStore = {};
    unreadCounts = {};
    sessionStorage.clear();

    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('messenger-screen').classList.add('hidden');
    document.getElementById('messages-container').innerHTML = '';
    document.getElementById('login-password').value = '';
}

// ==================== PASSWORD CHANGE ====================
async function changePassword() {
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-new-password').value;

    if (!oldPassword || !newPassword || !confirmPassword) {
        showStatus('password-change-status', 'Please fill all fields', true);
        return;
    }

    if (newPassword !== confirmPassword) {
        showStatus('password-change-status', 'New passwords do not match', true);
        return;
    }

    if (newPassword.length < 12) {
        showStatus('password-change-status', 'Password must be at least 12 characters', true);
        return;
    }

    try {
        showStatus('password-change-status', 'Re-encrypting vault...', false);

        const encryptedVault = sessionStorage.getItem('encryptedVault');

        // Re-encrypt vault with new password
        const result = await CryptoManager.changePassword(
            currentUser,
            oldPassword,
            newPassword,
            encryptedVault
        );

        // Send to server
        const response = await fetch('/api/update-vault', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: currentUser,
                old_auth_hash: result.oldAuthHash,
                new_auth_hash: result.newAuthHash,
                new_encrypted_vault: result.newEncryptedVault
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Update stored encrypted vault
            sessionStorage.setItem('encryptedVault', result.newEncryptedVault);

            showStatus('password-change-status', 'Password updated successfully!', false);
            setTimeout(() => {
                hideChangePassword();
                // Clear password fields
                document.getElementById('old-password').value = '';
                document.getElementById('new-password').value = '';
                document.getElementById('confirm-new-password').value = '';
            }, 2000);
        } else {
            showStatus('password-change-status', data.detail || 'Update failed', true);
        }
    } catch (error) {
        showStatus('password-change-status', 'Error: ' + error.message, true);
    }
}

// ==================== WEBSOCKET ====================
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/${currentUser}`;

    websocket = new WebSocket(wsUrl);

    websocket.onopen = async () => {
        console.log('WebSocket connected - sending authentication');

        // Send authentication message with session token
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
                logout();
            }
        } else if (data.type === 'message') {
            await handleIncomingMessage(data);
        } else if (data.type === "delivery_status") {
            const bubble = document.querySelector(`[data-message-id="${data.message_id}"]`);
            if (bubble) {
                bubble.dataset.status = "delivered";
                updateBubbleStatus(bubble);
            }
        } else if (data.type === "read_receipt") {
            const bubbles = document.querySelectorAll(".message-bubble.sent");
            bubbles.forEach(b => {
                b.dataset.status = "read";
                updateBubbleStatus(b);
            });
        } else if (data.type === "typing") {
            showTypingIndicator();
        }
    };

    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };

    websocket.onclose = (event) => {
        console.log('WebSocket disconnected', event.code, event.reason);

        // Don't reconnect if intentionally logged out or auth failed
        if (event.code === 1008) {  // Policy violation (auth failed)
            console.log('WebSocket closed due to authentication failure');
            return;
        }

        // Reconnect after 3 seconds with exponential backoff
        if (currentUser && sessionToken) {
            setTimeout(() => {
                console.log('Attempting to reconnect WebSocket...');
                connectWebSocket();
            }, 3000);
        }
    };
}

// ==================== MESSAGING ====================
async function sendMessage() {
    const input = document.getElementById('message-input');
    const message = input.value.trim();

    if (!message || !currentRecipient) {
        return;
    }

    const messageId = crypto.randomUUID();
    const timestamp = Date.now();

    // If WebSocket is not open → show failed bubble immediately
    if (!websocket || websocket.readyState !== WebSocket.OPEN) {
        const bubble = displayMessage(message, 'sent', timestamp, messageId, "failed");
        bubble.dataset.messageId = messageId;
        bubble.dataset.status = "failed";
        updateBubbleStatus(bubble);

        // Save to history
        if (!chatHistory[currentRecipient]) chatHistory[currentRecipient] = [];
        chatHistory[currentRecipient].push({
            text: message,
            type: "sent",
            timestamp,
            messageId,
            status: "failed"
        });

        return;
    }

    try {
        // Get recipient's public key
        const recipientContact = contacts.find(c => c.username === currentRecipient);
        if (!recipientContact) {
            alert('Recipient not found');
            return;
        }

        // Encrypt message
        const encrypted = await CryptoManager.encryptMessage(
            message,
            recipientContact.public_key,
            userKeys.privateKey
        );

        // Create payload
        const payload = JSON.stringify({
            sender_public_key: userKeys.publicKey,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce
        });

        // Send via WebSocket
        websocket.send(JSON.stringify({
            type: 'message',
            from: currentUser,
            to: currentRecipient,
            payload: payload,
            message_id: messageId
        }));

        // Display bubble immediately (optimistic UI)
        const bubble = displayMessage(message, 'sent', timestamp, messageId, "sent");
        bubble.dataset.messageId = messageId;
        bubble.dataset.status = "sent";
        updateBubbleStatus(bubble);

        // Save to history
        if (!chatHistory[currentRecipient]) chatHistory[currentRecipient] = [];
        chatHistory[currentRecipient].push({
            text: message,
            type: "sent",
            timestamp,
            messageId,
            status: "sent"
        });

        input.value = '';

    } catch (error) {
        console.error('Error sending message:', error);

        // Show failed bubble
        const bubble = displayMessage(message, 'sent', timestamp, messageId, "failed");
        bubble.dataset.messageId = messageId;
        bubble.dataset.status = "failed";
        updateBubbleStatus(bubble);

        // Save failed message to history
        if (!chatHistory[currentRecipient]) chatHistory[currentRecipient] = [];
        chatHistory[currentRecipient].push({
            text: message,
            type: "sent",
            timestamp,
            messageId,
            status: "failed"
        });
    }
}

async function handleIncomingMessage(data) {
    try {
        // ⭐ UNREAD BADGE + SAVE TO HISTORY BUT DO NOT DISPLAY ⭐
        if (data.from !== currentRecipient) {
            if (!unreadCounts[data.from]) unreadCounts[data.from] = 0;
            unreadCounts[data.from]++;
            updateContactUnreadBadge(data.from);

            const payload = JSON.parse(data.payload);
            const encryptedPreview = payload.ciphertext.slice(0, 40) + '...';
            const serverTimestamp = new Date(data.timestamp).getTime();

            if (!chatHistory[data.from]) chatHistory[data.from] = [];
            chatHistory[data.from].push({
                text: encryptedPreview,
                type: "received",
                timestamp: serverTimestamp,
                messageId: data.message_id || null,
                status: null
            });

            // decrypt in background
            setTimeout(async () => {
                try {
                    const decrypted = await CryptoManager.decryptMessage(
                        payload.ciphertext,
                        payload.nonce,
                        payload.sender_public_key,
                        userKeys.privateKey
                    );
                    updateHistoryMessage(data.from, serverTimestamp, decrypted);
                } catch {
                    updateHistoryMessage(data.from, serverTimestamp, "[Decryption failed]");
                }
            }, 1000);

            return; // DO NOT DISPLAY
        }

        const payload = JSON.parse(data.payload);

        // Show encrypted preview
        const encryptedPreview = payload.ciphertext.slice(0, 40) + '...';
        const serverTimestamp = new Date(data.timestamp).getTime();
        const bubble = displayMessage(encryptedPreview, 'received', serverTimestamp);

        // Save encrypted preview to history for active chat
        if (!chatHistory[currentRecipient]) chatHistory[currentRecipient] = [];
        chatHistory[currentRecipient].push({
            text: encryptedPreview,
            type: "received",
            timestamp: serverTimestamp,
            messageId: data.message_id || null,
            status: null
        });

        // Decrypt after delay
        setTimeout(async () => {
            try {
                const decrypted = await CryptoManager.decryptMessage(
                    payload.ciphertext,
                    payload.nonce,
                    payload.sender_public_key,
                    userKeys.privateKey
                );

                const textDiv = bubble.querySelector(".message-text");
                textDiv.classList.add("fade-out");

                setTimeout(() => {
                    textDiv.textContent = decrypted;
                    textDiv.classList.remove("fade-out");
                    textDiv.classList.add("fade-in");

                    requestAnimationFrame(() => {
                        textDiv.classList.add("show");
                    });

                    updateHistoryMessage(data.from, serverTimestamp, decrypted);
                }, 300);
            } catch (e) {
                const textDiv = bubble.querySelector(".message-text");
                textDiv.textContent = "[Decryption failed]";
            }
        }, 1000);

    } catch (error) {
        console.error('Error handling message:', error);
    }
}


async function processPendingMessage(msg) {
    try {
        const payload = JSON.parse(msg.payload);

        const encryptedPreview = payload.ciphertext.slice(0, 40) + '...';
        const serverTimestamp = new Date(msg.timestamp).getTime();
        const bubble = displayMessage(encryptedPreview, 'received', serverTimestamp);

        // Save encrypted preview to history
        if (!chatHistory[currentRecipient]) chatHistory[currentRecipient] = [];
        chatHistory[currentRecipient].push({
            text: encryptedPreview,
            type: "received",
            timestamp: serverTimestamp,
            messageId: msg.message_id || null,
            status: null
        });

        setTimeout(async () => {
            try {
                const decrypted = await CryptoManager.decryptMessage(
                    payload.ciphertext,
                    payload.nonce,
                    payload.sender_public_key,
                    userKeys.privateKey
                );

                const textDiv = bubble.querySelector(".message-text");
                textDiv.classList.add("fade-out");

                setTimeout(() => {
                    textDiv.textContent = decrypted;
                    textDiv.classList.remove("fade-out");
                    textDiv.classList.add("fade-in");
                    requestAnimationFrame(() => {
                        textDiv.classList.add("show");
                    });

                    updateHistoryMessage(msg.from, serverTimestamp, decrypted);
                }, 300);

            } catch (e) {
                const textDiv = bubble.querySelector(".message-text");
                textDiv.textContent = "[Decryption failed]";
            }
        }, 1000);

    } catch (error) {
        console.error('Error processing pending message:', error);
    }
}

function displayMessage(text, type, timestamp = Date.now(), messageId = null, status = null) {
    const container = document.getElementById("messages-container");

    // ---- DATE SEPARATOR LOGIC ----
    const dateLabel = formatDateLabel(timestamp);
    const lastSeparator = container.querySelector(".date-separator:last-of-type");
    const lastSeparatorText = lastSeparator ? lastSeparator.getAttribute("data-date") : null;

    if (dateLabel !== lastSeparatorText) {
        const sep = document.createElement("div");
        sep.className = "date-separator text-gray-400 text-center text-xs my-2";
        sep.setAttribute("data-date", dateLabel);
        sep.textContent = dateLabel;
        container.appendChild(sep);
    }

    // ---- MESSAGE BUBBLE ----
    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${type} fade-in`;

    bubble.innerHTML = `
        <div class="message-text">${text}</div>
        <div class="message-meta flex items-center justify-end gap-1 mt-1">
            <span class="message-time text-xs opacity-70">${formatTime(timestamp)}</span>
            <span class="tick text-xs opacity-70"></span>
        </div>
    `;

    // attach messageId + status if provided
    if (messageId) bubble.dataset.messageId = messageId;
    if (status) {
        bubble.dataset.status = status;
        updateBubbleStatus(bubble);
    }

    container.appendChild(bubble);

    // trigger fade-in
    requestAnimationFrame(() => {
        bubble.classList.add("show");
    });

    // ---- AUTO SCROLL ----
    container.scrollTo({ top: container.scrollHeight, behavior: "smooth" });

    return bubble;
}

// ==================== CONTACTS ====================
async function loadContacts() {
    try {
        const response = await fetch('/api/users');
        const data = await response.json();

        contacts = data.users.filter(u => u.username !== currentUser);

        const contactsList = document.getElementById('contacts-list');
        contactsList.innerHTML = '';

        contacts.forEach(contact => {
            const contactEl = document.createElement('div');
            contactEl.className = 'p-3 bg-gray-700 rounded mb-2 cursor-pointer hover:bg-gray-600 transition';

            contactEl.innerHTML = `
                <div class="flex justify-between items-center">
                    <span>${contact.username}</span>
                    <span id="badge-${contact.username}" 
                          class="hidden bg-blue-500 text-white text-xs px-2 py-1 rounded-full">
                    </span>
                </div>
            `;

            contactEl.addEventListener('click', () => selectContact(contact.username));
            contactsList.appendChild(contactEl);
        });
        contacts.forEach(c => updateContactUnreadBadge(c.username));
    } catch (error) {
        console.error('Error loading contacts:', error);
    }
}

async function selectContact(username) {
    // Clear unread count for this user
    unreadCounts[username] = 0;
    updateContactUnreadBadge(username);

    currentRecipient = username;
    document.getElementById('chat-with').textContent = `Chat with ${username}`;

    const container = document.getElementById('messages-container');
    container.innerHTML = '';

    // ---- 1. Load chat history first ----
    const history = chatHistory[username] || [];

    history.forEach(msg => {
        const bubble = displayMessage(
            msg.text,
            msg.type,
            msg.timestamp,
            msg.messageId,
            msg.status
        );

        if (msg.messageId) {
            bubble.dataset.messageId = msg.messageId;
        }
        if (msg.status) {
            bubble.dataset.status = msg.status;
            updateBubbleStatus(bubble);
        }
    });

    // ---- 2. Load pending messages for this user ----
    if (pendingMessagesStore[username]) {
        for (const msg of pendingMessagesStore[username]) {
            await processPendingMessage(msg);
        }

        // Clear them after displaying
        delete pendingMessagesStore[username];
    }

    // ---- 3. Send read receipt AFTER messages are shown ----
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({
            type: "read_receipt",
            from: currentUser,
            to: username
        }));
    }
}

//UI ticks
function updateBubbleStatus(bubble) {
    const status = bubble.dataset.status;
    const tick = bubble.querySelector(".tick");

    if (!tick) return;

    if (status === "sent") {
        tick.textContent = "✓";
        tick.className = "tick grey";
    }

    if (status === "delivered") {
        tick.textContent = "✓✓";
        tick.className = "tick grey";
    }

    if (status === "read") {
        tick.textContent = "✓✓";
        tick.className = "tick blue";
    }

    if (status === "failed") {
        tick.textContent = "❗";
        tick.className = "tick text-red-500 cursor-pointer";
    }
}

//typing indicator
function showTypingIndicator() {
    const el = document.getElementById("typing-indicator");
    el.classList.remove("hidden");

    clearTimeout(window.typingHideTimer);
    window.typingHideTimer = setTimeout(() => {
        hideTypingIndicator();
    }, 3000);
}

function hideTypingIndicator() {
    document.getElementById("typing-indicator").classList.add("hidden");
}

// retry message
async function retryMessage(bubble) {
    const messageId = bubble.dataset.messageId;
    const text = bubble.querySelector(".message-text").textContent;

    // Reset status to "sent"
    bubble.dataset.status = "sent";
    updateBubbleStatus(bubble);

    try {
        const recipientContact = contacts.find(c => c.username === currentRecipient);
        if (!recipientContact) return;

        const encrypted = await CryptoManager.encryptMessage(
            text,
            recipientContact.public_key,
            userKeys.privateKey
        );

        const payload = JSON.stringify({
            sender_public_key: userKeys.publicKey,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce
        });

        websocket.send(JSON.stringify({
            type: "message",
            from: currentUser,
            to: currentRecipient,
            payload: payload,
            message_id: messageId
        }));

    } catch (err) {
        console.error("Retry failed:", err);
        bubble.dataset.status = "failed";
        updateBubbleStatus(bubble);
    }
}

// update history entries
function updateHistoryMessage(recipient, timestamp, newText) {
    if (!chatHistory[recipient]) return;

    const entry = chatHistory[recipient].find(m => m.timestamp === timestamp);
    if (entry) {
        entry.text = newText;
    }
}

// add msg badge visibility
function updateContactUnreadBadge(username) {
    const badge = document.getElementById(`badge-${username}`);
    if (!badge) return;

    const count = unreadCounts[username] || 0;

    if (count > 0) {
        badge.textContent = count;
        badge.classList.remove("hidden");
    } else {
        badge.classList.add("hidden");
    }
}

// ==================== EVENT LISTENERS ====================
document.addEventListener('DOMContentLoaded', () => {
    // Auth screen event listeners
    document.getElementById('login-btn').addEventListener('click', login);
    document.getElementById('register-btn').addEventListener('click', register);
    document.getElementById('show-register-link').addEventListener('click', (e) => {
        e.preventDefault();
        showRegister();
    });
    document.getElementById('show-login-link').addEventListener('click', (e) => {
        e.preventDefault();
        showLogin();
    });

    // Login on Enter key
    document.getElementById('login-password').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });

    // Register on Enter key
    document.getElementById('register-confirm').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') register();
    });

    // Messenger screen event listeners
    document.getElementById('logout-btn').addEventListener('click', logout);
    document.getElementById('change-password-btn').addEventListener('click', showChangePassword);
    document.getElementById('send-message-btn').addEventListener('click', sendMessage);
    document.getElementById('message-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // Password change modal event listeners
    document.getElementById('update-password-btn').addEventListener('click', changePassword);
    document.getElementById('cancel-password-btn').addEventListener('click', hideChangePassword);

    //end typing events
    let typingTimeout;

    document.getElementById("message-input").addEventListener("input", () => {
        if (!currentRecipient || !websocket || websocket.readyState !== WebSocket.OPEN) return;

        websocket.send(JSON.stringify({
            type: "typing",
            from: currentUser,
            to: currentRecipient
        }));

        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            hideTypingIndicator();
        }, 3000);
    });
});
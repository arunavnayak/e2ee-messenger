// ==================== GLOBAL STATE ====================
let currentUser = null;
let currentRecipient = null;
let websocket = null;
let sessionToken = null;
let userKeys = {
    publicKey: null,
    privateKey: null
};
let contacts = [];
let chatHistory = {}; // { username: [ {text, type, timestamp, messageId, status, date} ] }
let pendingMessagesStore = {};
let unreadCounts = {};
let typingTimeout = null;

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
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
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

    try {
        showStatus('authStatus', 'Generating encryption keys...', false);

        const keyPair = await CryptoManager.generateKeyPair();
        const authHash = await CryptoManager.deriveAuthHash(username, password);
        const storageKey = await CryptoManager.deriveStorageKey(username, password);
        const encryptedVault = await CryptoManager.encryptVault(keyPair.privateKey, storageKey);

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
            showStatus('authStatus', 'Registration successful! Logging in...', false);
            setTimeout(() => {
                document.getElementById('loginUsername').value = username;
                document.getElementById('loginPassword').value = password;
                switchTab('login');
                handleLogin();
            }, 1000);
        } else {
            showStatus('authStatus', data.detail || 'Registration failed', true);
        }
    } catch (error) {
        showStatus('authStatus', 'Error: ' + error.message, true);
    }
}

async function handleLogin() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showStatus('authStatus', 'Please enter username and password', true);
        return;
    }

    try {
        showStatus('authStatus', 'Authenticating...', false);

        const authHash = await CryptoManager.deriveAuthHash(username, password);

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
            showStatus('authStatus', 'Decrypting vault...', false);

            const storageKey = await CryptoManager.deriveStorageKey(username, password);
            const privateKey = await CryptoManager.decryptVault(data.encrypted_vault, storageKey);

            currentUser = username.toLowerCase();
            userKeys.publicKey = data.public_key;
            userKeys.privateKey = privateKey;
            sessionToken = data.session_token;

            sessionStorage.setItem('encryptedVault', data.encrypted_vault);

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
        } else {
            showStatus('authStatus', data.detail || 'Login failed', true);
        }
    } catch (error) {
        showStatus('authStatus', 'Error: ' + error.message, true);
    }
}

function handleLogout() {
    if (websocket) {
        websocket.close();
    }

    currentUser = null;
    currentRecipient = null;
    sessionToken = null;
    userKeys = { publicKey: null, privateKey: null };
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
        } else if (data.type === 'delivery_status') {
            updateMessageStatus(data.message_id, data.status);
        } else if (data.type === 'read_receipt') {
            markMessagesAsRead(data.from);
        } else if (data.type === 'typing') {
            showTypingIndicator(data.from);
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
    const search = document.getElementById('userSearch').value.toLowerCase();
    const userItems = document.querySelectorAll('.user-item');

    userItems.forEach(item => {
        const name = item.querySelector('.user-name').textContent.toLowerCase();
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

    // Load messages
    const messagesArea = document.getElementById('messagesArea');
    messagesArea.innerHTML = '';

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

        const messageEl = createMessageElement(msg);
        messagesArea.appendChild(messageEl);
    });

    // Load pending messages
    if (pendingMessagesStore[username]) {
        for (const msg of pendingMessagesStore[username]) {
            await processPendingMessage(msg);
        }
        delete pendingMessagesStore[username];
    }

    // Scroll to bottom
    messagesArea.scrollTop = messagesArea.scrollHeight;

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

    messageDiv.innerHTML = `
        <div class="message-bubble">
            <div class="message-text ${msg.text.includes('...') ? 'encrypted' : ''}">${msg.text}</div>
            <div class="message-footer">
                <span>${formatTime(msg.timestamp)}</span>
                ${msg.type === 'sent' ? `<span class="message-status">${statusIcon}</span>` : ''}
            </div>
        </div>
    `;

    return messageDiv;
}

function getStatusIcon(status) {
    switch(status) {
        case 'sent': return '<span class="status-sent">✓</span>';
        case 'delivered': return '<span class="status-delivered">✓✓</span>';
        case 'read': return '<span class="status-read">✓✓</span>';
        case 'failed': return '<span class="status-failed">❌</span>';
        default: return '';
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

    const msgEl = createMessageElement({ text, type, timestamp, messageId, status });
    messagesArea.appendChild(msgEl);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function saveToHistory(username, text, type, timestamp, messageId, status) {
    if (!chatHistory[username]) {
        chatHistory[username] = [];
    }

    chatHistory[username].push({ text, type, timestamp, messageId, status });

    // Update user list if not in chat with this user
    if (currentRecipient !== username) {
        renderUsersList();
    }
}

async function handleIncomingMessage(data) {
    try {
        const payload = JSON.parse(data.payload);
        const serverTimestamp = new Date(data.timestamp).getTime();

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
    document.getElementById('changePasswordMenuBtn').addEventListener('click', showChangePasswordModal);
    document.getElementById('logoutMenuBtn').addEventListener('click', handleLogout);

    // Search input
    document.getElementById('userSearch').addEventListener('input', filterUsers);

    // ===== CHAT PAGE EVENT LISTENERS =====

    // Back button
    document.getElementById('backBtn').addEventListener('click', backToUserList);

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

    // ===== MOBILE VIEWPORT HEIGHT =====
    function setVH() {
        let vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    }

    setVH();
    window.addEventListener('resize', setVH);
});
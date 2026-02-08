// ==================== CRYPTOGRAPHIC CONSTANTS ====================
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_HASH = 'SHA-256';
const VAULT_SALT = 'e2ee-vault-salt-v1';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ==================== UTILITY FUNCTIONS ====================
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function randomBytes(len) {
    return crypto.getRandomValues(new Uint8Array(len));
}

// ==================== PBKDF2 KEY DERIVATION ====================
async function deriveAuthHash(username, password) {
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const authSalt = encoder.encode(`auth-${username.toLowerCase()}`);
    const authBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: authSalt,
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
        },
        passwordKey,
        256
    );

    return arrayBufferToBase64(authBits);
}

async function deriveStorageKey(username, password) {
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const storageSalt = encoder.encode(`storage-${username.toLowerCase()}-${VAULT_SALT}`);

    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: storageSalt,
            iterations: PBKDF2_ITERATIONS,
            hash: PBKDF2_HASH
        },
        passwordKey,
        {name: 'AES-GCM', length: 256},
        false,
        ['encrypt', 'decrypt']
    );
}

// ==================== SESSION TOKEN GENERATION ====================
// Generate a cryptographically secure session token for WebSocket authentication
async function generateSessionToken() {
    const tokenBytes = randomBytes(32); // 256 bits of randomness
    return arrayBufferToBase64(tokenBytes.buffer);
}

// Derive a session authentication hash from username and token
async function deriveSessionAuth(username, sessionToken) {
    const combined = encoder.encode(`${username.toLowerCase()}:${sessionToken}`);
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    return arrayBufferToBase64(hashBuffer);
}

// ==================== ECDH KEY GENERATION ====================
async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey']
    );

    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    return {
        publicKey: arrayBufferToBase64(publicKey),
        privateKey: arrayBufferToBase64(privateKey)
    };
}

// ==================== VAULT ENCRYPTION ====================
async function encryptVault(privateKey, storageKey) {
    const iv = randomBytes(12);

    const ciphertext = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv: iv},
        storageKey,
        encoder.encode(privateKey)
    );

    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return arrayBufferToBase64(combined.buffer);
}

async function decryptVault(encryptedVault, storageKey) {
    const combined = new Uint8Array(base64ToArrayBuffer(encryptedVault));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    try {
        const decrypted = await crypto.subtle.decrypt(
            {name: 'AES-GCM', iv: iv},
            storageKey,
            ciphertext
        );

        return decoder.decode(decrypted);
    } catch (e) {
        throw new Error('Decryption failed: Invalid password');
    }
}

// ==================== PASSWORD CHANGE ====================
async function changePassword(username, oldPassword, newPassword, encryptedVault) {
    const oldStorageKey = await deriveStorageKey(username, oldPassword);
    const oldAuthHash = await deriveAuthHash(username, oldPassword);

    let privateKey;
    try {
        privateKey = await decryptVault(encryptedVault, oldStorageKey);
    } catch {
        throw new Error('Current password is incorrect');
    }

    const newStorageKey = await deriveStorageKey(username, newPassword);
    const newAuthHash = await deriveAuthHash(username, newPassword);

    const newEncryptedVault = await encryptVault(privateKey, newStorageKey);

    return {
        oldAuthHash,
        newAuthHash,
        newEncryptedVault
    };
}

// ==================== MESSAGE ENCRYPTION ====================
async function importPublicKey(base64) {
    return crypto.subtle.importKey(
        'raw',
        base64ToArrayBuffer(base64),
        {name: 'ECDH', namedCurve: 'P-256'},
        false,
        []
    );
}

async function importPrivateKey(base64) {
    return crypto.subtle.importKey(
        'pkcs8',
        base64ToArrayBuffer(base64),
        {name: 'ECDH', namedCurve: 'P-256'},
        false,
        ['deriveKey']
    );
}

async function deriveSharedKey(privateKey, publicKey) {
    return crypto.subtle.deriveKey(
        {name: 'ECDH', public: publicKey},
        privateKey,
        {name: 'AES-GCM', length: 256},
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptMessage(message, recipientPublicKey, senderPrivateKey) {
    const pub = await importPublicKey(recipientPublicKey);
    const priv = await importPrivateKey(senderPrivateKey);
    const sharedKey = await deriveSharedKey(priv, pub);

    const iv = randomBytes(12);

    const ciphertext = await crypto.subtle.encrypt(
        {name: 'AES-GCM', iv},
        sharedKey,
        encoder.encode(message)
    );

    return {
        ciphertext: arrayBufferToBase64(ciphertext),
        nonce: arrayBufferToBase64(iv.buffer)
    };
}

async function decryptMessage(ciphertext, nonce, senderPublicKey, recipientPrivateKey) {
    const pub = await importPublicKey(senderPublicKey);
    const priv = await importPrivateKey(recipientPrivateKey);
    const sharedKey = await deriveSharedKey(priv, pub);

    const iv = new Uint8Array(base64ToArrayBuffer(nonce));
    const ct = base64ToArrayBuffer(ciphertext);

    const decrypted = await crypto.subtle.decrypt(
        {name: 'AES-GCM', iv},
        sharedKey,
        ct
    );

    return decoder.decode(decrypted);
}

// ==================== EXPORT ====================
window.CryptoManager = {
    deriveAuthHash,
    deriveStorageKey,
    generateKeyPair,
    encryptVault,
    decryptVault,
    changePassword,
    encryptMessage,
    decryptMessage,
    generateSessionToken,
    deriveSessionAuth
};
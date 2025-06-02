// frontend/js/crypto.js

// --- Constantes ---
const SALT_LENGTH = 16; // bytes
const IV_LENGTH = 12;   // bytes para AES-GCM
const PBKDF2_ITERATIONS_KEY = 310000; // Para derivação da chave de criptografia (mais alto é melhor)
const PBKDF2_ITERATIONS_LOGIN_HASH = 100000; // Para o hash de login (pode ser menor se o servidor re-hashear)

// --- Geração de Salt ---
function generateSalt() {
    return window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
}

// --- Derivação da Chave de Criptografia (a partir da Senha Mestra) ---
async function deriveKeyFromMasterPassword(masterPassword, salt) {
    const masterKeyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(masterPassword),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS_KEY,
            hash: "SHA-256",
        },
        masterKeyMaterial,
        { name: "AES-GCM", length: 256 },
        false, // Não exportável (mais seguro)
        ["encrypt", "decrypt"]
    );
}

// --- Criptografar Dados ---
async function encryptData(data, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encodedData = new TextEncoder().encode(data);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encodedData
    );
    return {
        iv: bufferToBase64(iv),
        encryptedData: bufferToBase64(encryptedBuffer),
    };
}

// --- Descriptografar Dados ---
async function decryptData(encryptedDataB64, ivB64, key) {
    const iv = base64ToBuffer(ivB64);
    const encryptedBuffer = base64ToBuffer(encryptedDataB64);
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            key,
            encryptedBuffer
        );
        return new TextDecoder().decode(decryptedBuffer);
    } catch (e) {
        console.error("Erro ao descriptografar:", e);
        throw new Error("Falha na descriptografia. Senha mestra incorreta ou dados corrompidos.");
    }
}

// --- Gerar Hash da Senha Mestra para Login (Zero-Knowledge) ---
// O cliente deriva um hash da senha mestra usando um salt específico para login.
// O servidor armazena este hash e o salt de login.
async function hashMasterPasswordForLogin(masterPassword, loginSalt) {
    const masterKeyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(masterPassword),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: loginSalt,
            iterations: PBKDF2_ITERATIONS_LOGIN_HASH,
            hash: "SHA-256",
        },
        masterKeyMaterial,
        256 // Tamanho do hash em bits (32 bytes)
    );
    return bufferToBase64(new Uint8Array(derivedBits));
}


// --- Funções Utilitárias para Base64 ---
function bufferToBase64(buffer) {
    // Converte ArrayBuffer para string binária e depois para base64
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
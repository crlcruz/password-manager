// frontend/js/api.js

const API_BASE_URL = 'http://172.245.214.165:3000/api'; // Configure para sua URL de API em produção

async function request(endpoint, method = 'GET', data = null, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method: method,
        headers: headers,
    };

    if (data && (method === 'POST' || method === 'PUT')) {
        config.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: response.statusText }));
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }
        if (response.status === 204) { // No Content
            return null;
        }
        return await response.json();
    } catch (error) {
        console.error(`API Error (${method} ${endpoint}):`, error);
        throw error; // Re-throw para ser tratado pelo chamador
    }
}

// --- Auth Endpoints ---
async function registerUser(username, loginPasswordHash, keyDerivationSaltBase64, loginSaltBase64) {
    return request('/auth/register', 'POST', { username, loginPasswordHash, keyDerivationSalt: keyDerivationSaltBase64, loginSalt: loginSaltBase64 });
}

// Backend precisa de uma rota para fornecer os salts ANTES do login
async function getLoginSalts(username) {
    // Exemplo: GET /auth/salts?username=fulano
    // O backend deve retornar { loginSalt: "base64salt", keyDerivationSalt: "base64salt" }
    // keyDerivationSalt é retornado aqui para simplificar, mas poderia ser retornado só após login bem-sucedido.
    // Por segurança, keyDerivationSalt é mais seguro se retornado APENAS após login bem-sucedido.
    // Para o hash de login, precisamos do loginSalt.
    return request(`/auth/salts/${encodeURIComponent(username)}`, 'GET');
}


async function loginUser(username, loginPasswordHash) {
    // O backend deve retornar { token: "jwt", keyDerivationSalt: "base64salt" }
    return request('/auth/login', 'POST', { username, loginPasswordHash });
}

// --- Password Endpoints ---
async function fetchPasswords(token) {
    return request('/passwords', 'GET', null, token);
}

async function addPasswordEntry(token, siteName, siteUsername, encryptedPassword, iv) {
    return request('/passwords', 'POST', { siteName, siteUsername, encryptedPassword, iv }, token);
}

async function updatePasswordEntry(token, id, siteName, siteUsername, encryptedPassword, iv) {
    return request(`/passwords/${id}`, 'PUT', { siteName, siteUsername, encryptedPassword, iv }, token);
}

async function deletePasswordEntry(token, id) {
    return request(`/passwords/${id}`, 'DELETE', null, token);
}
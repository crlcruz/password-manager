// frontend/js/app.js

document.addEventListener('DOMContentLoaded', () => {
    // --- Elementos do DOM ---
    const messagesDiv = document.getElementById('messages');
    const authSection = document.getElementById('authSection');
    const appSection = document.getElementById('appSection');

    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const showRegisterFormBtn = document.getElementById('showRegisterFormBtn');
    const showLoginFormBtn = document.getElementById('showLoginFormBtn');

    const addPasswordForm = document.getElementById('addPasswordForm');
    const passwordsList = document.getElementById('passwordsList');
    const logoutBtn = document.getElementById('logoutBtn');

    // --- Estado da Aplicação ---
    let currentUserToken = sessionStorage.getItem('pm_token'); // Persiste o token na sessão do navegador
    let encryptionKey = null; // NUNCA armazene no localStorage. Apenas em memória.
    // keyDerivationSalt será buscado do servidor após login bem-sucedido

    // --- Funções de UI ---
    function displayMessage(message, type = 'error') {
        messagesDiv.textContent = message;
        messagesDiv.className = type; // 'success' ou 'error'
        setTimeout(() => messagesDiv.textContent = '', 5000); // Limpa após 5s
    }

    function showView(view) {
        if (view === 'app') {
            authSection.classList.add('hidden');
            appSection.classList.remove('hidden');
            loadUserPasswords();
        } else { // auth
            authSection.classList.remove('hidden');
            appSection.classList.add('hidden');
            currentUserToken = null;
            encryptionKey = null;
            sessionStorage.removeItem('pm_token');
            passwordsList.innerHTML = ''; // Limpa a lista de senhas ao sair
        }
    }

    function toggleAuthForms() {
        document.getElementById('loginFormContainer').classList.toggle('hidden');
        document.getElementById('registerFormContainer').classList.toggle('hidden');
        messagesDiv.textContent = ''; // Limpa mensagens ao trocar de formulário
    }
    showRegisterFormBtn.addEventListener('click', toggleAuthForms);
    showLoginFormBtn.addEventListener('click', toggleAuthForms);


    // --- Lógica de Autenticação ---
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.username.value;
        const masterPassword = e.target.masterPassword.value;
        const masterPasswordConfirm = e.target.masterPasswordConfirm.value;

        if (masterPassword !== masterPasswordConfirm) {
            displayMessage("As senhas mestras não coincidem!");
            return;
        }
        if (masterPassword.length < 8) { // Adicione mais validações
            displayMessage("Senha mestra muito curta (mínimo 8 caracteres).");
            return;
        }

        try {
            const keyDerivationSalt = generateSalt(); // Para criptografar as senhas armazenadas
            const loginSalt = generateSalt();         // Para o hash da senha mestra para login

            const loginPasswordHash = await hashMasterPasswordForLogin(masterPassword, loginSalt);

            await registerUser(
                username,
                loginPasswordHash,
                bufferToBase64(keyDerivationSalt),
                bufferToBase64(loginSalt)
            );
            displayMessage('Usuário registrado com sucesso! Faça o login.', 'success');
            registerForm.reset();
            toggleAuthForms(); // Mostra formulário de login
        } catch (error) {
            displayMessage(`Erro no registro: ${error.message}`);
        }
    });

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = e.target.username.value;
        const masterPassword = e.target.masterPassword.value;

        try {
            // 1. Obter o salt de login do servidor
            const salts = await getLoginSalts(username);
            if (!salts || !salts.loginSalt) {
                displayMessage("Usuário não encontrado ou erro ao obter dados de login.");
                return;
            }
            const loginSalt = base64ToBuffer(salts.loginSalt);

            // 2. Gerar o hash da senha mestra com o salt obtido
            const loginPasswordHash = await hashMasterPasswordForLogin(masterPassword, loginSalt);

            // 3. Fazer o login
            const loginResponse = await loginUser(username, loginPasswordHash);
            currentUserToken = loginResponse.token;
            sessionStorage.setItem('pm_token', currentUserToken); // Salva token

            const keyDerivationSalt = base64ToBuffer(loginResponse.keyDerivationSalt);
            encryptionKey = await deriveKeyFromMasterPassword(masterPassword, keyDerivationSalt);

            displayMessage('Login bem-sucedido!', 'success');
            loginForm.reset();
            showView('app');
        } catch (error) {
            encryptionKey = null; // Limpa chave em caso de erro
            displayMessage(`Erro no login: ${error.message}`);
        }
    });

    logoutBtn.addEventListener('click', () => {
        showView('auth');
        displayMessage('Você saiu.', 'success');
    });

    // --- Lógica de Gerenciamento de Senhas ---
    async function loadUserPasswords() {
        if (!currentUserToken || !encryptionKey) {
            displayMessage("Não autenticado ou chave de criptografia ausente.");
            showView('auth'); // Força logout se algo estiver errado
            return;
        }
        passwordsList.innerHTML = 'Carregando senhas...';
        try {
            const passwords = await fetchPasswords(currentUserToken);
            passwordsList.innerHTML = ''; // Limpa antes de adicionar
            if (passwords.length === 0) {
                passwordsList.innerHTML = '<li>Nenhuma senha salva ainda.</li>';
                return;
            }
            for (const item of passwords) {
                try {
                    const decryptedPassword = await decryptData(item.encrypted_password, item.iv, encryptionKey);
                    renderPasswordItem(item, decryptedPassword);
                } catch (decryptionError) {
                    console.error(`Falha ao descriptografar senha para ${item.site_name}: ${decryptionError.message}`);
                    renderPasswordItem(item, "ERRO NA DESCRIPTOGRAFIA", true);
                }
            }
        } catch (error) {
            displayMessage(`Erro ao carregar senhas: ${error.message}`);
            if (error.message.toLowerCase().includes("token inválido") || error.message.toLowerCase().includes("unauthorized")) {
                showView('auth'); // Se o token expirou ou é inválido
            }
            passwordsList.innerHTML = '<li>Erro ao carregar senhas.</li>';
        }
    }

    function renderPasswordItem(item, decryptedPassword, isError = false) {
        const li = document.createElement('li');
        li.setAttribute('data-id', item.id);

        let passwordDisplay = '••••••••';
        if (isError) {
            passwordDisplay = `<span style="color:red;">${decryptedPassword}</span>`;
        }

        li.innerHTML = `
            <div class="details">
                <strong>Site:</strong> ${item.site_name}<br>
                <strong>Usuário:</strong> ${item.site_username || 'N/A'}<br>
                <div class="password-field">
                    <strong>Senha:</strong> 
                    <input type="text" value="${isError ? decryptedPassword : '••••••••'}" readonly class="password-value-field">
                    <button class="toggle-visibility-btn">👁️</button>
                </div>
            </div>
            <div class="actions">
                <button class="delete-btn danger">Excluir</button>
            </div>
        `;
        passwordsList.appendChild(li);

        const toggleBtn = li.querySelector('.toggle-visibility-btn');
        const passwordField = li.querySelector('.password-value-field');

        if (isError) {
            toggleBtn.disabled = true;
            toggleBtn.style.opacity = "0.5";
        } else {
            toggleBtn.addEventListener('click', () => {
                if (passwordField.value === '••••••••') {
                    passwordField.value = decryptedPassword;
                    toggleBtn.textContent = '🙈';
                } else {
                    passwordField.value = '••••••••';
                    toggleBtn.textContent = '👁️';
                }
            });
        }
    }

    addPasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!encryptionKey) {
            displayMessage("Chave de criptografia não está disponível. Faça login novamente.");
            return;
        }

        const siteName = e.target.siteName.value;
        const siteUsername = e.target.siteUsername.value;
        const sitePassword = e.target.sitePassword.value;

        try {
            const { iv, encryptedData } = await encryptData(sitePassword, encryptionKey);
            await addPasswordEntry(currentUserToken, siteName, siteUsername, encryptedData, iv);
            displayMessage('Senha adicionada com sucesso!', 'success');
            addPasswordForm.reset();
            loadUserPasswords(); // Recarrega a lista
        } catch (error) {
            displayMessage(`Erro ao adicionar senha: ${error.message}`);
        }
    });

    // Delegação de eventos para botões de excluir
    passwordsList.addEventListener('click', async (e) => {
        if (e.target.classList.contains('delete-btn')) {
            const listItem = e.target.closest('li');
            const passwordId = listItem.getAttribute('data-id');
            if (confirm('Tem certeza que deseja excluir esta senha?')) {
                try {
                    await deletePasswordEntry(currentUserToken, passwordId);
                    displayMessage('Senha excluída com sucesso!', 'success');
                    loadUserPasswords(); // Recarrega a lista
                } catch (error) {
                    displayMessage(`Erro ao excluir senha: ${error.message}`);
                }
            }
        }
    });


    // --- Inicialização ---
    function init() {
        if (currentUserToken) {
            // Se temos um token, tentamos obter a chave de criptografia (requer senha mestra novamente)
            // Por simplicidade, vamos forçar o login para obter a chave de criptografia.
            // Uma implementação mais avançada poderia guardar o keyDerivationSalt criptografado
            // ou exigir a senha mestra para "desbloquear" a sessão.
            // Aqui, apenas limpamos e pedimos login se a chave não estiver presente.
            if (!encryptionKey) { // Se a página foi recarregada, encryptionKey será null
                displayMessage("Sessão expirada ou inválida. Por favor, faça login novamente.");
                showView('auth'); // Força login para rederivar a chave.
                return;
            }
            showView('app');
        } else {
            showView('auth');
        }
    }

    init();
});
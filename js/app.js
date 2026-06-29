/**
 * BlindBase POC UI logic
 *
 * Kept in an external file (no inline scripts / inline event handlers) so the
 * page can enforce a strict Content-Security-Policy of `script-src 'self'`.
 */

// Initialize BlindBase client
const vault = new BlindBase('api.php');

// Status display helper
function showStatus(message, type = 'info') {
    const el = document.getElementById('status');
    el.textContent = message;
    el.className = `status status--${type}`;
    el.classList.remove('hidden');

    // Auto-hide success messages
    if (type === 'success') {
        setTimeout(() => el.classList.add('hidden'), 3000);
    }
}

function hideStatus() {
    document.getElementById('status').classList.add('hidden');
}

// Login handler
async function handleLogin() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        showStatus('Please enter both username and password.', 'warning');
        return;
    }

    const loginBtn = document.getElementById('login-btn');
    const loginText = document.getElementById('login-text');
    const loginLoading = document.getElementById('login-loading');

    loginBtn.disabled = true;
    loginText.classList.add('hidden');
    loginLoading.classList.remove('hidden');
    hideStatus();

    try {
        showStatus('Deriving encryption key (this may take a moment)...', 'info');

        const data = await vault.init(username, password);

        // Update UI
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('vault-screen').classList.remove('hidden');
        document.getElementById('user-badge').textContent = `Logged in as: ${vault.getUsername()}`;

        if (data) {
            // Pretty-print if it's an object
            const display = typeof data === 'object'
                ? JSON.stringify(data, null, 2)
                : data;
            document.getElementById('secret-data').value = display;
            showStatus('Vault unlocked. Data loaded successfully.', 'success');
        } else {
            document.getElementById('secret-data').value = '';
            document.getElementById('secret-data').placeholder = 'No existing data. Start typing to create new content.';
            showStatus('Vault unlocked. No existing data found.', 'success');
        }
    } catch (error) {
        showStatus(`Login failed: ${error.message}`, 'error');
        loginBtn.disabled = false;
        loginText.classList.remove('hidden');
        loginLoading.classList.add('hidden');
    }
}

// Save handler
async function handleSave() {
    const content = document.getElementById('secret-data').value;
    const saveText = document.getElementById('save-text');
    const saveLoading = document.getElementById('save-loading');

    saveText.classList.add('hidden');
    saveLoading.classList.remove('hidden');

    try {
        // Try to parse as JSON, otherwise save as raw string
        let dataToSave;
        try {
            dataToSave = JSON.parse(content);
        } catch {
            dataToSave = content;
        }

        const result = await vault.save(dataToSave);
        showStatus(`Saved successfully at ${result.updated_at}`, 'success');
    } catch (error) {
        showStatus(`Save failed: ${error.message}`, 'error');
    } finally {
        saveText.classList.remove('hidden');
        saveLoading.classList.add('hidden');
    }
}

// Reload data from server
async function handleReload() {
    try {
        showStatus('Reloading data...', 'info');
        const data = await vault.load();

        if (data) {
            const display = typeof data === 'object'
                ? JSON.stringify(data, null, 2)
                : data;
            document.getElementById('secret-data').value = display;
            showStatus('Data reloaded successfully.', 'success');
        } else {
            document.getElementById('secret-data').value = '';
            showStatus('No data found on server.', 'warning');
        }
    } catch (error) {
        showStatus(`Reload failed: ${error.message}`, 'error');
    }
}

// Logout handler
function handleLogout() {
    if (confirm('Are you sure you want to logout? Make sure your data is saved.')) {
        vault.logout();
    }
}

// Wire up event listeners once the DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('save-btn').addEventListener('click', handleSave);
    document.getElementById('reload-btn').addEventListener('click', handleReload);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // Handle Enter key on password field
    document.getElementById('password').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            handleLogin();
        }
    });

    // Focus username field on load
    document.getElementById('username').focus();
});

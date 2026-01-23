/**
 * BlindBase Client SDK
 * Zero-knowledge encryption client for the BlindBase framework
 *
 * @version 1.0.0
 * @license MIT
 *
 * Usage:
 *   const vault = new BlindBase('/api.php');
 *   await vault.init('username', 'password');
 *   const data = await vault.load();
 *   await vault.save({ myData: 'encrypted' });
 *   vault.logout();
 */
class BlindBase {
    /**
     * Create a new BlindBase client instance
     * @param {string} apiUrl - URL to the BlindBase API endpoint
     */
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
        this.key = null;      // Encryption key - stored in RAM only
        this.username = null;
        this.salt = null;

        // Configuration
        this.config = {
            pbkdf2Iterations: 100000,
            keyLength: 256,
            ivLength: 12,  // 96 bits for AES-GCM
        };
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Initialize the vault: fetch salt, derive key, and optionally load data
     * @param {string} username - Username (3-32 chars, lowercase alphanumeric + underscore)
     * @param {string} password - User's password (used to derive encryption key)
     * @returns {Promise<object|null>} Decrypted data or null if no data exists
     * @throws {Error} If initialization fails
     */
    async init(username, password) {
        if (!username || !password) {
            throw new Error('Username and password are required');
        }

        this.username = username.toLowerCase().trim();

        // Fetch salt from server
        const saltResponse = await this._fetch(`${this.apiUrl}?action=get_salt&user=${encodeURIComponent(this.username)}`);
        const saltData = await this._handleResponse(saltResponse);

        this.salt = saltData.salt;

        // Derive encryption key from password
        this.key = await this._deriveKey(password, this.salt);

        // Load existing data
        return this.load();
    }

    /**
     * Save data to the vault
     * @param {object|string} data - Data to encrypt and save
     * @returns {Promise<object>} Server response with status and updated_at
     * @throws {Error} If vault is locked or save fails
     */
    async save(data) {
        this._requireUnlocked();

        const payload = typeof data === 'string' ? data : JSON.stringify(data);
        const encrypted = await this._encrypt(payload);

        const formData = new FormData();
        formData.append('user', this.username);
        formData.append('payload', encrypted);

        const response = await this._fetch(`${this.apiUrl}?action=save`, {
            method: 'POST',
            body: formData
        });

        return this._handleResponse(response);
    }

    /**
     * Load and decrypt data from the vault
     * @returns {Promise<object|null>} Decrypted data or null if no data exists
     * @throws {Error} If vault is locked or decryption fails
     */
    async load() {
        this._requireUnlocked();

        const response = await this._fetch(`${this.apiUrl}?action=load&user=${encodeURIComponent(this.username)}`);
        const result = await this._handleResponse(response);

        if (!result.data) {
            return null;
        }

        try {
            const decrypted = await this._decrypt(result.data);
            return JSON.parse(decrypted);
        } catch (e) {
            throw new Error('Decryption failed. Invalid password or corrupted data.');
        }
    }

    /**
     * Clear encryption key from memory and reload the page
     * This is the only secure way to "log out" - ensures key is removed from RAM
     */
    logout() {
        this.key = null;
        this.username = null;
        this.salt = null;
        location.reload();
    }

    /**
     * Check if the vault is unlocked (key is derived)
     * @returns {boolean}
     */
    isUnlocked() {
        return this.key !== null;
    }

    /**
     * Get the current username
     * @returns {string|null}
     */
    getUsername() {
        return this.username;
    }

    /**
     * Check API health status
     * @returns {Promise<object>} Health check response
     */
    async checkHealth() {
        const response = await this._fetch(`${this.apiUrl}?action=health`);
        return this._handleResponse(response);
    }

    // =========================================================================
    // PRIVATE METHODS - CRYPTOGRAPHY
    // =========================================================================

    /**
     * Derive an AES-256-GCM key from password using PBKDF2
     * @private
     */
    async _deriveKey(password, saltHex) {
        const encoder = new TextEncoder();

        // Import password as key material
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Convert hex salt to Uint8Array
        const salt = this._hexToBytes(saltHex);

        // Derive the AES-GCM key
        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.config.pbkdf2Iterations,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: this.config.keyLength },
            false,  // Key cannot be exported (security)
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt plaintext using AES-256-GCM
     * @private
     */
    async _encrypt(plaintext) {
        const iv = window.crypto.getRandomValues(new Uint8Array(this.config.ivLength));
        const encoded = new TextEncoder().encode(plaintext);

        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            this.key,
            encoded
        );

        // Pack IV and ciphertext into JSON format
        return JSON.stringify({
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(ciphertext))
        });
    }

    /**
     * Decrypt ciphertext using AES-256-GCM
     * @private
     */
    async _decrypt(jsonString) {
        const payload = JSON.parse(jsonString);
        const iv = new Uint8Array(payload.iv);
        const data = new Uint8Array(payload.data);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            this.key,
            data
        );

        return new TextDecoder().decode(decrypted);
    }

    // =========================================================================
    // PRIVATE METHODS - UTILITIES
    // =========================================================================

    /**
     * Ensure vault is unlocked before operations
     * @private
     */
    _requireUnlocked() {
        if (!this.key) {
            throw new Error('Vault is locked. Call init() first.');
        }
    }

    /**
     * Convert hex string to Uint8Array
     * @private
     */
    _hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    /**
     * Fetch wrapper with timeout support
     * @private
     */
    async _fetch(url, options = {}) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000); // 30 second timeout

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            return response;
        } finally {
            clearTimeout(timeout);
        }
    }

    /**
     * Handle API response and extract data or throw error
     * @private
     */
    async _handleResponse(response) {
        const data = await response.json();

        if (data.error) {
            const error = new Error(data.error.message || 'API error');
            error.code = data.error.code;
            error.status = response.status;
            throw error;
        }

        return data;
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BlindBase;
}
if (typeof window !== 'undefined') {
    window.BlindBase = BlindBase;
}

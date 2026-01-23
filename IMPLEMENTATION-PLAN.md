# BlindBase Framework - Technical Implementation Plan

## Executive Summary

This document outlines the technical improvements needed for the BlindBase (Zero-Vault) framework based on the updated PRD. The current implementation is functional but requires security hardening, better error handling, and production-ready features.

---

## Current State Analysis

### What Exists
- `api.php`: Basic endpoints for get_salt, save, load
- `index.html`: POC with ZeroVault class demonstrating encryption/decryption
- File-based storage in `/storage/` directory

### Gaps Identified

| Gap | Severity | Current State | Required State |
|-----|----------|---------------|----------------|
| Hardcoded secret key | **Critical** | Key in source code | Environment variable |
| No CORS configuration | High | Any origin allowed | Whitelist origins |
| No rate limiting | High | Unlimited requests | Rate limits per endpoint |
| Weak input validation | High | Basic regex only | Comprehensive validation |
| No structured errors | Medium | Inconsistent responses | Standardized error format |
| No CSP headers | Medium | Not set | Strict CSP |
| Missing health check | Low | None | `/health` endpoint |

---

## Implementation Tasks

### Task 1: Environment Variable Configuration

**File:** `api.php`

**Changes:**
```php
// BEFORE (line 8)
$SERVER_SECRET_KEY = hex2bin('32669e4f52636a0c56312d1c6762391629735d48255b0851452309727508605c');

// AFTER
$SERVER_SECRET_KEY = getenv('BLINDBASE_SECRET');
if (!$SERVER_SECRET_KEY) {
    http_response_code(500);
    die(json_encode(['error' => ['code' => 'CONFIG_ERROR', 'message' => 'Server not configured']]));
}
$SERVER_SECRET_KEY = hex2bin($SERVER_SECRET_KEY);

// Add configurable storage path
$STORAGE_DIR = getenv('BLINDBASE_STORAGE_PATH') ?: __DIR__ . '/storage/';
```

**Verification:**
- [ ] Server returns 500 if `BLINDBASE_SECRET` not set
- [ ] Server works correctly when env var is set

---

### Task 2: Input Validation Enhancement

**File:** `api.php`

**Add validation function:**
```php
function validateUsername($user) {
    if (!$user) {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username is required'];
    }
    if (strlen($user) < 3 || strlen($user) > 32) {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username must be 3-32 characters'];
    }
    if (!preg_match('/^[a-z0-9_]+$/', $user)) {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username can only contain lowercase letters, numbers, and underscores'];
    }
    return ['valid' => true];
}

function validatePayload($payload) {
    $maxSize = (int)(getenv('BLINDBASE_MAX_PAYLOAD_MB') ?: 10) * 1024 * 1024;
    if (strlen($payload) > $maxSize) {
        return ['valid' => false, 'code' => 'PAYLOAD_TOO_LARGE', 'message' => 'Payload exceeds maximum size'];
    }
    // Verify it's valid JSON (the encrypted format)
    $decoded = json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload must be valid JSON'];
    }
    if (!isset($decoded['iv']) || !isset($decoded['data'])) {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload missing required fields'];
    }
    return ['valid' => true];
}
```

**Apply to each endpoint:**
```php
// get_salt endpoint
$validation = validateUsername($_GET['user'] ?? '');
if (!$validation['valid']) {
    http_response_code(400);
    die(json_encode(['error' => ['code' => $validation['code'], 'message' => $validation['message']]]));
}
$user = $_GET['user'];
```

---

### Task 3: Standardized Error Response Format

**File:** `api.php`

**Add helper function:**
```php
function respondError($code, $message, $httpStatus = 400) {
    http_response_code($httpStatus);
    echo json_encode([
        'error' => [
            'code' => $code,
            'message' => $message
        ]
    ]);
    exit;
}

function respondSuccess($data) {
    echo json_encode($data);
    exit;
}
```

**Error codes to implement:**
| Code | HTTP Status | When |
|------|-------------|------|
| `CONFIG_ERROR` | 500 | Server misconfigured |
| `INVALID_USER` | 400 | Username validation failed |
| `USER_NOT_FOUND` | 404 | User doesn't exist (on load) |
| `INVALID_PAYLOAD` | 400 | Payload validation failed |
| `PAYLOAD_TOO_LARGE` | 413 | Exceeds size limit |
| `DECRYPT_FAILED` | 500 | Server-side decryption failed |
| `RATE_LIMITED` | 429 | Too many requests |
| `METHOD_NOT_ALLOWED` | 405 | Wrong HTTP method |

---

### Task 4: CORS Configuration

**File:** `api.php`

**Add at the top after `header('Content-Type: application/json')`:**
```php
// CORS Configuration
$allowedOrigins = getenv('BLINDBASE_ALLOWED_ORIGINS');
if ($allowedOrigins) {
    $origins = array_map('trim', explode(',', $allowedOrigins));
    $requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if (in_array($requestOrigin, $origins)) {
        header("Access-Control-Allow-Origin: $requestOrigin");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
        header("Access-Control-Allow-Headers: Content-Type");
        header("Access-Control-Max-Age: 86400");
    }
} else {
    // Development mode: allow all (should be disabled in production)
    header("Access-Control-Allow-Origin: *");
}

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}
```

---

### Task 5: Rate Limiting

**File:** `api.php` (or separate `rate-limiter.php`)

**Simple file-based rate limiter:**
```php
class RateLimiter {
    private $storageDir;

    public function __construct($storageDir) {
        $this->storageDir = rtrim($storageDir, '/') . '/rate_limits/';
        if (!file_exists($this->storageDir)) {
            mkdir($this->storageDir, 0700, true);
        }
    }

    public function check($identifier, $limit, $windowSeconds) {
        $file = $this->storageDir . md5($identifier) . '.json';
        $now = time();

        $data = file_exists($file) ? json_decode(file_get_contents($file), true) : ['requests' => [], 'window_start' => $now];

        // Reset window if expired
        if ($now - $data['window_start'] > $windowSeconds) {
            $data = ['requests' => [], 'window_start' => $now];
        }

        // Count requests in current window
        $data['requests'] = array_filter($data['requests'], fn($t) => $now - $t < $windowSeconds);

        if (count($data['requests']) >= $limit) {
            return false;
        }

        $data['requests'][] = $now;
        file_put_contents($file, json_encode($data));
        return true;
    }
}

// Usage in endpoints
$rateLimiter = new RateLimiter($STORAGE_DIR);
$clientIP = $_SERVER['REMOTE_ADDR'];

// Different limits per endpoint
$limits = [
    'get_salt' => [10, 60],   // 10 requests per minute
    'save' => [30, 60],        // 30 requests per minute
    'load' => [60, 60]         // 60 requests per minute
];

if (isset($limits[$action])) {
    [$limit, $window] = $limits[$action];
    if (!$rateLimiter->check("{$action}_{$clientIP}", $limit, $window)) {
        respondError('RATE_LIMITED', 'Too many requests. Please wait.', 429);
    }
}
```

---

### Task 6: Security Headers

**File:** `api.php`

**Add security headers at the top:**
```php
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
```

---

### Task 7: Health Check Endpoint

**File:** `api.php`

**Add new endpoint:**
```php
if ($action === 'health') {
    $checks = [
        'storage_writable' => is_writable($STORAGE_DIR),
        'secret_configured' => !empty(getenv('BLINDBASE_SECRET')),
        'sodium_available' => function_exists('sodium_crypto_secretbox')
    ];

    $healthy = !in_array(false, $checks, true);

    http_response_code($healthy ? 200 : 503);
    respondSuccess([
        'status' => $healthy ? 'healthy' : 'unhealthy',
        'checks' => $checks,
        'timestamp' => date('c')
    ]);
}
```

---

### Task 8: Client SDK Enhancement

**File:** `js/blindbase-client.js` (new file to extract from index.html)

```javascript
/**
 * BlindBase Client SDK
 * Zero-knowledge encryption client for the BlindBase framework
 */
class BlindBase {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
        this.key = null;
        this.username = null;
        this.salt = null;
    }

    /**
     * Initialize vault: fetch salt, derive key, optionally load data
     * @param {string} username
     * @param {string} password
     * @returns {Promise<object|null>} Decrypted data or null if empty
     */
    async init(username, password) {
        this.username = username;

        // Fetch salt
        const saltRes = await fetch(`${this.apiUrl}?action=get_salt&user=${encodeURIComponent(username)}`);
        const saltData = await saltRes.json();

        if (saltData.error) {
            throw new Error(saltData.error.message || 'Failed to get salt');
        }

        this.salt = saltData.salt;
        this.key = await this._deriveKey(password, this.salt);

        return this.load();
    }

    /**
     * Save data to vault
     * @param {object} data - Data to encrypt and save
     */
    async save(data) {
        if (!this.key) throw new Error('Vault is locked');

        const encrypted = await this._encrypt(JSON.stringify(data));

        const formData = new FormData();
        formData.append('user', this.username);
        formData.append('payload', encrypted);

        const res = await fetch(`${this.apiUrl}?action=save`, {
            method: 'POST',
            body: formData
        });

        const result = await res.json();
        if (result.error) {
            throw new Error(result.error.message || 'Save failed');
        }

        return result;
    }

    /**
     * Load and decrypt data from vault
     * @returns {Promise<object|null>}
     */
    async load() {
        if (!this.key) throw new Error('Vault is locked');

        const res = await fetch(`${this.apiUrl}?action=load&user=${encodeURIComponent(this.username)}`);
        const result = await res.json();

        if (result.error) {
            throw new Error(result.error.message || 'Load failed');
        }

        if (!result.data) return null;

        try {
            const decrypted = await this._decrypt(result.data);
            return JSON.parse(decrypted);
        } catch (e) {
            throw new Error('Decryption failed. Invalid password?');
        }
    }

    /**
     * Clear key from memory and reload page
     */
    logout() {
        this.key = null;
        this.username = null;
        this.salt = null;
        location.reload();
    }

    /**
     * Check if vault is unlocked
     */
    isUnlocked() {
        return this.key !== null;
    }

    // Private methods
    async _deriveKey(password, saltHex) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
        );

        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        return window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async _encrypt(text) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(text);

        const ciphertext = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.key,
            encoded
        );

        return JSON.stringify({
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(ciphertext))
        });
    }

    async _decrypt(jsonString) {
        const payload = JSON.parse(jsonString);
        const iv = new Uint8Array(payload.iv);
        const data = new Uint8Array(payload.data);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.key,
            data
        );

        return new TextDecoder().decode(decrypted);
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BlindBase;
}
```

---

## Implementation Order

1. **Task 1: Environment Variables** - Critical security fix
2. **Task 6: Security Headers** - Quick security win
3. **Task 3: Error Responses** - Foundation for other changes
4. **Task 2: Input Validation** - Security hardening
5. **Task 4: CORS Configuration** - Required for blind-board integration
6. **Task 5: Rate Limiting** - Abuse prevention
7. **Task 7: Health Check** - Operational readiness
8. **Task 8: Client SDK** - Clean interface for consumers

---

## Testing Checklist

### Security Tests
- [ ] Server rejects requests when `BLINDBASE_SECRET` not configured
- [ ] Invalid usernames are rejected with proper error
- [ ] Oversized payloads are rejected
- [ ] Rate limiting kicks in after threshold
- [ ] CORS only allows whitelisted origins (when configured)

### Functional Tests
- [ ] New user can register (get_salt creates user)
- [ ] Existing user can login (get_salt returns salt)
- [ ] Data can be saved and loaded
- [ ] Wrong password fails decryption gracefully
- [ ] Health endpoint reports correct status

### Client SDK Tests
- [ ] `init()` successfully derives key and loads data
- [ ] `save()` encrypts and persists data
- [ ] `load()` decrypts and returns data
- [ ] `logout()` clears key from memory
- [ ] Error handling works for network failures

---

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `api.php` | Modify | Add all security improvements |
| `js/blindbase-client.js` | Create | Extract and enhance client SDK |
| `.htaccess` | Create | Deny access to storage directory |
| `.env.example` | Create | Document required environment variables |
| `index.html` | Modify | Use new client SDK |

---

## Environment Setup (.env.example)

```bash
# BlindBase Server Configuration

# REQUIRED: 32-byte hex-encoded secret key
# Generate with: php -r "echo bin2hex(sodium_crypto_secretbox_keygen());"
BLINDBASE_SECRET=

# OPTIONAL: Storage directory path (default: ./storage/)
BLINDBASE_STORAGE_PATH=./storage/

# OPTIONAL: Maximum payload size in MB (default: 10)
BLINDBASE_MAX_PAYLOAD_MB=10

# OPTIONAL: Comma-separated list of allowed CORS origins
# Leave empty to allow all origins (development only!)
BLINDBASE_ALLOWED_ORIGINS=https://example.com,https://app.example.com
```

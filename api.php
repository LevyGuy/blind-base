<?php
/**
 * BlindBase API
 * Zero-knowledge encryption framework server endpoint
 *
 * Endpoints:
 *   GET  ?action=health              - Health check
 *   GET  ?action=get_salt&user=xxx   - Get/create user salt
 *   POST ?action=save                - Save encrypted data
 *   GET  ?action=load&user=xxx       - Load encrypted data
 */

// =========================================================================
// TASK 6: SECURITY HEADERS
// =========================================================================
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

// =========================================================================
// TASK 4: CORS CONFIGURATION
// =========================================================================
$allowedOrigins = getenv('BLINDBASE_ALLOWED_ORIGINS');
if ($allowedOrigins) {
    $origins = array_map('trim', explode(',', $allowedOrigins));
    $requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if (in_array($requestOrigin, $origins, true)) {
        header("Access-Control-Allow-Origin: $requestOrigin");
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Max-Age: 86400');
    }
} else {
    // Development mode: allow all origins (disable in production!)
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// =========================================================================
// TASK 3: STANDARDIZED ERROR RESPONSE HELPERS
// =========================================================================

/**
 * Send an error response and exit
 */
function respondError(string $code, string $message, int $httpStatus = 400): void {
    http_response_code($httpStatus);
    echo json_encode([
        'error' => [
            'code' => $code,
            'message' => $message
        ]
    ]);
    exit;
}

/**
 * Send a success response and exit
 */
function respondSuccess(array $data): void {
    echo json_encode($data);
    exit;
}

// =========================================================================
// TASK 2: INPUT VALIDATION FUNCTIONS
// =========================================================================

/**
 * Validate username format
 */
function validateUsername(?string $user): array {
    if (!$user || trim($user) === '') {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username is required'];
    }

    $user = trim($user);

    if (strlen($user) < 3 || strlen($user) > 32) {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username must be 3-32 characters'];
    }

    if (!preg_match('/^[a-z0-9_]+$/', $user)) {
        return ['valid' => false, 'code' => 'INVALID_USER', 'message' => 'Username can only contain lowercase letters, numbers, and underscores'];
    }

    return ['valid' => true, 'username' => $user];
}

/**
 * Validate encrypted payload format and size
 */
function validatePayload(?string $payload, int $maxSizeMB): array {
    if (!$payload || trim($payload) === '') {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload is required'];
    }

    $maxSize = $maxSizeMB * 1024 * 1024;
    if (strlen($payload) > $maxSize) {
        return ['valid' => false, 'code' => 'PAYLOAD_TOO_LARGE', 'message' => "Payload exceeds maximum size of {$maxSizeMB}MB"];
    }

    // Verify it's valid JSON with expected structure
    $decoded = json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload must be valid JSON'];
    }

    if (!isset($decoded['iv']) || !isset($decoded['data'])) {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload missing required fields (iv, data)'];
    }

    if (!is_array($decoded['iv']) || !is_array($decoded['data'])) {
        return ['valid' => false, 'code' => 'INVALID_PAYLOAD', 'message' => 'Payload iv and data must be arrays'];
    }

    return ['valid' => true];
}

// =========================================================================
// TASK 5: RATE LIMITING
// =========================================================================

class RateLimiter {
    private string $storageDir;

    public function __construct(string $storageDir) {
        $this->storageDir = rtrim($storageDir, '/') . '/rate_limits/';
        if (!file_exists($this->storageDir)) {
            @mkdir($this->storageDir, 0700, true);
        }
    }

    /**
     * Check if request is within rate limit
     * @return bool True if allowed, false if rate limited
     */
    public function check(string $identifier, int $limit, int $windowSeconds): bool {
        // Skip rate limiting if directory isn't writable
        if (!is_writable($this->storageDir)) {
            return true;
        }

        $file = $this->storageDir . md5($identifier) . '.json';
        $now = time();

        $data = ['requests' => [], 'window_start' => $now];
        if (file_exists($file)) {
            $content = @file_get_contents($file);
            if ($content) {
                $data = json_decode($content, true) ?: $data;
            }
        }

        // Reset window if expired
        if ($now - ($data['window_start'] ?? 0) > $windowSeconds) {
            $data = ['requests' => [], 'window_start' => $now];
        }

        // Filter requests within current window
        $data['requests'] = array_filter(
            $data['requests'] ?? [],
            fn($t) => $now - $t < $windowSeconds
        );

        // Check limit
        if (count($data['requests']) >= $limit) {
            return false;
        }

        // Record this request
        $data['requests'][] = $now;
        @file_put_contents($file, json_encode($data), LOCK_EX);

        return true;
    }

    /**
     * Clean up old rate limit files (call periodically)
     */
    public function cleanup(int $maxAgeSeconds = 3600): void {
        $files = glob($this->storageDir . '*.json');
        $now = time();

        foreach ($files as $file) {
            if ($now - filemtime($file) > $maxAgeSeconds) {
                @unlink($file);
            }
        }
    }
}

// =========================================================================
// TASK 1: CONFIGURATION (Environment Variables)
// =========================================================================

// Load .env file if it exists (simple implementation)
$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue; // Skip comments
        if (strpos($line, '=') === false) continue;
        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        if (!getenv($name)) {
            putenv("$name=$value");
        }
    }
}

// Get configuration from environment
$serverSecretHex = getenv('BLINDBASE_SECRET');
if (!$serverSecretHex) {
    respondError('CONFIG_ERROR', 'Server not configured: BLINDBASE_SECRET environment variable is required', 500);
}

// Validate secret key format (must be 64 hex chars = 32 bytes)
if (!preg_match('/^[a-fA-F0-9]{64}$/', $serverSecretHex)) {
    respondError('CONFIG_ERROR', 'Server configuration error: Invalid secret key format', 500);
}

$SERVER_SECRET_KEY = hex2bin($serverSecretHex);
$STORAGE_DIR = getenv('BLINDBASE_STORAGE_PATH') ?: __DIR__ . '/storage/';
$MAX_PAYLOAD_MB = (int)(getenv('BLINDBASE_MAX_PAYLOAD_MB') ?: 10);

// Ensure storage directory exists
if (!file_exists($STORAGE_DIR)) {
    if (!@mkdir($STORAGE_DIR, 0700, true)) {
        respondError('CONFIG_ERROR', 'Unable to create storage directory', 500);
    }
}

// Initialize rate limiter
$rateLimiter = new RateLimiter($STORAGE_DIR);
$clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Rate limits per endpoint: [requests, window_seconds]
$rateLimits = [
    'get_salt' => [10, 60],   // 10 requests per minute (prevents user enumeration)
    'save'     => [30, 60],   // 30 requests per minute
    'load'     => [60, 60],   // 60 requests per minute
    'health'   => [30, 60],   // 30 requests per minute
];

// Get action
$action = $_GET['action'] ?? '';

// Apply rate limiting
if (isset($rateLimits[$action])) {
    [$limit, $window] = $rateLimits[$action];
    if (!$rateLimiter->check("{$action}_{$clientIP}", $limit, $window)) {
        respondError('RATE_LIMITED', 'Too many requests. Please wait and try again.', 429);
    }
}

// =========================================================================
// TASK 7: HEALTH CHECK ENDPOINT
// =========================================================================
if ($action === 'health') {
    $checks = [
        'storage_writable' => is_writable($STORAGE_DIR),
        'secret_configured' => !empty($serverSecretHex),
        'sodium_available' => function_exists('sodium_crypto_secretbox'),
    ];

    $healthy = !in_array(false, $checks, true);

    http_response_code($healthy ? 200 : 503);
    respondSuccess([
        'status' => $healthy ? 'healthy' : 'unhealthy',
        'checks' => $checks,
        'timestamp' => date('c'),
        'version' => '1.0.0'
    ]);
}

// =========================================================================
// ENDPOINT 1: GET SALT (Registration / Login Lookup)
// =========================================================================
if ($action === 'get_salt') {
    // Validate username
    $validation = validateUsername($_GET['user'] ?? null);
    if (!$validation['valid']) {
        respondError($validation['code'], $validation['message']);
    }
    $user = $validation['username'];

    $file = $STORAGE_DIR . $user . '.json';

    if (file_exists($file)) {
        // User exists, return their specific salt
        $data = json_decode(file_get_contents($file), true);
        if (!$data || !isset($data['salt'])) {
            respondError('DATA_CORRUPTED', 'User data is corrupted', 500);
        }
        respondSuccess(['salt' => $data['salt']]);
    } else {
        // New user: Generate a new random salt and save it
        $salt = bin2hex(random_bytes(16)); // 16 bytes = 32 hex chars
        $initialData = [
            'salt' => $salt,
            'encrypted_blob' => null,
            'created_at' => date('c'),
            'updated_at' => null
        ];

        if (!@file_put_contents($file, json_encode($initialData), LOCK_EX)) {
            respondError('STORAGE_ERROR', 'Unable to create user record', 500);
        }

        respondSuccess(['salt' => $salt, 'new_user' => true]);
    }
}

// =========================================================================
// ENDPOINT 2: SAVE (Server Encryption - Layer 2)
// =========================================================================
if ($action === 'save') {
    // Verify HTTP method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        respondError('METHOD_NOT_ALLOWED', 'POST method required', 405);
    }

    // Validate username
    $validation = validateUsername($_POST['user'] ?? null);
    if (!$validation['valid']) {
        respondError($validation['code'], $validation['message']);
    }
    $user = $validation['username'];

    // Validate payload
    $payloadValidation = validatePayload($_POST['payload'] ?? null, $MAX_PAYLOAD_MB);
    if (!$payloadValidation['valid']) {
        respondError($payloadValidation['code'], $payloadValidation['message'],
            $payloadValidation['code'] === 'PAYLOAD_TOO_LARGE' ? 413 : 400);
    }
    $clientPayload = $_POST['payload'];

    $file = $STORAGE_DIR . $user . '.json';
    if (!file_exists($file)) {
        respondError('USER_NOT_FOUND', 'User does not exist. Call get_salt first.', 404);
    }

    // Layer 2 Encryption (Server Side)
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $layer2_ciphertext = sodium_crypto_secretbox($clientPayload, $nonce, $SERVER_SECRET_KEY);

    // Encode for storage (Nonce + Ciphertext)
    $storedBlob = base64_encode($nonce . $layer2_ciphertext);

    // Update storage
    $data = json_decode(file_get_contents($file), true);
    if (!$data) {
        respondError('DATA_CORRUPTED', 'User data is corrupted', 500);
    }

    $data['encrypted_blob'] = $storedBlob;
    $data['updated_at'] = date('c');

    if (!@file_put_contents($file, json_encode($data), LOCK_EX)) {
        respondError('STORAGE_ERROR', 'Unable to save data', 500);
    }

    respondSuccess(['status' => 'saved', 'updated_at' => $data['updated_at']]);
}

// =========================================================================
// ENDPOINT 3: LOAD (Server Decryption - Layer 2)
// =========================================================================
if ($action === 'load') {
    // Validate username
    $validation = validateUsername($_GET['user'] ?? null);
    if (!$validation['valid']) {
        respondError($validation['code'], $validation['message']);
    }
    $user = $validation['username'];

    $file = $STORAGE_DIR . $user . '.json';

    if (!file_exists($file)) {
        // User doesn't exist - return null data (not an error for new users)
        respondSuccess(['data' => null]);
    }

    $data = json_decode(file_get_contents($file), true);
    if (!$data) {
        respondError('DATA_CORRUPTED', 'User data is corrupted', 500);
    }

    if (empty($data['encrypted_blob'])) {
        // User exists but has no data yet
        respondSuccess(['data' => null]);
    }

    // Decode stored blob
    $decoded = base64_decode($data['encrypted_blob']);
    if ($decoded === false || strlen($decoded) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        respondError('DATA_CORRUPTED', 'Stored data is corrupted', 500);
    }

    $nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    // Layer 2 Decrypt
    $layer1_ciphertext = sodium_crypto_secretbox_open($ciphertext, $nonce, $SERVER_SECRET_KEY);

    if ($layer1_ciphertext === false) {
        respondError('DECRYPT_FAILED', 'Server-side decryption failed. This may indicate key rotation or data corruption.', 500);
    }

    // Return the Layer 1 ciphertext (still encrypted by client password)
    respondSuccess([
        'data' => $layer1_ciphertext,
        'updated_at' => $data['updated_at'] ?? null
    ]);
}

// =========================================================================
// UNKNOWN ACTION
// =========================================================================
respondError('INVALID_ACTION', 'Unknown action. Valid actions: health, get_salt, save, load', 400);

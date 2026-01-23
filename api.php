<?php
// api.php
header('Content-Type: application/json');

// CONFIGURATION
// Ideally, this key should be in an Environment Variable, not code.
// Run this once to generate a key: echo bin2hex(sodium_crypto_secretbox_keygen());
$SERVER_SECRET_KEY = hex2bin('32669e4f52636a0c56312d1c6762391629735d48255b0851452309727508605c'); 
$STORAGE_DIR = __DIR__ . '/storage/';

if (!file_exists($STORAGE_DIR)) {
    mkdir($STORAGE_DIR, 0777, true);
}

$action = $_GET['action'] ?? '';

// -------------------------------------------------------
// ENDPOINT 1: GET SALT (Registration / Login Lookup)
// -------------------------------------------------------
if ($action === 'get_salt') {
    $user = preg_replace('/[^a-z0-9_]/', '', $_GET['user']); // Sanitize
    $file = $STORAGE_DIR . $user . '.json';
    
    if (file_exists($file)) {
        // User exists, return their specific salt
        $data = json_decode(file_get_contents($file), true);
        echo json_encode(['salt' => $data['salt']]);
    } else {
        // New user: Generate a new random salt and save it
        // Salt for PBKDF2 should be at least 16 bytes
        $salt = bin2hex(random_bytes(16));
        $initialData = [
            'salt' => $salt,
            'encrypted_blob' => null
        ];
        file_put_contents($file, json_encode($initialData));
        echo json_encode(['salt' => $salt]);
    }
    exit;
}

// -------------------------------------------------------
// ENDPOINT 2: SAVE (Server Encryption - Layer 2)
// -------------------------------------------------------
if ($action === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = preg_replace('/[^a-z0-9_]/', '', $_POST['user']);
    $clientPayload = $_POST['payload']; // This is ALREADY encrypted by JS
    
    $file = $STORAGE_DIR . $user . '.json';
    if (!file_exists($file)) die(json_encode(['error' => 'User not found']));

    // 1. Layer 2 Encryption (Server Side)
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $layer2_ciphertext = sodium_crypto_secretbox($clientPayload, $nonce, $SERVER_SECRET_KEY);

    // 2. Encode for storage (Nonce + Ciphertext)
    $storedBlob = base64_encode($nonce . $layer2_ciphertext);

    // 3. Update DB
    $data = json_decode(file_get_contents($file), true);
    $data['encrypted_blob'] = $storedBlob;
    file_put_contents($file, json_encode($data));

    echo json_encode(['status' => 'saved']);
    exit;
}

// -------------------------------------------------------
// ENDPOINT 3: LOAD (Server Decryption - Layer 2)
// -------------------------------------------------------
if ($action === 'load') {
    $user = preg_replace('/[^a-z0-9_]/', '', $_GET['user']);
    $file = $STORAGE_DIR . $user . '.json';

    if (!file_exists($file)) {
        echo json_encode(['data' => null]);
        exit;
    }

    $data = json_decode(file_get_contents($file), true);
    
    if (!$data['encrypted_blob']) {
        echo json_encode(['data' => null]);
        exit;
    }

    // 1. Decode
    $decoded = base64_decode($data['encrypted_blob']);
    $nonce = substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    // 2. Layer 2 Decrypt
    $layer1_ciphertext = sodium_crypto_secretbox_open($ciphertext, $nonce, $SERVER_SECRET_KEY);

    if ($layer1_ciphertext === false) {
        echo json_encode(['error' => 'Server key mismatch or corruption']);
        exit;
    }

    // Return the Layer 1 ciphertext (still encrypted by client password)
    echo json_encode(['data' => $layer1_ciphertext]);
    exit;
}
?>

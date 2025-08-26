<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Разрешаем preflight запросы
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Проверяем метод запроса
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit();
}

// Получаем данные из запроса
$input = json_decode(file_get_contents('php://input'), true);
$code = $input['code'] ?? '';
$redirect_uri = $input['redirect_uri'] ?? '';
$code_verifier = $input['code_verifier'] ?? '';

// Конфигурация внешнего OAuth провайдера
$config = [
    'token_url' => 'https://external-oauth-provider.com/oauth/token',
    'client_id' => 'YOUR_CLIENT_ID',
    'client_secret' => 'YOUR_CLIENT_SECRET',
    'allowed_redirect_uris' => [
        'http://localhost:3000/callback',
        'https://yourusername.github.io/callback.html'
    ]
];

// Валидация входных данных
if (empty($code)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request', 'error_description' => 'Authorization code is required']);
    exit();
}

if (empty($redirect_uri) || !in_array($redirect_uri, $config['allowed_redirect_uris'])) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request', 'error_description' => 'Invalid redirect URI']);
    exit();
}

try {
    // Обмениваем код на токен у внешнего провайдера
    $token_data = exchangeCodeForToken($code, $redirect_uri, $code_verifier, $config);
    
    // Возвращаем токен клиенту
    echo json_encode([
        'success' => true,
        'access_token' => $token_data['access_token'],
        'token_type' => $token_data['token_type'] ?? 'bearer',
        'expires_in' => $token_data['expires_in'] ?? 3600,
        'refresh_token' => $token_data['refresh_token'] ?? null,
        'scope' => $token_data['scope'] ?? ''
    ]);
    
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'error' => 'token_exchange_failed',
        'error_description' => $e->getMessage()
    ]);
}

/**
 * Обмен authorization code на access token у внешнего OAuth провайдера
 */
function exchangeCodeForToken($code, $redirect_uri, $code_verifier, $config) {
    // Подготовка данных для запроса
    $post_data = [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $redirect_uri,
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret']
    ];
    
    // Добавляем code_verifier если предоставлен (для PKCE)
    if (!empty($code_verifier)) {
        $post_data['code_verifier'] = $code_verifier;
    }
    
    // Настройка cURL запроса
    $ch = curl_init();
    
    curl_setopt_array($ch, [
        CURLOPT_URL => $config['token_url'],
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($post_data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ],
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2
    ]);
    
    // Выполнение запроса
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    // Обработка ошибок cURL
    if ($error) {
        throw new Exception("cURL error: " . $error);
    }
    
    // Парсинг ответа
    $response_data = json_decode($response, true);
    
    if ($http_code !== 200) {
        $error_msg = $response_data['error'] ?? 'Unknown error';
        $error_desc = $response_data['error_description'] ?? 'Token exchange failed';
        throw new Exception("$error_msg: $error_desc");
    }
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response from OAuth provider");
    }
    
    if (!isset($response_data['access_token'])) {
        throw new Exception("No access token in response");
    }
    
    return $response_data;
}

/**
 * Валидация redirect_uri
 */
function isValidRedirectUri($redirect_uri, $allowed_uris) {
    foreach ($allowed_uris as $allowed_uri) {
        if (strpos($redirect_uri, $allowed_uri) === 0) {
            return true;
        }
    }
    return false;
}
?>
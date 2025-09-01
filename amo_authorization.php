<?php

use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

require_once 'vendor/autoload.php';

// Включаем сессии для хранения state
session_start();

// Получаем переменные из GitHub Secrets (работает в GitHub Actions)
// Локально используем переменные окружения
$clientId = getenv('ID') ?: ($_ENV['ID'] ?? null);
$clientSecret = getenv('SECRET_KEY') ?: ($_ENV['SECRET_KEY'] ?? null);
$appURL = "https://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";

// Отладочная информация (уберите в production)
echo "<!-- Debug: Client ID: " . ($clientId ? 'set' : 'not set') . " -->\n";
echo "<!-- Debug: Client Secret: " . ($clientSecret ? 'set' : 'not set') . " -->\n";

if (!$clientId || !$clientSecret) {
    exit("Пожалуйста, настройте переменные окружения ID и SECRET_KEY в настройках GitHub Secrets.");
}

$provider = new GenericProvider([
    'clientId'                => $clientId,
    'clientSecret'            => $clientSecret,
    'redirectUri'             => $appURL,
    'urlAuthorize'            => 'https://id.amo.tm/access',
    'urlAccessToken'          => 'https://id.amo.tm/oauth2/access_token',
    'urlResourceOwnerDetails' => null
]);

// Если нет кода авторизации, перенаправляем на страницу авторизации
if (!isset($_GET['code'])) {
    $authorizationUrl = $provider->getAuthorizationUrl();
    
    // Сохраняем state в сессии для проверки после redirect
    $_SESSION['oauth2state'] = $provider->getState();
    
    header('Location: ' . $authorizationUrl);
    exit;
}

// Проверяем state для защиты от CSRF атак
if (empty($_GET['state']) || (!isset($_SESSION['oauth2state']) || $_GET['state'] !== $_SESSION['oauth2state'])) {
    unset($_SESSION['oauth2state']);
    exit('Неверный state параметр');
}

try {
    // Получаем access token используя authorization code
    $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Делаем запрос к API amo-мессенджера для получения информации о пользователе
    $request = $provider->getAuthenticatedRequest(
        'GET',
        'https://id.amo.tm/oauth2/validate',
        $accessToken,
        [
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $accessToken->getToken()
            ]
        ]
    );
    
    $client = new \GuzzleHttp\Client();
    $response = $client->send($request);
    $responseJson = json_decode($response->getBody(), true);

    // Выводим информацию
    echo '<h2>Успешная авторизация в amo-мессенджер</h2>';
    echo '<strong>Access Token:</strong> ' . $accessToken->getToken() . "<br>";
    echo '<strong>Refresh Token:</strong> ' . $accessToken->getRefreshToken() . "<br>";
    echo '<strong>Срок действия:</strong> ' . date('Y-m-d H:i:s', $accessToken->getExpires()) . "<br>";
    echo '<strong>Истек:</strong> ' . ($accessToken->hasExpired() ? 'да' : 'нет') . "<br>";
    echo '<hr>';

    if ($responseJson) {
        echo '<strong>User UUID:</strong> ' . ($responseJson['user_uuid'] ?? 'N/A') . "<br>";
        echo '<strong>Company UUID:</strong> ' . ($responseJson['company_uuid'] ?? 'N/A') . "<br>";
        echo '<strong>Client UUID:</strong> ' . ($responseJson['client_uuid'] ?? 'N/A') . "<br>";
        echo '<strong>Account ID:</strong> ' . ($responseJson['account_id'] ?? 'N/A') . "<br>";
    }

    // Сохраняем токены в сессии для дальнейшего использования
    $_SESSION['amo_access_token'] = $accessToken->getToken();
    $_SESSION['amo_refresh_token'] = $accessToken->getRefreshToken();
    $_SESSION['amo_token_expires'] = $accessToken->getExpires();
    
    echo '<hr>';
    echo '<p>Токены сохранены в сессии. Окно закроется автоматически через 15 секунд.</p>';
    echo '<script>setTimeout(function(){window.close()}, 15 * 1000);</script>';

} catch (IdentityProviderException $e) {
    exit('Ошибка авторизации amo-мессенджер: ' . $e->getMessage());
} catch (Exception $e) {
    exit('Произошла ошибка: ' . $e->getMessage());
}

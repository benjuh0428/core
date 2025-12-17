<?php
/**
 * CORE Auth (IIS/PHP-CGI robust)
 * - Session cookie ends when browser closes
 * - session_regenerate_id on login
 * - UA binding
 * - idle timeout
 */

require_once 'C:\\inetpub\\core_config\\config.php';

function core_is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);
}

$secure = core_is_https();

// IMPORTANT: Lax works best for login flows on HTTP + IIS
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

define('CORE_IDLE_TIMEOUT', 60 * 60 * 12); // 12 hours

function core_is_logged_in(): bool {
    return !empty($_SESSION['core_uid']);
}

function core_user_uid(): ?string {
    return $_SESSION['core_uid'] ?? null;
}

function core_user_email(): ?string {
    return $_SESSION['core_email'] ?? null;
}

function core_user_role(): ?string {
    return $_SESSION['core_role'] ?? null;
}

function core_login_user(string $uid, string $email, string $role): void {
    session_regenerate_id(true);

    $_SESSION['core_uid']   = $uid;
    $_SESSION['core_email'] = $email;
    $_SESSION['core_role']  = $role;

    $_SESSION['core_ua']   = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    $_SESSION['core_last'] = time();
}

function core_logout_user(): void {
    $_SESSION = [];

    setcookie(session_name(), '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_destroy();
}

function core_require_login(): void {
    if (!core_is_logged_in()) {
        header("Location: /login.php");
        exit;
    }

    $ua = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    if (!hash_equals($_SESSION['core_ua'] ?? '', $ua)) {
        core_logout_user();
        header("Location: /login.php?expired=1");
        exit;
    }

    if (!($_SESSION['remember'] ?? false)) {
        $last = (int)($_SESSION['core_last'] ?? 0);
        if ($last > 0 && (time() - $last) > CORE_IDLE_TIMEOUT) {
            core_logout_user();
            header("Location: /login.php?expired=1");
            exit;
        }
    }

    $_SESSION['core_last'] = time();
}

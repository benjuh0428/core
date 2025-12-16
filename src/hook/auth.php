<?php
/**
 * CORE minimal session auth (IIS-friendly, no CSRF)
 * - Session cookie ends when browser closes
 * - Regenerate session ID on login
 * - Bind session to User-Agent hash
 * - Optional idle timeout
 */

require_once 'C:\\inetpub\\core_config\\config.php';

/* ---------------------------------------
   Session cookie settings (works on HTTP)
---------------------------------------- */
$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');

session_set_cookie_params([
    'lifetime' => 0,          // browser session only (logout when browser closes)
    'path'     => '/',
    'domain'   => '',
    'secure'   => $secure,    // only secure if https
    'httponly' => true,
    'samesite' => 'Lax',      // safe and works for normal forms
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ---------------------------------------
   Config
---------------------------------------- */
define('CORE_IDLE_TIMEOUT', 60 * 60 * 12); // 12 hours (change if you want)

/* ---------------------------------------
   Helpers
---------------------------------------- */
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

/* ---------------------------------------
   Login
---------------------------------------- */
function core_login_user(string $uid, string $email, string $role): void {
    // Prevent session fixation
    session_regenerate_id(true);

    $_SESSION['core_uid']   = $uid;
    $_SESSION['core_email'] = $email;
    $_SESSION['core_role']  = $role;

    // Bind to UA (basic hijack protection)
    $_SESSION['core_ua'] = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');

    // Idle timeout tracking
    $_SESSION['core_last'] = time();
}

/* ---------------------------------------
   Logout
---------------------------------------- */
function core_logout_user(): void {
    // clear session
    $_SESSION = [];

    // clear session cookie
    setcookie(session_name(), '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_destroy();
}

/* ---------------------------------------
   Guard (protect pages)
---------------------------------------- */
function core_require_login(): void {
    if (!core_is_logged_in()) {
        header("Location: /login.php");
        exit;
    }

    // UA bind check
    $ua = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    if (!hash_equals($_SESSION['core_ua'] ?? '', $ua)) {
        core_logout_user();
        header("Location: /login.php?expired=1");
        exit;
    }

    // idle timeout check
    $last = (int)($_SESSION['core_last'] ?? 0);
    if ($last > 0 && (time() - $last) > CORE_IDLE_TIMEOUT) {
        core_logout_user();
        header("Location: /login.php?expired=1");
        exit;
    }

    // refresh activity timestamp
    $_SESSION['core_last'] = time();
}

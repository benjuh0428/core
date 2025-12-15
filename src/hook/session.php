<?php
/**
 * CORE Session & Authentication Handler
 */

require_once 'C:\\inetpub\\core_config\\config.php';

/* -------------------------------------------------
   Constants
-------------------------------------------------- */
define('CORE_SESSION_TIMEOUT_REMEMBER', 86400 * 30); // 30 days
define('CORE_REMEMBER_DAYS', 30);
define('CORE_REMEMBER_COOKIE', 'core_remember');

/* -------------------------------------------------
   HTTPS detection (proxy safe)
-------------------------------------------------- */
function core_is_https(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
    if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) return true;
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) &&
        strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') return true;
    return false;
}

/* -------------------------------------------------
   Session cookie defaults
   lifetime = 0 → browser session only
-------------------------------------------------- */
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => core_is_https(),
    'httponly' => true,
    'samesite' => 'Strict',
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* -------------------------------------------------
   Change session cookie lifetime
-------------------------------------------------- */
function core_set_session_cookie_lifetime(int $seconds): void {
    $params = session_get_cookie_params();

    setcookie(session_name(), session_id(), [
        'expires'  => $seconds > 0 ? time() + $seconds : 0,
        'path'     => $params['path'] ?? '/',
        'domain'   => $params['domain'] ?? '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

/* -------------------------------------------------
   CSRF
-------------------------------------------------- */
function core_csrf_token(): string {
    if (empty($_SESSION['core_csrf'])) {
        $_SESSION['core_csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['core_csrf'];
}

function core_csrf_verify(): void {
    if (
        empty($_POST['csrf']) ||
        empty($_SESSION['core_csrf']) ||
        !hash_equals($_SESSION['core_csrf'], (string)$_POST['csrf'])
    ) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }
}

/* -------------------------------------------------
   Auth getters
-------------------------------------------------- */
function core_is_logged_in(): bool {
    return !empty($_SESSION['core_user_uid']);
}

function core_user_uid(): ?string {
    return $_SESSION['core_user_uid'] ?? null;
}

function core_user_email(): ?string {
    return $_SESSION['core_user_email'] ?? null;
}

function core_user_role(): ?string {
    return $_SESSION['core_user_role'] ?? null;
}

function core_is_admin(): bool {
    return core_user_role() === 'ADMIN';
}

/* -------------------------------------------------
   Login event logging
-------------------------------------------------- */
function core_log_login_event(
    string $email,
    bool $success,
    string $reason = 'NONE',
    ?string $uid = null
): void {
    require 'C:\\inetpub\\core_config\\config.php';

    $stmt = $conn->prepare("
        INSERT INTO login_events
        (user_uid, email_attempted, success, fail_reason, ip_address, user_agent, session_id_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ");

    $stmt->bind_param(
        "ssissss",
        $uid,
        $email,
        $success ? 1 : 0,
        $reason,
        inet_pton($_SERVER['REMOTE_ADDR'] ?? ''),
        substr($_SERVER['HTTP_USER_AGENT'] ?? '', 255),
        hash('sha256', session_id())
    );

    $stmt->execute();
    $stmt->close();
}

/* -------------------------------------------------
   Login / Logout
-------------------------------------------------- */
function core_login(string $uid, string $email, string $role, bool $remember): void {
    session_regenerate_id(true);

    $_SESSION['core_user_uid']   = $uid;
    $_SESSION['core_user_email'] = $email;
    $_SESSION['core_user_role']  = $role;
    $_SESSION['core_remember']   = $remember ? 1 : 0;
    $_SESSION['core_ua_hash']    = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    $_SESSION['core_last_activity'] = time();

    // ✅ THIS IS THE KEY
    core_set_session_cookie_lifetime($remember ? CORE_SESSION_TIMEOUT_REMEMBER : 0);

    if ($remember) {
        core_create_remember_cookie($uid);
    }
}

function core_logout(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    if (!empty($_COOKIE[CORE_REMEMBER_COOKIE])) {
        [$selector] = explode(':', (string)$_COOKIE[CORE_REMEMBER_COOKIE], 2);
        if ($selector) {
            $stmt = $conn->prepare("DELETE FROM auth_tokens WHERE selector = ?");
            $stmt->bind_param("s", $selector);
            $stmt->execute();
            $stmt->close();
        }
    }

    setcookie(CORE_REMEMBER_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    setcookie(session_name(), '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    $_SESSION = [];
    session_destroy();
}

/* -------------------------------------------------
   Timeout handling
-------------------------------------------------- */
function core_handle_timeout(): void {
    // UA binding
    if (!hash_equals(
        $_SESSION['core_ua_hash'] ?? '',
        hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '')
    )) {
        core_logout();
        exit;
    }

    // ❌ NO TIMEOUT when remember is OFF
    if (empty($_SESSION['core_remember'])) {
        return;
    }

    // ✅ 30-day inactivity when remember ON
    if (!empty($_SESSION['core_last_activity'])) {
        if (time() - (int)$_SESSION['core_last_activity'] > CORE_SESSION_TIMEOUT_REMEMBER) {
            core_logout();
            header("Location: /login.php?expired=1");
            exit;
        }
    }

    $_SESSION['core_last_activity'] = time();
}

/* -------------------------------------------------
   Remember-me
-------------------------------------------------- */
function core_create_remember_cookie(string $uid): void {
    require 'C:\\inetpub\\core_config\\config.php';

    $selector  = bin2hex(random_bytes(12));
    $validator = bin2hex(random_bytes(32));
    $hash      = hash('sha256', $validator);

    $conn->query("DELETE FROM auth_tokens WHERE user_uid = '".$conn->real_escape_string($uid)."'");

    $stmt = $conn->prepare("
        INSERT INTO auth_tokens (user_uid, selector, validator_hash, expires_at)
        VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))
    ");
    $stmt->bind_param("sss", $uid, $selector, $hash);
    $stmt->execute();
    $stmt->close();

    setcookie(CORE_REMEMBER_COOKIE, "$selector:$validator", [
        'expires'  => time() + 86400 * 30,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

function core_try_remember_login(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    if (core_is_logged_in() || empty($_COOKIE[CORE_REMEMBER_COOKIE])) return;

    if (!str_contains($_COOKIE[CORE_REMEMBER_COOKIE], ':')) return;

    [$selector, $validator] = explode(':', $_COOKIE[CORE_REMEMBER_COOKIE], 2);

    $stmt = $conn->prepare("
        SELECT user_uid, validator_hash, expires_at
        FROM auth_tokens WHERE selector = ? LIMIT 1
    ");
    $stmt->bind_param("s", $selector);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row || strtotime($row['expires_at']) < time()) return;
    if (!hash_equals($row['validator_hash'], hash('sha256', $validator))) return;

    $stmt = $conn->prepare("
        SELECT uid, email, role, is_active
        FROM users WHERE uid = ? AND is_active = 1
    ");
    $stmt->bind_param("s", $row['user_uid']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) return;

    core_login($user['uid'], $user['email'], $user['role'], true);
    core_create_remember_cookie($user['uid']); // rotate
}

/* -------------------------------------------------
   Auto run
-------------------------------------------------- */
core_try_remember_login();
if (core_is_logged_in()) {
    core_handle_timeout();
}
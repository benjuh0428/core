<?php
/**
 * CORE Session & Authentication Handler
 * Path: core/src/hook/session.php
 */

require_once 'C:\\inetpub\\core_config\\config.php';

/* -------------------------------------------------
   Session cookie hardening
-------------------------------------------------- */
$cookieParams = session_get_cookie_params();

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => $cookieParams['path'] ?: '/',
    'domain'   => $cookieParams['domain'] ?: '',
    'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* -------------------------------------------------
   Constants
-------------------------------------------------- */
define('CORE_SESSION_TIMEOUT', 3600); // 1 hour inactivity
define('CORE_REMEMBER_DAYS', 30);
define('CORE_REMEMBER_COOKIE', 'core_remember');

/* -------------------------------------------------
   Basic getters
-------------------------------------------------- */
function core_is_logged_in(): bool {
    return !empty($_SESSION['core_user_uid']);
}

function core_user_uid(): ?string {
    return $_SESSION['core_user_uid'] ?? null; // raw 16 bytes
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
   Utility helpers
-------------------------------------------------- */
function core_ip_to_varbinary16(): ?string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($ip === '') return null;

    $packed = @inet_pton($ip);
    if ($packed === false) return null;

    // IPv4 → pad to 16 bytes
    if (strlen($packed) === 4) {
        return $packed . str_repeat("\0", 12);
    }

    return $packed; // IPv6
}

/* -------------------------------------------------
   Login event logging (audit trail)
-------------------------------------------------- */
function core_log_login_event(
    string $emailAttempted,
    bool $success,
    string $failReason = 'NONE',
    ?string $userUidBin = null
): void {
    require 'C:\\inetpub\\core_config\\config.php';

    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
    $ip = core_ip_to_varbinary16();
    $sidHash = hash('sha256', session_id());
    $successInt = $success ? 1 : 0;

    $stmt = $conn->prepare("
        INSERT INTO login_events
        (user_uid, email_attempted, success, fail_reason, ip_address, user_agent, session_id_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ");

    $stmt->bind_param(
        "ssissss",
        $userUidBin,
        $emailAttempted,
        $successInt,
        $failReason,
        $ip,
        $ua,
        $sidHash
    );

    $stmt->execute();
    $stmt->close();
}

/* -------------------------------------------------
   Core authentication
-------------------------------------------------- */
function core_login(string $userUidBin, string $email, string $role, bool $remember): void {
    session_regenerate_id(true);

    $_SESSION['core_user_uid']      = $userUidBin; // raw 16 bytes
    $_SESSION['core_user_email']    = $email;
    $_SESSION['core_user_role']     = $role;
    $_SESSION['core_last_activity'] = time();
    $_SESSION['core_remember']      = $remember ? 1 : 0;

    if ($remember) {
        core_create_remember_cookie($userUidBin);
    }
}

function core_logout(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    if (!empty($_COOKIE[CORE_REMEMBER_COOKIE])) {
        [$selector] = explode(':', $_COOKIE[CORE_REMEMBER_COOKIE], 2);

        $stmt = $conn->prepare("DELETE FROM auth_tokens WHERE selector = ?");
        $stmt->bind_param("s", $selector);
        $stmt->execute();
        $stmt->close();

        setcookie(CORE_REMEMBER_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }

    session_destroy();
}

/* -------------------------------------------------
   Guards
-------------------------------------------------- */
function core_require_login(): void {
    if (!core_is_logged_in()) {
        header("Location: /login.php");
        exit;
    }
}

function core_require_admin(): void {
    core_require_login();
    if (!core_is_admin()) {
        http_response_code(403);
        exit('403 Forbidden');
    }
}

/* -------------------------------------------------
   Inactivity timeout
-------------------------------------------------- */
function core_handle_timeout(): void {
    if (!empty($_SESSION['core_remember'])) {
        $_SESSION['core_last_activity'] = time();
        return;
    }

    if (!empty($_SESSION['core_last_activity'])) {
        if (time() - $_SESSION['core_last_activity'] > CORE_SESSION_TIMEOUT) {
            core_logout();
            header("Location: /login.php?expired=1");
            exit;
        }
    }

    $_SESSION['core_last_activity'] = time();
}

/* -------------------------------------------------
   Remember-me system
-------------------------------------------------- */
function core_create_remember_cookie(string $userUidBin): void {
    require 'C:\\inetpub\\core_config\\config.php';

    $selector  = bin2hex(random_bytes(12));
    $validator = bin2hex(random_bytes(32));
    $hash      = hash('sha256', $validator);

    $expires = (new DateTime('+'.CORE_REMEMBER_DAYS.' days'))->format('Y-m-d H:i:s');

    $conn->prepare("DELETE FROM auth_tokens WHERE user_uid = ?")
         ->bind_param("s", $userUidBin)
         ->execute();

    $stmt = $conn->prepare("
        INSERT INTO auth_tokens (user_uid, selector, validator_hash, expires_at)
        VALUES (?, ?, ?, ?)
    ");
    $stmt->bind_param("ssss", $userUidBin, $selector, $hash, $expires);
    $stmt->execute();
    $stmt->close();

    setcookie(CORE_REMEMBER_COOKIE, "$selector:$validator", [
        'expires'  => time() + CORE_REMEMBER_DAYS * 86400,
        'path'     => '/',
        'secure'   => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

function core_try_remember_login(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    if (core_is_logged_in() || empty($_COOKIE[CORE_REMEMBER_COOKIE])) return;

    [$selector, $validator] = explode(':', $_COOKIE[CORE_REMEMBER_COOKIE], 2);

    $stmt = $conn->prepare("
        SELECT user_uid, validator_hash, expires_at
        FROM auth_tokens
        WHERE selector = ?
        LIMIT 1
    ");
    $stmt->bind_param("s", $selector);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res->fetch_assoc();
    $stmt->close();

    if (!$row || strtotime($row['expires_at']) < time()) return;
    if (!hash_equals($row['validator_hash'], hash('sha256', $validator))) return;

    $stmt = $conn->prepare("
        SELECT uid, email, role, is_active
        FROM users
        WHERE uid = ?
        LIMIT 1
    ");
    $stmt->bind_param("s", $row['user_uid']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user || !$user['is_active']) return;

    core_login($user['uid'], $user['email'], $user['role'], true);
}

/* -------------------------------------------------
   Auto-run
-------------------------------------------------- */
core_try_remember_login();
if (core_is_logged_in()) {
    core_handle_timeout();
}
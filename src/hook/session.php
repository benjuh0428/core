<?php
/**
 * CORE Session & Authentication Handler (IIS safe)
 */

require_once 'C:\\inetpub\\core_config\\config.php';

/* -------------------------------------------------
   Constants
-------------------------------------------------- */
define('CORE_REMEMBER_DAYS', 30);
define('CORE_REMEMBER_COOKIE', 'core_remember');

/* -------------------------------------------------
   HTTPS detection (proxy safe)
-------------------------------------------------- */
function core_is_https(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
    if (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443) return true;

    $xfp = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    if (is_string($xfp) && strtolower($xfp) === 'https') return true;

    return false;
}

/* -------------------------------------------------
   Start session (COOKIE MUST WORK ON HTTP)
   - secure = ONLY when https
   - samesite = Lax for login forms
   - lifetime = 0 => ends when browser closes
-------------------------------------------------- */
$secureCookie = core_is_https();

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $secureCookie,
    'httponly' => true,
    'samesite' => 'Lax',
]);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
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
    $post = (string)($_POST['csrf'] ?? '');
    $sess = (string)($_SESSION['core_csrf'] ?? '');

    if ($post === '' || $sess === '' || !hash_equals($sess, $post)) {
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
    return (core_user_role() === 'ADMIN');
}

/* -------------------------------------------------
   Require login
-------------------------------------------------- */
function core_require_login(): void {
    if (!core_is_logged_in()) {
        header("Location: /login.php");
        exit;
    }
}

/* -------------------------------------------------
   IP helper -> VARBINARY(16)
-------------------------------------------------- */
function core_ip_to_varbinary16(): ?string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($ip === '') return null;

    $packed = inet_pton($ip);
    if ($packed === false) return null;

    return strlen($packed) === 4 ? ($packed . str_repeat("\0", 12)) : $packed;
}

/* -------------------------------------------------
   Login event logging (never break login)
-------------------------------------------------- */
function core_log_login_event(string $email, bool $success, string $reason = 'NONE', ?string $uid = null): void {
    try {
        require 'C:\\inetpub\\core_config\\config.php';

        $uidSafe = $uid ?? '';
        $stmt = $conn->prepare("
            INSERT INTO login_events
            (user_uid, email_attempted, success, fail_reason, ip_address, user_agent, session_id_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        if (!$stmt) return;

        $ipBin = core_ip_to_varbinary16() ?? str_repeat("\0", 16);
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
        $sidHash = hash('sha256', session_id());
        $successInt = $success ? 1 : 0;

        $stmt->bind_param("ssissss", $uidSafe, $email, $successInt, $reason, $ipBin, $ua, $sidHash);
        $stmt->execute();
        $stmt->close();
    } catch (Throwable $e) {
        // swallow
    }
}

/* -------------------------------------------------
   Login / Logout
-------------------------------------------------- */
function core_login(string $uid, string $email, string $role, bool $remember): void {
    // IMPORTANT: regenerate after login to prevent fixation
    session_regenerate_id(true);

    $_SESSION['core_user_uid']   = $uid;
    $_SESSION['core_user_email'] = $email;
    $_SESSION['core_user_role']  = $role;
    $_SESSION['core_ua_hash']    = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? '');
    $_SESSION['core_last_activity'] = time();

    if ($remember) {
        core_create_remember_cookie($uid);
    }
}

function core_logout(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    // revoke remember token
    if (!empty($_COOKIE[CORE_REMEMBER_COOKIE])) {
        $raw = (string)$_COOKIE[CORE_REMEMBER_COOKIE];
        $parts = explode(':', $raw, 2);
        $selector = $parts[0] ?? '';

        if ($selector !== '') {
            $stmt = $conn->prepare("DELETE FROM auth_tokens WHERE selector = ?");
            if ($stmt) {
                $stmt->bind_param("s", $selector);
                $stmt->execute();
                $stmt->close();
            }
        }
    }

    // clear remember cookie
    setcookie(CORE_REMEMBER_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    // clear session cookie
    setcookie(session_name(), '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    $_SESSION = [];
    session_destroy();
}

/* -------------------------------------------------
   Timeout handling (only for logged-in users)
   - If NOT remember: session ends when browser closes (cookie lifetime=0)
   - If remember: handled by remember-cookie + DB token expiry
-------------------------------------------------- */
function core_handle_timeout(): void {
    if (!hash_equals($_SESSION['core_ua_hash'] ?? '', hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? ''))) {
        core_logout();
        exit;
    }

    // optional inactivity timeout (example: 12h)
    $MAX_IDLE = 43200; // 12 hours
    if (!empty($_SESSION['core_last_activity']) && (time() - (int)$_SESSION['core_last_activity'] > $MAX_IDLE)) {
        core_logout();
        header("Location: /login.php?expired=1");
        exit;
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

    // delete old tokens
    $stmt = $conn->prepare("DELETE FROM auth_tokens WHERE user_uid = ?");
    if ($stmt) {
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $stmt->close();
    }

    // insert new token
    $stmt = $conn->prepare("
        INSERT INTO auth_tokens (user_uid, selector, validator_hash, expires_at)
        VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))
    ");
    if ($stmt) {
        $stmt->bind_param("sss", $uid, $selector, $hash);
        $stmt->execute();
        $stmt->close();
    }

    setcookie(CORE_REMEMBER_COOKIE, $selector . ':' . $validator, [
        'expires'  => time() + (86400 * 30),
        'path'     => '/',
        'domain'   => '',
        'secure'   => core_is_https(),
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

function core_try_remember_login(): void {
    require 'C:\\inetpub\\core_config\\config.php';

    if (core_is_logged_in()) return;
    if (empty($_COOKIE[CORE_REMEMBER_COOKIE])) return;

    $raw = (string)$_COOKIE[CORE_REMEMBER_COOKIE];
    if (strpos($raw, ':') === false) return;

    [$selector, $validator] = explode(':', $raw, 2);
    if ($selector === '' || $validator === '') return;

    $stmt = $conn->prepare("
        SELECT user_uid, validator_hash, expires_at
        FROM auth_tokens
        WHERE selector = ?
        LIMIT 1
    ");
    if (!$stmt) return;

    $stmt->bind_param("s", $selector);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$row) return;
    if (strtotime((string)$row['expires_at']) < time()) return;
    if (!hash_equals((string)$row['validator_hash'], hash('sha256', $validator))) return;

    $stmt = $conn->prepare("
        SELECT uid, email, role, is_active
        FROM users
        WHERE uid = ? AND is_active = 1
        LIMIT 1
    ");
    if (!$stmt) return;

    $stmt->bind_param("s", $row['user_uid']);
    $stmt->execute();
    $user = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$user) return;

    core_login((string)$user['uid'], (string)$user['email'], (string)$user['role'], true);

    // rotate token
    core_create_remember_cookie((string)$user['uid']);
}

/* -------------------------------------------------
   Auto run (SAFE)
-------------------------------------------------- */
$isLoginPost =
    ($_SERVER['REQUEST_METHOD'] === 'POST')
    && (basename($_SERVER['SCRIPT_NAME'] ?? '') === 'login.php');

if (!$isLoginPost) {
    core_try_remember_login();
    if (core_is_logged_in()) {
        core_handle_timeout();
    }
}

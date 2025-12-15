<?php
require_once __DIR__ . '/../hook/session.php';
require_once __DIR__ . '/../hook/core_error.php';
require_once 'C:\\inetpub\\core_config\\config.php';

if (basename($_SERVER['SCRIPT_NAME'] ?? '') !== 'login.php') {
    header("Location: /login.php");
    exit;
}

$errorPublic = '';
$expired = !empty($_GET['expired']);
$formAction = '/login.php';

/* helpers */
function core_table_exists(mysqli $conn, string $table): bool {
    try {
        $stmt = $conn->prepare("SHOW TABLES LIKE ?");
        if (!$stmt) return false;
        $stmt->bind_param("s", $table);
        $stmt->execute();
        $res = $stmt->get_result();
        $ok = $res && $res->num_rows > 0;
        $stmt->close();
        return $ok;
    } catch (Throwable $e) {
        return false;
    }
}
function core_column_exists(mysqli $conn, string $table, string $column): bool {
    try {
        $stmt = $conn->prepare("SHOW COLUMNS FROM `$table` LIKE ?");
        if (!$stmt) return false;
        $stmt->bind_param("s", $column);
        $stmt->execute();
        $res = $stmt->get_result();
        $ok = $res && $res->num_rows > 0;
        $stmt->close();
        return $ok;
    } catch (Throwable $e) {
        return false;
    }
}

/* POST login */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // ✅ CSRF CHECK (only once)
    core_csrf_verify();

    $email    = trim((string)($_POST['email'] ?? $_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $remember = !empty($_POST['remember']);

    if ($email === '' || $password === '') {
        $errorPublic = 'Please enter email and password.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorPublic = 'Please enter a valid email address.';
    } elseif (!isset($conn) || !($conn instanceof mysqli) || $conn->connect_errno) {
        core_log_error("DB connection unavailable on login", [
            "email" => $email,
            "ip" => $_SERVER['REMOTE_ADDR'] ?? '',
            "db_err" => $conn->connect_error ?? 'no-conn'
        ]);
        $errorPublic = 'Database is currently unavailable. Please try again later.';
    } else {
        try {
            $failCount = 0;

            if (core_table_exists($conn, 'login_events')) {
                $hasCreatedAt = core_column_exists($conn, 'login_events', 'created_at');

                if ($hasCreatedAt) {
                    $bf = $conn->prepare("
                        SELECT COUNT(*)
                        FROM login_events
                        WHERE email_attempted = ?
                          AND success = 0
                          AND created_at > NOW() - INTERVAL 15 MINUTE
                    ");
                } else {
                    $bf = $conn->prepare("
                        SELECT COUNT(*)
                        FROM login_events
                        WHERE email_attempted = ?
                          AND success = 0
                    ");
                }

                if ($bf) {
                    $bf->bind_param("s", $email);
                    $bf->execute();
                    $bf->bind_result($failCount);
                    $bf->fetch();
                    $bf->close();
                }
            }

            if ($failCount >= 5) {
                $errorPublic = 'Too many login attempts. Please wait 15 minutes.';
            } else {
                $stmt = $conn->prepare("
                    SELECT uid, email, password_hash, role, is_active
                    FROM users
                    WHERE email = ?
                    LIMIT 1
                ");

                if (!$stmt) {
                    core_log_error("Prepare failed for users lookup", [
                        "err" => $conn->error,
                        "email" => $email,
                    ]);
                    $errorPublic = 'Database is currently unavailable. Please try again later.';
                } else {
                    $stmt->bind_param("s", $email);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    $user = $res ? $res->fetch_assoc() : null;
                    $stmt->close();

                    if (!$user) {
                        core_log_login_event($email, false, 'NO_USER', null);
                        $errorPublic = 'Wrong email or password.';
                    } elseif ((int)$user['is_active'] !== 1) {
                        core_log_login_event($email, false, 'INACTIVE', (string)$user['uid']);
                        $errorPublic = 'This account is disabled.';
                    } elseif (!password_verify($password, (string)$user['password_hash'])) {
                        core_log_login_event($email, false, 'BAD_PASSWORD', (string)$user['uid']);
                        $errorPublic = 'Wrong email or password.';
                    } else {
                        core_log_login_event($email, true, 'NONE', (string)$user['uid']);

                        try {
                            $up = $conn->prepare("UPDATE users SET last_login_at = NOW() WHERE uid = ?");
                            if ($up) {
                                $up->bind_param("s", $user['uid']);
                                $up->execute();
                                $up->close();
                            }
                        } catch (Throwable $e) {}

                        core_login(
                            (string)$user['uid'],
                            (string)$user['email'],
                            (string)$user['role'],
                            $remember
                        );

                        header("Location: /serverlist.php");
                        exit;
                    }
                }
            }

        } catch (Throwable $e) {
            core_log_error("Login exception", [
                "err" => $e->getMessage(),
                "email" => $email,
                "mysql_err" => $conn->error ?? '',
            ]);
            $errorPublic = 'An unexpected error occurred. Please try again.';
        }
    }
}
?>

<div class="login-page">
    <div class="login-card">
        <div class="login-top">
            <img src="src/images/coreico.png" alt="CORE">
            <div>
                <h1>Login</h1>
                <div class="login-sub">Access your server console and tools.</div>
            </div>
        </div>

        <?php if ($expired): ?>
            <div class="login-alert">Session expired. Please log in again.</div>
        <?php endif; ?>

        <?php if ($errorPublic !== ''): ?>
            <div class="login-alert login-alert-error">
                <?= htmlspecialchars($errorPublic) ?>
            </div>
        <?php endif; ?>

        <form class="login-form" method="post" action="<?= $formAction ?>">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(core_csrf_token()) ?>">

            <div>
                <label for="email">Email</label>
                <input id="email" name="email" type="email" autocomplete="username" required>
            </div>

            <div>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
            </div>

            <div class="remember-row">
                <input id="remember" name="remember" type="checkbox">
                <label for="remember">Remember me (30 days)</label>
            </div>

            <div class="login-actions">
                <button class="btn btn-primary" type="submit">Login</button>
                <a class="back-link" href="/">← Back to Home</a>
            </div>
        </form>
    </div>
</div>

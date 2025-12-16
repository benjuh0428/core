<?php
require_once __DIR__ . '/src/hook/auth.php';
require_once 'C:\\inetpub\\core_config\\config.php';

if (core_is_logged_in()) {
    header("Location: /serverlist.php");
    exit;
}

$errorPublic = '';
$expired = !empty($_GET['expired']);

/**
 * IIS/PHP-CGI fallback:
 * Sometimes $_POST is empty even on POST.
 * This reads raw input and parses form-urlencoded bodies.
 */
function core_read_post_fallback(): array {
    // If PHP already parsed it, use it
    if (!empty($_POST) && is_array($_POST)) return $_POST;

    $raw = file_get_contents('php://input');
    if (!is_string($raw) || $raw === '') return [];

    $out = [];
    parse_str($raw, $out); // works for application/x-www-form-urlencoded
    return is_array($out) ? $out : [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $post = core_read_post_fallback();

    $email    = trim((string)($post['email'] ?? $post['username'] ?? ''));
    $password = (string)($post['password'] ?? '');

    // If still empty, it means the browser didn't submit the fields or inputs not inside form.
    if ($email === '' || $password === '') {
        $errorPublic = 'Please enter email and password.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorPublic = 'Please enter a valid email address.';
    } elseif (!isset($conn) || !($conn instanceof mysqli) || $conn->connect_errno) {
        $errorPublic = 'Database is currently unavailable. Please try again later.';
    } else {
        try {
            $stmt = $conn->prepare("
                SELECT uid, email, password_hash, role, is_active
                FROM users
                WHERE email = ?
                LIMIT 1
            ");

            if (!$stmt) {
                $errorPublic = 'Database is currently unavailable. Please try again later.';
            } else {
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $res = $stmt->get_result();
                $user = $res ? $res->fetch_assoc() : null;
                $stmt->close();

                if (
                    !$user ||
                    (int)$user['is_active'] !== 1 ||
                    !password_verify($password, (string)$user['password_hash'])
                ) {
                    // Don't leak which part failed
                    $errorPublic = 'Wrong email or password.';
                } else {
                    core_login_user((string)$user['uid'], (string)$user['email'], (string)$user['role']);
                    header("Location: /serverlist.php");
                    exit;
                }
            }
        } catch (Throwable $e) {
            $errorPublic = 'An unexpected error occurred. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CORE | Login</title>

    <link rel="icon" type="image/png" href="src/images/coreico.png">
    <link rel="stylesheet" href="src/css/main.css?v=5">
</head>
<body>
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

        <!-- IMPORTANT: action="" stays on /login.php -->
        <form class="login-form" method="post" action="" autocomplete="on">
            <div>
                <label for="email">Email</label>
                <input id="email" name="email" type="email" autocomplete="username" required>
            </div>

            <div>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
            </div>

            <div class="login-actions">
                <button class="btn btn-primary" type="submit">Login</button>
                <a class="back-link" href="/">← Back to Home</a>
            </div>
        </form>
    </div>
</div>
</body>
</html>
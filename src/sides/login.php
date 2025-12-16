<?php
require_once __DIR__ . '/../hook/auth.php';
require_once 'C:\\inetpub\\core_config\\config.php';

$errorPublic = '';
$expired = !empty($_GET['expired']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $email    = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

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

                // Generic error message: do NOT leak details
                if (!$user || (int)$user['is_active'] !== 1 || !password_verify($password, (string)$user['password_hash'])) {
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

        <!-- IMPORTANT: action="" posts back to THIS file -->
        <form class="login-form" method="post" action="">

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
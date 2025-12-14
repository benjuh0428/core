<?php
require_once __DIR__ . '/../hook/session.php';
require_once __DIR__ . '/../hook/core_error.php';
require_once 'C:\\inetpub\\core_config\\config.php';

/**
 * IMPORTANT:
 * If someone opens /src/sides/login.php directly, redirect to /login.php
 * so POST always targets the correct root page.
 */
if (basename($_SERVER['SCRIPT_NAME'] ?? '') !== 'login.php') {
    header("Location: /login.php");
    exit;
}

$errorPublic = '';
$expired = !empty($_GET['expired']);

// For IIS virtual directory setups, this always points to the current script path:
$formAction = htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/login.php', ENT_QUOTES, 'UTF-8');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Robust input read (accept email OR username just in case)
    $email = trim((string)($_POST['email'] ?? $_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    $remember = !empty($_POST['remember']);

    // If POST is empty, it’s 100% routing/form action issue
    if (empty($_POST)) {
        core_log_error("POST body empty on login submit", [
            "script" => $_SERVER['SCRIPT_NAME'] ?? '',
            "uri" => $_SERVER['REQUEST_URI'] ?? '',
        ]);
        $errorPublic = 'Login submit failed (no form data received). Check URL path / virtual directory.';
    } elseif ($email === '' || $password === '') {
        $errorPublic = 'Please enter email and password.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errorPublic = 'Please enter a valid email address.';
    } elseif ($conn === null) {
        core_log_error("DB connection unavailable on login", [
            "email" => $email,
            "ip" => $_SERVER['REMOTE_ADDR'] ?? '',
        ]);
        $errorPublic = 'Database is currently unavailable. Please try again later.';
    } else {
        try {
            $stmt = $conn->prepare("SELECT uid, email, password_hash, role, is_active FROM users WHERE email = ? LIMIT 1");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $res = $stmt->get_result();
            $user = $res ? $res->fetch_assoc() : null;
            $stmt->close();

            if (!$user) {
                core_log_login_event($email, false, 'NO_USER', null);
                $errorPublic = 'Wrong email or password.';
            } elseif ((int)$user['is_active'] !== 1) {
                core_log_login_event($email, false, 'INACTIVE', $user['uid']);
                $errorPublic = 'This account is disabled.';
            } elseif (!password_verify($password, $user['password_hash'])) {
                core_log_login_event($email, false, 'BAD_PASSWORD', $user['uid']);
                $errorPublic = 'Wrong email or password.';
            } else {
                core_log_login_event($email, true, 'NONE', $user['uid']);

                // Best-effort update
                try {
                    $up = $conn->prepare("UPDATE users SET last_login_at = NOW() WHERE uid = ?");
                    $up->bind_param("s", $user['uid']);
                    $up->execute();
                    $up->close();
                } catch (Throwable $e) {
                    core_log_error("Failed updating last_login_at", ["err" => $e->getMessage()]);
                }

                core_login($user['uid'], $user['email'], $user['role'], $remember);
                header("Location: /serverlist.php");
                exit;
            }
        } catch (Throwable $e) {
            core_log_error("Login exception", [
                "err" => $e->getMessage(),
                "email" => $email,
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
            <div class="login-alert login-alert-error"><?php echo htmlspecialchars($errorPublic); ?></div>
        <?php endif; ?>

        <!-- ✅ Posts to the CURRENT URL (works with virtual dirs) -->
        <form class="login-form" method="post" action="<?php echo $formAction; ?>">
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

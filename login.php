<?php
require_once 'C:\\inetpub\\core_config\\config.php';

require_once __DIR__ . '/src/hook/auth.php';

if (isset($_GET['logout'])) {
    core_logout_user();
    header("Location: http://192.168.1.252/login.php");
    exit;
}

if (core_is_logged_in()) {
    header("Location: serverlist.php");
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($email && $password) {
        if ($conn) {
            $stmt = $conn->prepare("SELECT uid, email, password_hash, role FROM users WHERE email = ?");
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($row = $result->fetch_assoc()) {
                if (password_verify($password, $row['password_hash'])) {
                    core_login_user($row['uid'], $row['email'], $row['role']);
                    if (isset($_POST['remember'])) {
                        $_SESSION['remember'] = true;
                        $secure = core_is_https();
                        setcookie(session_name(), session_id(), time() + 30 * 24 * 3600, '/', '', $secure, true);
                    }
                    header("Location: serverlist.php");
                    exit;
                } else {
                    $error = 'Invalid email or password.';
                }
            } else {
                $error = 'Invalid email or password.';
            }
            $stmt->close();
        } else {
            $error = 'Database connection failed.';
        }
    } else {
        $error = 'Please fill in all fields.';
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
    <link rel="stylesheet" href="src/css/login.css?v=5">
    <link rel="stylesheet" href="src/css/main.css?v=5">
</head>
<body>
    <div class="login-page">
        <div class="login-card">
            <div class="login-top">
                <img src="src/images/coreico.png" alt="CORE Icon">
                <h1>CORE</h1>
            </div>
            <div class="login-sub">Sign in to your account</div>
            <?php if ($error): ?>
                <div class="login-alert login-alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <form class="login-form" method="post">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
                <div class="remember-row">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember">Remember me</label>
                </div>
                <div class="login-actions">
                    <button type="submit" class="btn btn-primary">Sign In</button>
                </div>
            </form>
            <a href="/" class="back-link">Back to Home</a>
        </div>
    </div>
</body>
</html>

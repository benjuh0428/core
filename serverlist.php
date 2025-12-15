<?php
require_once __DIR__ . '/src/hook/session.php';

/**
 * Failsafe: Intelephense / wrong include path / old session.php
 * If core_require_login() is missing, define it here so the page never 500s.
 */
if (!function_exists('core_require_login')) {
    function core_require_login(): void {
        if (empty($_SESSION) || empty($_SESSION['core_user_uid'])) {
            header("Location: /login.php");
            exit;
        }
    }
}

core_require_login();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CORE | Server List</title>

    <link rel="icon" type="image/png" href="src/images/coreico.png">

    <link rel="stylesheet" href="src/css/main.css?v=5">
    <link rel="stylesheet" href="src/css/header.css?v=5">
    <link rel="stylesheet" href="src/css/footer.css?v=5">
</head>
<body>
<?php
$view = __DIR__ . '/src/sides/serverlist.php';
if (is_file($view)) {
    include $view;
} else {
    http_response_code(500);
    echo "<pre>Missing view: " . htmlspecialchars($view) . "</pre>";
}
?>
</body>
</html>

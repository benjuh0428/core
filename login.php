<?php
require_once __DIR__ . '/src/hook/auth.php';

// already logged in? go in
if (core_is_logged_in()) {
    header("Location: /serverlist.php");
    exit;
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
<?php include __DIR__ . '/src/sides/login.php'; ?>
</body>
</html>

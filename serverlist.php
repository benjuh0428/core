<?php
require_once __DIR__ . '/src/hook/session.php';

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
    <?php include __DIR__ . '/src/sides/serverlist.php'; ?>
</body>
</html>

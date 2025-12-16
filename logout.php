<?php
require_once __DIR__ . '/src/hook/auth.php';

core_logout_user();
header("Location: /login.php");
exit;
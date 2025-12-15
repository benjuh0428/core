<?php
require_once __DIR__ . '/src/hook/session.php';

core_logout();
header("Location: " . (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . '/login.php');
exit;
?>
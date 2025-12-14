<?php
require_once 'C:\\inetpub\\core_config\\config.php';

$email = 'benjuh0428@student.grillska.se';
$password = 'IJFPLVOA//28_b#'; // you provided this
$displayName = 'Benjamin';
$role = 'ADMIN';

$uidText = bin2hex(random_bytes(16)); // just for debug display
$uid = random_bytes(16);              // 16 bytes = UUID-like unique id

$hash = password_hash($password, PASSWORD_DEFAULT);

$stmt = $conn->prepare("
    INSERT INTO users (uid, email, password_hash, display_name, role, is_active, created_by_uid)
    VALUES (?, ?, ?, ?, ?, 1, NULL)
");

if (!$stmt) {
    die("Prepare failed: " . $conn->error);
}

$stmt->bind_param("sssss",
    $uid,          // binary
    $email,
    $hash,
    $displayName,
    $role
);

if ($stmt->execute()) {
    echo "✅ Admin created: " . $email . PHP_EOL;
} else {
    echo "❌ Insert failed: " . $stmt->error . PHP_EOL;
}

$stmt->close();

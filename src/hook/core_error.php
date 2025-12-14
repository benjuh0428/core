<?php
function core_log_error(string $message, array $context = []): void {
    $dir = 'C:\\inetpub\\core_logs';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }

    $file = $dir . '\\core.log';

    $line = "[" . date("Y-m-d H:i:s") . "] " . $message;
    if (!empty($context)) {
        $line .= " | " . json_encode($context, JSON_UNESCAPED_SLASHES);
    }
    $line .= PHP_EOL;

    @file_put_contents($file, $line, FILE_APPEND);
}

function core_safe_error_box(string $text): string {
    return '<div class="login-alert login-alert-error">' . htmlspecialchars($text) . '</div>';
}

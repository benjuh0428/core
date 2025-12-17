<?php
require_once __DIR__ . '/../hook/auth.php';
require_once __DIR__ . '/../hook/core_error.php';

core_require_login();

$server = $_GET['server'] ?? '';
if (!$server || !preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $server)) {
    header("Location: serverlist.php");
    exit;
}

$serverPath = 'C:\\servers\\' . $server;
if (!is_dir($serverPath)) {
    header("Location: serverlist.php");
    exit;
}

$guidePath = $serverPath . '\\guide\\server.java';
$propsFile = $serverPath . '\\server.properties';

function parseProperties($file) {
    $props = [];
    if (file_exists($file)) {
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            if (strpos($line, '=') !== false && substr($line, 0, 1) !== '#') {
                list($key, $value) = explode('=', $line, 2);
                $props[trim($key)] = trim($value);
            }
        }
    }
    return $props;
}

$props = parseProperties($propsFile);
$rconPort = (int)($props['rcon.port'] ?? 25575);
$rconPass = $props['rcon.password'] ?? '';
$serverIp = $props['server-ip'] ?? '127.0.0.1';

function rconAuth($host, $port, $pass) {
    $sock = @fsockopen($host, $port, $errno, $errstr, 5);
    if (!$sock) return false;
    $id = 1;
    $type = 3;
    $data = $pass . "\x00\x00";
    $packet = pack('VVV', strlen($data) + 10, $id, $type) . $data;
    fwrite($sock, $packet);
    $response = fread($sock, 4096);
    if (strlen($response) < 12) { fclose($sock); return false; }
    $resp = unpack('Vlen/Vid/Vtype', $response);
    if ($resp['id'] == $id && $resp['type'] == 2) {
        return $sock;
    }
    fclose($sock);
    return false;
}

function rconCommand($sock, $cmd) {
    $id = 2;
    $type = 2;
    $data = $cmd . "\x00\x00";
    $packet = pack('VVV', strlen($data) + 10, $id, $type) . $data;
    fwrite($sock, $packet);
    $response = fread($sock, 4096);
    if (strlen($response) < 12) return '';
    $resp = unpack('Vlen/Vid/Vtype', substr($response, 0, 12));
    $data = substr($response, 12, $resp['len'] - 10);
    return rtrim($data, "\x00");
}

$status = 'unknown';
$sock = null;
if ($rconPass) {
    $sock = rconAuth($serverIp, $rconPort, $rconPass);
    $status = $sock ? 'running' : 'stopped';
}

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'start' && !$sock) {
        $minMem = (int)($_POST['minMem'] ?? 1024);
        $maxMem = (int)($_POST['maxMem'] ?? 1024);
        $startCmd = '';
        if (file_exists($guidePath)) {
            $startCmd = trim(file_get_contents($guidePath));
        }
        if (!$startCmd) {
            // Default command
            $startCmd = '"C:\Program Files\Java\jdk-21\bin\java.exe" -Xmx' . $maxMem . 'M -Xms' . $minMem . 'M -jar server.jar nogui';
        }
        // Run in background
        $cmd = 'start /b cmd /c "cd /d ' . escapeshellarg($serverPath) . ' && ' . $startCmd . '"';
        exec($cmd);
        $message = 'Server start initiated.';
        sleep(2); // wait a bit
        $sock = rconAuth($serverIp, $rconPort, $rconPass);
        $status = $sock ? 'running' : 'stopped';
    } elseif ($action === 'stop' && $sock) {
        rconCommand($sock, 'stop');
        fclose($sock);
        $sock = null;
        $status = 'stopped';
        $message = 'Server stopped.';
    } elseif ($action === 'restart' && $sock) {
        rconCommand($sock, 'stop');
        fclose($sock);
        $sock = null;
        $status = 'stopped';
        $message = 'Server stopping...';
        sleep(10); // wait for stop
        // then start
        $startCmd = '';
        if (file_exists($guidePath)) {
            $startCmd = trim(file_get_contents($guidePath));
        }
        if (!$startCmd) {
            // Default command
            $startCmd = '"C:\Program Files\Java\jdk-21\bin\java.exe" -Xmx1024M -Xms1024M -jar server.jar nogui';
        }
        $cmd = 'start /b cmd /c "cd /d ' . escapeshellarg($serverPath) . ' && ' . $startCmd . '"';
        exec($cmd);
        $message = 'Server restart initiated.';
        sleep(2);
        $sock = rconAuth($serverIp, $rconPort, $rconPass);
        $status = $sock ? 'running' : 'stopped';
    } elseif ($action === 'command' && $sock) {
        $cmd = trim($_POST['cmd'] ?? '');
        if ($cmd) {
            $response = rconCommand($sock, $cmd);
            $message = 'Command sent: ' . htmlspecialchars($cmd) . '<br>Response: ' . htmlspecialchars($response);
        }
    }
}

if ($sock) fclose($sock);
?>

<div class="landing-page">
    <?php include __DIR__ . '/../components/header.php'; ?>

    <main class="page-wrap">
        <div class="topbar">
            <div>
                <h2 class="page-title">Console - <?php echo htmlspecialchars($server); ?></h2>
                <div class="page-sub">
                    Status: <?php echo htmlspecialchars($status); ?>
                </div>
            </div>
            <a class="nav-btn" href="serverlist.php">Back to List</a>
        </div>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">Server Controls</div>
            </div>

            <form method="post" style="display: inline;">
                <?php if ($status === 'stopped'): ?>
                    <label>Min Memory (MB):</label>
                    <input type="number" name="minMem" value="1024" min="512" max="32768">
                    <label>Max Memory (MB):</label>
                    <input type="number" name="maxMem" value="1024" min="512" max="32768">
                    <button type="submit" name="action" value="start">Start Server</button>
                <?php elseif ($status === 'running'): ?>
                    <button type="submit" name="action" value="stop">Stop Server</button>
                    <button type="submit" name="action" value="restart">Restart Server</button>
                <?php endif; ?>
            </form>

            <?php if ($message): ?>
                <div class="message"><?php echo $message; ?></div>
            <?php endif; ?>

            <?php if ($status === 'running'): ?>
                <form method="post" style="margin-top: 1rem;">
                    <label>Send Command:</label>
                    <input type="text" name="cmd" required>
                    <button type="submit" name="action" value="command">Send</button>
                </form>
            <?php endif; ?>
        </section>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">Console Log</div>
            </div>
            <pre><?php
                $logFile = $serverPath . '\\logs\\latest.log';
                if (file_exists($logFile)) {
                    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
                    $lastLines = array_slice($lines, -50);
                    echo htmlspecialchars(implode("\n", $lastLines));
                } else {
                    echo 'No log available.';
                }
            ?></pre>
        </section>
    </main>

    <?php include __DIR__ . '/../components/footer.php'; ?>
</div>

<style>
.page-wrap{max-width:1100px;margin:0 auto;padding:2.5rem 2rem;}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1.6rem;}
.page-title{margin:0;font-size:2rem;font-weight:900;}
.page-sub{color:#b0b0b0;font-weight:600;}

.panel{
    border-radius:16px;border:1px solid rgba(255,255,255,0.10);
    background:rgba(255,255,255,0.04);padding:1.3rem;
}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;}
.panel-title{font-size:1.1rem;font-weight:900;}

.message{margin-top:1rem;padding:0.9rem;border-radius:12px;
    border:1px solid rgba(255,255,255,0.12);
    background:rgba(255,255,255,0.06);
    font-weight:800;}

form{display:flex;gap:0.5rem;align-items:center;margin-top:0.5rem;flex-wrap:wrap;}
input[type="number"]{width:100px;padding:0.5rem;border-radius:8px;border:1px solid rgba(255,255,255,0.12);background:rgba(0,0,0,0.35);color:#fff;}
button{padding:0.5rem 1rem;border-radius:8px;border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);color:#fff;font-weight:800;}

pre{white-space:pre-wrap;font-family:monospace;font-size:0.9rem;max-height:400px;overflow-y:auto;background:rgba(0,0,0,0.5);padding:1rem;border-radius:8px;}
</style>

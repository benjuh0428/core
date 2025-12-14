<?php
require_once __DIR__ . '/../hook/session.php';
require_once __DIR__ . '/../hook/core_error.php';

core_require_login();

$SERVERS_ROOT = 'C:\\servers';

$servers = [];
$publicError = '';

try {
    if (!is_dir($SERVERS_ROOT)) {
        $publicError = 'Server storage is currently unavailable.';
        core_log_error('Servers root missing or not directory', ['path' => $SERVERS_ROOT]);
    } else {
        $items = @scandir($SERVERS_ROOT);

        if ($items === false) {
            $publicError = 'Unable to read server storage.';
            core_log_error('scandir failed for servers root', ['path' => $SERVERS_ROOT]);
        } else {
            foreach ($items as $name) {
                if ($name === '.' || $name === '..') continue;

                // Whitelist: prevents traversal & weird names
                if (!preg_match('/^[a-zA-Z0-9._-]{1,64}$/', $name)) continue;

                $full = $SERVERS_ROOT . DIRECTORY_SEPARATOR . $name;
                if (is_dir($full)) $servers[] = $name;
            }

            sort($servers, SORT_NATURAL | SORT_FLAG_CASE);
        }
    }
} catch (Throwable $e) {
    $publicError = 'Unexpected server error.';
    core_log_error('Serverlist exception', ['error' => $e->getMessage()]);
}
?>

<div class="landing-page">
    <?php include __DIR__ . '/../components/header.php'; ?>

    <main class="page-wrap">
        <div class="topbar">
            <div>
                <h2 class="page-title">Server List</h2>
                <div class="page-sub">
                    Logged in as: <?php echo htmlspecialchars(core_user_email() ?? ''); ?>
                </div>
            </div>

            <div class="role-pill">
                Role: <?php echo htmlspecialchars(core_user_role() ?? ''); ?>
            </div>
        </div>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">Available servers</div>
                <a class="nav-btn" href="/logout.php">Logout</a>
            </div>

            <?php if ($publicError !== ''): ?>
                <div class="error-box"><?php echo htmlspecialchars($publicError); ?></div>
            <?php else: ?>

                <?php if (empty($servers)): ?>
                    <div class="empty-text">No servers found.</div>
                <?php else: ?>
                    <div class="server-grid">
                        <?php foreach ($servers as $server): ?>
                            <a class="server-card" href="/console.php?server=<?php echo urlencode($server); ?>">
                                <div class="server-name"><?php echo htmlspecialchars($server); ?></div>
                                <div class="server-sub">Folder-based server</div>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

            <?php endif; ?>
        </section>
    </main>

    <?php include __DIR__ . '/../components/footer.php'; ?>
</div>

<style>
.page-wrap{max-width:1100px;margin:0 auto;padding:2.5rem 2rem;}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1.6rem;}
.page-title{margin:0;font-size:2rem;font-weight:900;}
.page-sub{color:#b0b0b0;font-weight:600;}

.role-pill{
    padding:0.55rem 0.9rem;border-radius:999px;
    border:1px solid rgba(255,255,255,0.12);
    background:rgba(255,255,255,0.04);
    font-weight:800;color:#d0d0d0;
}

.panel{
    border-radius:16px;border:1px solid rgba(255,255,255,0.10);
    background:rgba(255,255,255,0.04);padding:1.3rem;
}
.panel-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;}
.panel-title{font-size:1.1rem;font-weight:900;}

.server-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem;margin-top:1.2rem;}
.server-card{
    display:block;padding:1rem;border-radius:14px;
    border:1px solid rgba(255,255,255,0.10);
    background:rgba(0,0,0,0.25);
    text-decoration:none;color:inherit;
    transition:transform .15s ease,border-color .15s ease;
}
.server-card:hover{transform:translateY(-2px);border-color:rgba(255,255,255,0.25);}
.server-name{font-weight:900;margin-bottom:0.25rem;}
.server-sub{color:#b0b0b0;font-weight:600;font-size:0.95rem;}

.error-box{
    margin-top:1rem;padding:0.9rem;border-radius:12px;
    border:1px solid rgba(255,80,80,0.35);
    background:rgba(255,80,80,0.10);
    font-weight:800;
}
.empty-text{margin-top:1rem;color:#b0b0b0;font-weight:700;}

@media(max-width:980px){.server-grid{grid-template-columns:1fr;}}
</style>

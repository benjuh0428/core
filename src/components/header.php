<header class="header">
    <nav class="navbar">
        <a class="logo" href="/" aria-label="Go to home">
            <img src="src/images/coreico.png" alt="CORE Logo" class="logo-icon">
            <h1>CORE</h1>
        </a>

        <ul class="nav-links">
            <li><a href="#home">Home</a></li>
            <li><a href="#features">Features</a></li>
            <li><a href="#about">About</a></li>
        </ul>

        <div class="nav-actions">
            <?php
            require_once __DIR__ . '/../hook/auth.php';
            if (core_is_logged_in()) {
                echo '<a class="nav-btn" href="serverlist.php">Console</a>';
            } else {
                echo '<a class="nav-btn" href="login.php">Login</a>';
            }
            ?>
        </div>
    </nav>
</header>
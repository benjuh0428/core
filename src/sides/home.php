<div class="landing-page" id="home">
    <?php include 'src/components/header.php'; ?>

    <main class="hero-section">
        <div class="hero-content">
            <div class="hero-badge">Server Control • Console • File Manager (soon)</div>

            <img src="src/images/bigcore.png" alt="CORE" class="hero-image">

            <h2>One panel for your servers.</h2>

            <p>
                CORE is a clean, fast control platform for managing game servers.
                Today: Minecraft. Next: CS2 manager with console, files, and tools.
            </p>

            <div class="cta-buttons">
                <a class="btn btn-primary" href="login.php">Login to Console</a>
                <a class="btn btn-secondary" href="#features">See Features</a>
            </div>

            <div class="hero-mini">
                <div class="mini-card">
                    <div class="mini-title">Live Console</div>
                    <div class="mini-text">Run commands, view logs, manage uptime.</div>
                </div>
                <div class="mini-card">
                    <div class="mini-title">Server List</div>
                    <div class="mini-text">All servers in one place with status info.</div>
                </div>
                <div class="mini-card">
                    <div class="mini-title">File Manager</div>
                    <div class="mini-text">Coming soon: edit configs & upload files.</div>
                </div>
            </div>
        </div>
    </main>

    <section class="section" id="features">
        <div class="section-inner">
            <h3>Features</h3>
            <p class="section-sub">
                Built for speed, clarity, and real server workflows.
            </p>

            <div class="grid">
                <div class="card">
                    <h4>Modern UI</h4>
                    <p>Minimal, dark, clean layout — looks premium on any screen.</p>
                </div>
                <div class="card">
                    <h4>Secure Access</h4>
                    <p>Login-based access so your tools aren’t public.</p>
                </div>
                <div class="card">
                    <h4>Expandable</h4>
                    <p>Minecraft now, CS2 management next (console + files).</p>
                </div>
            </div>
        </div>
    </section>

    <section class="section" id="about">
        <div class="section-inner">
            <h3>About CORE</h3>
            <p class="section-sub">
                CORE is designed to be your “single source of control” for game servers.
                No messy panels — just the tools you actually need.
            </p>

            <div class="about-box">
                <div>
                    <h4>Roadmap</h4>
                    <ul class="bullets">
                        <li>Minecraft server console + management</li>
                        <li>CS2 server manager expansion</li>
                        <li>File browser + editor + uploads</li>
                        <li>Permissions + roles (admin / staff)</li>
                    </ul>
                </div>

                <div class="about-cta">
                    <h4>Ready?</h4>
                    <p>Login and start managing.</p>
                    <a class="btn btn-primary" href="login.php">Go to Login</a>
                </div>
            </div>
        </div>
    </section>

    <?php include 'src/components/footer.php'; ?>
</div>
<div class="login-page">
    <div class="login-card">
        <div class="login-top">
            <img src="src/images/coreico.png" alt="CORE">
            <div>
                <h1>Login</h1>
                <div class="login-sub">Access your server console and tools.</div>
            </div>
        </div>

        <form class="login-form" method="post" action="#">
            <div>
                <label for="username">Username</label>
                <input id="username" name="username" type="text" autocomplete="username" required>
            </div>

            <div>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
            </div>

            <div class="login-actions">
                <button class="btn btn-primary" type="submit">Login</button>
                <a class="back-link" href="index.php">← Back to Home</a>
            </div>
        </form>
    </div>
</div>
// GhostMail Webmail Login
async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    btn.disabled = true;
    btn.textContent = 'Signing in...';
    errorEl.classList.remove('show');

    try {
        const res = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (data.ok) {
            window.location.replace('/mail/');
        } else {
            errorEl.textContent = data.error || 'Login failed';
            errorEl.classList.add('show');
        }
    } catch (err) {
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.classList.add('show');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Sign In';
    }
    return false;
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('login-form').addEventListener('submit', handleLogin);
});

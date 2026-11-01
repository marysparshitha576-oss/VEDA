# Password Security & Authentication Analysis

A local educational Flask + SQLite application demonstrating:

- Registration and login
- Secure password hashing with Werkzeug (`scrypt`)
- Server-side password policy validation
- Browser-side password-strength feedback
- Failed-login tracking and a 10-minute lockout after 5 consecutive failures
- Authentication event logging in SQLite (`auth_logs`) and `auth.log`
- A dashboard showing the signed-in user's recent authentication events

## Requirements

- Python 3.10 or newer
- VS Code (recommended)
- A web browser

## Run on Windows PowerShell

1. Open this folder in VS Code.
2. Open Terminal → New Terminal.
3. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

4. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt instead and run:

   ```cmd
   .venv\Scripts\activate.bat
   ```

5. Install the dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

6. Start the app:

   ```powershell
   py app.py
   ```

7. Open `http://127.0.0.1:5000` in your browser.

## Test the features

1. Select **Create a demo account**.
2. Register a fictional username, for example `demo_user`.
3. Use a practice-only password that meets the displayed policy. Never use a real password.
4. Log in and view the dashboard.
5. Log out, then try a deliberately incorrect password several times. After five consecutive failures, the account is temporarily locked for ten minutes.
6. Log in successfully after the lock period expires. The failed-attempt counter resets after a successful login.
7. Inspect `auth.log` and the `auth_logs` table in `password_security.db` to see recorded events.

## Database

The SQLite database is created automatically the first time the app starts. It contains:

- `users`: username, password hash, failed-attempt counter, lockout expiry, and account creation time.
- `auth_logs`: username, event type, source IP, details, and timestamp.

Submitted passwords are never written to the log. Password hashes are generated with Werkzeug's `scrypt` method.

## Password policy used in this demo

- At least 8 characters
- At least one lowercase letter
- At least one uppercase letter
- At least one number
- At least one special character

This is a basic teaching policy, not a complete production password policy.

## Important security limitations

This project is intended for local learning with synthetic accounts only. It is not production-ready. Before any real deployment, use HTTPS, a strong secret key stored outside the source code, production-grade CSRF protection, rate limiting by account and source, secure cookie settings, monitoring, dependency updates, and a tested account recovery process. Account lockout can be abused to deny service to a user, so production systems should use a carefully designed throttling and recovery strategy. Do not expose the Flask development server to the public internet.

## Suggested GitHub commit

```powershell
git add .
git commit -m "Build password security and authentication analysis app"
git push
```

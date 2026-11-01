import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, flash, g, redirect, render_template, request,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "password_security.db"
LOG_PATH = BASE_DIR / "auth.log"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "local-demo-key-change-before-deployment"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Keep False for local http://127.0.0.1 development.
    # Set True when deployed behind HTTPS.
    SESSION_COOKIE_SECURE=False,
)

# This project is a local educational demo. Use a production WSGI server,
# HTTPS, a secret key from the environment, CSRF protection, and rate limiting
# before adapting it for real users.

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
security_logger = logging.getLogger("authentication")

LOCK_AFTER_FAILURES = 5
LOCK_MINUTES = 10


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            created_at TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )
    """)
    db.commit()
    db.close()


def utc_now():
    return datetime.now(timezone.utc)


def record_event(username, event_type, details=""):
    """Record an event without ever storing a submitted password."""
    timestamp = utc_now().isoformat(timespec="seconds")
    source_ip = request.remote_addr or "unknown"
    get_db().execute(
        "INSERT INTO auth_logs (username, event_type, source_ip, details, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, event_type, source_ip, details, timestamp),
    )
    get_db().commit()
    security_logger.info(
        "event=%s username=%s source_ip=%s details=%s",
        event_type, username, source_ip, details
    )


def password_policy_errors(password):
    errors = []
    if len(password) < 8:
        errors.append("Use at least 8 characters.")
    if not re.search(r"[a-z]", password):
        errors.append("Include at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Include at least one uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Include at least one number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Include at least one special character.")
    return errors


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not submitted or not expected or not secrets.compare_digest(submitted, expected):
            return "Invalid or missing form token. Refresh the page and try again.", 400


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to view that page.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3–30 characters and use only letters, numbers, or underscores.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        else:
            errors = password_policy_errors(password)
            if errors:
                for error in errors:
                    flash(error, "error")
            else:
                password_hash = generate_password_hash(password, method="scrypt")
                try:
                    db = get_db()
                    cursor = db.execute(
                        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, password_hash, utc_now().isoformat(timespec="seconds")),
                    )
                    db.commit()
                    record_event(username, "REGISTRATION_SUCCESS", "New local demo account created")
                    flash("Account created successfully. You can now log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("That username is already registered. Choose another one.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Use a generic failure message so the page does not disclose whether
        # a username exists. Failed attempts are logged for this local demo.
        if user is None:
            record_event(username or "(blank)", "LOGIN_FAILURE", "Invalid credentials")
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        now = utc_now()
        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if locked_until > now:
                remaining = max(1, int((locked_until - now).total_seconds() // 60) + 1)
                record_event(username, "LOGIN_BLOCKED", "Account temporarily locked")
                flash(f"This account is temporarily locked. Try again in about {remaining} minute(s).", "error")
                return render_template("login.html")
            # Lock period expired: clear the old lock and counter.
            get_db().execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],),
            )
            get_db().commit()
            user = get_db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

        if not check_password_hash(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= LOCK_AFTER_FAILURES:
                locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat(timespec="seconds")
                record_event(username, "ACCOUNT_LOCKOUT", f"Locked for {LOCK_MINUTES} minutes after repeated failures")
            get_db().execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            get_db().commit()
            record_event(username, "LOGIN_FAILURE", f"Failed attempt {attempts}")
            if locked_until:
                flash(f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes.", "error")
            else:
                remaining = LOCK_AFTER_FAILURES - attempts
                flash(f"Invalid username or password. {remaining} attempt(s) left before temporary lockout.", "error")
            return render_template("login.html")

        get_db().execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        get_db().commit()
        record_event(username, "LOGIN_SUCCESS", "Authentication successful")
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        csrf_token()
        flash("You are now logged in.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    logs = get_db().execute(
        "SELECT event_type, source_ip, details, created_at FROM auth_logs "
        "WHERE username = ? ORDER BY id DESC LIMIT 15",
        (session["username"],),
    ).fetchall()
    return render_template("dashboard.html", logs=logs)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username", "unknown")
    record_event(username, "LOGOUT", "User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.context_processor
def inject_current_user():
    return {"current_username": session.get("username")}


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)

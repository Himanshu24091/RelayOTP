import re
import bcrypt
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from utils.db import fetch_one, fetch_all, execute_query
from utils.code_gen import ensure_active_code
from utils.rate_limiter import rate_limiter, get_client_ip
from config import Config

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('dashboard.dashboard_view'))
        return render_template('register.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    admin_key = request.form.get('admin_key', '').strip()

    # Validation
    if not username or not password:
        flash("Username and password are required.", "danger")
        return render_template('register.html', username=username)

    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        flash("Username must be 3-30 characters (letters, numbers, underscores only).", "danger")
        return render_template('register.html', username=username)

    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "danger")
        return render_template('register.html', username=username)

    if password != confirm_password:
        flash("Passwords do not match.", "danger")
        return render_template('register.html', username=username)

    # Check if username already exists
    existing = fetch_one("SELECT id FROM users WHERE username = %s", (username,))
    if existing:
        flash("Username is already taken. Please choose another.", "danger")
        return render_template('register.html')

    # Hash password with bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Determine if user is admin: first registered user OR valid admin_key provided
    all_users = fetch_all("SELECT id FROM users")
    is_admin = False
    if len(all_users) == 0:
        is_admin = True
    elif admin_key and admin_key == Config.ADMIN_SECRET:
        is_admin = True

    try:
        execute_query(
            """
            INSERT INTO users (username, password_hash, is_admin)
            VALUES (%s, %s, %s)
            """,
            (username, password_hash, is_admin)
        )
        # Log user in directly upon creation and guide them to Settings page to connect Gmail
        new_user = fetch_one("SELECT id, username, is_admin FROM users WHERE username = %s", (username,))
        session.clear()
        session['user_id'] = new_user['id']
        session['username'] = new_user['username']
        session['is_admin'] = bool(new_user.get('is_admin', False))
        session['mailbox_unlocked'] = False
        ensure_active_code(new_user['id'])

        flash("Account created! Step 1: Connect your Gmail account to this portal.", "success")
        return redirect(url_for('settings.settings_view'))
    except Exception as e:
        flash(f"Registration failed: {str(e)}", "danger")
        return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'user_id' in session:
            curr = fetch_one("SELECT gmail_address, encrypted_app_password FROM users WHERE id = %s", (session['user_id'],))
            if curr and not (curr.get('gmail_address') and curr.get('encrypted_app_password')):
                return redirect(url_for('settings.settings_view'))
            return redirect(url_for('dashboard.dashboard_view'))
        return render_template('login.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    client_ip = get_client_ip(request)
    rate_key = f"{username.lower()}_{client_ip}"

    # 1. Check if user/IP is locked out
    is_locked, rem_sec = rate_limiter.is_locked('login', rate_key)
    if is_locked:
        flash(f"Account temporarily locked due to excessive failed attempts. Try again in {rem_sec}s.", "danger")
        return render_template('login.html'), 429

    if not username or not password:
        flash("Please enter both username and password.", "danger")
        return render_template('login.html')

    user = fetch_one("SELECT id, username, password_hash, is_admin, gmail_address, encrypted_app_password FROM users WHERE username = %s", (username,))
    
    # Verify bcrypt hash
    pw_match = False
    if user:
        try:
            pw_match = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
        except Exception:
            pw_match = False

    if not user or not pw_match:
        locked_now, rem_lockout = rate_limiter.record_failure('login', rate_key, max_attempts=5, window_seconds=300, lockout_seconds=300)
        if locked_now:
            flash(f"Excessive failed attempts. Security lockout active for {rem_lockout}s.", "danger")
            return render_template('login.html'), 429

        flash("Invalid username or password.", "danger")
        return render_template('login.html'), 401

    # Successful login: reset failed attempts
    rate_limiter.reset('login', rate_key)

    # Initialize tab-scoped session
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user.get('is_admin', False))
    # Mailbox remains locked upon fresh login
    session['mailbox_unlocked'] = False

    # Ensure 12-hour code is active or generated
    ensure_active_code(user['id'])

    # Check if user has already linked their Gmail account
    has_credentials = bool(user.get('gmail_address') and user.get('encrypted_app_password'))
    if not has_credentials:
        flash("Please connect your Gmail account in the Vault to activate verification code relay.", "info")
        return redirect(url_for('settings.settings_view'))

    return redirect(url_for('dashboard.dashboard_view'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out securely.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/auth/tab-logout', methods=['POST'])
def tab_logout():
    """
    Called by navigator.sendBeacon on pagehide to destroy the session instantly
    when the browser tab or window is closed.
    """
    session.clear()
    return jsonify({'status': 'logged_out', 'message': 'Session cleared on tab close'}), 200

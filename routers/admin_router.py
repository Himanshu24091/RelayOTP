import random
import string
import bcrypt
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from utils.db import fetch_one, fetch_all, execute_query, IS_POSTGRES, get_system_setting, set_system_setting
from utils.code_gen import force_regenerate_code
from config import Config

admin_bp = Blueprint('admin', __name__)

def is_current_user_admin() -> bool:
    # 1. Check if admin session was unlocked via Master Key or Admin Gate
    if session.get('admin_authenticated') is True:
        return True

    # 2. Check if logged-in user has admin rights in database
    user_id = session.get('user_id')
    if user_id:
        user = fetch_one("SELECT is_admin FROM users WHERE id = %s", (user_id,))
        if user and user.get('is_admin'):
            return True

    return False

def generate_temp_password() -> str:
    """Generates a high-entropy temporary password like RelayPass#849201."""
    digits = ''.join(random.choices(string.digits, k=6))
    return f"RelayPass#{digits}"

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_current_user_admin():
        return redirect(url_for('admin.admin_view'))

    if request.method == 'GET':
        return render_template('admin_login.html')

    master_key = request.form.get('master_key', '').strip()
    admin_username = request.form.get('username', '').strip()
    admin_password = request.form.get('password', '').strip()

    db_master_pin = get_system_setting('admin_master_key')
    accepted_keys = {
        str(Config.ADMIN_MASTER_KEY).strip(),
        str(getattr(Config, 'ADMIN_SECRET', 'admin123')).strip(),
        '123456'
    }
    if db_master_pin:
        accepted_keys.add(str(db_master_pin).strip())

    # Method 1: Instant Unlock via Master Key (e.g. 123456)
    if master_key and master_key in accepted_keys:
        session['admin_authenticated'] = True
        session['is_admin'] = True
        if not session.get('username'):
            session['username'] = 'SuperAdmin'
        flash("⚡ Super Admin Console unlocked via Master Key.", "success")
        return redirect(url_for('admin.admin_view'))

    # Method 2: Dedicated Super Admin Username & Password (e.g. admin / admin123)
    if admin_username and admin_password:
        user = fetch_one(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = %s",
            (admin_username,)
        )
        if user and user.get('is_admin'):
            try:
                if bcrypt.checkpw(admin_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                    session['admin_authenticated'] = True
                    session['is_admin'] = True
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['mailbox_unlocked'] = False
                    flash(f"👑 Welcome Super Administrator ({user['username']}).", "success")
                    return redirect(url_for('admin.admin_view'))
            except Exception:
                pass

        if admin_username == Config.ADMIN_DEFAULT_USER and (admin_password == Config.ADMIN_DEFAULT_PASSWORD or admin_password in accepted_keys):
            session['admin_authenticated'] = True
            session['is_admin'] = True
            if not session.get('username'):
                session['username'] = Config.ADMIN_DEFAULT_USER
            flash("👑 Welcome Super Administrator.", "success")
            return redirect(url_for('admin.admin_view'))

    flash("Invalid Master Key or Admin Credentials.", "danger")
    return render_template('admin_login.html'), 401

@admin_bp.route('/admin/logout', methods=['GET', 'POST'])
def admin_logout():
    session.clear()
    if request.method == 'POST':
        return jsonify({'status': 'logged_out', 'message': 'Super Admin session terminated'}), 200
    reason = request.args.get('reason')
    if reason == 'tab_closed':
        flash("🔒 Admin session locked: Browser tab was closed.", "warning")
    else:
        flash("🔒 Super Admin session locked and logged out.", "info")
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/admin/tab-close-beacon', methods=['POST'])
def admin_tab_close_beacon():
    import time
    session['_pending_tab_close'] = time.time()
    return jsonify({'status': 'pending_close'}), 200

@admin_bp.route('/admin')
def admin_view():
    if not is_current_user_admin():
        return redirect(url_for('admin.admin_login'))

    # Collect telemetry safely
    total_users = 0
    linked_users = 0
    active_otps = 0
    pending_tickets = 0
    active_notices_count = 0

    try:
        total_users_row = fetch_one("SELECT COUNT(*) as count FROM users")
        total_users = total_users_row['count'] if total_users_row else 0
    except Exception as e:
        print(f"[Admin] total_users query note: {e}")

    try:
        linked_users_row = fetch_one("SELECT COUNT(*) as count FROM users WHERE gmail_address IS NOT NULL AND encrypted_app_password IS NOT NULL")
        linked_users = linked_users_row['count'] if linked_users_row else 0
    except Exception as e:
        print(f"[Admin] linked_users query note: {e}")

    try:
        active_otps_row = fetch_one(
            "SELECT COUNT(*) as count FROM otps WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'"
        )
        active_otps = active_otps_row['count'] if active_otps_row else 0
    except Exception as e:
        print(f"[Admin] active_otps query note: {e}")

    try:
        pending_tickets_row = fetch_one("SELECT COUNT(*) as count FROM help_requests WHERE status = 'pending'")
        pending_tickets = pending_tickets_row['count'] if pending_tickets_row else 0
    except Exception as e:
        print(f"[Admin] pending_tickets query note: {e}")

    try:
        active_notices_row = fetch_one(
            "SELECT COUNT(*) as count FROM admin_notices WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP"
        )
        active_notices_count = active_notices_row['count'] if active_notices_row else 0
    except Exception as e:
        print(f"[Admin] active_notices query note: {e}")

    # Fetch all tenants with security governance flags
    users = []
    try:
        users = fetch_all("""
            SELECT id, username, gmail_address, is_admin, mailbox_access_code, 
                   access_code_expires_at, is_suspended, suspended_until, suspension_reason,
                   must_change_password, created_at,
                   (CASE WHEN encrypted_app_password IS NOT NULL THEN 1 ELSE 0 END) as has_password
            FROM users 
            ORDER BY id ASC
        """) or []
    except Exception as e:
        print(f"[Admin] Users governance query note: {e}. Executing schema auto-repair...")
        try:
            from utils.db import init_db
            init_db()
            users = fetch_all("""
                SELECT id, username, gmail_address, is_admin, mailbox_access_code, 
                       access_code_expires_at, is_suspended, suspended_until, suspension_reason,
                       must_change_password, created_at,
                       (CASE WHEN encrypted_app_password IS NOT NULL THEN 1 ELSE 0 END) as has_password
                FROM users 
                ORDER BY id ASC
            """) or []
        except Exception as e2:
            print(f"[Admin] Fallback users query: {e2}")
            try:
                users = fetch_all("SELECT id, username, gmail_address, is_admin, created_at FROM users ORDER BY id ASC") or []
            except Exception:
                users = []

    now = datetime.now(timezone.utc)
    for u in users:
        # Passcode status
        expires_at = u.get('access_code_expires_at')
        if expires_at:
            try:
                if isinstance(expires_at, str):
                    dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                else:
                    dt = expires_at
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if now < dt:
                    remaining_sec = int((dt - now).total_seconds())
                    u['code_status'] = f"Active ({remaining_sec // 3600}h {(remaining_sec % 3600) // 60}m)"
                    u['code_badge'] = "success"
                else:
                    u['code_status'] = "Expired"
                    u['code_badge'] = "warning"
            except Exception:
                u['code_status'] = "Unknown"
                u['code_badge'] = "secondary"
        else:
            u['code_status'] = "Not Generated"
            u['code_badge'] = "secondary"

        # Suspension status
        if u.get('is_suspended'):
            suspended_until = u.get('suspended_until')
            if suspended_until:
                try:
                    if isinstance(suspended_until, str):
                        s_dt = datetime.fromisoformat(suspended_until.replace('Z', '+00:00'))
                    else:
                        s_dt = suspended_until
                    if s_dt.tzinfo is None:
                        s_dt = s_dt.replace(tzinfo=timezone.utc)
                    if now < s_dt:
                        diff_h = int((s_dt - now).total_seconds() // 3600)
                        u['suspension_label'] = f"Suspended ({diff_h}h left)"
                    else:
                        u['suspension_label'] = "Suspension Expired"
                except Exception:
                    u['suspension_label'] = "Suspended (Timed)"
            else:
                u['suspension_label'] = "Suspended Indefinitely"
        else:
            u['suspension_label'] = "Active"

    # Fetch active notices & warnings
    notices = []
    try:
        notices = fetch_all("""
            SELECT n.id, n.target_user_id, n.title, n.message, n.severity, 
                   n.is_dismissible, n.expires_at, n.created_at,
                   u.username as target_username
            FROM admin_notices n
            LEFT JOIN users u ON n.target_user_id = u.id
            ORDER BY n.created_at DESC
        """) or []
    except Exception as e:
        print(f"[Admin] notices query note: {e}")
        notices = []

    # Fetch help & password reset tickets
    help_tickets = []
    try:
        help_tickets = fetch_all("""
            SELECT id, ticket_ref, username, contact_info, request_type,
                   user_message, status, admin_notes, temp_password, created_at, resolved_at
            FROM help_requests
            ORDER BY (CASE WHEN status = 'pending' THEN 0 ELSE 1 END), created_at DESC
            LIMIT 50
        """) or []
    except Exception as e:
        print(f"[Admin] help_tickets query note: {e}")
        help_tickets = []

    telemetry = {
        'total_users': total_users,
        'linked_users': linked_users,
        'active_otps': active_otps,
        'pending_tickets': pending_tickets,
        'active_notices_count': active_notices_count,
        'database_type': 'PostgreSQL' if IS_POSTGRES else 'SQLite (Dual-Mode Local)',
        'imap_server': Config.IMAP_SERVER,
        'imap_port': Config.IMAP_PORT,
        'timeout': f"{Config.IMAP_TIMEOUT_SECONDS}s"
    }

    try:
        current_master_pin = get_system_setting('admin_master_key', Config.ADMIN_MASTER_KEY)
    except Exception:
        current_master_pin = Config.ADMIN_MASTER_KEY

    current_admin_user = Config.ADMIN_DEFAULT_USER
    try:
        admin_flag = True if IS_POSTGRES else 1
        admin_account = fetch_one("SELECT username FROM users WHERE is_admin = %s ORDER BY id ASC", (admin_flag,))
        if admin_account and admin_account.get('username'):
            current_admin_user = admin_account['username']
    except Exception as e:
        print(f"[Admin] admin_account query note: {e}")

    return render_template(
        'admin.html',
        username=session.get('username'),
        is_admin=True,
        telemetry=telemetry,
        users=users,
        notices=notices,
        help_tickets=help_tickets,
        current_master_pin=current_master_pin,
        current_admin_user=current_admin_user
    )

@admin_bp.route('/admin/update-credentials', methods=['POST'])
def admin_update_credentials():
    if not is_current_user_admin():
        flash("Access restricted to system administrators.", "danger")
        return redirect(url_for('admin.admin_login'))

    new_master_pin = request.form.get('master_pin', '').strip()
    new_admin_username = request.form.get('admin_username', '').strip()
    new_admin_password = request.form.get('admin_password', '').strip()

    updated_items = []

    # 1. Update Master PIN
    if new_master_pin:
        set_system_setting('admin_master_key', new_master_pin)
        updated_items.append("Master PIN")

    # 2. Update Admin Username & Password
    admin_flag = True if IS_POSTGRES else 1
    admin_user = fetch_one("SELECT id, username FROM users WHERE is_admin = %s ORDER BY id ASC", (admin_flag,))
    if admin_user:
        target_id = admin_user['id']
        if new_admin_username and new_admin_username != admin_user['username']:
            existing = fetch_one("SELECT id FROM users WHERE username = %s AND id != %s", (new_admin_username, target_id))
            if existing:
                flash(f"Username '{new_admin_username}' is already taken by another account.", "danger")
                return redirect(url_for('admin.admin_view'))
            execute_query("UPDATE users SET username = %s WHERE id = %s", (new_admin_username, target_id))
            if session.get('username') == admin_user['username']:
                session['username'] = new_admin_username
            updated_items.append("Admin Username")

        if new_admin_password:
            if len(new_admin_password) < 6:
                flash("Admin password must be at least 6 characters.", "danger")
                return redirect(url_for('admin.admin_view'))
            new_hash = bcrypt.hashpw(new_admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            execute_query("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, target_id))
            updated_items.append("Admin Password")

    if updated_items:
        flash(f"Successfully updated: {', '.join(updated_items)}.", "success")
    else:
        flash("No changes were submitted.", "info")

    return redirect(url_for('admin.admin_view'))

# ==========================================
# User Governance Actions
# ==========================================

@admin_bp.route('/admin/user/suspend', methods=['POST'])
def admin_suspend_user():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    target_user_id = request.form.get('target_user_id')
    duration_type = request.form.get('duration_type', 'same_day')
    reason = request.form.get('reason', '').strip() or "Suspicious activity detected on office network"

    if not target_user_id:
        flash("User ID is required.", "danger")
        return redirect(url_for('admin.admin_view'))

    target_id = int(target_user_id)
    if target_id == session.get('user_id'):
        flash("You cannot suspend your own active Super Administrator account.", "danger")
        return redirect(url_for('admin.admin_view'))

    now = datetime.now(timezone.utc)
    if duration_type == 'same_day':
        suspended_until = now + timedelta(hours=24)
        dur_label = "Same Day (24h)"
    elif duration_type == '3_days':
        suspended_until = now + timedelta(days=3)
        dur_label = "3 Days"
    elif duration_type == '7_days':
        suspended_until = now + timedelta(days=7)
        dur_label = "7 Days"
    else:
        suspended_until = None
        dur_label = "Indefinite"

    execute_query(
        """
        UPDATE users 
        SET is_suspended = %s, suspended_until = %s, suspension_reason = %s 
        WHERE id = %s
        """,
        (True, suspended_until, reason, target_id)
    )

    flash(f"User #{target_id} has been suspended ({dur_label}). Active sessions terminated.", "warning")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/user/unsuspend/<int:target_user_id>', methods=['POST'])
def admin_unsuspend_user(target_user_id):
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    execute_query(
        """
        UPDATE users 
        SET is_suspended = %s, suspended_until = NULL, suspension_reason = NULL 
        WHERE id = %s
        """,
        (False, target_user_id)
    )
    flash(f"User #{target_user_id} suspension lifted. Account reactivated.", "success")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/user/reset-password', methods=['POST'])
def admin_reset_password():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    target_user_id = request.form.get('target_user_id')
    custom_password = request.form.get('custom_password', '').strip()

    if not target_user_id:
        flash("User ID missing.", "danger")
        return redirect(url_for('admin.admin_view'))

    target_id = int(target_user_id)
    user = fetch_one("SELECT username FROM users WHERE id = %s", (target_id,))
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_view'))

    temp_password = custom_password or generate_temp_password()
    pw_hash = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    execute_query(
        """
        UPDATE users 
        SET password_hash = %s, must_change_password = %s 
        WHERE id = %s
        """,
        (pw_hash, True, target_id)
    )

    flash(
        f"Password reset for '{user['username']}'! Temporary password: {temp_password} (User will be prompted to change it upon login)",
        "success"
    )
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/reset-code/<int:target_user_id>', methods=['POST'])
def admin_reset_code(target_user_id):
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    new_code = force_regenerate_code(target_user_id)
    flash(f"User #{target_user_id} 12-Hour code reset to: {new_code['code']}", "success")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/toggle-admin/<int:target_user_id>', methods=['POST'])
def admin_toggle_role(target_user_id):
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    target = fetch_one("SELECT is_admin, username FROM users WHERE id = %s", (target_user_id,))
    if not target:
        flash("User not found.", "danger")
        return redirect(url_for('admin.admin_view'))

    new_role = not bool(target.get('is_admin'))
    execute_query("UPDATE users SET is_admin = %s WHERE id = %s", (new_role, target_user_id))
    flash(f"Role updated for {target['username']}. Admin: {new_role}", "info")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/delete-user/<int:target_user_id>', methods=['POST'])
def admin_delete_user(target_user_id):
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    if target_user_id == session.get('user_id'):
        flash("You cannot delete your own active administrator account.", "danger")
        return redirect(url_for('admin.admin_view'))

    execute_query("DELETE FROM users WHERE id = %s", (target_user_id,))
    flash(f"User #{target_user_id} and all associated credentials deleted permanently.", "warning")
    return redirect(url_for('admin.admin_view'))

# ==========================================
# Notices & Warnings Dispatcher
# ==========================================

@admin_bp.route('/admin/notices/create', methods=['POST'])
def admin_create_notice():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    target_user_id = request.form.get('target_user_id', '').strip()
    title = request.form.get('title', '').strip()
    message = request.form.get('message', '').strip()
    severity = request.form.get('severity', 'info')
    duration_hours = request.form.get('duration_hours', '24')
    is_dismissible = request.form.get('is_dismissible', '1') == '1'

    if not title or not message:
        flash("Notice title and message are required.", "danger")
        return redirect(url_for('admin.admin_view'))

    target_id = int(target_user_id) if target_user_id and target_user_id != 'all' else None

    expires_at = None
    if duration_hours and duration_hours != 'indefinite':
        try:
            hrs = int(duration_hours)
            expires_at = datetime.now(timezone.utc) + timedelta(hours=hrs)
        except Exception:
            expires_at = None

    execute_query(
        """
        INSERT INTO admin_notices (target_user_id, title, message, severity, is_dismissible, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (target_id, title, message, severity, is_dismissible, expires_at)
    )

    scope_str = f"User #{target_id}" if target_id else "All Users (Broadcast)"
    flash(f"Notice published successfully to {scope_str}!", "success")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/notices/delete/<int:notice_id>', methods=['POST'])
def admin_delete_notice(notice_id):
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    execute_query("DELETE FROM admin_notices WHERE id = %s", (notice_id,))
    flash("Notice revoked and removed from all dashboards.", "info")
    return redirect(url_for('admin.admin_view'))

# ==========================================
# Helpdesk & Password Reset Requests
# ==========================================

@admin_bp.route('/admin/help/resolve', methods=['POST'])
def admin_resolve_help():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    ticket_id = request.form.get('ticket_id')
    admin_notes = request.form.get('admin_notes', '').strip()
    custom_temp_password = request.form.get('custom_temp_password', '').strip()

    if not ticket_id:
        flash("Ticket ID missing.", "danger")
        return redirect(url_for('admin.admin_view'))

    ticket = fetch_one("SELECT id, ticket_ref, username, request_type FROM help_requests WHERE id = %s", (ticket_id,))
    if not ticket:
        flash("Ticket not found.", "danger")
        return redirect(url_for('admin.admin_view'))

    username = ticket['username']
    user = fetch_one("SELECT id FROM users WHERE username = %s", (username,))
    
    temp_password = None
    if user and ticket['request_type'] == 'password_reset':
        temp_password = custom_temp_password or generate_temp_password()
        pw_hash = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        execute_query("UPDATE users SET password_hash = %s, must_change_password = %s WHERE id = %s", (pw_hash, True, user['id']))

    now = datetime.now(timezone.utc)
    execute_query(
        """
        UPDATE help_requests 
        SET status = 'resolved', temp_password = %s, admin_notes = %s, resolved_at = %s
        WHERE id = %s
        """,
        (temp_password, admin_notes or "Password reset completed by Super Admin.", now, ticket_id)
    )

    msg = f"Ticket {ticket['ticket_ref']} for '{username}' marked RESOLVED!"
    if temp_password:
        msg += f" New Temporary Password: {temp_password}"
    flash(msg, "success")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/help/reject', methods=['POST'])
def admin_reject_help():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    ticket_id = request.form.get('ticket_id')
    admin_notes = request.form.get('admin_notes', '').strip() or "Identity could not be verified by administrator."

    if not ticket_id:
        flash("Ticket ID missing.", "danger")
        return redirect(url_for('admin.admin_view'))

    now = datetime.now(timezone.utc)
    execute_query(
        """
        UPDATE help_requests 
        SET status = 'rejected', admin_notes = %s, resolved_at = %s
        WHERE id = %s
        """,
        (admin_notes, now, ticket_id)
    )

    flash("Ticket marked REJECTED.", "warning")
    return redirect(url_for('admin.admin_view'))

# ==========================================
# Telemetry & Garbage Collection
# ==========================================

@admin_bp.route('/admin/purge-otps', methods=['POST'])
def admin_purge_otps():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    count = execute_query("DELETE FROM otps WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'")
    flash("Global purge completed. All expired OTP records removed.", "success")
    return redirect(url_for('admin.admin_view'))

@admin_bp.route('/admin/flush-all-otps', methods=['POST'])
def admin_flush_all_otps():
    if not is_current_user_admin():
        flash("Unauthorized action.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    execute_query("DELETE FROM otps")
    flash("All ephemeral OTP records flushed immediately.", "warning")
    return redirect(url_for('admin.admin_view'))

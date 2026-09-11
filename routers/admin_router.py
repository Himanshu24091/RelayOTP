from datetime import datetime, timezone
from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from utils.db import fetch_one, fetch_all, execute_query, IS_POSTGRES
from utils.code_gen import force_regenerate_code
from config import Config

admin_bp = Blueprint('admin', __name__)

def is_current_user_admin() -> bool:
    user_id = session.get('user_id')
    if not user_id:
        return False
    user = fetch_one("SELECT is_admin FROM users WHERE id = %s", (user_id,))
    return bool(user and user.get('is_admin'))

@admin_bp.route('/admin')
def admin_view():
    if not is_current_user_admin():
        flash("Access restricted to system administrators.", "danger")
        return redirect(url_for('dashboard.dashboard_view'))

    # Collect telemetry
    total_users_row = fetch_one("SELECT COUNT(*) as count FROM users")
    total_users = total_users_row['count'] if total_users_row else 0

    linked_users_row = fetch_one("SELECT COUNT(*) as count FROM users WHERE gmail_address IS NOT NULL AND encrypted_app_password IS NOT NULL")
    linked_users = linked_users_row['count'] if linked_users_row else 0

    active_otps_row = fetch_one(
        "SELECT COUNT(*) as count FROM otps WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'"
    )
    active_otps = active_otps_row['count'] if active_otps_row else 0

    # Fetch all users
    users = fetch_all("""
        SELECT id, username, gmail_address, is_admin, mailbox_access_code, 
               access_code_expires_at, created_at,
               (CASE WHEN encrypted_app_password IS NOT NULL THEN 1 ELSE 0 END) as has_password
        FROM users 
        ORDER BY id ASC
    """)

    now = datetime.now(timezone.utc)
    for u in users:
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

    telemetry = {
        'total_users': total_users,
        'linked_users': linked_users,
        'active_otps': active_otps,
        'database_type': 'PostgreSQL' if IS_POSTGRES else 'SQLite (Dual-Mode Local)',
        'imap_server': Config.IMAP_SERVER,
        'imap_port': Config.IMAP_PORT,
        'timeout': f"{Config.IMAP_TIMEOUT_SECONDS}s"
    }

    return render_template(
        'admin.html',
        username=session.get('username'),
        is_admin=True,
        telemetry=telemetry,
        users=users
    )

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
    flash(f"User #{target_user_id} deleted permanently.", "warning")
    return redirect(url_for('admin.admin_view'))

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

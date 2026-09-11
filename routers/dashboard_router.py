from datetime import datetime, timezone
from flask import Blueprint, render_template, session, redirect, url_for, flash
from utils.db import fetch_one, fetch_all, execute_query
from utils.code_gen import ensure_active_code

dashboard_bp = Blueprint('dashboard', __name__)

def mask_email(email_addr: str) -> str:
    if not email_addr or '@' not in email_addr:
        return ""
    parts = email_addr.split('@')
    name = parts[0]
    domain = parts[1]
    if len(name) <= 2:
        masked_name = name[0] + "***"
    else:
        masked_name = name[0] + "***" + name[-1]
    return f"{masked_name}@{domain}"

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def dashboard_view():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = fetch_one("SELECT id, username, gmail_address, encrypted_app_password, is_admin FROM users WHERE id = %s", (user_id,))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))

    gmail_address = user.get('gmail_address')
    has_credentials = bool(gmail_address and user.get('encrypted_app_password'))
    if not has_credentials:
        flash("Please connect your Gmail account in Settings first before accessing the verification dashboard.", "info")
        return redirect(url_for('settings.settings_view'))

    is_locked = not session.get('mailbox_unlocked', False)
    code_info = ensure_active_code(user_id)
    masked_gmail = mask_email(gmail_address)

    otps = []
    if not is_locked:
        # Purge OTPs older than 10 minutes
        execute_query(
            "DELETE FROM otps WHERE user_id = %s AND created_at < CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'",
            (user_id,)
        )
        
        # Load remaining valid OTPs
        rows = fetch_all(
            "SELECT id, sender_name, subject_snippet, otp_code, item_type, created_at FROM otps WHERE user_id = %s ORDER BY created_at DESC",
            (user_id,)
        )
        now = datetime.now(timezone.utc)
        for r in rows:
            created_at = r.get('created_at')
            # Calculate human-readable time ago
            time_ago = "Just now"
            if created_at:
                try:
                    if isinstance(created_at, str):
                        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    else:
                        dt = created_at
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    diff_sec = int((now - dt).total_seconds())
                    if diff_sec < 60:
                        time_ago = f"{diff_sec}s ago"
                    elif diff_sec < 3600:
                        time_ago = f"{diff_sec // 60}m ago"
                    else:
                        time_ago = f"{diff_sec // 3600}h ago"
                except Exception:
                    time_ago = "Recently"

            item_type = r.get('item_type') or ('link' if str(r.get('otp_code', '')).startswith('http') else 'code')
            otps.append({
                'id': r['id'],
                'sender_name': r['sender_name'],
                'subject_snippet': r['subject_snippet'] or "No subject snippet",
                'otp_code': r['otp_code'],
                'item_type': item_type,
                'time_ago': time_ago
            })

    # Fetch active notices: broadcast (target_user_id IS NULL) OR targeted to this user
    # excluding those already dismissed by this user
    active_notices = fetch_all(
        """
        SELECT n.id, n.title, n.message, n.severity, n.is_dismissible, n.created_at
        FROM admin_notices n
        WHERE (n.target_user_id IS NULL OR n.target_user_id = %s)
          AND (n.expires_at IS NULL OR n.expires_at > CURRENT_TIMESTAMP)
          AND n.id NOT IN (SELECT notice_id FROM user_notice_reads WHERE user_id = %s)
        ORDER BY n.created_at DESC
        """,
        (user_id, user_id)
    )

    return render_template(
        'dashboard.html',
        username=user['username'],
        is_admin=user.get('is_admin', False),
        is_locked=is_locked,
        has_credentials=has_credentials,
        masked_gmail=masked_gmail,
        code_info=code_info,
        otps=otps,
        active_notices=active_notices
    )

@dashboard_bp.route('/api/notices/dismiss/<int:notice_id>', methods=['POST'])
def dismiss_notice(notice_id):
    from flask import jsonify
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    try:
        execute_query(
            "INSERT INTO user_notice_reads (notice_id, user_id) VALUES (%s, %s)",
            (notice_id, user_id)
        )
        return jsonify({'success': True}), 200
    except Exception:
        return jsonify({'success': True}), 200

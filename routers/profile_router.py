from datetime import datetime, timezone
from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from utils.db import fetch_one
from utils.code_gen import ensure_active_code, force_regenerate_code

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/profile')
def profile_view():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = fetch_one("SELECT id, username, gmail_address, is_admin FROM users WHERE id = %s", (user_id,))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))

    code_info = ensure_active_code(user_id)

    expires_at_dt = code_info.get('expires_at')
    expires_str = expires_at_dt.strftime('%d %b %Y, %I:%M %p UTC') if expires_at_dt else "N/A"

    return render_template(
        'profile.html',
        username=user['username'],
        is_admin=user.get('is_admin', False),
        gmail_address=user.get('gmail_address') or "Not configured",
        code_info=code_info,
        expires_str=expires_str
    )

@profile_bp.route('/profile/regenerate', methods=['POST'])
def regenerate():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    new_info = force_regenerate_code(user_id)
    # Mailbox must be unlocked again with the new code
    session['mailbox_unlocked'] = False
    flash(f"New 12-Hour Passcode generated: {new_info['code']}. Existing code has been revoked.", "success")
    return redirect(url_for('profile.profile_view'))

from flask import Blueprint, render_template, session, redirect, url_for
from utils.db import fetch_one
from utils.crypto import decrypt_credential

settings_bp = Blueprint('settings', __name__)

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

@settings_bp.route('/settings')
def settings_view():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = fetch_one("SELECT id, username, gmail_address, encrypted_app_password, is_admin FROM users WHERE id = %s", (user_id,))
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))

    gmail_address = user.get('gmail_address')
    encrypted_pass = user.get('encrypted_app_password')
    has_credentials = bool(gmail_address and encrypted_pass)
    masked_gmail = mask_email(gmail_address) if has_credentials else None

    saved_app_password = ""
    if has_credentials and encrypted_pass:
        try:
            saved_app_password = decrypt_credential(encrypted_pass)
        except Exception:
            saved_app_password = ""

    return render_template(
        'settings.html',
        username=user['username'],
        is_admin=user.get('is_admin', False),
        gmail_address=gmail_address or "",
        app_password=saved_app_password,
        has_credentials=has_credentials,
        masked_gmail=masked_gmail
    )

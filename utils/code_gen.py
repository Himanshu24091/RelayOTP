import secrets
import string
from datetime import datetime, timedelta, timezone
from utils.db import execute_query, fetch_one

def generate_alphanumeric_code() -> str:
    """
    Generates cryptographically secure 12-Hour passcode in format [A-Z]{2}-[0-9]{4}
    Example: TK-9281, NX-3849
    """
    prefix = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(2))
    suffix = ''.join(secrets.choice(string.digits) for _ in range(4))
    return f"{prefix}-{suffix}"

def _parse_dt(val):
    if val is None:
        return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, str):
        # Handle SQLite ISO format strings
        clean_str = val.replace('Z', '+00:00')
        try:
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return None

def ensure_active_code(user_id: int) -> dict:
    """
    Checks if the user has an active, unexpired 12-hour code.
    If code is NULL or expired, generates a new one expiring in 12 hours.
    Returns dict: {'code': str, 'expires_at': datetime, 'remaining_seconds': int}
    """
    now = datetime.now(timezone.utc)
    user = fetch_one("SELECT mailbox_access_code, access_code_expires_at FROM users WHERE id = %s", (user_id,))
    
    if not user:
        return None

    code = user.get('mailbox_access_code')
    expires_at = _parse_dt(user.get('access_code_expires_at'))

    needs_new = False
    if not code or not expires_at or now >= expires_at:
        needs_new = True

    if needs_new:
        new_code = generate_alphanumeric_code()
        new_expires_at = now + timedelta(hours=12)
        # Store in UTC
        execute_query(
            "UPDATE users SET mailbox_access_code = %s, access_code_expires_at = %s WHERE id = %s",
            (new_code, new_expires_at.strftime('%Y-%m-%d %H:%M:%S'), user_id)
        )
        code = new_code
        expires_at = new_expires_at

    remaining = max(0, int((expires_at - now).total_seconds()))
    hours = remaining // 3600
    minutes = (remaining % 3600) // 60

    return {
        'code': code,
        'expires_at': expires_at,
        'remaining_seconds': remaining,
        'formatted_remaining': f"{hours:02d}h {minutes:02d}m",
        'verbose_remaining': f"{hours:02d} Hours {minutes:02d} Minutes"
    }

def force_regenerate_code(user_id: int) -> dict:
    """
    Immediately revokes existing code and creates a fresh 12-hour passcode.
    """
    now = datetime.now(timezone.utc)
    new_code = generate_alphanumeric_code()
    new_expires_at = now + timedelta(hours=12)
    execute_query(
        "UPDATE users SET mailbox_access_code = %s, access_code_expires_at = %s WHERE id = %s",
        (new_code, new_expires_at.strftime('%Y-%m-%d %H:%M:%S'), user_id)
    )
    return {
        'code': new_code,
        'expires_at': new_expires_at,
        'remaining_seconds': 12 * 3600,
        'formatted_remaining': "12h 00m",
        'verbose_remaining': "12 Hours 00 Minutes"
    }

def verify_mailbox_code(user_id: int, entered_code: str) -> bool:
    """
    Validates user's entered 12-hour code.
    Matches case-insensitively and strips whitespace/hyphens if entered as TK9281.
    """
    if not entered_code:
        return False
    
    clean_entered = entered_code.strip().upper().replace(" ", "")
    user = fetch_one("SELECT mailbox_access_code, access_code_expires_at FROM users WHERE id = %s", (user_id,))
    if not user:
        return False
    
    actual_code = (user.get('mailbox_access_code') or '').strip().upper()
    expires_at = _parse_dt(user.get('access_code_expires_at'))
    now = datetime.now(timezone.utc)

    if not actual_code or not expires_at or now >= expires_at:
        return False

    # Compare with or without dash
    clean_actual = actual_code.replace("-", "")
    clean_input = clean_entered.replace("-", "")

    return clean_input == clean_actual

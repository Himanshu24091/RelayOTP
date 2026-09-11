import urllib.parse
import re
import requests
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, session, make_response
from utils.db import fetch_one, fetch_all, execute_query
from utils.crypto import encrypt_credential, decrypt_credential
from utils.code_gen import verify_mailbox_code
from utils.imap_engine import test_imap_connection, fetch_recent_otps_from_gmail
from utils.rate_limiter import rate_limiter, get_client_ip

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/verify-code', methods=['POST'])
def api_verify_code():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized session'}), 401

    client_ip = get_client_ip(request)
    rate_key = f"{user_id}_{client_ip}"

    # 1. Check if user is currently locked out
    is_locked, rem_sec = rate_limiter.is_locked('verify_code', rate_key)
    if is_locked:
        return jsonify({
            'success': False,
            'message': f'Too many failed attempts. Security lockout active ({rem_sec}s remaining).',
            'lockout': True,
            'remaining_seconds': rem_sec
        }), 429

    data = request.get_json(silent=True) or request.form
    entered_code = data.get('code', '').strip()

    if not entered_code:
        return jsonify({'success': False, 'message': 'Please provide your 12-Hour passcode'}), 400

    is_valid = verify_mailbox_code(user_id, entered_code)
    if is_valid:
        rate_limiter.reset('verify_code', rate_key)
        session['mailbox_unlocked'] = True
        return jsonify({'success': True, 'message': 'Mailbox access granted'}), 200
    else:
        # Record failed attempt and trigger lockout if >= 5 failures
        locked_now, rem_lockout = rate_limiter.record_failure(
            'verify_code', rate_key, max_attempts=5, window_seconds=300, lockout_seconds=300
        )
        if locked_now:
            return jsonify({
                'success': False,
                'message': f'Too many failed attempts. Security lockout active for {rem_lockout}s.',
                'lockout': True,
                'remaining_seconds': rem_lockout
            }), 429

        return jsonify({'success': False, 'message': 'Invalid or expired 12-Hour Passcode'}), 400

@api_bp.route('/api/test-vault', methods=['POST'])
def api_test_vault():
    data = request.get_json(silent=True) or request.form
    email_addr = data.get('gmail_address', '').strip()
    app_password = data.get('app_password', '').strip()

    if not email_addr or not app_password:
        return jsonify({'success': False, 'message': 'Gmail address and 16-character App Password are required.'}), 400

    success, msg = test_imap_connection(email_addr, app_password)
    if success:
        return jsonify({'success': True, 'message': msg}), 200
    else:
        return jsonify({'success': False, 'message': msg}), 400

@api_bp.route('/api/save-vault', methods=['POST'])
def api_save_vault():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Session expired. Please log in again to save credentials.'}), 401

    data = request.get_json(silent=True) or request.form
    email_addr = data.get('gmail_address', '').strip()
    app_password = data.get('app_password', '').strip()

    if not email_addr or not app_password:
        return jsonify({'success': False, 'message': 'Both Gmail address and App Password are required.'}), 400

    # Encrypt password using Fernet AES-256
    try:
        encrypted_blob = encrypt_credential(app_password)
        # Update user record
        execute_query(
            """
            UPDATE users 
            SET gmail_address = %s, encrypted_app_password = %s 
            WHERE id = %s
            """,
            (email_addr, encrypted_blob, user_id)
        )
        return jsonify({'success': True, 'message': 'Gmail credentials encrypted and saved securely.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f"Failed to save credentials: {str(e)}"}), 500

@api_bp.route('/api/disconnect-vault', methods=['POST'])
def api_disconnect_vault():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    try:
        # Erase credentials and purge all user's OTPs
        execute_query(
            "UPDATE users SET gmail_address = NULL, encrypted_app_password = NULL WHERE id = %s",
            (user_id,)
        )
        execute_query("DELETE FROM otps WHERE user_id = %s", (user_id,))
        return jsonify({'success': True, 'message': 'Gmail credentials disconnected and all OTPs purged.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f"Error disconnecting vault: {str(e)}"}), 500

@api_bp.route('/api/fetch-otp', methods=['POST'])
def api_fetch_otp():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    if not session.get('mailbox_unlocked', False):
        return jsonify({'success': False, 'message': 'Mailbox is locked. Please enter your 12-Hour code.'}), 403

    user = fetch_one("SELECT gmail_address, encrypted_app_password FROM users WHERE id = %s", (user_id,))
    if not user or not user.get('gmail_address') or not user.get('encrypted_app_password'):
        return jsonify({'success': False, 'message': 'Gmail credentials not configured in Settings.'}), 400

    email_addr = user['gmail_address']
    # In-memory decryption strictly for this operation
    try:
        raw_password = decrypt_credential(user['encrypted_app_password'])
    except Exception as e:
        return jsonify({'success': False, 'message': f"Decryption failure: {str(e)}"}), 500

    try:
        # IMAP Pipeline with PEEK mode
        new_otps = fetch_recent_otps_from_gmail(email_addr, raw_password)
        
        # Write to database (TTL: 10 minutes)
        for item in new_otps:
            item_type = item.get('item_type', 'code')
            # Check if this exact OTP was already recorded recently for this user
            existing = fetch_one(
                """
                SELECT id FROM otps 
                WHERE user_id = %s AND otp_code = %s AND created_at >= CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'
                """,
                (user_id, item['otp_code'])
            )
            if not existing:
                execute_query(
                    """
                    INSERT INTO otps (user_id, sender_name, subject_snippet, otp_code, item_type)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (user_id, item['sender_name'], item['subject_snippet'], item['otp_code'], item_type)
                )

        # Clear expired OTPs
        execute_query(
            "DELETE FROM otps WHERE user_id = %s AND created_at < CURRENT_TIMESTAMP - INTERVAL '10 MINUTE'",
            (user_id,)
        )

        # Return latest active OTPs
        active_records = fetch_all(
            """
            SELECT id, sender_name, subject_snippet, otp_code, item_type, created_at 
            FROM otps 
            WHERE user_id = %s 
            ORDER BY created_at DESC
            """,
            (user_id,)
        )

        now = datetime.now(timezone.utc)
        result = []
        for r in active_records:
            created_at = r.get('created_at')
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
            result.append({
                'id': r['id'],
                'sender_name': r['sender_name'],
                'subject_snippet': r['subject_snippet'],
                'otp_code': r['otp_code'],
                'item_type': item_type,
                'time_ago': time_ago
            })

        item_count = len(new_otps)
        msg_text = f"Scan complete. {item_count} verification item(s) detected." if item_count > 0 else "Scan complete. 0 new code(s) or link(s) detected."
        return jsonify({
            'success': True,
            'message': msg_text,
            'otps': result
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f"IMAP Fetch failed: {str(e)}"}), 500

@api_bp.route('/api/delete-otp', methods=['POST'])
def api_delete_otp():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json(silent=True) or request.form
    otp_id = data.get('otp_id')
    if not otp_id:
        return jsonify({'success': False, 'message': 'OTP ID missing'}), 400

    execute_query("DELETE FROM otps WHERE id = %s AND user_id = %s", (otp_id, user_id))
ANTHROPIC_CARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anthropic Claude.ai Secure Sign-In</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0b0f19;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1.5rem;
  }
  .card {
    max-width: 580px;
    width: 100%;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(245, 158, 11, 0.45);
    border-radius: 16px;
    padding: 2.25rem 2rem;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7), 0 0 35px rgba(245, 158, 11, 0.12);
    text-align: center;
    backdrop-filter: blur(16px);
  }
  .icon-wrap {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    background: rgba(245, 158, 11, 0.15);
    border: 1px solid rgba(245, 158, 11, 0.35);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 2rem;
    margin-bottom: 1rem;
  }
  .title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #fbbf24;
    margin-bottom: 0.4rem;
  }
  .subtitle {
    font-size: 0.88rem;
    color: #94a3b8;
    line-height: 1.5;
    margin-bottom: 1.4rem;
  }
  .token-container {
    background: rgba(0, 0, 0, 0.55);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    padding: 0.9rem 1.15rem;
    margin-bottom: 1.4rem;
    text-align: left;
  }
  .token-label {
    font-size: 0.72rem;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    margin-bottom: 0.35rem;
    display: flex;
    justify-content: space-between;
  }
  .token-val {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.88rem;
    color: #38bdf8;
    word-break: break-all;
    user-select: all;
  }
  .btn-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    width: 100%;
    background: linear-gradient(135deg, #d97706, #b45309);
    color: #fff;
    font-weight: 700;
    font-size: 1rem;
    padding: 0.85rem 1.25rem;
    border-radius: 8px;
    text-decoration: none;
    cursor: pointer;
    border: none;
    transition: transform 0.15s, box-shadow 0.15s;
    box-shadow: 0 4px 15px rgba(217, 119, 6, 0.4);
  }
  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 6px 22px rgba(217, 119, 6, 0.55);
  }
  .btn-group {
    display: flex;
    gap: 0.6rem;
    margin-top: 0.75rem;
  }
  .btn-sub {
    flex: 1;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.15);
    color: #cbd5e1;
    font-size: 0.82rem;
    font-weight: 600;
    padding: 0.55rem 0.85rem;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn-sub:hover {
    background: rgba(255, 255, 255, 0.12);
    color: #fff;
  }
  .privacy-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #34d399;
    padding: 0.35rem 0.85rem;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
    margin-top: 1.25rem;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="icon-wrap">🤖</div>
    <div class="title">Anthropic Claude.ai Secure Sign-In</div>
    <div class="subtitle">
      Claude.ai client-side cryptographic token extracted. To establish your session while maintaining zero workplace tracking:
    </div>

    <div class="token-container">
      <div class="token-label">
        <span>AUTHENTICATION TOKEN</span>
        <span style="color: #34d399;">● READY</span>
      </div>
      <div class="token-val">__TOKEN__</div>
    </div>

    <a href="__URL__" target="_blank" rel="noreferrer noopener" onclick="stealthLaunch(event, '__URL__')" class="btn-primary">
      🚀 Complete Sign-In (Zero-Referrer Stealth Mode)
    </a>

    <div class="btn-group">
      <button type="button" class="btn-sub" onclick="copyVal('__TOKEN__', this, '✓ Token Copied!')">
        📋 Copy Token Only
      </button>
      <button type="button" class="btn-sub" onclick="copyVal('__URL__', this, '✓ Link Copied!')">
        📋 Copy Magic Link
      </button>
    </div>

    <div class="privacy-badge">
      🛡️ Strict Referrer Stripping Active • Zero Network Trace
    </div>
  </div>

  <script>
  function stealthLaunch(e, url) {
    if (window.parent && window.parent !== window) {
      try {
        window.parent.postMessage({ type: 'OPEN_STEALTH', url: url }, '*');
      } catch(err) {}
    }
  }

  function copyVal(text, btn, successMsg) {
    var ok = false;
    try {
      var t = document.createElement('textarea');
      t.value = text;
      t.style.position = 'fixed';
      t.style.top = '-9999px';
      t.style.left = '-9999px';
      t.setAttribute('readonly', '');
      document.body.appendChild(t);
      t.focus();
      t.select();
      t.setSelectionRange(0, text.length);
      ok = document.execCommand('copy');
      document.body.removeChild(t);
    } catch(err) {
      ok = false;
    }

    if (!ok && window.navigator && window.navigator.clipboard && typeof window.navigator.clipboard.writeText === 'function') {
      window.navigator.clipboard.writeText(text).then(function() {
        showSuccess(btn, successMsg);
      }).catch(function() {
        prompt('Copy to clipboard (Ctrl+C, Enter):', text);
      });
      return;
    }

    if (ok) {
      showSuccess(btn, successMsg);
    } else {
      prompt('Copy to clipboard (Ctrl+C, Enter):', text);
    }
  }

  function showSuccess(btn, successMsg) {
    if (!btn) return;
    var orig = btn.innerText;
    btn.innerText = successMsg;
    btn.style.borderColor = '#34d399';
    btn.style.color = '#34d399';
    setTimeout(function() {
      btn.innerText = orig;
      btn.style.borderColor = '';
      btn.style.color = '';
    }, 2000);
  }
  </script>
</body>
</html>"""

FALLBACK_CARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sandboxed Verification Hub</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0b0f19;
    color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 1.5rem;
  }
  .card {
    max-width: 560px;
    width: 100%;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid rgba(56, 189, 248, 0.35);
    border-radius: 16px;
    padding: 2.25rem 2rem;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7);
    text-align: center;
  }
  .title { font-size: 1.3rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem; }
  .desc { font-size: 0.88rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.25rem; }
  .url-box { font-family: monospace; font-size: 0.82rem; color: #a5f3fc; background: #030712; padding: 0.8rem; border-radius: 8px; border: 1px solid rgba(6,182,212,0.3); word-break: break-all; margin-bottom: 1.25rem; }
  .btn-primary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    width: 100%;
    background: linear-gradient(135deg, #0284c7, #0369a1);
    color: #fff;
    font-weight: 700;
    font-size: 0.95rem;
    padding: 0.8rem 1.25rem;
    border-radius: 8px;
    text-decoration: none;
    cursor: pointer;
    border: none;
  }
  .btn-sub {
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.15);
    color: #cbd5e1;
    font-size: 0.82rem;
    font-weight: 600;
    padding: 0.55rem 0.85rem;
    border-radius: 6px;
    cursor: pointer;
  }
</style>
</head>
<body>
  <div class="card">
    <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">🛡️</div>
    <div class="title">Sandboxed Verification Hub</div>
    <div class="desc">The upstream service requires direct client navigation or returned __STATUS__. You can complete verification with zero referrer leakage:</div>
    <div class="url-box">__URL__</div>
    <a href="__URL__" target="_blank" rel="noreferrer noopener" onclick="stealthLaunch(event, '__URL__')" class="btn-primary">
      🚀 Open in Zero-Referrer Mode
    </a>
    <button type="button" class="btn-sub" onclick="copyVal('__URL__', this, '✓ Link Copied!')" style="margin-top:0.75rem; width:100%;">
      📋 Copy Verification Link
    </button>
  </div>
  <script>
  function stealthLaunch(e, url) {
    if (window.parent && window.parent !== window) {
      try {
        window.parent.postMessage({ type: 'OPEN_STEALTH', url: url }, '*');
      } catch(err) {}
    }
  }
  function copyVal(text, btn, successMsg) {
    var ok = false;
    try {
      var t = document.createElement('textarea');
      t.value = text;
      t.style.position = 'fixed';
      t.style.top = '-9999px';
      t.style.left = '-9999px';
      t.setAttribute('readonly', '');
      document.body.appendChild(t);
      t.focus();
      t.select();
      t.setSelectionRange(0, text.length);
      ok = document.execCommand('copy');
      document.body.removeChild(t);
    } catch(err) {
      ok = false;
    }
    if (!ok && window.navigator && window.navigator.clipboard && typeof window.navigator.clipboard.writeText === 'function') {
      window.navigator.clipboard.writeText(text).then(function() {
        showSuccess(btn, successMsg);
      }).catch(function() {
        prompt('Copy to clipboard:', text);
      });
      return;
    }
    if (ok) {
      showSuccess(btn, successMsg);
    } else {
      prompt('Copy to clipboard:', text);
    }
  }
  function showSuccess(btn, successMsg) {
    if (!btn) return;
    var orig = btn.innerText;
    btn.innerText = successMsg;
    setTimeout(function() { btn.innerText = orig; }, 2000);
  }
  </script>
</body>
</html>"""

ERROR_CARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sandboxed Verification Viewer</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #e2e8f0; padding: 2.5rem 1.5rem; text-align: center; }
  .card { max-width: 540px; margin: 2rem auto; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.12); border-radius: 12px; padding: 2rem; }
  .title { font-size: 1.25rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem; }
  .desc { font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.25rem; }
  .url-box { word-break: break-all; font-family: monospace; font-size: 0.85rem; color: #a5f3fc; background: #030712; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid rgba(6,182,212,0.3); margin-bottom: 1rem; }
</style>
</head>
<body>
  <div class="card">
    <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">🛡️</div>
    <div class="title">Sandboxed In-App Verification Viewer</div>
    <div class="desc">Unable to establish proxy stream to destination (__ERROR__).</div>
    <div class="url-box">__URL__</div>
    <a href="__URL__" target="_blank" rel="noreferrer noopener" onclick="stealthLaunch(event, '__URL__')" style="display:inline-block; padding: 0.75rem 1.25rem; background: #0284c7; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600;">
      🚀 Open with Zero-Referrer
    </a>
  </div>
  <script>
  function stealthLaunch(e, url) {
    if (window.parent && window.parent !== window) {
      try {
        window.parent.postMessage({ type: 'OPEN_STEALTH', url: url }, '*');
      } catch(err) {}
    }
  }
  </script>
</body>
</html>"""

@api_bp.route('/api/sandbox-view')
def api_sandbox_view():
    user_id = session.get('user_id')
    if not user_id:
        return "Unauthorized. Please log in to view verification items.", 401

    target_url = request.args.get('url', '').strip()
    if not target_url or not (target_url.startswith('https://') or target_url.startswith('http://')):
        return "Invalid or unsupported verification link protocol.", 400

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or '').lower()
    if hostname in ['localhost', '127.0.0.1', '::1', '0.0.0.0'] or hostname.startswith('192.168.') or hostname.startswith('10.') or hostname.endswith('.internal') or hostname.endswith('.local'):
        return "Access to internal network addresses is blocked for security.", 403

    token = ""
    if '#' in target_url:
        token = target_url.split('#', 1)[1]

    # Special dedicated In-App Privacy Card for Anthropic Claude.ai client-side hash auth
    if 'claude.ai' in hostname or 'anthropic.com' in hostname:
        clean_token = token or "Single-Sign-On-Link"
        card_html = ANTHROPIC_CARD_TEMPLATE.replace('__TOKEN__', clean_token).replace('__URL__', target_url)
        resp = make_response(card_html, 200)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
        return resp

    try:
        req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        resp = requests.get(target_url, headers=req_headers, timeout=10, allow_redirects=True)
        content_type = resp.headers.get('Content-Type', 'text/html')

        if 'text/html' in content_type and resp.status_code == 200:
            html_text = resp.text
            # Neutralize frame buster scripts
            html_text = re.sub(r'top\.location\s*=\s*(?:self\.location|location)', '/* frame-buster neutral */', html_text, flags=re.IGNORECASE)
            # Ensure body is visible (some SPAs have opacity:0 until bootstrap)
            inject_head = f'<base href="{target_url}"><style>body {{ opacity: 1 !important; visibility: visible !important; }}</style>'
            if '<head>' in html_text:
                html_text = html_text.replace('<head>', f'<head>{inject_head}', 1)
            elif '<HEAD>' in html_text:
                html_text = html_text.replace('<HEAD>', f'<HEAD>{inject_head}', 1)
            else:
                html_text = f"{inject_head}{html_text}"

            response = make_response(html_text, 200)
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
            return response
        else:
            # If upstream returns 403 / 401 or non-200, render a clean Sandboxed Fallback Card
            status_desc = f"HTTP {resp.status_code}"
            fallback_html = FALLBACK_CARD_TEMPLATE.replace('__STATUS__', status_desc).replace('__URL__', target_url)
            resp_out = make_response(fallback_html, 200)
            resp_out.headers['Content-Type'] = 'text/html; charset=utf-8'
            resp_out.headers['X-Frame-Options'] = 'SAMEORIGIN'
            resp_out.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
            return resp_out

    except Exception as e:
        error_html = ERROR_CARD_TEMPLATE.replace('__ERROR__', str(e)).replace('__URL__', target_url)
        resp = make_response(error_html, 200)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Content-Security-Policy'] = "frame-ancestors 'self'"
        return resp

@api_bp.route('/api/trigger-verification', methods=['POST'])
def api_trigger_verification():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'Unauthorized session'}), 401

    data = request.get_json(silent=True) or request.form
    target_url = (data.get('url') or '').strip()
    if not target_url or not (target_url.startswith('https://') or target_url.startswith('http://')):
        return jsonify({'success': False, 'message': 'Invalid verification link protocol'}), 400

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or '').lower()
    if hostname in ['localhost', '127.0.0.1', '::1', '0.0.0.0'] or hostname.startswith('192.168.') or hostname.startswith('10.') or hostname.endswith('.internal') or hostname.endswith('.local'):
        return jsonify({'success': False, 'message': 'Intranet or localhost destinations are forbidden'}), 403

    # For Claude.ai / Anthropic, handle client-side token auth
    if 'claude.ai' in hostname or 'anthropic.com' in hostname:
        token = target_url.split('#', 1)[1] if '#' in target_url else ''
        token_snippet = token[:12] + '...' if len(token) > 12 else token
        return jsonify({
            'success': True,
            'status_code': 200,
            'message': f"Anthropic token detected ({token_snippet}). Click 'Complete Sign-In' or 'Zero-Referrer Open' to establish your Claude session.",
            'final_url': target_url
        }), 200

    try:
        req_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }
        resp = requests.get(target_url, headers=req_headers, timeout=12, allow_redirects=True)
        status_msg = f"HTTP {resp.status_code}"
        return jsonify({
            'success': resp.status_code < 400,
            'status_code': resp.status_code,
            'message': f"Verification token dispatched by backend server ({status_msg}). Account verification triggered!",
            'final_url': resp.url
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f"Failed to dispatch verification request: {str(e)}"
        }), 500


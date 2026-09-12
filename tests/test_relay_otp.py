import unittest
import re
import os
import json
from datetime import datetime, timezone

# Ensure testing configuration uses isolated local SQLite test DB
os.environ['SQLITE_DB_NAME'] = 'relay_otp_test.db'
os.environ['DATABASE_URL'] = ''
os.environ['SECRET_KEY'] = 'test-secret-key-12345'
os.environ['FLASK_ENV'] = 'testing'

from app import create_app
from utils.db import init_db, execute_query, fetch_one, fetch_all
from utils.crypto import encrypt_credential, decrypt_credential
from utils.code_gen import generate_alphanumeric_code, ensure_active_code, verify_mailbox_code, force_regenerate_code
from utils.otp_parser import parse_otp_from_text, normalize_code, extract_friendly_sender, parse_verification_item, extract_magic_link
from utils.rate_limiter import rate_limiter

class RelayOTPTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            init_db()

    def setUp(self):
        self.client = self.app.test_client()
        # Clear rate limiter state
        rate_limiter._lockouts.clear()
        rate_limiter._failures.clear()
        # Clear users and otps for clean test runs
        execute_query("DELETE FROM otps")
        execute_query("DELETE FROM users")

    def test_crypto_fernet(self):
        """Test AES-256 Fernet encryption and decryption."""
        plain_password = "abcd efgh ijkl mnop"
        encrypted = encrypt_credential(plain_password)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, plain_password.encode('utf-8'))
        
        decrypted = decrypt_credential(encrypted)
        self.assertEqual(decrypted, "abcdefghijklmnop")

    def test_code_gen_format_and_verification(self):
        """Test 12-Hour alphanumeric passcode generation and verification."""
        code = generate_alphanumeric_code()
        # Verify format: 2 uppercase letters, hyphen, 4 digits
        self.assertTrue(re.match(r'^[A-Z]{2}-[0-9]{4}$', code), f"Code {code} did not match [A-Z]{{2}}-[0-9]{{4}}")

        # Create dummy user to test database code lifecycle
        execute_query("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ("testuser", "dummyhash"))
        user = fetch_one("SELECT id FROM users WHERE username = %s", ("testuser",))
        user_id = user['id']

        info = ensure_active_code(user_id)
        self.assertIsNotNone(info)
        active_code = info['code']
        self.assertTrue(re.match(r'^[A-Z]{2}-[0-9]{4}$', active_code))
        self.assertGreater(info['remaining_seconds'], 43000) # close to 12 hours (43200s)

        # Test verification matching
        self.assertTrue(verify_mailbox_code(user_id, active_code))
        self.assertTrue(verify_mailbox_code(user_id, active_code.lower()))
        self.assertTrue(verify_mailbox_code(user_id, active_code.replace("-", "")))
        self.assertFalse(verify_mailbox_code(user_id, "ZZ-9999"))

        # Test force regeneration
        new_info = force_regenerate_code(user_id)
        self.assertNotEqual(active_code, new_info['code'])
        self.assertTrue(verify_mailbox_code(user_id, new_info['code']))
        self.assertFalse(verify_mailbox_code(user_id, active_code))

    def test_otp_parser_3_layer_model(self):
        """Test 3-Layer Scoring Model: contextual, blacklist, normalization."""
        # Layer 1: Contextual match
        sample_email_1 = "Your GitHub verification code is 849201. Please enter this within 10 minutes."
        self.assertEqual(parse_otp_from_text(sample_email_1), "849201")

        sample_email_2 = "Amazon security code: 193048 to authenticate your session."
        self.assertEqual(parse_otp_from_text(sample_email_2), "193048")

        sample_email_3 = "682910 is your OTP for transaction at SBI."
        self.assertEqual(parse_otp_from_text(sample_email_3), "682910")

        # Layer 2: Blacklist rejection of year and currency
        sample_currency = "Order confirmed for ₹1299 in year 2025. Your OTP is 482910."
        self.assertEqual(parse_otp_from_text(sample_currency), "482910")

        sample_false_positive = "Invoice total $2024.50 paid on 2026-05-10."
        self.assertIsNone(parse_otp_from_text(sample_false_positive))

        # Layer 3: Normalization
        self.assertEqual(normalize_code("123-456"), "123456")
        self.assertEqual(normalize_code("849 201"), "849201")
        self.assertEqual(normalize_code("G-482910"), "482910")

        # Friendly sender extraction
        self.assertEqual(extract_friendly_sender('"GitHub" <notifications@github.com>'), "GitHub")
        self.assertEqual(extract_friendly_sender('AWS Notifications <no-reply@amazon.com>'), "AWS Notifications")

    def test_registration_and_login_flow(self):
        """Test user registration, login, mailbox lock and admin assignment."""
        # First registered user should automatically become Admin
        resp = self.client.post('/register', data={
            'username': 'admin_user',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        user = fetch_one("SELECT id, is_admin FROM users WHERE username = %s", ("admin_user",))
        self.assertIsNotNone(user)
        self.assertTrue(bool(user['is_admin']))

        # Log in
        login_resp = self.client.post('/login', data={
            'username': 'admin_user',
            'password': 'Password123!'
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)

        # Mailbox should be initially locked
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get('mailbox_unlocked'))

        # Fetch 12-hour code and verify via API
        user_id = user['id']
        code_info = ensure_active_code(user_id)
        valid_code = code_info['code']

        verify_resp = self.client.post('/api/verify-code', 
            data=json.dumps({'code': valid_code}),
            content_type='application/json'
        )
        self.assertEqual(verify_resp.status_code, 200)
        verify_data = json.loads(verify_resp.data)
        self.assertTrue(verify_data['success'])

        # Now mailbox should be unlocked in session
        with self.client.session_transaction() as sess:
            self.assertTrue(sess.get('mailbox_unlocked'))

        # Test Tab-Logout beacon
        beacon_resp = self.client.post('/api/auth/tab-logout')
        self.assertEqual(beacon_resp.status_code, 200)
        with self.client.session_transaction() as sess:
            self.assertNotIn('user_id', sess)

    def test_admin_control_access(self):
        """Test Admin Control Page access and unauthorized restriction."""
        # Create regular user
        self.client.post('/register', data={
            'username': 'regular_user',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }, follow_redirects=True)

        user = fetch_one("SELECT id FROM users WHERE username = %s", ("regular_user",))
        # Even if first user was regular_user, let's explicitly set is_admin=False
        execute_query("UPDATE users SET is_admin = %s WHERE id = %s", (False, user['id']))
        self.client.get('/logout')

        # Log in as regular user
        self.client.post('/login', data={
            'username': 'regular_user',
            'password': 'Password123!'
        }, follow_redirects=True)

        # Admin page access should redirect regular user to admin gateway
        admin_resp = self.client.get('/admin', follow_redirects=True)
        self.assertIn(b"Super Admin Gateway", admin_resp.data)

        # Unlock using Master Key (123456)
        unlock_resp = self.client.post('/admin/login', data={'master_key': '123456'}, follow_redirects=True)
        self.assertEqual(unlock_resp.status_code, 200)
        self.assertIn(b"Administrative Control Center", unlock_resp.data)

        # Lock admin session again
        self.client.get('/admin/logout')

        # Promote to admin in DB
        execute_query("UPDATE users SET is_admin = %s WHERE id = %s", (True, user['id']))
        # Re-login to update session
        self.client.post('/login', data={
            'username': 'regular_user',
            'password': 'Password123!'
        }, follow_redirects=True)

        admin_resp = self.client.get('/admin')
        self.assertEqual(admin_resp.status_code, 200)
        self.assertIn(b"Administrative Control Center", admin_resp.data)

    def test_admin_actions(self):
        """Test admin actions: reset code, toggle role, delete user, global purge."""
        # Create admin user
        self.client.post('/register', data={
            'username': 'admin_root',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        })
        # Create secondary user
        client2 = self.app.test_client()
        client2.post('/register', data={
            'username': 'target_user',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        })
        target = fetch_one("SELECT id, mailbox_access_code FROM users WHERE username = %s", ("target_user",))
        target_id = target['id']
        old_code = target['mailbox_access_code']

        # Log in as admin
        self.client.post('/login', data={
            'username': 'admin_root',
            'password': 'Password123!'
        })

        # 1. Reset target user's code
        reset_resp = self.client.post(f'/admin/reset-code/{target_id}', follow_redirects=True)
        self.assertEqual(reset_resp.status_code, 200)
        target_updated = fetch_one("SELECT mailbox_access_code FROM users WHERE id = %s", (target_id,))
        self.assertNotEqual(old_code, target_updated['mailbox_access_code'])

        # 2. Toggle target user role to Admin
        toggle_resp = self.client.post(f'/admin/toggle-admin/{target_id}', follow_redirects=True)
        self.assertEqual(toggle_resp.status_code, 200)
        target_updated2 = fetch_one("SELECT is_admin FROM users WHERE id = %s", (target_id,))
        self.assertTrue(bool(target_updated2['is_admin']))

        # 3. Global purge OTPs
        purge_resp = self.client.post('/admin/purge-otps', follow_redirects=True)
        self.assertEqual(purge_resp.status_code, 200)

        # 4. Flush all OTPs
        flush_resp = self.client.post('/admin/flush-all-otps', follow_redirects=True)
        self.assertEqual(flush_resp.status_code, 200)

        # 5. Delete target user
        del_resp = self.client.post(f'/admin/delete-user/{target_id}', follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)
        target_deleted = fetch_one("SELECT id FROM users WHERE id = %s", (target_id,))
        self.assertIsNone(target_deleted)

    def test_vault_api_lifecycle(self):
        """Test API save vault, credential encryption in DB, and disconnect danger zone."""
        self.client.post('/register', data={
            'username': 'vault_user',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        })
        self.client.post('/login', data={
            'username': 'vault_user',
            'password': 'Password123!'
        })

        # Save credentials to vault
        save_resp = self.client.post('/api/save-vault', 
            data=json.dumps({
                'gmail_address': 'aman.work@gmail.com',
                'app_password': 'abcd efgh ijkl mnop'
            }),
            content_type='application/json'
        )
        self.assertEqual(save_resp.status_code, 200)
        user = fetch_one("SELECT gmail_address, encrypted_app_password FROM users WHERE username = %s", ("vault_user",))
        self.assertEqual(user['gmail_address'], 'aman.work@gmail.com')
        self.assertIsNotNone(user['encrypted_app_password'])
        # Plain text should NOT be stored
        self.assertNotIn('abcd', str(user['encrypted_app_password']))

        # Disconnect vault
        dc_resp = self.client.post('/api/disconnect-vault')
        self.assertEqual(dc_resp.status_code, 200)
        user_dc = fetch_one("SELECT gmail_address, encrypted_app_password FROM users WHERE username = %s", ("vault_user",))
        self.assertIsNone(user_dc['gmail_address'])
        self.assertIsNone(user_dc['encrypted_app_password'])

    def test_magic_link_extraction_and_lifecycle(self):
        """Test Anthropic / Claude.ai magic link parsing, database persistence, and dashboard rendering."""
        # 1. Anthropic / Claude.ai HTML email
        subject = "Your secure link to Claude.ai is here | 2026-09-10 06:25:57"
        plain_text = "Sign in to Claude.ai Click the button below to finish signing in. This link will expire in 10 minutes."
        raw_html = """
        <div style="font-family: sans-serif;">
            <h2>Sign in to Claude.ai</h2>
            <p>Click the button below to finish signing in.</p>
            <table border="0">
                <tr>
                    <td>
                        <a href="https://claude.ai/api/auth/magic-link?token=anthropic_secure_jwt_token_999" style="background: #c15f3e; color: #fff; padding: 12px 24px; text-decoration: none;">
                            Sign in to Claude.ai
                        </a>
                    </td>
                </tr>
            </table>
            <p><a href="https://anthropic.com/legal">Privacy & Terms</a></p>
        </div>
        """
        item = parse_verification_item(subject=subject, body_text=plain_text, raw_html=raw_html)
        self.assertIsNotNone(item)
        self.assertEqual(item['type'], 'link')
        self.assertEqual(item['value'], 'https://claude.ai/api/auth/magic-link?token=anthropic_secure_jwt_token_999')

        # 2. Standard numeric OTP parsing remains intact
        otp_subject = "Your Google Verification Code"
        otp_body = "G-492019 is your Google verification code."
        otp_item = parse_verification_item(subject=otp_subject, body_text=otp_body)
        self.assertIsNotNone(otp_item)
        self.assertEqual(otp_item['type'], 'code')
        self.assertEqual(otp_item['value'], '492019')

        # 3. Database persistence of magic link
        execute_query("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ("link_user", "dummyhash"))
        user = fetch_one("SELECT id FROM users WHERE username = %s", ("link_user",))
        user_id = user['id']

        execute_query(
            "INSERT INTO otps (user_id, sender_name, subject_snippet, otp_code, item_type) VALUES (%s, %s, %s, %s, %s)",
            (user_id, "Anthropic", subject, item['value'], item['type'])
        )

        saved = fetch_one("SELECT otp_code, item_type FROM otps WHERE user_id = %s", (user_id,))
        self.assertEqual(saved['item_type'], 'link')
        self.assertEqual(saved['otp_code'], 'https://claude.ai/api/auth/magic-link?token=anthropic_secure_jwt_token_999')

    def test_security_headers(self):
        """Test injection of strict HTTP security headers on all responses."""
        resp = self.client.get('/health')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(resp.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        self.assertIn("default-src 'self'", resp.headers.get('Content-Security-Policy', ''))
        self.assertIn("frame-ancestors 'none'", resp.headers.get('Content-Security-Policy', ''))

    def test_verify_code_brute_force_lockout(self):
        """Test brute-force rate limiting on 12-hour mailbox code verification (5 attempts -> lockout)."""
        # Create user
        execute_query("INSERT INTO users (username, password_hash) VALUES (%s, %s)", ("brute_target", "dummyhash"))
        user = fetch_one("SELECT id FROM users WHERE username = %s", ("brute_target",))
        user_id = user['id']

        # Log in
        with self.client.session_transaction() as sess:
            sess['user_id'] = user_id
            sess['username'] = "brute_target"

        # Attempt 1-4: Invalid codes (returns 400)
        for i in range(4):
            resp = self.client.post('/api/verify-code', json={'code': f'ZZ-000{i}'})
            self.assertEqual(resp.status_code, 400)

        # Attempt 5: Triggers rate limiter lockout (returns 429)
        resp5 = self.client.post('/api/verify-code', json={'code': 'ZZ-0005'})
        self.assertEqual(resp5.status_code, 429)
        data = json.loads(resp5.data)
        self.assertTrue(data.get('lockout'))
        self.assertGreater(data.get('remaining_seconds', 0), 200)

    def test_xss_magic_link_protection(self):
        """Test that non-HTTP/HTTPS schemes like javascript: are rejected by parser."""
        dangerous_html = '<a href="javascript:alert(document.cookie)">Sign in to Claude.ai</a>'
        dangerous_link = extract_magic_link(raw_html=dangerous_html, subject="Sign in to Claude.ai")
        self.assertIsNone(dangerous_link, "javascript: scheme was not rejected!")

        data_uri_html = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Sign in</a>'
        data_link = extract_magic_link(raw_html=data_uri_html, subject="Sign in")
        self.assertIsNone(data_link, "data: scheme was not rejected!")

if __name__ == '__main__':
    unittest.main()

import requests
import json
import re
import random

BASE_URL = "http://127.0.0.1:5000"

def run_e2e_verification():
    from utils.db import execute_query
    execute_query("DELETE FROM users WHERE username = 'aman_dev'")
    
    test_user = f"test_{random.randint(10000, 99999)}"
    session = requests.Session()
    print(f"--- 1. Registering New User ({test_user}) ---")
    reg_resp = session.post(f"{BASE_URL}/register", data={
        'username': test_user,
        'password': 'Password123!',
        'confirm_password': 'Password123!',
        'admin_key': 'admin123'
    }, allow_redirects=True)
    print(f"Register response URL: {reg_resp.url}")
    assert reg_resp.status_code == 200
    # Must land on Settings page with Step 1 onboarding
    assert "/settings" in reg_resp.url or "Step 1: Connect Your Gmail Account" in reg_resp.text
    print("User correctly directed to Settings page right after ID creation!")

    print("\n--- 2. Verifying Dashboard Redirects to Settings If Not Connected ---")
    dash_unlinked_resp = session.get(f"{BASE_URL}/dashboard", allow_redirects=True)
    assert "/settings" in dash_unlinked_resp.url or "Gmail Credential Vault" in dash_unlinked_resp.text
    print("Dashboard prevented locked modal and safely redirected unlinked user to Settings!")

    print("\n--- 3. Connecting Gmail Account via /api/save-vault ---")
    save_resp = session.post(f"{BASE_URL}/api/save-vault", json={
        'gmail_address': 'aman.work@gmail.com',
        'app_password': 'abcd efgh ijkl mnop'
    })
    print(f"Save Vault response: {save_resp.json()}")
    assert save_resp.json()['success'] is True
    print("Gmail successfully connected!")

    print("\n--- 4. Checking Profile & Retrieving 12-Hour Code ---")
    prof_resp = session.get(f"{BASE_URL}/profile")
    match = re.search(r'([A-Z]{2}-[0-9]{4})', prof_resp.text)
    assert match, "12-hour passcode not found in profile page"
    code = match.group(1)
    print(f"Retrieved 12-Hour passcode: {code}")

    print("\n--- 5. Visiting Dashboard with Connected Gmail (Modal Appears) ---")
    dash_resp = session.get(f"{BASE_URL}/dashboard")
    assert "MAILBOX ACCESS RESTRICTED" in dash_resp.text
    print("Mailbox gatekeeper modal correctly displayed now that Gmail is connected!")

    print("\n--- 6. Unlocking Mailbox via /api/verify-code ---")
    unlock_resp = session.post(f"{BASE_URL}/api/verify-code", json={'code': code})
    print(f"Unlock response: {unlock_resp.json()}")
    assert unlock_resp.json()['success'] is True

    print("\n--- 7. Checking Unlocked Dashboard ---")
    dash_unlocked_resp = session.get(f"{BASE_URL}/dashboard")
    assert "Active Verification Items" in dash_unlocked_resp.text
    assert "MAILBOX ACCESS RESTRICTED" not in dash_unlocked_resp.text
    print("Dashboard successfully unlocked and active verification items ready!")

    print("\n--- 7b. Calling /api/fetch-otp (Authorized Session) ---")
    fetch_resp = session.post(f"{BASE_URL}/api/fetch-otp")
    print(f"Fetch OTP response status: {fetch_resp.status_code}")
    # Must NOT be 401 Unauthorized!
    assert fetch_resp.status_code != 401, f"Expected authorized request but got 401: {fetch_resp.text}"
    print("/api/fetch-otp verified: User session and mailbox lock are valid (Not 401 Unauthorized)!")

    print("\n--- 8. Checking Admin Control Center (/admin) ---")
    admin_resp = session.get(f"{BASE_URL}/admin")
    assert "Administrative Control Center" in admin_resp.text
    assert "Registered Tenant Accounts" in admin_resp.text
    assert test_user in admin_resp.text
    print("Admin Control Page successfully loaded and verified!")

    print("\n--- 9. Testing Admin 12-Hour Code Reset ---")
    id_match = re.search(r'/admin/reset-code/(\d+)', admin_resp.text)
    assert id_match, "Could not find reset-code link for user in admin table"
    target_id = id_match.group(1)
    reset_resp = session.post(f"{BASE_URL}/admin/reset-code/{target_id}", allow_redirects=True)
    assert reset_resp.status_code == 200
    print(f"Admin code reset for user #{target_id} verified!")

    print("\n--- 10. Testing Tab-Logout Beacon (/api/auth/tab-logout) ---")
    logout_resp = session.post(f"{BASE_URL}/api/auth/tab-logout")
    print(f"Tab logout response: {logout_resp.json()}")
    assert logout_resp.json()['status'] == 'logged_out'

    # Verify session is destroyed
    post_logout_resp = session.get(f"{BASE_URL}/dashboard")
    assert "Portal Sign In" in post_logout_resp.text
    print("Tab-logout successfully destroyed session!")

    print("\n==========================================")
    print("ALL 10 REAL-USER ONBOARDING & VAULT FLOW CHECKS PASSED!")
    print("==========================================")

if __name__ == '__main__':
    run_e2e_verification()

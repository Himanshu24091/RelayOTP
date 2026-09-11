import random
import string
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from utils.db import fetch_one, fetch_all, execute_query
from utils.rate_limiter import rate_limiter, get_client_ip

help_bp = Blueprint('help', __name__)

def generate_ticket_ref() -> str:
    """Generates a human-friendly ticket reference like REQ-839210."""
    digits = ''.join(random.choices(string.digits, k=6))
    return f"REQ-{digits}"

@help_bp.route('/help', methods=['GET'])
def help_view():
    ref = request.args.get('ref', '').strip()
    status_data = None
    if ref:
        status_data = fetch_one(
            """
            SELECT ticket_ref, username, request_type, user_message, status, admin_notes, temp_password, created_at, resolved_at
            FROM help_requests
            WHERE ticket_ref = %s
            """,
            (ref,)
        )
    return render_template('help.html', ref=ref, status_data=status_data)

@help_bp.route('/help/submit', methods=['POST'])
def help_submit():
    client_ip = get_client_ip(request)
    rate_key = f"help_{client_ip}"

    # Rate limiting: max 4 submissions per 30 minutes
    is_locked, rem_sec = rate_limiter.is_locked('help_submit', rate_key)
    if is_locked:
        flash(f"Too many help requests submitted. Please wait {rem_sec}s before submitting again.", "danger")
        return redirect(url_for('help.help_view'))

    username = request.form.get('username', '').strip()
    contact_info = request.form.get('contact_info', '').strip()
    request_type = request.form.get('request_type', 'password_reset').strip()
    user_message = request.form.get('user_message', '').strip()

    if not username:
        flash("Username is required so the administrator can locate your account.", "danger")
        return redirect(url_for('help.help_view'))

    if not user_message:
        flash("Please provide a brief explanation of your issue.", "danger")
        return redirect(url_for('help.help_view'))

    # Record attempt against rate limiter
    rate_limiter.record_failure('help_submit', rate_key, max_attempts=4, window_seconds=1800, lockout_seconds=1800)

    # Check if user exists in the system
    user = fetch_one("SELECT id, is_suspended, suspension_reason FROM users WHERE username = %s", (username,))
    
    # Generate unique ticket reference
    for _ in range(10):
        ref = generate_ticket_ref()
        exists = fetch_one("SELECT id FROM help_requests WHERE ticket_ref = %s", (ref,))
        if not exists:
            break

    try:
        execute_query(
            """
            INSERT INTO help_requests (ticket_ref, username, contact_info, request_type, user_message, status)
            VALUES (%s, %s, %s, %s, %s, 'pending')
            """,
            (ref, username, contact_info or None, request_type, user_message)
        )
        flash(f"Help request submitted successfully! Your Ticket Reference is: {ref}", "success")
        return redirect(url_for('help.help_view', ref=ref))
    except Exception as e:
        flash(f"Failed to submit help request: {str(e)}", "danger")
        return redirect(url_for('help.help_view'))

@help_bp.route('/help/status', methods=['GET', 'POST'])
def help_status():
    query_ref = (request.form.get('ticket_ref') or request.args.get('ref') or '').strip()
    username = (request.form.get('username') or request.args.get('username') or '').strip()

    ticket = None
    if query_ref:
        ticket = fetch_one(
            """
            SELECT ticket_ref, username, request_type, user_message, status, admin_notes, temp_password, created_at, resolved_at
            FROM help_requests
            WHERE ticket_ref = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (query_ref,)
        )
    elif username:
        ticket = fetch_one(
            """
            SELECT ticket_ref, username, request_type, user_message, status, admin_notes, temp_password, created_at, resolved_at
            FROM help_requests
            WHERE username = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (username,)
        )

    if not ticket and (query_ref or username):
        flash(f"No help ticket found matching reference/username: {query_ref or username}", "warning")

    return render_template('help.html', ref=query_ref, status_data=ticket)

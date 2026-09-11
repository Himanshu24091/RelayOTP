import imaplib
import email
import socket
import re
from datetime import datetime, timedelta, timezone
from config import Config
from utils.otp_parser import decode_mime_header, extract_friendly_sender, parse_otp_from_text, parse_verification_item

def clean_html(html_content: str) -> str:
    """Strips HTML tags while preserving word boundary spacing."""
    # Replace block tags with newline
    text = re.sub(r'<(?:div|p|br|tr|td|h\d)[^>]*>', ' ', html_content, flags=re.IGNORECASE)
    # Strip remaining tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Replace common HTML entities
    text = text.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    return ' '.join(text.split())

def extract_email_payloads(msg) -> tuple[str, str]:
    """
    Extracts body text and raw HTML from email.message.Message.
    Returns (plain_text, raw_html).
    """
    plain_text = ""
    raw_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in content_disposition.lower():
                continue

            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                charset = part.get_content_charset() or 'utf-8'
                decoded_str = payload.decode(charset, errors='replace')
                if content_type == "text/plain" and not plain_text:
                    plain_text = decoded_str
                elif content_type == "text/html" and not raw_html:
                    raw_html = decoded_str
            except Exception:
                continue
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                decoded_str = payload.decode(charset, errors='replace')
                if content_type == "text/html":
                    raw_html = decoded_str
                else:
                    plain_text = decoded_str
        except Exception:
            pass

    # If plain text is empty but raw_html exists, generate plain text by cleaning html
    cleaned_plain = plain_text if plain_text else (clean_html(raw_html) if raw_html else "")
    return cleaned_plain, raw_html

def extract_email_body(msg) -> str:
    """
    Extracts body text from email.message.Message.
    Priority: text/plain -> fallback: cleaned text/html
    """
    plain, _ = extract_email_payloads(msg)
    return plain

def test_imap_connection(email_address: str, app_password: str) -> tuple[bool, str]:
    """
    Performs a non-destructive SSL handshake to test Gmail credentials.
    Returns (success: bool, message: str).
    """
    if not email_address or not app_password:
        return False, "Email address and Google App Password are required."

    cleaned_pw = app_password.replace(" ", "").strip()
    client = None
    try:
        # Set socket timeout
        client = imaplib.IMAP4_SSL(
            host=Config.IMAP_SERVER,
            port=Config.IMAP_PORT,
            timeout=Config.IMAP_TIMEOUT_SECONDS
        )
        status, response = client.login(email_address.strip(), cleaned_pw)
        if status != 'OK':
            return False, f"Authentication rejected by Google: {response}"
        
        # Verify INBOX access
        status, _ = client.select('INBOX', readonly=True)
        if status != 'OK':
            return False, "Could not open INBOX in read-only mode."

        return True, "Gmail IMAP SSL connection verified successfully!"
    except imaplib.IMAP4.error as e:
        err_msg = str(e)
        if "AUTHENTICATIONFAILED" in err_msg or "Invalid credentials" in err_msg:
            return False, "Google authentication failed. Please ensure 2-Step Verification is ON in your Google Account and you are using a 16-character Google App Password (not your normal Gmail password)."
        return False, f"IMAP authentication failed: {err_msg}"
    except (socket.timeout, TimeoutError):
        return False, f"Connection timed out ({Config.IMAP_TIMEOUT_SECONDS}s). Please verify network access."
    except Exception as e:
        return False, f"Connection error: {str(e)}"
    finally:
        if client:
            try:
                client.logout()
            except Exception:
                pass

def fetch_recent_otps_from_gmail(email_address: str, app_password: str) -> list[dict]:
    """
    Connects to Gmail IMAP, fetches latest verification emails in read-only mode using BODY.PEEK[],
    and parses OTP codes with 3-layer scoring.
    Returns list of dicts: [{'sender_name': str, 'subject_snippet': str, 'otp_code': str}]
    """
    if not email_address or not app_password:
        return []

    cleaned_pw = app_password.replace(" ", "").strip()
    client = None
    extracted_otps = []

    try:
        client = imaplib.IMAP4_SSL(
            host=Config.IMAP_SERVER,
            port=Config.IMAP_PORT,
            timeout=Config.IMAP_TIMEOUT_SECONDS
        )
        client.login(email_address.strip(), cleaned_pw)
        client.select('INBOX', readonly=True)

        # Search for recent messages
        # Formulate IMAP SINCE query for yesterday and today to avoid timezone edge cases
        yesterday_str = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%d-%b-%Y")
        search_criteria = f'(SINCE "{yesterday_str}")'
        status, data = client.search(None, search_criteria)
        
        msg_ids = []
        if status == 'OK' and data and data[0]:
            msg_ids = data[0].split()
        else:
            # Fallback to ALL if SINCE returns nothing
            status, data = client.search(None, 'ALL')
            if status == 'OK' and data and data[0]:
                msg_ids = data[0].split()

        if not msg_ids:
            return []

        # Take up to MAX_EMAILS_PER_FETCH most recent messages
        max_fetch = max(Config.MAX_EMAILS_PER_FETCH, 15)
        target_ids = msg_ids[-max_fetch:]
        target_ids.reverse() # newest first

        for mid in target_ids:
            try:
                # Use BODY.PEEK[] so unread flag is strictly preserved
                status, msg_data = client.fetch(mid, '(BODY.PEEK[])')
                if status != 'OK' or not msg_data or not msg_data[0]:
                    continue

                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Extract headers
                subject = decode_mime_header(msg.get('Subject', ''))
                from_header = msg.get('From', '')
                sender = extract_friendly_sender(from_header)

                # Extract body text and raw HTML
                body_text, raw_html = extract_email_payloads(msg)
                
                # Parse verification item (numeric OTP code or Magic Link)
                item = parse_verification_item(subject=subject, body_text=body_text, raw_html=raw_html)

                if item:
                    snippet = subject[:180] if subject else body_text[:180]
                    extracted_otps.append({
                        'sender_name': sender,
                        'subject_snippet': snippet.strip(),
                        'otp_code': item['value'],
                        'item_type': item['type']
                    })
            except Exception as item_err:
                print(f"[RelayOTP] Error parsing message {mid}: {item_err}")
                continue

    except Exception as e:
        print(f"[RelayOTP] IMAP fetch error: {e}")
        raise e
    finally:
        if client:
            try:
                client.logout()
            except Exception:
                pass

    return extracted_otps

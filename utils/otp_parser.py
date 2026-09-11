import re
import email.utils
from email.header import decode_header

BLACKLIST_YEARS = {'2023', '2024', '2025', '2026', '2027', '2028'}
CURRENCY_PREFIXES = r'(?:[\$₹€£]|rs\.?|inr|usd|eur|gbp)\s*'
CURRENCY_SUFFIXES = r'\s*(?:[\$₹€£]|rs\.?|inr|usd|eur|gbp)'

def decode_mime_header(header_str: str) -> str:
    """Decodes MIME encoded header strings (e.g. =?UTF-8?B?...?=)."""
    if not header_str:
        return ""
    try:
        parts = decode_header(header_str)
        decoded = []
        for content, encoding in parts:
            if isinstance(content, bytes):
                decoded.append(content.decode(encoding or 'utf-8', errors='replace'))
            else:
                decoded.append(str(content))
        return "".join(decoded).strip()
    except Exception:
        return str(header_str).strip()

def extract_friendly_sender(from_header: str) -> str:
    """
    Extracts a friendly sender name from a From header.
    Examples:
      'GitHub <notifications@github.com>' -> 'GitHub'
      'AWS Notifications <no-reply@amazon.com>' -> 'AWS Notifications'
      'accounts@google.com' -> 'Google'
    """
    decoded = decode_mime_header(from_header)
    name, addr = email.utils.parseaddr(decoded)
    if name and name.strip():
        # Clean quotes
        return name.strip(' "\'')
    if addr and '@' in addr:
        domain = addr.split('@')[1].split('.')[0].capitalize()
        return domain
    return decoded or "Verification Service"

def is_blacklisted(candidate: str, raw_text: str, match_pos: int) -> bool:
    """
    Layer 2: Blacklist Filtering
    Returns True if candidate should be rejected.
    """
    digits_only = re.sub(r'\D', '', candidate)
    
    # 1. Reject if length not between 4 and 8 digits
    if len(digits_only) < 4 or len(digits_only) > 8:
        return True

    # 2. Reject years
    if digits_only in BLACKLIST_YEARS:
        return True

    # 3. Contextual currency check: examine ±15 characters around match
    start = max(0, match_pos - 15)
    end = min(len(raw_text), match_pos + len(candidate) + 15)
    window = raw_text[start:end]

    # Check for currency symbols or decimal price points
    if re.search(CURRENCY_PREFIXES + re.escape(candidate), window, re.IGNORECASE):
        return True
    if re.search(re.escape(candidate) + CURRENCY_SUFFIXES, window, re.IGNORECASE):
        return True
    if re.search(r'\.\d{2}\b', window) and '.' in candidate:
        return True

    # 4. Check if part of date or time (e.g. 10:20:30)
    if re.search(r':\d{2}', window):
        # Allow if it's explicitly labeled as otp: 123456
        if not re.search(r'(?:code|otp|passcode)', window, re.IGNORECASE):
            return True

    return False

def normalize_code(raw_candidate: str) -> str:
    """
    Layer 3: Normalization
    Converts '123-456' -> '123456', '849 201' -> '849201', 'G-482910' -> '482910'
    """
    # Remove leading G- or similar single-letter prefix common in Google codes
    cleaned = re.sub(r'^[A-Za-z]-', '', raw_candidate.strip())
    # Extract only the digits
    digits = re.sub(r'\D', '', cleaned)
    return digits

def parse_otp_from_text(text: str) -> str:
    """
    Executes the 3-Layer Scoring Model to extract the highest confidence OTP.
    Returns normalized OTP string, or None if no valid code found.
    """
    if not text:
        return None

    # Strip excessive whitespace
    clean_text = ' '.join(text.split())

    # Layer 1: Contextual Match (Highest Confidence)
    # Pattern A: Trigger word followed within 30 non-digits by code
    # Supports formatted codes like 123-456, G-482910, 849 201
    pattern_forward = re.compile(
        r'(?i)(?:otp|verification\s*code|security\s*code|login\s*code|confirmation\s*code|one-time\s*password|passcode|secret\s*code|auth\s*code)[\D]{0,30}\b([A-Za-z]-?\d{4,8}|\d{3,4}[-\s]\d{3,4}|\d{4,8})\b'
    )
    
    # Pattern B: Code followed within 30 non-digits by trigger word
    # e.g., "849201 is your verification code"
    pattern_backward = re.compile(
        r'(?i)\b([A-Za-z]-?\d{4,8}|\d{3,4}[-\s]\d{3,4}|\d{4,8})\b[\D]{0,30}(?:is\s+your\s+(?:otp|verification|security|code)|to\s+verify|to\s+authenticate)'
    )

    candidates = []

    # Search forward pattern
    for match in pattern_forward.finditer(clean_text):
        raw_code = match.group(1)
        if not is_blacklisted(raw_code, clean_text, match.start(1)):
            candidates.append((raw_code, 100)) # high priority score

    # Search backward pattern
    for match in pattern_backward.finditer(clean_text):
        raw_code = match.group(1)
        if not is_blacklisted(raw_code, clean_text, match.start(1)):
            candidates.append((raw_code, 90))

    # Fallback Pattern: Standalone bold or isolated 6-digit number if context contains "code" or "verify"
    if not candidates and re.search(r'(?i)\b(code|verify|pin|security|one-time)\b', clean_text):
        fallback_pattern = re.compile(r'\b(\d{6})\b')
        for match in fallback_pattern.finditer(clean_text):
            raw_code = match.group(1)
            if not is_blacklisted(raw_code, clean_text, match.start(1)):
                candidates.append((raw_code, 50))

    if not candidates:
        return None

    # Sort by confidence score
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_candidate = candidates[0][0]

    # Layer 3: Normalization
    return normalize_code(best_candidate)

LINK_TRIGGER_KEYWORDS = [
    'magic-link', 'magic_link', 'magic', 'token=', 'verify', 'verification',
    'signin', 'sign-in', 'login', 'auth', 'callback', 'ticket=',
    'confirm', 'confirm-email', 'activate', 'activation', 'session',
    'claude.ai', 'anthropic', 'notion.so', 'slack.com', 'supabase.co'
]

LINK_TEXT_KEYWORDS = [
    'sign in', 'log in', 'finish signing in', 'click here to sign in',
    'verify', 'confirm email', 'confirm your email', 'access account',
    'secure link', 'magic link', 'log into', 'continue to', 'activate account',
    'claude.ai', 'anthropic', 'click the button below', 'open in claude'
]

LINK_BLACKLIST = [
    'unsubscribe', 'privacy', 'terms', 'support', 'twitter.com', 'x.com',
    'facebook.com', 'instagram.com', 'linkedin.com', 'youtube.com',
    'github.com/about', 'settings/notifications', 'preferences',
    'view in browser', 'list-manage.com', 'google.com/policies',
    'help.anthropic.com', 'status.anthropic.com', 'support.anthropic.com',
    'anthropic.com/legal'
]

def extract_magic_link(raw_html: str = "", plain_text: str = "", subject: str = "") -> str:
    """
    Extracts high-confidence one-time sign-in or verification links
    from HTML anchor tags or plain text (e.g. Anthropic/Claude, Slack, Notion, Supabase).
    """
    candidates = []
    subject_lower = subject.lower() if subject else ""

    # Calculate subject boost if subject expresses sign-in / magic link intent
    subject_bonus = 0
    for kw in LINK_TEXT_KEYWORDS:
        if kw in subject_lower:
            subject_bonus += 35
            break

    # 1. Parse HTML anchor tags
    if raw_html:
        anchor_pattern = re.compile(
            r'<a\s+[^>]*href=["\']?\s*(https?://[^"\'\s>]+)\s*["\']?[^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )
        for match in anchor_pattern.finditer(raw_html):
            url = match.group(1).replace('&amp;', '&').strip()
            # Security: enforce strict http/https protocol
            if not (url.startswith('https://') or url.startswith('http://')):
                continue
            if any(bad in url.lower() for bad in ['javascript:', 'data:', 'vbscript:']):
                continue

            anchor_text = re.sub(r'<[^>]+>', ' ', match.group(2)).strip().lower()
            url_lower = url.lower()

            # Skip blacklisted links
            if any(bl in url_lower or bl in anchor_text for bl in LINK_BLACKLIST):
                continue

            score = subject_bonus
            for kw in LINK_TRIGGER_KEYWORDS:
                if kw in url_lower:
                    score += 50

            for kw in LINK_TEXT_KEYWORDS:
                if kw in anchor_text:
                    score += 60

            # Check surrounding HTML (e.g., text preceding the button)
            start_surround = max(0, match.start() - 250)
            end_surround = min(len(raw_html), match.end() + 100)
            surrounding = raw_html[start_surround:end_surround].lower()
            for kw in LINK_TEXT_KEYWORDS:
                if kw in surrounding:
                    score += 30

            if score >= 35:
                candidates.append((url, score))

    # 2. Parse plain text URLs if no candidate found
    if not candidates and plain_text:
        url_pattern = re.compile(r'(https?://[^\s<>"\'\)\]]+)', re.IGNORECASE)
        for match in url_pattern.finditer(plain_text):
            url = match.group(1).rstrip('.,;:!?')
            # Security: enforce strict http/https protocol
            if not (url.startswith('https://') or url.startswith('http://')):
                continue
            if any(bad in url.lower() for bad in ['javascript:', 'data:', 'vbscript:']):
                continue

            url_lower = url.lower()

            if any(bl in url_lower for bl in LINK_BLACKLIST):
                continue

            score = subject_bonus
            for kw in LINK_TRIGGER_KEYWORDS:
                if kw in url_lower:
                    score += 40

            start = max(0, match.start() - 250)
            end = min(len(plain_text), match.end() + 100)
            window = plain_text[start:end].lower()
            for kw in LINK_TEXT_KEYWORDS:
                if kw in window:
                    score += 50

            if score >= 35:
                candidates.append((url, score))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]

def parse_verification_item(subject: str, body_text: str, raw_html: str = "") -> dict:
    """
    Unified extraction engine:
    1. Checks for 4-8 digit numeric OTP codes.
    2. If no numeric OTP found, checks for Magic / Verification Links.
    Returns dict: {'type': 'code'|'link', 'value': str} or None.
    """
    combined_text = f"{subject}\n{body_text}"
    otp_code = parse_otp_from_text(combined_text)
    if otp_code:
        return {
            'type': 'code',
            'value': otp_code
        }

    # If no numeric code, check for magic link
    link_intent = re.search(r'(?i)(?:sign\s*in|log\s*in|secure\s*link|magic\s*link|verify|confirm|activation|authenticate|claude|anthropic|slack|notion)', combined_text)
    if link_intent or raw_html:
        magic_link = extract_magic_link(raw_html=raw_html, plain_text=body_text, subject=subject)
        if magic_link:
            return {
                'type': 'link',
                'value': magic_link
            }

    return None

import os
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

def get_or_create_master_key():
    env_key = os.getenv('MASTER_ENCRYPTION_KEY', '').strip()
    if env_key:
        return env_key
    
    # In local development, preserve key across reboots so encrypted passwords decrypt reliably
    dev_key_file = os.path.join(BASE_DIR, '.dev_master.key')
    if os.path.exists(dev_key_file):
        try:
            with open(dev_key_file, 'r', encoding='utf-8') as f:
                saved = f.read().strip()
                if saved:
                    return saved
        except Exception:
            pass

    new_key = Fernet.generate_key().decode('utf-8')
    try:
        with open(dev_key_file, 'w', encoding='utf-8') as f:
            f.write(new_key)
    except Exception:
        pass
    return new_key


class Config:
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    SECRET_KEY = os.getenv('SECRET_KEY', 'relay-otp-session-secret-key-development-mode')
    DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
    MASTER_ENCRYPTION_KEY = get_or_create_master_key()

    # IMAP Configuration
    IMAP_SERVER = os.getenv('IMAP_SERVER', 'imap.gmail.com')
    IMAP_PORT = int(os.getenv('IMAP_PORT', '993'))
    IMAP_TIMEOUT_SECONDS = int(os.getenv('IMAP_TIMEOUT_SECONDS', '8'))
    MAX_EMAILS_PER_FETCH = int(os.getenv('MAX_EMAILS_PER_FETCH', '7'))

    # Cookie & Security settings
    SESSION_PERMANENT = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Admin Control & Master Key settings
    ADMIN_MASTER_KEY = os.getenv('ADMIN_MASTER_KEY', '123456')
    ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'admin123')
    ADMIN_DEFAULT_USER = os.getenv('ADMIN_DEFAULT_USER', 'admin')
    ADMIN_DEFAULT_PASSWORD = os.getenv('ADMIN_DEFAULT_PASSWORD', 'admin123')

from cryptography.fernet import Fernet
from config import Config

def _get_fernet() -> Fernet:
    key = Config.MASTER_ENCRYPTION_KEY
    if isinstance(key, str):
        key = key.encode('utf-8')
    return Fernet(key)

def encrypt_credential(plain_text: str) -> bytes:
    """
    Encrypts a plain-text credential (e.g. Google App Password)
    using AES-256 Fernet. Returns cipher bytes for database storage.
    """
    if not plain_text:
        return b""
    fernet = _get_fernet()
    # Normalize: strip spaces if Google gave 'abcd efgh ijkl mnop'
    cleaned = plain_text.replace(" ", "").strip()
    return fernet.encrypt(cleaned.encode('utf-8'))

def decrypt_credential(cipher_bytes) -> str:
    """
    Decrypts encrypted byte blob into a plain-text string.
    Decryption happens in memory strictly for the duration of IMAP query.
    """
    if not cipher_bytes:
        return ""
    fernet = _get_fernet()
    if isinstance(cipher_bytes, memoryview):
        cipher_bytes = bytes(cipher_bytes)
    elif isinstance(cipher_bytes, str):
        cipher_bytes = cipher_bytes.encode('utf-8')
    
    decrypted_bytes = fernet.decrypt(cipher_bytes)
    return decrypted_bytes.decode('utf-8')

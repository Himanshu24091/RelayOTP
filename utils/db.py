import os
import re
import sqlite3
import datetime
from contextlib import contextmanager
from config import Config, BASE_DIR

# Global connection pool for PostgreSQL if enabled
pg_pool = None
IS_POSTGRES = False

def init_db_connection():
    global pg_pool, IS_POSTGRES
    db_url = Config.DATABASE_URL
    if db_url and (db_url.startswith('postgres://') or db_url.startswith('postgresql://')):
        # Normalize postgres:// to postgresql://
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        try:
            import psycopg2
            from psycopg2 import pool
            pg_pool = pool.ThreadedConnectionPool(minconn=1, maxconn=10, dsn=db_url)
            IS_POSTGRES = True
            print("[RelayOTP] Connected to PostgreSQL successfully.")
            return
        except Exception as e:
            print(f"[RelayOTP] PostgreSQL connection failed: {e}. Falling back to SQLite.")
            IS_POSTGRES = False
    else:
        IS_POSTGRES = False
        print("[RelayOTP] No PostgreSQL DATABASE_URL detected. Using SQLite for storage.")

def get_sqlite_path():
    db_name = os.environ.get('SQLITE_DB_NAME', 'relay_otp.db')
    return os.path.join(BASE_DIR, db_name)

@contextmanager
def get_db_connection():
    global pg_pool, IS_POSTGRES
    if IS_POSTGRES:
        if pg_pool is None:
            init_db_connection()
        if pg_pool:
            import psycopg2.extras
            conn = pg_pool.getconn()
            try:
                if conn.closed:
                    pg_pool.putconn(conn, close=True)
                    conn = pg_pool.getconn()
                yield conn
            finally:
                if conn:
                    pg_pool.putconn(conn)
            return

    sqlite_file = get_sqlite_path()
    conn = sqlite3.connect(sqlite_file, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()

def _adapt_params(params):
    if not IS_POSTGRES or not params:
        return params or ()
    import psycopg2
    adapted = []
    for p in params:
        if isinstance(p, (bytes, bytearray)):
            adapted.append(psycopg2.Binary(p))
        else:
            adapted.append(p)
    return tuple(adapted)

def _adapt_query(query: str) -> str:
    """Adapts Postgres style queries (%s placeholders, types) to SQLite if needed."""
    if IS_POSTGRES:
        return query
    
    # Replace %s with ? for SQLite
    query = re.sub(r'(?<!%)(%s)', '?', query)
    
    # SQLite translations for datetime arithmetic:
    # e.g., NOW() -> CURRENT_TIMESTAMP
    query = re.sub(r'\bNOW\(\)', 'CURRENT_TIMESTAMP', query, flags=re.IGNORECASE)
    # NOW() - INTERVAL '10 MINUTE' -> datetime('now', '-10 minutes')
    query = re.sub(r"CURRENT_TIMESTAMP\s*-\s*INTERVAL\s*'10\s*MINUTE'", "datetime('now', '-10 minutes')", query, flags=re.IGNORECASE)
    query = re.sub(r"CURRENT_TIMESTAMP\s*-\s*INTERVAL\s*'10\s*MINUTES'", "datetime('now', '-10 minutes')", query, flags=re.IGNORECASE)
    query = re.sub(r"CURRENT_TIMESTAMP\s*\+\s*INTERVAL\s*'12\s*HOURS'", "datetime('now', '+12 hours')", query, flags=re.IGNORECASE)
    query = re.sub(r"CURRENT_TIMESTAMP\s*\+\s*INTERVAL\s*'12\s*HOUR'", "datetime('now', '+12 hours')", query, flags=re.IGNORECASE)
    return query

def execute_query(query: str, params=None, commit=True):
    """Executes a query (INSERT, UPDATE, DELETE). Returns lastrowid or rowcount."""
    adapted = _adapt_query(query)
    clean_params = _adapt_params(params)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(adapted, clean_params)
            if commit:
                conn.commit()
            last_id = None
            if hasattr(cursor, 'lastrowid'):
                last_id = cursor.lastrowid
            return last_id or cursor.rowcount
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

def fetch_one(query: str, params=None):
    """Fetches a single row as a dictionary."""
    adapted = _adapt_query(query)
    clean_params = _adapt_params(params)
    with get_db_connection() as conn:
        if IS_POSTGRES:
            import psycopg2.extras
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()
        
        try:
            cursor.execute(adapted, clean_params)
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(row)
        finally:
            cursor.close()

def fetch_all(query: str, params=None):
    """Fetches all rows as a list of dictionaries."""
    adapted = _adapt_query(query)
    clean_params = _adapt_params(params)
    with get_db_connection() as conn:
        if IS_POSTGRES:
            import psycopg2.extras
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cursor = conn.cursor()
        
        try:
            cursor.execute(adapted, clean_params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            cursor.close()

def init_db():
    """Initializes the database schema."""
    init_db_connection()

    if IS_POSTGRES:
        users_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            gmail_address VARCHAR(255) DEFAULT NULL,
            encrypted_app_password BYTEA DEFAULT NULL,
            mailbox_access_code VARCHAR(10) DEFAULT NULL,
            access_code_expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        otps_table_sql = """
        CREATE TABLE IF NOT EXISTS otps (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            sender_name VARCHAR(100) NOT NULL,
            subject_snippet VARCHAR(180),
            otp_code TEXT NOT NULL,
            item_type VARCHAR(20) DEFAULT 'code',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        index_sql = """
        CREATE INDEX IF NOT EXISTS idx_otps_user_lifecycle ON otps(user_id, created_at);
        """
    else:
        users_table_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            gmail_address VARCHAR(255) DEFAULT NULL,
            encrypted_app_password BLOB DEFAULT NULL,
            mailbox_access_code VARCHAR(10) DEFAULT NULL,
            access_code_expires_at TIMESTAMP DEFAULT NULL,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        otps_table_sql = """
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            sender_name VARCHAR(100) NOT NULL,
            subject_snippet VARCHAR(180),
            otp_code TEXT NOT NULL,
            item_type VARCHAR(20) DEFAULT 'code',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        index_sql = """
        CREATE INDEX IF NOT EXISTS idx_otps_user_lifecycle ON otps(user_id, created_at);
        """

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(users_table_sql)
            cursor.execute(otps_table_sql)
            cursor.execute(index_sql)
            conn.commit()
            # Migration check for existing SQLite / Postgres tables
            try:
                cursor.execute("ALTER TABLE otps ADD COLUMN item_type VARCHAR(20) DEFAULT 'code'")
                conn.commit()
            except Exception:
                pass
            print("[RelayOTP] Database schema initialized successfully.")
        except Exception as e:
            conn.rollback()
            print(f"[RelayOTP] Error initializing database: {e}")
            raise
        finally:
            cursor.close()

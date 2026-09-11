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
            is_suspended BOOLEAN DEFAULT FALSE,
            suspended_until TIMESTAMP WITH TIME ZONE DEFAULT NULL,
            suspension_reason TEXT DEFAULT NULL,
            must_change_password BOOLEAN DEFAULT FALSE,
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
        admin_notices_sql = """
        CREATE TABLE IF NOT EXISTS admin_notices (
            id SERIAL PRIMARY KEY,
            target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(120) NOT NULL,
            message TEXT NOT NULL,
            severity VARCHAR(20) DEFAULT 'info',
            is_dismissible BOOLEAN DEFAULT TRUE,
            expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        user_notice_reads_sql = """
        CREATE TABLE IF NOT EXISTS user_notice_reads (
            id SERIAL PRIMARY KEY,
            notice_id INTEGER REFERENCES admin_notices(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            dismissed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(notice_id, user_id)
        );
        """
        help_requests_sql = """
        CREATE TABLE IF NOT EXISTS help_requests (
            id SERIAL PRIMARY KEY,
            ticket_ref VARCHAR(20) UNIQUE NOT NULL,
            username VARCHAR(50) NOT NULL,
            contact_info VARCHAR(150) DEFAULT NULL,
            request_type VARCHAR(30) DEFAULT 'password_reset',
            user_message TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            admin_notes TEXT DEFAULT NULL,
            temp_password VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
        );
        """
        index_sql = """
        CREATE INDEX IF NOT EXISTS idx_otps_user_lifecycle ON otps(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_notices_target ON admin_notices(target_user_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_help_status ON help_requests(status, created_at);
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
            is_suspended BOOLEAN DEFAULT 0,
            suspended_until TIMESTAMP DEFAULT NULL,
            suspension_reason TEXT DEFAULT NULL,
            must_change_password BOOLEAN DEFAULT 0,
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
        admin_notices_sql = """
        CREATE TABLE IF NOT EXISTS admin_notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(120) NOT NULL,
            message TEXT NOT NULL,
            severity VARCHAR(20) DEFAULT 'info',
            is_dismissible BOOLEAN DEFAULT 1,
            expires_at TIMESTAMP DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        user_notice_reads_sql = """
        CREATE TABLE IF NOT EXISTS user_notice_reads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            notice_id INTEGER REFERENCES admin_notices(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            dismissed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(notice_id, user_id)
        );
        """
        help_requests_sql = """
        CREATE TABLE IF NOT EXISTS help_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_ref VARCHAR(20) UNIQUE NOT NULL,
            username VARCHAR(50) NOT NULL,
            contact_info VARCHAR(150) DEFAULT NULL,
            request_type VARCHAR(30) DEFAULT 'password_reset',
            user_message TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'pending',
            admin_notes TEXT DEFAULT NULL,
            temp_password VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP DEFAULT NULL
        );
        """
        index_sql = """
        CREATE INDEX IF NOT EXISTS idx_otps_user_lifecycle ON otps(user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_notices_target ON admin_notices(target_user_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_help_status ON help_requests(status, created_at);
        """

    tables_to_init = [
        ("users", users_table_sql),
        ("otps", otps_table_sql),
        ("admin_notices", admin_notices_sql),
        ("user_notice_reads", user_notice_reads_sql),
        ("help_requests", help_requests_sql),
        ("system_settings", """
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_key VARCHAR(60) PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
    ]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for tbl_name, tbl_sql in tables_to_init:
            try:
                cursor.execute(tbl_sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"[RelayOTP] Schema creation note for {tbl_name}: {e}")

        # Indexes
        for idx_stmt in index_sql.strip().split(';'):
            clean_stmt = idx_stmt.strip()
            if clean_stmt:
                try:
                    cursor.execute(clean_stmt)
                    conn.commit()
                except Exception as e:
                    conn.rollback()

        # Schema migrations for existing databases (Postgres & SQLite)
        if IS_POSTGRES:
            pg_migrations = [
                "ALTER TABLE otps ADD COLUMN IF NOT EXISTS item_type VARCHAR(20) DEFAULT 'code'",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMP WITH TIME ZONE DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS suspension_reason TEXT DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS mailbox_access_code VARCHAR(10) DEFAULT NULL",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS access_code_expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL"
            ]
            for stmt in pg_migrations:
                try:
                    cursor.execute(stmt)
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    print(f"[RelayOTP] Migration note on '{stmt}': {e}")
        else:
            sqlite_migrations = [
                ("otps", "item_type", "VARCHAR(20) DEFAULT 'code'"),
                ("users", "is_suspended", "BOOLEAN DEFAULT 0"),
                ("users", "suspended_until", "TIMESTAMP DEFAULT NULL"),
                ("users", "suspension_reason", "TEXT DEFAULT NULL"),
                ("users", "must_change_password", "BOOLEAN DEFAULT 0"),
                ("users", "is_admin", "BOOLEAN DEFAULT 0"),
                ("users", "mailbox_access_code", "VARCHAR(10) DEFAULT NULL"),
                ("users", "access_code_expires_at", "TIMESTAMP DEFAULT NULL")
            ]
            for tbl, col, col_def in sqlite_migrations:
                try:
                    cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_def}")
                    conn.commit()
                except Exception:
                    conn.rollback()

        cursor.close()
        print("[RelayOTP] Database schema and migrations initialized successfully.")

    # Ensure dedicated Super Admin account exists
    ensure_default_admin()


def ensure_default_admin():
    """Ensures a dedicated Super Admin account exists in the database."""
    try:
        import bcrypt
        admin_username = Config.ADMIN_DEFAULT_USER
        admin_pass = Config.ADMIN_DEFAULT_PASSWORD
        existing = fetch_one("SELECT id, is_admin FROM users WHERE username = %s", (admin_username,))
        if not existing:
            hashed = bcrypt.hashpw(admin_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            execute_query(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                (admin_username, hashed, True if IS_POSTGRES else 1)
            )
            print(f"[RelayOTP] Dedicated Super Admin account '{admin_username}' initialized.")
        elif not existing.get('is_admin'):
            execute_query("UPDATE users SET is_admin = %s WHERE id = %s", (True if IS_POSTGRES else 1, existing['id']))
    except Exception as e:
        print(f"[RelayOTP] Note on default admin init: {e}")


def get_system_setting(key: str, default: str = None) -> str:
    """Retrieves a persistent system configuration value."""
    try:
        row = fetch_one("SELECT setting_value FROM system_settings WHERE setting_key = %s", (key,))
        if row and row.get('setting_value') is not None:
            return str(row['setting_value']).strip()
    except Exception:
        pass
    return default


def set_system_setting(key: str, value: str):
    """Persists a system configuration key-value pair."""
    if IS_POSTGRES:
        execute_query(
            """
            INSERT INTO system_settings (setting_key, setting_value, updated_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = CURRENT_TIMESTAMP
            """,
            (key, str(value).strip())
        )
    else:
        execute_query(
            """
            INSERT INTO system_settings (setting_key, setting_value, updated_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP
            """,
            (key, str(value).strip())
        )


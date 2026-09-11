# ⚡ RelayOTP - Ephemeral Verification & Magic Link Gateway

> **Privacy-first, zero-trace verification gateway for corporate workstations and restricted networks.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/)

---

## 🌟 Key Features

- 🛡️ **IMAP PEEK Pipeline (Zero Mailbox Trace)**: Reads verification emails from Gmail via SSL/TLS using the `BODY.PEEK[]` flag — target emails remain completely **UNREAD** in your Gmail inbox.
- 🔐 **AES-256 Fernet Credential Vault**: Stores Gmail App Passwords encrypted at rest using AES-256 (Fernet). Passwords are only decrypted in-memory during active IMAP fetch cycles.
- 🌐 **In-App Privacy Sandbox**: Preview and interact with Magic Links, account verification pages, and confirmation portals directly inside an in-app sandbox modal. Never leaves URLs in browser history.
- 🤖 **Anthropic Claude & Google Auth Support**: Dedicated in-app token extraction and zero-referrer stealth launch for client-side single-page applications.
- ⚡ **Silent Server-Side Token Trigger**: Verify accounts directly from the server background (`/api/trigger-verification`) without opening any external browser tabs.
- ⏳ **12-Hour Mailbox Gatekeeper**: Enforces an ephemeral session lock requiring a rotating 12-hour alphanumeric passcode (e.g. `TK-9281`) to access mailbox data.
- 🎭 **Camouflage Terminal Mode**: Double-tap `ESC` anywhere to instantly swap the UI for an active Linux kernel/Prometheus terminal display.
- 📋 **Tactile Clipboard & Auto-Clear**: Fallback-resilient clipboard support with automatic 30-second memory purging.
- 📱 **Ultra-Responsive UI**: Desktop table view and optimized mobile cards layout with glassmorphic aesthetic.
- 🚂 **Production Ready for Railway**: Includes `Procfile`, `nixpacks.toml`, `Dockerfile`, `gunicorn.conf.py`, and automatic PostgreSQL integration.

---

## 📁 Project Structure

```
RelayOTP/
├── app.py                  # Application entrypoint, CSP, and security middleware
├── config.py               # Dynamic config loader (PostgreSQL / SQLite, secrets)
├── gunicorn.conf.py        # Production WSGI server configuration
├── Procfile                # Railway / Heroku process declaration
├── nixpacks.toml           # Railway Nixpacks build definition
├── Dockerfile              # Containerized Docker build
├── requirements.txt        # Production dependencies
├── routers/
│   ├── auth_router.py      # User authentication & rate limiting
│   ├── dashboard_router.py # Main verification dashboard
│   ├── profile_router.py   # 12-Hour passcode lifecycle management
│   ├── settings_router.py  # Gmail App Password vault & encryption
│   ├── admin_router.py     # Administrative controls
│   └── api_router.py       # IMAP scanner, sandbox proxy & silent verification
├── utils/
│   ├── db.py               # Unified PostgreSQL / SQLite database adapter
│   ├── crypto.py           # AES-256 Fernet encryption / decryption
│   └── imap_client.py      # Gmail IMAP PEEK parser & regex extractor
├── static/
│   ├── css/style.css       # Core design system & responsive UI
│   ├── css/camouflage.css  # Terminal camouflage styling
│   ├── js/app.js           # Dashboard controller & sandbox manager
│   ├── js/stealth.js       # Camouflage hotkey & anti-tracking
│   └── js/mailbox_lock.js  # Gatekeeper modal controller
└── templates/              # Jinja2 security-hardened templates
```

---

## 🚀 Quickstart (Local Development)

### 1. Prerequisites
- Python 3.10+
- A Google Account with 2-Step Verification enabled and a 16-character **App Password**.

### 2. Installation

```bash
# Clone repository
git clone https://github.com/Himanshu24091/RelayOTP.git
cd RelayOTP

# Create virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Generate Encryption Keys

```bash
# Generate MASTER_ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"

# Generate SECRET_KEY
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

### 4. Create `.env` file

```env
FLASK_ENV=development
SECRET_KEY=your-generated-secret-key
MASTER_ENCRYPTION_KEY=your-generated-fernet-key
DATABASE_URL=
```

### 5. Run Application

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🚂 Deploying to Railway

1. Push your repository to **GitHub**:
   ```bash
   git init
   git add .
   git commit -m "feat: RelayOTP production release"
   git branch -M main
   git remote add origin https://github.com/Himanshu24091/RelayOTP.git
   git push -u origin main
   ```

2. Open **[Railway.com](https://railway.com/)** and click **New Project** → **Deploy from GitHub repo**.
3. Select `RelayOTP`.
4. Add a **PostgreSQL Database** to the project (**+ New** → **Database** → **PostgreSQL**).
5. In your web service **Variables**, add:
   - `MASTER_ENCRYPTION_KEY` = *(Your 44-char Fernet Key)*
   - `SECRET_KEY` = *(Your 64-char Hex Secret)*
   - `FLASK_ENV` = `production`
6. Under **Settings** → **Networking**, click **Generate Domain**.
7. Railway will automatically build and deploy the app with HTTPS!

Detailed guide: [RAILWAY_DEPLOY_GUIDE.md](RAILWAY_DEPLOY_GUIDE.md).

---

## 🔒 Security & Privacy Architecture

| Component | Security Implementation |
|---|---|
| **App Password Storage** | AES-256 (Fernet) encryption at rest with PBKDF2 HMAC SHA-256 master key derivation |
| **Mailbox Inspection** | `IMAP4_SSL` read-only peek mode (`BODY.PEEK[]`); messages are never marked `\Seen` |
| **Data Retention** | Ephemeral TTL: all OTPs and Magic Links are permanently purged after 10 minutes |
| **Network Privacy** | All outbound navigation enforces `rel="noreferrer noopener"` to strip HTTP Referer headers |
| **Sandbox Isolation** | In-app iframe enforces strict CSP, `X-Frame-Options: SAMEORIGIN`, and isolated browsing context |

---

## 📄 License

MIT License © 2025 RelayOTP

# ⚡ RelayOTP - Ephemeral Verification & Magic Link Gateway

> **Privacy-first, zero-trace verification gateway for corporate workstations, restricted networks, and multi-tenant teams.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/)

---

## 🌟 Key Features

- 🛡️ **IMAP PEEK Pipeline (Zero Mailbox Trace)**: Reads verification emails from Gmail via SSL/TLS using the `BODY.PEEK[]` protocol — target emails remain completely **UNREAD** in your Gmail inbox.
- 🔐 **AES-256 Fernet Credential Vault**: Stores Gmail App Passwords encrypted at rest using AES-256 (Fernet). Passwords are only decrypted in-memory during active IMAP fetch cycles.
- 🌐 **In-App Privacy Sandbox**: Preview and interact with Magic Links, account verification pages, and confirmation portals directly inside an in-app sandbox modal. Never leaves URLs in browser history.
- 👑 **Super Admin Control Console (`/admin`)**: Fully decoupled administrative portal accessible via dedicated Admin credentials or instant Master PIN (`123456`). Manage tenant lifecycles, broadcast security notices, and configure credentials live without server restarts.
- 🎫 **Public Help Desk & Password Reset (`/help`)**: Self-service support portal where users can submit reset tickets (e.g. `REQ-849201`) and retrieve Super-Admin-generated temporary passwords.
- 🚫 **Granular Tenant Governance**: 1-click account suspensions with customizable timer presets (Same Day 24h, 3 Days, 7 Days, Indefinite), instant session cutoffs, and 1-click reactivations.
- 📢 **Admin Notices & Warning Dispatcher**: Broadcast announcements or send targeted security warnings to specific tenants with severity levels (`notice`, `timed`, `warning`, `critical`).
- ⏳ **12-Hour Mailbox Gatekeeper**: Enforces an ephemeral session lock requiring a rotating 12-hour alphanumeric passcode (e.g. `TK-9281`) to access mailbox data.
- 🎭 **Camouflage Terminal Mode**: Double-tap `ESC` anywhere to instantly swap the UI for an active Linux kernel/Prometheus terminal display.
- 📋 **Tactile Clipboard & Auto-Clear**: Fallback-resilient clipboard copy with automatic 30-second memory purging (configurable in Settings).
- ⚙️ **Dual-Engine Persistence**: Seamless auto-switching between local SQLite and production PostgreSQL (Railway).
- 📱 **Ultra-Responsive Glassmorphic UI**: High-contrast, accessibility-tested theme across desktop, tablet, and mobile displays.

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
├── .env.example            # Environment variables blueprint
├── routers/
│   ├── auth_router.py      # User authentication, registration & suspension guards
│   ├── dashboard_router.py # Main verification dashboard & notice display
│   ├── profile_router.py   # 12-Hour passcode lifecycle management
│   ├── settings_router.py  # Gmail App Password vault & privacy preferences
│   ├── admin_router.py     # Super Admin console, suspensions & credentials manager
│   ├── help_router.py      # Public help desk & password reset ticketing
│   └── api_router.py       # IMAP scanner, sandbox proxy & silent verification
├── utils/
│   ├── db.py               # Unified PostgreSQL / SQLite database adapter
│   ├── crypto.py           # AES-256 Fernet encryption / decryption
│   ├── code_gen.py         # 12-hour rotating passcode generator
│   └── imap_client.py      # Gmail IMAP PEEK parser & regex extractor
├── static/
│   ├── css/style.css       # Core design system & responsive UI
│   ├── css/camouflage.css  # Terminal camouflage styling
│   ├── js/app.js           # Dashboard controller, preferences & sandbox manager
│   ├── js/stealth.js       # Camouflage hotkey & anti-tracking
│   └── js/mailbox_lock.js  # Gatekeeper modal controller
├── templates/              # Jinja2 security-hardened templates
│   ├── admin.html          # Super Admin command console (4 tabs)
│   ├── admin_login.html    # Dedicated stealth admin login gate
│   ├── help.html           # Public help desk (submit ticket & check status)
│   ├── dashboard.html      # Primary OTP & Magic Link interface
│   ├── settings.html       # Gmail App Password setup & privacy toggles
│   └── ...
└── tests/
    └── test_relay_otp.py   # Full automated test suite (11 test cases)
```

---

## 👑 Super Admin Access & Management

The Super Admin portal is intentionally **decoupled** from the standard user navbar for security.

### Accessing the Admin Console
- **URL**: Navigate to `/admin` (e.g. `http://localhost:5000/admin` or `https://your-domain.up.railway.app/admin`).
- **Method 1 - Master PIN**: Enter your Master PIN (Default: `123456`) and click **Unlock Console**.
- **Method 2 - Credentials**: Sign in with dedicated Super Admin credentials (Default: `admin` / `admin123`).

### Customizing Admin ID, Password, and Master PIN
You can change these anytime in two ways:
1. **Directly from Web UI (Tab 4)**: Inside `/admin`, open the **⚙️ Maintenance** tab. Under **Super Admin Credentials & Master Access PIN**, update your Master PIN, Admin Username, or Admin Password in 1 click.
2. **Via Environment Variables**: Set `ADMIN_MASTER_KEY`, `ADMIN_DEFAULT_USER`, and `ADMIN_DEFAULT_PASSWORD` in your `.env` or Railway Variables tab.

---

## 🎫 Public Help Desk (`/help`)

If a tenant loses access or forgets their password:
1. User visits `/help` and submits a request with their username and issue description.
2. The user receives a unique reference tracking ID (e.g. `REQ-849201`).
3. Super Admin views the ticket in `/admin` (Tab 3) and clicks **⚡ Reset & Inform**.
4. A temporary password (e.g. `RelayPass#849201`) is generated, and an instant communication slip is copied to clipboard.
5. User checks `/help` -> **Check Ticket Status** to retrieve their temporary password.
6. Upon signing in, the user is required to set a new password before accessing their dashboard.

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
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Generate Security Keys

```bash
# Generate MASTER_ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"

# Generate SECRET_KEY
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

### 4. Configure `.env` File

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```env
FLASK_ENV=development
SECRET_KEY=your-generated-secret-key
MASTER_ENCRYPTION_KEY=your-generated-fernet-key
DATABASE_URL=

# Super Admin Credentials
ADMIN_MASTER_KEY=123456
ADMIN_DEFAULT_USER=admin
ADMIN_DEFAULT_PASSWORD=admin123
```

### 5. Run Application

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## 🚂 Deploying to Railway

1. Push your latest code to **GitHub**:
   ```bash
   git add .
   git commit -m "feat: complete Super Admin console, helpdesk and preferences"
   git push origin main
   ```

2. Open **[Railway.app](https://railway.app/)** and create a **New Project** → **Deploy from GitHub repo**.
3. Select `RelayOTP`.
4. Provision a **PostgreSQL Database** in the project (**+ New** → **Database** → **PostgreSQL**).
5. In your web service **Variables**, add:
   | Variable | Description | Example / Recommended |
   |---|---|---|
   | `MASTER_ENCRYPTION_KEY` | AES-256 Fernet encryption key | *(44-char Fernet string)* |
   | `SECRET_KEY` | Flask session cookie signer | *(64-char Hex string)* |
   | `FLASK_ENV` | Environment mode | `production` |
   | `ADMIN_MASTER_KEY` | PIN for instant `/admin` unlock | *(e.g. 6-digit PIN)* |
   | `ADMIN_DEFAULT_USER` | Initial Super Admin username | `admin` |
   | `ADMIN_DEFAULT_PASSWORD` | Initial Super Admin password | *(strong password)* |

6. Under **Settings** → **Networking**, click **Generate Domain**.
7. Railway will automatically build via `nixpacks.toml` and serve via Gunicorn with HTTPS.

---

## 🧪 Running Automated Tests

Run the complete test suite locally:

```bash
python -m unittest discover -s tests
```

---

## 🔒 Security & Privacy Architecture

| Component | Security Implementation |
|---|---|
| **App Password Storage** | AES-256 (Fernet) encryption at rest with PBKDF2 HMAC SHA-256 master key derivation |
| **Mailbox Inspection** | `IMAP4_SSL` read-only peek mode (`BODY.PEEK[]`); messages are never marked `\Seen` |
| **Data Retention** | Ephemeral TTL: all OTPs and Magic Links are permanently purged after 10 minutes |
| **Network Privacy** | All outbound navigation enforces `rel="noreferrer noopener"` to strip HTTP Referer headers |
| **Sandbox Isolation** | In-app iframe enforces strict CSP, `X-Frame-Options: SAMEORIGIN`, and isolated browsing context |
| **Admin Authorization** | Dual-gated authentication with bcrypt hashing, session validation, and database role checks |
| **Session Cutoffs** | Instant termination of active user sessions upon suspension or credential reset |

---

## 📄 License

MIT License © 2025 RelayOTP

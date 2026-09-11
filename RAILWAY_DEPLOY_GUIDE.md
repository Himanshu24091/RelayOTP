# 🚂 RelayOTP - Railway Production Deployment Guide

This guide walks you through deploying **RelayOTP** to [Railway](https://railway.com/) with a production-grade setup: **PostgreSQL database**, **Gunicorn multi-threaded WSGI server**, **automated HTTPS**, and **persistent AES-256 encryption**.

---

## 📁 1. Railway Configuration Files (Already Configured in Codebase)

Your project already includes all necessary configuration files ready for Railway:

| File | Purpose |
|---|---|
| [`Procfile`](file:///c:/Users/himan/Desktop/Email%20OTP/Procfile) | Defines web service start command (`gunicorn app:app`) |
| [`gunicorn.conf.py`](file:///c:/Users/himan/Desktop/Email%20OTP/gunicorn.conf.py) | Binds dynamically to Railway's `$PORT`, configures 2 workers & 4 threads |
| [`railway.json`](file:///c:/Users/himan/Desktop/Email%20OTP/railway.json) | Configures Nixpacks builder, health check (`/health`), and restart policy |
| [`nixpacks.toml`](file:///c:/Users/himan/Desktop/Email%20OTP/nixpacks.toml) | Specifies Python 3.11 and native PostgreSQL `libpq` client libraries |
| [`Dockerfile`](file:///c:/Users/himan/Desktop/Email%20OTP/Dockerfile) | Standalone container alternative if you prefer Docker builder |
| [`.gitignore`](file:///c:/Users/himan/Desktop/Email%20OTP/.gitignore) | Keeps `.env`, local `.dev_master.key`, and SQLite files off your Git repo |

---

## 🔑 2. Generate Production Encryption Keys

Before deploying, generate two 256-bit cryptographic keys on your machine:

Open PowerShell / Terminal in your project and run:

```powershell
# Generate MASTER_ENCRYPTION_KEY (Fernet AES-256)
.\venv\Scripts\python -c "from cryptography.fernet import Fernet; print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"

# Generate SECRET_KEY (Flask session secret)
.\venv\Scripts\python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

> [!IMPORTANT]
> Save the generated `MASTER_ENCRYPTION_KEY`. You **must** set this in your Railway Environment Variables so that saved Gmail App Passwords persist across restarts and re-deployments!

---

## 🚀 3. Deployment Steps on Railway

### Step 3.1: Push Project to GitHub

1. Initialize git (if not already done) and commit the project:
   ```bash
   git init
   git add .
   git commit -m "feat: RelayOTP v2.0 with Railway config, PostgreSQL, and Magic Link gateway"
   ```
2. Create a new repository on [GitHub](https://github.com/new) (Private recommended).
3. Link and push your repository:
   ```bash
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git branch -M main
   git push -u origin main
   ```

---

### Step 3.2: Create Project on Railway

1. Log into [railway.com](https://railway.com/).
2. Click **"+ New Project"**.
3. Select **"Deploy from GitHub repo"** and choose your repository.
4. Railway will automatically detect the repository and start building.

---

### Step 3.3: Add Managed PostgreSQL Database (1-Click)

1. In your Railway Project canvas, click **"+ Create"** (or press `Ctrl + K` / `Cmd + K`).
2. Select **"Database"** &rarr; **"Add PostgreSQL"**.
3. Railway will provision a dedicated PostgreSQL database container in a few seconds.
4. Railway automatically connects the database to your web service and injects the **`DATABASE_URL`** variable into your app!

---

### Step 3.4: Configure Environment Variables

1. Click on your **Web Service** card (the one deployed from your GitHub repo).
2. Go to the **"Variables"** tab.
3. Click **"New Variable"** (or **"RAW Editor"**) and add the following variables:

```ini
# Core Environment
FLASK_ENV=production

# The SECRET_KEY generated in Step 2
SECRET_KEY=your_generated_secret_key_here

# The MASTER_ENCRYPTION_KEY generated in Step 2 (CRITICAL FOR VAULT PERSISTENCE)
MASTER_ENCRYPTION_KEY=your_generated_fernet_key_here

# Administrative claims password
ADMIN_SECRET=admin123_change_this

# IMAP Performance Constraints
IMAP_SERVER=imap.gmail.com
IMAP_PORT=993
IMAP_TIMEOUT_SECONDS=8
MAX_EMAILS_PER_FETCH=15
```

> [!NOTE]
> You do **NOT** need to manually add `DATABASE_URL` or `PORT`. 
> - Railway's Postgres plugin automatically provides `DATABASE_URL`.
> - Railway automatically sets `PORT`.

---

### Step 3.5: Generate Public Domain

1. In your Web Service on Railway, go to the **"Settings"** tab.
2. Under **"Networking"**, find **"Public Networking"**.
3. Click **"Generate Domain"** (or enter your custom domain).
4. Railway will assign you an HTTPS URL like:
   `https://relayotp-production-xxxx.up.railway.app`

---

## ✅ 4. Verification & Health Check

1. **Verify Health Endpoint**:
   Open:
   ```
   https://YOUR_APP_DOMAIN.up.railway.app/health
   ```
   It should return:
   ```json
   {
     "service": "RelayOTP Gateway",
     "status": "healthy",
     "version": "2.0.0"
   }
   ```

2. **Register First User**:
   - Go to `https://YOUR_APP_DOMAIN.up.railway.app/register`.
   - The first user registered automatically becomes the **System Administrator**.

3. **Connect Gmail in Settings**:
   - Go to `/settings`.
   - Enter your personal Gmail and 16-character Google App Password.
   - Click **"Test IMAP Connection"** &rarr; **"Save Gmail Credentials"**.

4. **Test OTP & Magic Link Fetch**:
   - Go to `/dashboard`.
   - Unlock with your 12-hour code.
   - Click **⚡ FETCH LATEST OTP** to verify live IMAP polling.

---

## 🛠️ Alternative: Deploy via Railway CLI

If you prefer deploying directly from your terminal without GitHub:

1. Install Railway CLI:
   ```powershell
   npm i -g @railway/cli
   ```
2. Login and link:
   ```powershell
   railway login
   railway init
   ```
3. Add Postgres:
   ```powershell
   railway add --database postgres
   ```
4. Set variables:
   ```powershell
   railway variables set FLASK_ENV=production
   railway variables set SECRET_KEY="your_secret_key"
   railway variables set MASTER_ENCRYPTION_KEY="your_fernet_key"
   railway variables set ADMIN_SECRET="admin123"
   ```
5. Deploy:
   ```powershell
   railway up
   ```
6. Open domain:
   ```powershell
   railway domain
   railway open
   ```

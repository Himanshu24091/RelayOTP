import os

# Port assigned dynamically by Railway (or fallback to 5000)
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Concurrency configuration
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("PYTHON_THREADS", "4"))
worker_class = "gthread"

# Timeouts & Keepalive
timeout = int(os.environ.get("WEB_TIMEOUT", "120"))
keepalive = 5

# Logging to stdout/stderr for Railway log streaming
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
capture_output = True
enable_stdio_inheritance = True

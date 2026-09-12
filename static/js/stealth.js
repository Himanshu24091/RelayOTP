/* RelayOTP - Stealth & Tab-Logout Controller */

let lastEscTime = 0;
let stealthInterval = null;

// Double-tap Escape listener
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    const now = Date.now();
    if (now - lastEscTime < 450) {
      toggleStealthMode();
      lastEscTime = 0;
    } else {
      lastEscTime = now;
    }
  }
});

function toggleStealthMode() {
  const isStealth = document.body.classList.toggle('stealth-active');
  const mainContent = document.querySelector('.main-content');
  const navbar = document.querySelector('.navbar');

  if (isStealth) {
    // 1. Zero-Trace Clipboard Purge
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText('').catch(() => {});
      } else {
        const t = document.createElement('textarea');
        t.value = '';
        t.style.position = 'fixed';
        t.style.top = '-9999px';
        document.body.appendChild(t);
        t.focus();
        t.select();
        document.execCommand('copy');
        document.body.removeChild(t);
      }
    } catch (err) {}

    // 2. Re-mask any unmasked OTP codes immediately
    document.querySelectorAll('.otp-box').forEach(el => {
      el.innerText = '• • • • • •';
      el.setAttribute('data-masked', 'true');
    });
    document.querySelectorAll('.btn-toggle-mask').forEach(btn => {
      btn.innerHTML = '👁️';
    });

    // 3. Accessibility and visual cloaking
    if (mainContent) {
      mainContent.setAttribute('aria-hidden', 'true');
      mainContent.style.filter = 'blur(30px)';
      mainContent.style.pointerEvents = 'none';
    }
    if (navbar) {
      navbar.setAttribute('aria-hidden', 'true');
      navbar.style.filter = 'blur(15px)';
    }

    startSimulatedLogs();
  } else {
    clearInterval(stealthInterval);
    if (mainContent) {
      mainContent.removeAttribute('aria-hidden');
      mainContent.style.filter = '';
      mainContent.style.pointerEvents = '';
    }
    if (navbar) {
      navbar.removeAttribute('aria-hidden');
      navbar.style.filter = '';
    }
  }
}

// Simulated Kubernetes / Cloud Pod Log Stream
function startSimulatedLogs() {
  const logContainer = document.getElementById('term-log-stream');
  if (!logContainer) return;

  const mockServices = ['auth-service', 'ingress-nginx', 'payment-worker', 'redis-replica', 'metric-collector'];
  const mockMessages = [
    'GET /healthz HTTP/1.1 200 OK 1.4ms',
    'Upstream keepalive connection reused (fd: 34)',
    'Flushed metrics buffer to Prometheus gateway (142 series)',
    'TLS handshake completed with 10.244.0.1:443 (TLS_AES_256_GCM_SHA384)',
    'Pod worker-c794f sync status: IN_SYNC [replica: 3/3]',
    'Cache hit ratio 98.4% across 4 shards',
    'GC cycle completed in 0.8ms (reclaimed 124MB)',
    'Kafka consumer group heartbeat acknowledged'
  ];

  clearInterval(stealthInterval);
  stealthInterval = setInterval(() => {
    const time = new Date().toISOString().substring(11, 19);
    const svc = mockServices[Math.floor(Math.random() * mockServices.length)];
    const msg = mockMessages[Math.floor(Math.random() * mockMessages.length)];
    
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML = `<span class="log-dim">[${time}]</span> <span class="log-info">[${svc}]</span> <span class="log-ok">INF</span> ${msg}`;
    logContainer.appendChild(div);
    
    // Auto-scroll
    logContainer.scrollTop = logContainer.scrollHeight;

    // Prune excessive lines
    if (logContainer.childElementCount > 60) {
      logContainer.removeChild(logContainer.firstElementChild);
    }
  }, 1200);
}

// Tab-Scoped Session Guard (Browser Tab Close Termination):
// HTML5 sessionStorage is strictly isolated to a single browser tab.
// - It natively survives all in-app navigation (Dashboard, Settings, Profile, Admin) and page reloads (F5, Ctrl+R, reload button).
// - When the browser tab or the browser window is closed, the browser automatically destroys sessionStorage.
// - If a closed tab is reopened, restored ("Continue where you left off"), or opened afresh, the missing tab token
//   immediately terminates the session and redirects to login with reason=tab_closed.
(function initTabScopedSession() {
  const config = window.RELAY_CONFIG || {};

  // If user is unauthenticated (e.g. on /login, /register, /admin/login):
  if (!config.isLoggedIn) {
    try {
      sessionStorage.setItem('relay_active_tab', '1');
    } catch (e) {}

    document.addEventListener('submit', () => {
      try {
        sessionStorage.setItem('relay_active_tab', '1');
      } catch (e) {}
    }, true);
    return;
  }

  // User is authenticated according to server session:
  const hasActiveTab = sessionStorage.getItem('relay_active_tab') === '1';
  const ref = document.referrer || '';
  const isFromAuth = ref.includes('/login') || ref.includes('/register') || ref.includes('/admin/login') || ref.includes('/change-password');

  if (!hasActiveTab) {
    if (isFromAuth) {
      // Just logged in from auth flow: mark tab as active
      try {
        sessionStorage.setItem('relay_active_tab', '1');
      } catch (e) {}
    } else {
      // Browser tab was closed and subsequently restored or opened in a fresh tab.
      // Terminate session immediately.
      const logoutUrl = config.isAdmin 
        ? '/admin/logout?reason=tab_closed' 
        : '/logout?reason=tab_closed';
      window.location.replace(logoutUrl);
      return;
    }
  } else {
    // Keep tab token confirmed
    try {
      sessionStorage.setItem('relay_active_tab', '1');
    } catch (e) {}
  }
})();

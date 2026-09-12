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

// Tab-Scoped Session Management & Instant Tab-Close Terminator:
// 1. In modern browsers, session cookies can persist across tab closes or restarts ("Continue where you left off").
// 2. We employ a dual-layer strategy:
//    - Layer 1 (navigator.sendBeacon): On pagehide/tab-close without internal navigation,
//      synchronously dispatch a beacon to /api/auth/tab-logout (or /admin/logout) to clear server session instantly.
//    - Layer 2 (sessionStorage Tab Guard): sessionStorage is isolated per tab and purged on tab close.
//      If an authenticated page loads without active tab state (restored/orphaned tab), immediately flush & logout.
(function initTabScopedSession() {
  const config = window.RELAY_CONFIG || {};

  // If user is unauthenticated, clean any lingering markers and listen for auth form submits
  if (!config.isLoggedIn) {
    try {
      sessionStorage.removeItem('relay_tab_active');
      sessionStorage.removeItem('relay_is_navigating');
    } catch (e) {}

    // When submitting login / register, flag internal navigation so next landing knows it's legitimate
    document.addEventListener('submit', () => {
      try {
        sessionStorage.setItem('relay_is_navigating', '1');
      } catch (e) {}
    }, true);
    return;
  }

  // Layer 2: Client Tab-Lifecycle Validation
  const hasActiveTab = sessionStorage.getItem('relay_tab_active') === '1';
  const wasNavigating = sessionStorage.getItem('relay_is_navigating') === '1';
  const ref = document.referrer || '';
  const isFromAuth = ref.includes('/login') || ref.includes('/register') || ref.includes('/admin/login') || ref.includes('/change-password');

  // If authenticated on server, but tab was opened afresh / restored without tab state or navigation flag
  if (!hasActiveTab && !wasNavigating && !isFromAuth) {
    const logoutUrl = config.isAdmin ? '/admin/logout?reason=tab_closed' : '/logout?reason=tab_closed';
    window.location.replace(logoutUrl);
    return;
  }

  // Tab is verified active
  try {
    sessionStorage.setItem('relay_tab_active', '1');
    sessionStorage.removeItem('relay_is_navigating');
  } catch (e) {}

  let isInternalNav = false;

  function markInternalNav() {
    isInternalNav = true;
    try {
      sessionStorage.setItem('relay_is_navigating', '1');
    } catch (e) {}
  }

  // Intercept internal link clicks
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a');
    if (!link) return;

    const href = link.getAttribute('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
    if (link.target === '_blank' || e.ctrlKey || e.metaKey || e.shiftKey) return;

    try {
      const destUrl = new URL(link.href, window.location.origin);
      if (destUrl.origin === window.location.origin) {
        markInternalNav();
      }
    } catch (err) {}
  }, true);

  // Intercept form submissions
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const action = form.getAttribute('action') || window.location.pathname;
    try {
      const destUrl = new URL(action, window.location.origin);
      if (destUrl.origin === window.location.origin) {
        markInternalNav();
      }
    } catch (err) {}
  }, true);

  // Detect keyboard reload shortcuts (F5, Ctrl+R, Cmd+R)
  window.addEventListener('keydown', (e) => {
    if (e.key === 'F5' || ((e.ctrlKey || e.metaKey) && (e.key === 'r' || e.key === 'R'))) {
      markInternalNav();
    }
  });

  // Layer 1: sendBeacon on Tab/Browser Close
  const beaconEndpoint = config.isAdmin ? '/admin/tab-close-beacon' : '/api/auth/tab-close-beacon';

  function handleTabTermination(e) {
    if (e && e.persisted) return; // bfcache (back/forward history navigation)

    // Check if internal navigation was flagged
    if (isInternalNav || sessionStorage.getItem('relay_is_navigating') === '1') {
      return;
    }

    // Tab is closing, browser is quitting, or user navigated to an external website
    const payload = JSON.stringify({ reason: 'tab_closed' });
    if (navigator.sendBeacon) {
      const blob = new Blob([payload], { type: 'application/json' });
      navigator.sendBeacon(beaconEndpoint, blob);
    } else {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', beaconEndpoint, false);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(payload);
    }
  }

  window.addEventListener('pagehide', handleTabTermination);
  window.addEventListener('beforeunload', () => {
    // Keep internal navigation synchronized
  });
})();

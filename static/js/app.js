/* RelayOTP - Main Application Frontend Controller */

// Global Toast Notification Utility
window.showToast = function(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'danger' || type === 'error') icon = '❌';
  if (type === 'warning') icon = '⚠️';

  toast.innerHTML = `<span class="toast-icon">${icon}</span> <span class="toast-msg">${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
};

// Fallback clipboard copy using hidden textarea for non-secure contexts (HTTP, local IPs, restricted permissions)
function fallbackCopyText(text) {
  try {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.top = '-9999px';
    textArea.style.left = '-9999px';
    textArea.style.width = '2em';
    textArea.style.height = '2em';
    textArea.style.padding = '0';
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';
    textArea.style.background = 'transparent';
    textArea.setAttribute('readonly', '');
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    textArea.setSelectionRange(0, textArea.value.length);
    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);
    return successful;
  } catch (err) {
    console.error('Fallback clipboard copy failed:', err);
    return false;
  }
}

// Clipboard Handler with Tactile Visual Feedback & Configurable 30s Auto-Clear
window.copyToClipboard = function(text, label = "Code", triggerButton = null) {
  if (!text) return;

  const shouldAutoClear = localStorage.getItem('relay_pref_auto_clear') !== 'false';

  const onSuccess = () => {
    if (shouldAutoClear) {
      window.showToast(`${label} copied! Clipboard will clear in 30s.`, 'success');
    } else {
      window.showToast(`${label} copied to clipboard!`, 'success');
    }

    // Tactile button feedback
    if (triggerButton) {
      const originalHtml = triggerButton.innerHTML;
      triggerButton.innerHTML = '✅ Copied!';
      triggerButton.classList.add('btn-copied-active');
      setTimeout(() => {
        triggerButton.innerHTML = originalHtml;
        triggerButton.classList.remove('btn-copied-active');
      }, 2000);
    }

    // 30s memory clear if enabled in Privacy Preferences
    if (shouldAutoClear) {
      setTimeout(() => {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          navigator.clipboard.writeText('').catch(() => {});
        } else {
          fallbackCopyText('');
        }
      }, 30000);
    }
  };

  const onFail = () => {
    window.showToast("Failed to copy to clipboard", "danger");
  };

  // Modern Async Clipboard API (Available in Secure Contexts: HTTPS / localhost)
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    navigator.clipboard.writeText(text)
      .then(onSuccess)
      .catch(() => {
        // If modern API rejects (e.g. user blocked permissions), fallback immediately
        fallbackCopyText(text) ? onSuccess() : onFail();
      });
  } else {
    // Non-secure context (HTTP on local network IP, older browser, or browser extension restriction)
    fallbackCopyText(text) ? onSuccess() : onFail();
  }
};

// Global App Password Visibility Toggle
window.toggleAppPasswordVisibility = function(eventOrBtn, maybeBtn) {
  if (eventOrBtn && typeof eventOrBtn.preventDefault === 'function') {
    eventOrBtn.preventDefault();
  }
  if (eventOrBtn && typeof eventOrBtn.stopPropagation === 'function') {
    eventOrBtn.stopPropagation();
  }

  let btn = null;
  if (maybeBtn && maybeBtn.nodeType === 1) {
    btn = maybeBtn;
  } else if (eventOrBtn && eventOrBtn.nodeType === 1) {
    btn = eventOrBtn;
  } else {
    btn = document.getElementById('btn-toggle-app-password');
  }

  const input = document.getElementById('app_password');
  if (!input) return;

  if (input.type === 'password') {
    input.type = 'text';
    if (btn) {
      btn.innerText = '🙈';
      btn.title = 'Hide password';
    }
  } else {
    input.type = 'password';
    if (btn) {
      btn.innerText = '👁️';
      btn.title = 'Reveal password';
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {

  // ==========================================
  // 1. Mobile Navigation Hamburger Drawer
  // ==========================================
  const navToggle = document.getElementById('nav-toggle');
  const navLinks = document.getElementById('nav-links');

  if (navToggle && navLinks) {
    navToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = navLinks.classList.toggle('mobile-open');
      navToggle.classList.toggle('active', isOpen);
      navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    // Close mobile nav when clicking outside
    document.addEventListener('click', (e) => {
      if (!navLinks.contains(e.target) && !navToggle.contains(e.target)) {
        navLinks.classList.remove('mobile-open');
        navToggle.classList.remove('active');
        navToggle.setAttribute('aria-expanded', 'false');
      }
    });

    // Close when clicking any nav link
    navLinks.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('mobile-open');
        navToggle.classList.remove('active');
        navToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // ==========================================
  // 2. Click Delegation (Reveal, Copy, Purge)
  // ==========================================
  document.addEventListener('click', (e) => {
    // Reveal / Mask OTP toggles (supports eye button or direct click on otp-box)
    const toggleBtn = e.target.closest('.btn-toggle-mask');
    const otpBoxClick = !toggleBtn ? e.target.closest('.otp-box') : null;

    if (toggleBtn || otpBoxClick) {
      let targetEl = null;
      let btn = null;

      if (toggleBtn) {
        btn = toggleBtn;
        const targetId = toggleBtn.getAttribute('data-target');
        targetEl = targetId ? document.getElementById(targetId) : toggleBtn.parentElement?.querySelector('.otp-box');
      } else if (otpBoxClick) {
        targetEl = otpBoxClick;
        const container = otpBoxClick.closest('.otp-code-group, .otp-box-mobile, .passcode-interactive-row, td, .otp-card');
        if (container) {
          btn = container.querySelector('.btn-toggle-mask');
        }
      }

      if (!targetEl) return;

      const isMasked = targetEl.getAttribute('data-masked') === 'true';
      const realCode = targetEl.getAttribute('data-code');
      if (!realCode) return;

      if (isMasked) {
        targetEl.innerText = realCode;
        targetEl.setAttribute('data-masked', 'false');
        if (btn) {
          const hasLabel = btn.querySelector('.mask-label') !== null || btn.innerText.includes('Reveal') || btn.innerText.includes('Hide');
          btn.innerHTML = hasLabel ? '🙈 <span class="mask-label">Hide</span>' : '🙈';
          btn.title = "Hide code";
        }
      } else {
        targetEl.innerText = '• • • • • •';
        targetEl.setAttribute('data-masked', 'true');
        if (btn) {
          const hasLabel = btn.querySelector('.mask-label') !== null || btn.innerText.includes('Reveal') || btn.innerText.includes('Hide');
          btn.innerHTML = hasLabel ? '👁️ <span class="mask-label">Reveal</span>' : '👁️';
          btn.title = "Reveal code";
        }
      }
    }

    // Copy OTP buttons
    const copyBtn = e.target.closest('.btn-copy-code');
    if (copyBtn) {
      const code = copyBtn.getAttribute('data-code');
      window.copyToClipboard(code, "OTP Code", copyBtn);
    }

    // Copy Magic Link buttons
    const copyLinkBtn = e.target.closest('.btn-copy-link');
    if (copyLinkBtn) {
      const link = copyLinkBtn.getAttribute('data-link');
      window.copyToClipboard(link, "Magic Link", copyLinkBtn);
    }

    // Purge single OTP
    const purgeBtn = e.target.closest('.btn-purge-otp');
    if (purgeBtn) {
      const otpId = purgeBtn.getAttribute('data-otp-id');
      const container = purgeBtn.closest('tr') || purgeBtn.closest('.otp-card');
      purgeOtp(otpId, container);
    }

    // In-App Verification / Sandbox View Click
    const inboxViewBtn = e.target.closest('.btn-inbox-view');
    if (inboxViewBtn) {
      e.preventDefault();
      openInboxVerificationModal(inboxViewBtn);
      return;
    }

    // Snippet Popover Clickable (also opens in-app verification modal)
    const snippetEl = e.target.closest('.snippet-clickable');
    if (snippetEl) {
      openInboxVerificationModal(snippetEl);
      return;
    }

  });

  // Purge single OTP handler
  async function purgeOtp(otpId, containerElement) {
    if (!confirm("Purge this verification item permanently?")) return;
    try {
      const resp = await fetch('/api/delete-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp_id: otpId })
      });
      const data = await resp.json();
      if (data.success) {
        window.showToast("Item purged successfully", "info");
        if (containerElement) {
          containerElement.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
          containerElement.style.opacity = '0';
          containerElement.style.transform = 'scale(0.95)';
          setTimeout(() => {
            containerElement.remove();
            updateItemCounter();
          }, 250);
        }
      } else {
        window.showToast(data.message || "Failed to purge item", "danger");
      }
    } catch (err) {
      window.showToast("Network error purging item", "danger");
    }
  }

  // ==========================================
  // 3. In-App Privacy Verification & Sandbox Modal
  // ==========================================
  const inboxVerifyModal = document.getElementById('inbox-verify-modal');
  const closeVerifyModalBtn = document.getElementById('btn-close-verify-modal');
  const sandboxIframe = document.getElementById('inbox-sandbox-iframe');
  const sandboxLoading = document.getElementById('sandbox-loading-indicator');
  const sandboxBanner = document.getElementById('sandbox-status-banner');
  const triggerVerifyBtn = document.getElementById('btn-trigger-verify');
  const reloadSandboxBtn = document.getElementById('btn-reload-sandbox');
  const copyModalLinkBtn = document.getElementById('btn-copy-modal-link');
  const copyModalCodeBtn = document.getElementById('btn-copy-modal-code');
  const toggleModalCodeBtn = document.getElementById('btn-toggle-modal-code');

  let currentActiveUrl = '';

  function openInboxVerificationModal(el) {
    if (!inboxVerifyModal) return;

    const sender = el.getAttribute('data-sender') || 'Verification Item';
    const subject = el.getAttribute('data-subject') || '';
    const time = el.getAttribute('data-time') || 'Recently';
    const code = (el.getAttribute('data-code') || '').trim();
    const type = el.getAttribute('data-type') || (code.startsWith('http') ? 'link' : 'code');

    const senderEl = document.getElementById('verify-modal-sender');
    const timeEl = document.getElementById('verify-modal-time');
    const subjectEl = document.getElementById('verify-modal-subject');

    if (senderEl) senderEl.innerText = sender;
    if (timeEl) timeEl.innerText = time;
    if (subjectEl) subjectEl.innerText = subject;

    if (sandboxBanner) {
      sandboxBanner.style.display = 'none';
      sandboxBanner.className = 'sandbox-banner';
      sandboxBanner.innerText = '';
    }

    const linkContainer = document.getElementById('verify-link-container');
    const codeContainer = document.getElementById('verify-code-container');

    if (type === 'link' || code.startsWith('http')) {
      currentActiveUrl = code;
      if (linkContainer) linkContainer.style.display = 'block';
      if (codeContainer) codeContainer.style.display = 'none';

      const linkInput = document.getElementById('verify-modal-link-input');
      if (linkInput) linkInput.value = code;

      const stealthOpenBtn = document.getElementById('btn-stealth-open');
      if (stealthOpenBtn) stealthOpenBtn.href = code;

      if (sandboxLoading) sandboxLoading.style.display = 'flex';
      if (sandboxIframe) {
        sandboxIframe.onload = () => {
          if (sandboxLoading) sandboxLoading.style.display = 'none';
        };
        sandboxIframe.src = '/api/sandbox-view?url=' + encodeURIComponent(code);
      }
    } else {
      currentActiveUrl = '';
      if (linkContainer) linkContainer.style.display = 'none';
      if (codeContainer) codeContainer.style.display = 'block';

      const codeDisplay = document.getElementById('verify-modal-code-display');
      if (codeDisplay) {
        codeDisplay.innerText = code || '------';
        codeDisplay.setAttribute('data-code', code);
        codeDisplay.setAttribute('data-masked', 'false');
      }
      if (sandboxIframe) sandboxIframe.src = 'about:blank';
    }

    inboxVerifyModal.style.display = 'flex';
  }

  function closeInboxVerifyModal() {
    if (!inboxVerifyModal) return;
    inboxVerifyModal.style.display = 'none';
    if (sandboxIframe) {
      sandboxIframe.src = 'about:blank';
    }
  }

  if (closeVerifyModalBtn) {
    closeVerifyModalBtn.addEventListener('click', closeInboxVerifyModal);
  }

  if (inboxVerifyModal) {
    inboxVerifyModal.addEventListener('click', (e) => {
      if (e.target === inboxVerifyModal) {
        closeInboxVerifyModal();
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && inboxVerifyModal && inboxVerifyModal.style.display === 'flex') {
      closeInboxVerifyModal();
    }
  });

  // Stealth Open Relay from Sandboxed iframe to Main Window (Zero-Referrer)
  window.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'OPEN_STEALTH' && event.data.url) {
      const url = event.data.url;
      try {
        const win = window.open();
        if (win) {
          win.opener = null;
          win.location = url;
          return;
        }
      } catch (e) {}
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noreferrer noopener';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  });

  // Silent Server-Side Verification Trigger
  if (triggerVerifyBtn) {
    triggerVerifyBtn.addEventListener('click', async () => {
      if (!currentActiveUrl) return;

      triggerVerifyBtn.disabled = true;
      triggerVerifyBtn.innerHTML = `<span>⏳</span> Verifying on Server...`;

      if (sandboxBanner) {
        sandboxBanner.style.display = 'block';
        sandboxBanner.className = 'sandbox-banner info';
        sandboxBanner.innerText = '📡 Dispatching silent server-side verification request...';
      }

      try {
        const resp = await fetch('/api/trigger-verification', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: currentActiveUrl })
        });
        const data = await resp.json();

        if (resp.ok && data.success) {
          if (sandboxBanner) {
            sandboxBanner.className = 'sandbox-banner success';
            sandboxBanner.innerHTML = `✅ <strong>${data.message}</strong>`;
          }
          window.showToast("Account verification executed successfully via server!", "success");
          if (sandboxIframe) {
            sandboxIframe.src = '/api/sandbox-view?url=' + encodeURIComponent(currentActiveUrl);
          }
        } else {
          if (sandboxBanner) {
            sandboxBanner.className = 'sandbox-banner warning';
            sandboxBanner.innerText = data.message || 'Verification endpoint responded with non-200 status.';
          }
        }
      } catch (err) {
        if (sandboxBanner) {
          sandboxBanner.className = 'sandbox-banner warning';
          sandboxBanner.innerText = 'Connection timed out or network error while triggering verification.';
        }
      } finally {
        triggerVerifyBtn.disabled = false;
        triggerVerifyBtn.innerHTML = `⚡ Trigger Server Verify`;
      }
    });
  }

  // Reload sandbox preview button
  if (reloadSandboxBtn) {
    reloadSandboxBtn.addEventListener('click', () => {
      if (currentActiveUrl && sandboxIframe) {
        if (sandboxLoading) sandboxLoading.style.display = 'flex';
        sandboxIframe.src = '/api/sandbox-view?url=' + encodeURIComponent(currentActiveUrl) + '&_t=' + Date.now();
      }
    });
  }

  // Copy modal link button
  if (copyModalLinkBtn) {
    copyModalLinkBtn.addEventListener('click', () => {
      if (currentActiveUrl) {
        window.copyToClipboard(currentActiveUrl, "Verification Link", copyModalLinkBtn);
      }
    });
  }

  // Copy modal code button
  if (copyModalCodeBtn) {
    copyModalCodeBtn.addEventListener('click', () => {
      const codeDisplay = document.getElementById('verify-modal-code-display');
      const code = codeDisplay ? codeDisplay.getAttribute('data-code') : '';
      if (code) {
        window.copyToClipboard(code, "OTP Code", copyModalCodeBtn);
      }
    });
  }

  // Toggle mask inside modal code display
  if (toggleModalCodeBtn) {
    toggleModalCodeBtn.addEventListener('click', () => {
      const codeDisplay = document.getElementById('verify-modal-code-display');
      if (!codeDisplay) return;
      const isMasked = codeDisplay.getAttribute('data-masked') === 'true';
      const realCode = codeDisplay.getAttribute('data-code');
      if (isMasked) {
        codeDisplay.innerText = realCode;
        codeDisplay.setAttribute('data-masked', 'false');
        toggleModalCodeBtn.innerText = '🙈 Mask Code';
      } else {
        codeDisplay.innerText = '• • • • • •';
        codeDisplay.setAttribute('data-masked', 'true');
        toggleModalCodeBtn.innerText = '👁️ Reveal Code';
      }
    });
  }

  // ==========================================
  // 4. Fetch Latest OTP & Skeleton Loader
  // ==========================================
  const fetchOtpBtn = document.getElementById('btn-fetch-otp');
  const skeletonLoader = document.getElementById('fetch-skeleton-loader');

  async function executeFetchOtp(isSilent = false) {
    if (fetchOtpBtn && !isSilent) {
      fetchOtpBtn.disabled = true;
      const btnLabel = document.getElementById('fetch-btn-label');
      if (btnLabel) btnLabel.innerText = 'SCANNING IMAP...';
    }
    if (skeletonLoader && !isSilent) {
      skeletonLoader.style.display = 'block';
    }

    try {
      const resp = await fetch('/api/fetch-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await resp.json();

      if (resp.ok && data.success) {
        if (!isSilent) {
          window.showToast(data.message, 'success');
          setTimeout(() => window.location.reload(), 500);
        } else {
          // If silent auto-fetch detected new items, notify and refresh
          if (data.otps && data.otps.length > 0) {
            const currentRows = document.querySelectorAll('.otp-item-row').length;
            if (data.otps.length !== currentRows) {
              window.showToast("New verification item detected!", "success");
              setTimeout(() => window.location.reload(), 400);
            }
          }
        }
      } else {
        if (resp.status === 401) {
          window.showToast("Session expired. Please log in again.", 'danger');
          setTimeout(() => window.location.href = '/login', 1200);
        } else if (resp.status === 403) {
          window.showToast(data.message || "Mailbox locked. Enter your 12-Hour passcode.", 'warning');
          const lockModal = document.getElementById('mailbox-lock-modal');
          if (lockModal) lockModal.style.display = 'flex';
        } else if (!isSilent) {
          window.showToast(data.message || "Failed to fetch OTPs", 'danger');
        }
      }
    } catch (err) {
      if (!isSilent) {
        window.showToast("Network timeout or connection failure.", 'danger');
      }
    } finally {
      if (fetchOtpBtn && !isSilent) {
        fetchOtpBtn.disabled = false;
        const btnLabel = document.getElementById('fetch-btn-label');
        if (btnLabel) btnLabel.innerText = 'FETCH LATEST OTP';
      }
      if (skeletonLoader) {
        skeletonLoader.style.display = 'none';
      }
    }
  }

  if (fetchOtpBtn) {
    fetchOtpBtn.addEventListener('click', () => executeFetchOtp(false));
  }

  // ==========================================
  // 5. Auto-Fetch Toggle Engine (15s Polling)
  // ==========================================
  const autoFetchToggle = document.getElementById('auto-fetch-toggle');
  const autoFetchDot = document.getElementById('auto-fetch-dot');
  let autoFetchTimer = null;

  if (autoFetchToggle) {
    // Restore preference
    const savedAuto = localStorage.getItem('relay_auto_fetch') === 'true';
    if (savedAuto) {
      autoFetchToggle.checked = true;
      startAutoFetch();
    }

    autoFetchToggle.addEventListener('change', () => {
      if (autoFetchToggle.checked) {
        localStorage.setItem('relay_auto_fetch', 'true');
        startAutoFetch();
        window.showToast("Auto-Fetch enabled (polls every 15s)", "info");
      } else {
        localStorage.setItem('relay_auto_fetch', 'false');
        stopAutoFetch();
        window.showToast("Auto-Fetch disabled", "info");
      }
    });
  }

  function startAutoFetch() {
    stopAutoFetch();
    if (autoFetchDot) autoFetchDot.classList.add('active');
    autoFetchTimer = setInterval(() => {
      executeFetchOtp(true);
    }, 15000);
  }

  function stopAutoFetch() {
    if (autoFetchTimer) clearInterval(autoFetchTimer);
    autoFetchTimer = null;
    if (autoFetchDot) autoFetchDot.classList.remove('active');
  }

  // ==========================================
  // 6. Real-time Search & Filter Bar
  // ==========================================
  const searchInput = document.getElementById('otp-search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');
  const noResultsNotice = document.getElementById('no-search-results');

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const query = searchInput.value.toLowerCase().trim();
      if (clearSearchBtn) {
        clearSearchBtn.style.display = query.length > 0 ? 'block' : 'none';
      }
      filterOtps(query);
    });

    if (clearSearchBtn) {
      clearSearchBtn.addEventListener('click', () => {
        searchInput.value = '';
        clearSearchBtn.style.display = 'none';
        filterOtps('');
        searchInput.focus();
      });
    }
  }

  function filterOtps(query) {
    const desktopRows = document.querySelectorAll('.otp-item-row');
    const mobileCards = document.querySelectorAll('.otp-card');
    let visibleCount = 0;

    desktopRows.forEach(row => {
      const text = row.getAttribute('data-search') || '';
      const match = text.includes(query);
      row.style.display = match ? '' : 'none';
      if (match) visibleCount++;
    });

    mobileCards.forEach(card => {
      const text = card.getAttribute('data-search') || '';
      const match = text.includes(query);
      card.style.display = match ? 'flex' : 'none';
    });

    if (noResultsNotice) {
      noResultsNotice.style.display = (visibleCount === 0 && (desktopRows.length > 0 || mobileCards.length > 0)) ? 'block' : 'none';
    }

    updateItemCounter(visibleCount, query.length > 0);
  }

  function updateItemCounter(count = null, isFiltered = false) {
    const counter = document.getElementById('otp-counter');
    if (!counter) return;
    if (count === null) {
      count = document.querySelectorAll('.otp-item-row').length;
    }
    counter.innerText = isFiltered ? `${count} Found` : `${count} Active`;
  }

  // ==========================================
  // 7. Vault Settings: Test Connection
  // ==========================================
  const testVaultBtn = document.getElementById('btn-test-vault');
  if (testVaultBtn) {
    testVaultBtn.addEventListener('click', async () => {
      const emailInput = document.getElementById('gmail_address');
      const passInput = document.getElementById('app_password');

      if (!emailInput.value || !passInput.value) {
        window.showToast("Enter both Gmail address and 16-char App Password first.", "warning");
        return;
      }

      testVaultBtn.disabled = true;
      testVaultBtn.innerHTML = `<span>⏳</span> Testing SSL Handshake...`;

      try {
        const resp = await fetch('/api/test-vault', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gmail_address: emailInput.value,
            app_password: passInput.value
          })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
          window.showToast(data.message, "success");
          const saveBtn = document.getElementById('btn-save-vault');
          if (saveBtn) saveBtn.classList.add('btn-primary');
        } else {
          window.showToast(data.message, "danger");
        }
      } catch (err) {
        window.showToast("Handshake error or timeout.", "danger");
      } finally {
        testVaultBtn.disabled = false;
        testVaultBtn.innerHTML = `🧪 TEST CONNECTION`;
      }
    });
  }

  // ==========================================
  // 8. Vault Settings: Save Encrypted Vault
  // ==========================================
  const saveVaultForm = document.getElementById('vault-form');
  if (saveVaultForm) {
    saveVaultForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const emailInput = document.getElementById('gmail_address');
      const passInput = document.getElementById('app_password');
      const saveBtn = document.getElementById('btn-save-vault');

      if (!emailInput.value || !passInput.value) {
        window.showToast("Please provide both Gmail and App Password.", "warning");
        return;
      }

      saveBtn.disabled = true;
      saveBtn.innerText = "Encrypting & Saving...";

      try {
        const resp = await fetch('/api/save-vault', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            gmail_address: emailInput.value,
            app_password: passInput.value
          })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
          window.showToast(data.message, "success");
          passInput.value = '';
          const successModal = document.getElementById('connected-success-modal');
          if (successModal) {
            successModal.style.display = 'flex';
          } else {
            setTimeout(() => window.location.href = '/dashboard', 800);
          }
        } else {
          window.showToast(data.message, "danger");
        }
      } catch (err) {
        window.showToast("Failed to save credentials.", "danger");
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerText = "💾 ENCRYPT & SAVE VAULT";
      }
    });
  }

  // ==========================================
  // 9. Vault Settings: Disconnect Vault
  // ==========================================
  const disconnectBtn = document.getElementById('btn-disconnect-vault');
  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', async () => {
      if (!confirm("Are you sure? This will erase your Gmail credentials from the database and wipe all OTP history.")) return;
      try {
        const resp = await fetch('/api/disconnect-vault', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
          window.showToast(data.message, "info");
          setTimeout(() => window.location.reload(), 800);
        } else {
          window.showToast(data.message, "danger");
        }
      } catch (err) {
        window.showToast("Error disconnecting vault.", "danger");
      }
    });
  }

  // ==========================================
  // 10. Live Countdown Timer with Auto-Lock
  // ==========================================
  const countdownEl = document.getElementById('live-countdown-timer');
  if (countdownEl) {
    let remainingSec = parseInt(countdownEl.getAttribute('data-remaining-seconds'), 10) || 0;
    if (remainingSec > 0) {
      const countdownInterval = setInterval(() => {
        if (remainingSec <= 0) {
          clearInterval(countdownInterval);
          countdownEl.innerText = "Expired (00:00:00)";
          window.showToast("Your 12-Hour passcode has expired. Mailbox is locked.", "warning");
          const lockModal = document.getElementById('mailbox-lock-modal');
          if (lockModal) lockModal.style.display = 'flex';
          return;
        }
        remainingSec--;
        const hrs = Math.floor(remainingSec / 3600);
        const mins = Math.floor((remainingSec % 3600) / 60);
        const secs = remainingSec % 60;
        countdownEl.innerText = `${hrs}h ${mins.toString().padStart(2, '0')}m ${secs.toString().padStart(2, '0')}s`;
      }, 1000);
    }
  }

// Admin Notice Dismiss Handler
window.dismissAdminNotice = function(noticeId) {
  fetch('/api/notices/dismiss/' + noticeId, { method: 'POST' });
  const el = document.getElementById('notice-card-' + noticeId);
  if (el) {
    el.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
    el.style.opacity = '0';
    el.style.transform = 'translateY(-10px)';
    setTimeout(() => el.remove(), 250);
  }
};

  // ==========================================
  // 11. Workplace Privacy Preferences Handler
  // ==========================================
  const prefMask = document.getElementById('pref-mask-codes');
  const prefAutoClear = document.getElementById('pref-auto-clear');

  if (prefMask) {
    prefMask.checked = localStorage.getItem('relay_pref_mask_codes') !== 'false';
    prefMask.addEventListener('change', (e) => {
      localStorage.setItem('relay_pref_mask_codes', e.target.checked ? 'true' : 'false');
      window.showToast(e.target.checked ? 'Default code masking enabled' : 'Default code masking disabled (plain text)', 'info');
    });
  }

  if (prefAutoClear) {
    prefAutoClear.checked = localStorage.getItem('relay_pref_auto_clear') !== 'false';
    prefAutoClear.addEventListener('change', (e) => {
      localStorage.setItem('relay_pref_auto_clear', e.target.checked ? 'true' : 'false');
      window.showToast(e.target.checked ? 'Clipboard auto-clear (30s) enabled' : 'Clipboard auto-clear disabled', 'info');
    });
  }

  // If user disabled code masking by default in Privacy Preferences, reveal codes immediately on dashboard
  if (localStorage.getItem('relay_pref_mask_codes') === 'false') {
    document.querySelectorAll('.otp-box[data-masked="true"]').forEach(el => {
      const code = el.getAttribute('data-code');
      if (code) {
        el.innerText = code;
        el.setAttribute('data-masked', 'false');
        const container = el.closest('.otp-code-group, .otp-box-mobile');
        const btn = container ? container.querySelector('.btn-toggle-mask') : null;
        if (btn) {
          btn.innerHTML = '🙈';
          btn.title = "Hide code";
        }
      }
    });
  }

});

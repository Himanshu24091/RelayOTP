/* RelayOTP - 12-Hour Mailbox Lock & Gatekeeper Handler */

document.addEventListener('DOMContentLoaded', () => {
  const lockModal = document.getElementById('mailbox-lock-modal');
  const codeInput = document.getElementById('lock-code-input');
  const unlockBtn = document.getElementById('unlock-btn');
  const lockError = document.getElementById('lock-error-msg');

  if (!lockModal || !codeInput) return;

  // Auto-format: uppercase and insert hyphen after 2 letters (e.g. TK-9281)
  codeInput.addEventListener('input', (e) => {
    let val = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (val.length > 2) {
      val = val.substring(0, 2) + '-' + val.substring(2, 6);
    }
    e.target.value = val;
    if (lockError && !lockError.getAttribute('data-locked')) {
      lockError.style.display = 'none';
    }
  });

  codeInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submitUnlock();
    }
  });

  if (unlockBtn) {
    unlockBtn.addEventListener('click', submitUnlock);
  }

  async function submitUnlock() {
    const code = codeInput.value.trim();
    if (!code) {
      showError("Please enter your 12-Hour passcode.");
      return;
    }

    unlockBtn.disabled = true;
    unlockBtn.innerText = "Verifying...";

    try {
      const resp = await fetch('/api/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      const data = await resp.json();

      if (resp.ok && data.success) {
        if (window.showToast) window.showToast("Mailbox unlocked successfully!", "success");
        setTimeout(() => window.location.reload(), 300);
      } else {
        showError(data.message || "Invalid or expired passcode.");
        shakeInput();

        // Handle Brute-Force Rate Limit Lockout
        if (resp.status === 429 || data.lockout) {
          handleLockout(data.remaining_seconds || 300);
        }
      }
    } catch (err) {
      showError("Network error. Please try again.");
    } finally {
      if (!lockError.getAttribute('data-locked')) {
        unlockBtn.disabled = false;
        unlockBtn.innerText = "🔓 UNLOCK MAILBOX";
      }
    }
  }

  function handleLockout(seconds) {
    lockError.setAttribute('data-locked', 'true');
    codeInput.disabled = true;
    unlockBtn.disabled = true;

    let rem = seconds;
    const interval = setInterval(() => {
      rem--;
      if (rem <= 0) {
        clearInterval(interval);
        lockError.removeAttribute('data-locked');
        codeInput.disabled = false;
        unlockBtn.disabled = false;
        unlockBtn.innerText = "🔓 UNLOCK MAILBOX";
        lockError.style.display = 'none';
        codeInput.focus();
      } else {
        lockError.innerText = `🛑 Security Lockout: Too many failed attempts. Try again in ${rem}s.`;
        unlockBtn.innerText = `🔒 LOCKED (${rem}s)`;
      }
    }, 1000);
  }

  function showError(msg) {
    if (lockError) {
      lockError.innerText = msg;
      lockError.style.display = 'block';
    }
  }

  function shakeInput() {
    codeInput.style.borderColor = 'var(--accent-rose)';
    codeInput.style.transform = 'translateX(-6px)';
    setTimeout(() => { codeInput.style.transform = 'translateX(6px)'; }, 80);
    setTimeout(() => { codeInput.style.transform = 'translateX(-4px)'; }, 160);
    setTimeout(() => { codeInput.style.transform = 'translateX(0)'; }, 240);
  }
});

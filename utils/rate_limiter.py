import time
import threading
from collections import defaultdict

class InMemoryRateLimiter:
    """
    Thread-safe sliding-window rate limiter with automated lockout.
    Protects sensitive authentication endpoints (e.g. 12-Hour Mailbox code, Login)
    against automated brute-force attacks.
    """
    def __init__(self):
        self._lock = threading.Lock()
        # Structure: key -> list of failure timestamps
        self._failures = defaultdict(list)
        # Structure: key -> lockout expiry timestamp
        self._lockouts = {}

    def _clean_old_failures(self, key: str, window_seconds: int, now: float):
        cutoff = now - window_seconds
        self._failures[key] = [t for t in self._failures[key] if t > cutoff]

    def is_locked(self, action: str, identifier: str) -> tuple[bool, int]:
        """
        Checks if identifier is currently locked out for the given action.
        Returns (is_locked: bool, remaining_lockout_seconds: int).
        """
        key = f"{action}:{identifier}"
        now = time.time()
        with self._lock:
            lockout_expiry = self._lockouts.get(key, 0)
            if lockout_expiry > now:
                return True, int(lockout_expiry - now) + 1
            elif lockout_expiry > 0:
                del self._lockouts[key]
                self._failures.pop(key, None)
            return False, 0

    def record_failure(
        self,
        action: str,
        identifier: str,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 300
    ) -> tuple[bool, int]:
        """
        Records a failed attempt. If failed attempts in window >= max_attempts,
        activates a lockout for lockout_seconds.
        Returns (is_locked: bool, remaining_lockout_seconds: int).
        """
        key = f"{action}:{identifier}"
        now = time.time()
        with self._lock:
            # If already locked, return remaining time
            if self._lockouts.get(key, 0) > now:
                return True, int(self._lockouts[key] - now) + 1

            self._clean_old_failures(key, window_seconds, now)
            self._failures[key].append(now)

            if len(self._failures[key]) >= max_attempts:
                self._lockouts[key] = now + lockout_seconds
                return True, lockout_seconds

            return False, 0

    def reset(self, action: str, identifier: str):
        """Clears failure history and lockout on successful authentication."""
        key = f"{action}:{identifier}"
        with self._lock:
            self._failures.pop(key, None)
            self._lockouts.pop(key, None)

# Global singleton
rate_limiter = InMemoryRateLimiter()

def get_client_ip(req) -> str:
    """Extracts client IP considering trusted proxy headers."""
    if req.headers.getlist("X-Forwarded-For"):
        return req.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return req.remote_addr or "127.0.0.1"

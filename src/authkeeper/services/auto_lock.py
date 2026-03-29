"""Auto-lock manager for AuthKeeper.

Provides automatic locking of the vault after a period of inactivity.
This is an optional security feature that can be enabled/disabled.
"""

import threading
import time
from typing import Callable, Final


# Default timeout in seconds (5 minutes)
DEFAULT_LOCK_TIMEOUT: Final[int] = 300


class AutoLockManager:
    """Automatic vault locking after inactivity.

    Tracks user activity and triggers a lock callback when
    the inactivity timeout is exceeded.

    Example:
        >>> def lock_vault():
        ...     vault.lock()
        ...
        >>> auto_lock = AutoLockManager(timeout=300, on_lock=lock_vault)
        >>> auto_lock.start()
        >>> # ... user activity resets timer
        >>> auto_lock.record_activity()
        >>> # After 5 minutes of no activity, lock_vault() is called

    Attributes:
        timeout: Seconds of inactivity before auto-lock.
        enabled: Whether auto-lock is currently enabled.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_LOCK_TIMEOUT,
        on_lock: Callable[[], None] | None = None,
        enabled: bool = True,
    ) -> None:
        """Initialize the auto-lock manager.

        Args:
            timeout: Seconds of inactivity before lock (0 to disable).
            on_lock: Callback to execute when lock is triggered.
            enabled: Whether auto-lock is enabled.
        """
        self.timeout = timeout
        self._on_lock = on_lock
        self.enabled = enabled
        self._last_activity: float = time.time()
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()
        self._running = False

    def start(self) -> None:
        """Start the auto-lock monitoring."""
        if not self.enabled or self.timeout <= 0:
            return

        with self._lock:
            if self._running:
                return

            self._running = True
            self._last_activity = time.time()
            self._schedule_check()

    def stop(self) -> None:
        """Stop the auto-lock monitoring."""
        with self._lock:
            self._running = False
            if self._timer:
                self._timer.cancel()
                self._timer = None

    def record_activity(self) -> None:
        """Record user activity to reset the inactivity timer."""
        with self._lock:
            self._last_activity = time.time()

    def _schedule_check(self) -> None:
        """Schedule the next inactivity check."""
        if not self._running or not self.enabled:
            return

        # Calculate time until next check
        elapsed = time.time() - self._last_activity
        remaining = max(1, self.timeout - elapsed)

        if self._timer:
            self._timer.cancel()

        self._timer = threading.Timer(remaining, self._check_inactivity)
        self._timer.daemon = True
        self._timer.start()

    def _check_inactivity(self) -> None:
        """Check if inactivity timeout has been exceeded."""
        with self._lock:
            if not self._running:
                return

            elapsed = time.time() - self._last_activity

            if elapsed >= self.timeout:
                # Timeout exceeded - trigger lock
                self._running = False
                self._timer = None

                if self._on_lock:
                    try:
                        self._on_lock()
                    except Exception:
                        pass
            else:
                # Not yet timed out - schedule next check
                self._schedule_check()

    @property
    def time_remaining(self) -> float:
        """Get seconds remaining before auto-lock.

        Returns:
            Seconds remaining, or -1 if disabled.
        """
        if not self.enabled or self.timeout <= 0:
            return -1

        elapsed = time.time() - self._last_activity
        return max(0, self.timeout - elapsed)

    @property
    def is_running(self) -> bool:
        """Check if the auto-lock manager is running."""
        return self._running

    def set_timeout(self, timeout: int) -> None:
        """Update the inactivity timeout.

        Args:
            timeout: New timeout in seconds.
        """
        with self._lock:
            self.timeout = timeout
            if self._running:
                self._schedule_check()

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable auto-lock.

        Args:
            enabled: Whether to enable auto-lock.
        """
        if enabled and not self.enabled:
            self.enabled = True
            if self._running:
                self._schedule_check()
        elif not enabled and self.enabled:
            self.enabled = False
            if self._timer:
                self._timer.cancel()
                self._timer = None

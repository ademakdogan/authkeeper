"""Clipboard manager for AuthKeeper.

Provides secure clipboard operations with automatic clearing
after a configurable timeout.
"""

import threading
import time
from typing import Callable, Final

import pyperclip


# Default timeout in seconds
DEFAULT_CLEAR_TIMEOUT: Final[int] = 30


class ClipboardManager:
    """Secure clipboard manager with auto-clear functionality.

    Copies sensitive data to the clipboard and automatically clears
    it after a configurable timeout.

    Example:
        >>> clipboard = ClipboardManager(timeout=30)
        >>> clipboard.copy("secret_password")
        >>> # Password is cleared after 30 seconds

    Attributes:
        timeout: Seconds before clipboard is automatically cleared.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_CLEAR_TIMEOUT,
        on_clear: Callable[[], None] | None = None,
    ) -> None:
        """Initialize the clipboard manager.

        Args:
            timeout: Seconds before auto-clear (0 to disable).
            on_clear: Optional callback when clipboard is cleared.
        """
        self.timeout = timeout
        self._on_clear = on_clear
        self._clear_timer: threading.Timer | None = None
        self._last_copied: str | None = None
        self._lock = threading.Lock()

    def copy(self, text: str, timeout: int | None = None) -> None:
        """Copy text to clipboard with auto-clear.

        Args:
            text: The text to copy.
            timeout: Override timeout for this copy (None uses default).
        """
        with self._lock:
            # Cancel any existing timer
            self._cancel_timer()

            # Copy to clipboard
            try:
                pyperclip.copy(text)
                self._last_copied = text
            except pyperclip.PyperclipException:
                # Clipboard not available (headless environment)
                return

            # Start clear timer
            clear_timeout = timeout if timeout is not None else self.timeout
            if clear_timeout > 0:
                self._clear_timer = threading.Timer(
                    clear_timeout, self._clear_clipboard
                )
                self._clear_timer.daemon = True
                self._clear_timer.start()

    def _clear_clipboard(self) -> None:
        """Clear the clipboard if our content is still there."""
        with self._lock:
            try:
                current = pyperclip.paste()
                # Only clear if our content is still in clipboard
                if current == self._last_copied:
                    pyperclip.copy("")
                    self._last_copied = None
            except pyperclip.PyperclipException:
                pass

            self._clear_timer = None

            # Call callback
            if self._on_clear:
                try:
                    self._on_clear()
                except Exception:
                    pass

    def _cancel_timer(self) -> None:
        """Cancel the current clear timer if running."""
        if self._clear_timer:
            self._clear_timer.cancel()
            self._clear_timer = None

    def clear_now(self) -> None:
        """Immediately clear the clipboard."""
        with self._lock:
            self._cancel_timer()
            try:
                pyperclip.copy("")
            except pyperclip.PyperclipException:
                pass
            self._last_copied = None

    def stop(self) -> None:
        """Stop the clipboard manager and cancel pending timers."""
        with self._lock:
            self._cancel_timer()

    @property
    def has_pending_clear(self) -> bool:
        """Check if a clear is pending."""
        return self._clear_timer is not None


# Global clipboard manager instance
_clipboard: ClipboardManager | None = None


def get_clipboard_manager(timeout: int = DEFAULT_CLEAR_TIMEOUT) -> ClipboardManager:
    """Get the global clipboard manager instance.

    Args:
        timeout: Default timeout for auto-clear.

    Returns:
        The global ClipboardManager instance.
    """
    global _clipboard
    if _clipboard is None:
        _clipboard = ClipboardManager(timeout=timeout)
    return _clipboard


def copy_to_clipboard(text: str, timeout: int | None = None) -> None:
    """Copy text to clipboard with auto-clear.

    Convenience function using the global clipboard manager.

    Args:
        text: The text to copy.
        timeout: Override timeout for this copy.
    """
    get_clipboard_manager().copy(text, timeout)


def clear_clipboard() -> None:
    """Immediately clear the clipboard.

    Convenience function using the global clipboard manager.
    """
    if _clipboard:
        _clipboard.clear_now()

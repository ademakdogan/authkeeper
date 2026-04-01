"""Main AuthKeeper application.

Textual TUI application that orchestrates all screens and services.
"""

from pathlib import Path
from uuid import UUID

from textual.app import App
from textual.binding import Binding

from authkeeper.core.models import Entry
from authkeeper.services.auto_lock import AutoLockManager
from authkeeper.services.clipboard import ClipboardManager
from authkeeper.services.vault import InvalidPasswordError, Vault, VaultError
from authkeeper.ui.screens.dashboard import DashboardScreen
from authkeeper.ui.screens.entry_form import EntryFormScreen
from authkeeper.ui.screens.login import LoginScreen
from authkeeper.utils.config import get_config


class AuthKeeperApp(App):
    """Main AuthKeeper TUI application.

    Manages vault lifecycle, screen navigation, and service coordination.
    """

    TITLE = "AuthKeeper"
    CSS_PATH = "ui/styles/app.tcss"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=False),
    ]

    def __init__(self, data_dir: Path | None = None) -> None:
        """Initialize the application.

        Args:
            data_dir: Custom data directory for vault storage.
        """
        super().__init__()
        config = get_config()
        self._vault = Vault(data_dir or config.data_dir)
        self._clipboard = ClipboardManager(
            timeout=config.clipboard_timeout,
            on_clear=self._on_clipboard_cleared,
        )
        self._auto_lock = AutoLockManager(
            timeout=config.auto_lock_timeout,
            on_lock=self._on_auto_lock,
            enabled=config.auto_lock_enabled,
        )

    async def on_mount(self) -> None:
        """Mount the application and show login screen."""
        self._show_login()

    def _show_login(self) -> None:
        """Show the login screen."""
        login_screen = LoginScreen(
            vault_exists=self._vault.exists(),
            name="login",
        )
        self.push_screen(login_screen)

    def _show_dashboard(self) -> None:
        """Show the main dashboard."""
        entries = self._vault.get_all_entries()
        categories = self._vault.get_all_categories()

        dashboard = DashboardScreen(
            entries=entries,
            categories=categories,
            name="dashboard",
        )
        self.push_screen(dashboard)

        # Start auto-lock
        self._auto_lock.start()

    def _show_entry_form(self, entry: Entry | None = None) -> None:
        """Show the entry form screen.

        Args:
            entry: Entry to edit, or None for new entry.
        """
        categories = self._vault.get_all_categories()
        form = EntryFormScreen(
            entry=entry,
            categories=categories,
            name="entry_form",
        )
        self.push_screen(form)

    # Login screen handlers
    def on_login_screen_unlock_attempt(self, message: LoginScreen.UnlockAttempt) -> None:
        """Handle vault unlock attempt."""
        try:
            self._vault.unlock(message.password)
            self.pop_screen()  # Remove login
            self._show_dashboard()
            self.notify("🔓 Vault unlocked", severity="information")
        except InvalidPasswordError:
            login_screen = self.query_one(LoginScreen)
            login_screen.show_error("Invalid password")
        except VaultError as e:
            login_screen = self.query_one(LoginScreen)
            login_screen.show_error(str(e))

    def on_login_screen_create_attempt(self, message: LoginScreen.CreateAttempt) -> None:
        """Handle vault creation attempt."""
        try:
            self._vault.create(message.password)
            self.pop_screen()  # Remove login
            self._show_dashboard()
            self.notify("🎉 Vault created successfully!", severity="information")
        except VaultError as e:
            login_screen = self.query_one(LoginScreen)
            login_screen.show_error(str(e))
        except ValueError as e:
            login_screen = self.query_one(LoginScreen)
            login_screen.show_error(str(e))

    # Dashboard handlers
    def on_dashboard_screen_search_request(
        self, message: DashboardScreen.SearchRequest
    ) -> None:
        """Handle search request."""
        self._auto_lock.record_activity()
        entries = self._vault.search(message.query, fuzzy=True)
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)

    def on_dashboard_screen_category_selected(
        self, message: DashboardScreen.CategorySelected
    ) -> None:
        """Handle category selection."""
        self._auto_lock.record_activity()
        entries = self._vault.get_entries_by_category(message.category_id)
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)

    def on_dashboard_screen_favorites_selected(
        self, message: DashboardScreen.FavoritesSelected
    ) -> None:
        """Handle favorites selection."""
        self._auto_lock.record_activity()
        entries = self._vault.get_favorite_entries()
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)

    def on_dashboard_screen_add_entry_request(
        self, message: DashboardScreen.AddEntryRequest
    ) -> None:
        """Handle add entry request."""
        self._auto_lock.record_activity()
        self._show_entry_form()

    def on_dashboard_screen_entry_selected(
        self, message: DashboardScreen.EntrySelected
    ) -> None:
        """Handle entry selection (view/edit)."""
        self._auto_lock.record_activity()
        entry = self._vault.get_entry(message.entry_id)
        if entry:
            self._show_entry_form(entry)

    def on_dashboard_screen_copy_password_request(
        self, message: DashboardScreen.CopyPasswordRequest
    ) -> None:
        """Handle copy password request."""
        self._auto_lock.record_activity()
        entry = self._vault.get_entry(message.entry_id)
        if entry and entry.password:
            self._clipboard.copy(entry.password)
            self.notify(f"📋 Password copied (clears in 30s)", severity="information")

    def on_dashboard_screen_copy_username_request(
        self, message: DashboardScreen.CopyUsernameRequest
    ) -> None:
        """Handle copy username request."""
        self._auto_lock.record_activity()
        entry = self._vault.get_entry(message.entry_id)
        if entry and entry.username:
            self._clipboard.copy(entry.username, timeout=0)  # Don't auto-clear usernames
            self.notify("📋 Username copied", severity="information")

    def on_dashboard_screen_delete_entry_request(
        self, message: DashboardScreen.DeleteEntryRequest
    ) -> None:
        """Handle delete entry request."""
        self._auto_lock.record_activity()
        self._vault.delete_entry(message.entry_id)
        entries = self._vault.get_all_entries()
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)
        self.notify("🗑 Entry deleted", severity="warning")

    def on_dashboard_screen_lock_request(
        self, message: DashboardScreen.LockRequest
    ) -> None:
        """Handle lock request."""
        self._lock_vault()

    def on_dashboard_screen_generate_password_request(
        self, message: DashboardScreen.GeneratePasswordRequest
    ) -> None:
        """Handle generate password request."""
        self._auto_lock.record_activity()
        # Open form with no entry to access generator
        self._show_entry_form()

    # Entry form handlers
    def on_entry_form_screen_entry_saved(
        self, message: EntryFormScreen.EntrySaved
    ) -> None:
        """Handle entry saved."""
        self._auto_lock.record_activity()

        if message.is_new:
            self._vault.add_entry(message.entry)
            self.notify("✅ Entry added", severity="information")
        else:
            self._vault.update_entry(message.entry)
            self.notify("✅ Entry updated", severity="information")

        self.pop_screen()  # Remove form

        # Refresh dashboard
        entries = self._vault.get_all_entries()
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)

    def on_entry_form_screen_delete_requested(
        self, message: EntryFormScreen.DeleteRequested
    ) -> None:
        """Handle delete from form."""
        self._auto_lock.record_activity()
        self._vault.delete_entry(message.entry_id)
        self.pop_screen()  # Remove form

        entries = self._vault.get_all_entries()
        dashboard = self.query_one(DashboardScreen)
        dashboard.update_entries(entries)
        self.notify("🗑 Entry deleted", severity="warning")

    def on_entry_form_screen_cancelled(
        self, message: EntryFormScreen.Cancelled
    ) -> None:
        """Handle form cancellation."""
        self._auto_lock.record_activity()
        self.pop_screen()

    # Service callbacks
    def _on_clipboard_cleared(self) -> None:
        """Callback when clipboard is cleared."""
        # Note: Can't show notification from background thread safely
        pass

    def _on_auto_lock(self) -> None:
        """Callback when auto-lock triggers."""
        self.call_from_thread(self._lock_vault)

    def _lock_vault(self) -> None:
        """Lock the vault and return to login."""
        self._auto_lock.stop()
        self._clipboard.clear_now()
        self._vault.lock()

        # Clear screen stack and show login
        while len(self.screen_stack) > 1:
            self.pop_screen()

        self._show_login()
        self.notify("🔒 Vault locked", severity="warning")

    async def action_quit(self) -> None:
        """Handle quit action."""
        self._auto_lock.stop()
        self._clipboard.stop()
        if self._vault.is_unlocked:
            self._vault.lock()
        self.exit()


def main() -> None:
    """Run the AuthKeeper application."""
    app = AuthKeeperApp()
    app.run()


if __name__ == "__main__":
    main()

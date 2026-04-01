"""Login screen for AuthKeeper.

Provides master password input for vault unlock or creation.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, Static


class LoginScreen(Screen):
    """Login screen for vault authentication.

    Handles both initial vault creation and subsequent unlocking.
    """

    BINDINGS = [
        Binding("escape", "quit", "Quit", show=True),
        Binding("enter", "submit", "Submit", show=False),
    ]

    def __init__(
        self,
        vault_exists: bool = False,
        name: str | None = None,
    ) -> None:
        """Initialize the login screen.

        Args:
            vault_exists: Whether a vault already exists (unlock vs create).
            name: Screen name.
        """
        super().__init__(name=name)
        self.vault_exists = vault_exists

    def compose(self) -> ComposeResult:
        """Compose the login screen layout."""
        with Container(id="login-container"):
            yield Static("🔐 AuthKeeper", id="login-title")

            if self.vault_exists:
                yield Static("Enter your master password", id="login-subtitle")
            else:
                yield Static("Create a master password", id="login-subtitle")

            yield Input(
                placeholder="Master Password",
                password=True,
                id="password-input",
            )

            if not self.vault_exists:
                yield Input(
                    placeholder="Confirm Password",
                    password=True,
                    id="confirm-input",
                )

            button_text = "Unlock" if self.vault_exists else "Create Vault"
            yield Button(button_text, variant="primary", id="login-button")

            yield Static("", id="login-error")

    def on_mount(self) -> None:
        """Focus the password input on mount."""
        self.query_one("#password-input", Input).focus()

    def action_submit(self) -> None:
        """Submit the password form."""
        self.query_one("#login-button", Button).press()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button press."""
        if event.button.id == "login-button":
            self._handle_login()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle enter key in input fields."""
        if event.input.id == "password-input":
            if self.vault_exists:
                self._handle_login()
            else:
                # Focus confirm input
                self.query_one("#confirm-input", Input).focus()
        elif event.input.id == "confirm-input":
            self._handle_login()

    def _handle_login(self) -> None:
        """Process the login attempt."""
        password_input = self.query_one("#password-input", Input)
        password = password_input.value

        error_label = self.query_one("#login-error", Static)

        if not password:
            error_label.update("Please enter a password")
            return

        if self.vault_exists:
            # Unlock existing vault
            self.post_message(self.UnlockAttempt(password))
        else:
            # Create new vault
            confirm_input = self.query_one("#confirm-input", Input)
            confirm = confirm_input.value

            if password != confirm:
                error_label.update("Passwords do not match")
                return

            if len(password) < 4:
                error_label.update("Password must be at least 4 characters")
                return

            self.post_message(self.CreateAttempt(password))

    def show_error(self, message: str) -> None:
        """Display an error message.

        Args:
            message: The error message to display.
        """
        error_label = self.query_one("#login-error", Static)
        error_label.update(f"❌ {message}")

    def clear_error(self) -> None:
        """Clear any displayed error message."""
        error_label = self.query_one("#login-error", Static)
        error_label.update("")

    class UnlockAttempt:
        """Message sent when user attempts to unlock vault."""

        def __init__(self, password: str) -> None:
            self.password = password

    class CreateAttempt:
        """Message sent when user attempts to create vault."""

        def __init__(self, password: str) -> None:
            self.password = password

"""Entry form screen for AuthKeeper.

Add and edit password entries with integrated password generator.
"""

from uuid import UUID

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Input, Label, Select, Static, TextArea

from authkeeper.core.models import Category, Entry, EntryType
from authkeeper.services.password_generator import (
    CharacterSet,
    PasswordConfig,
    PasswordGenerator,
)


class EntryFormScreen(Screen):
    """Form screen for adding/editing entries.

    Features:
    - All entry fields (name, username, password, URL, notes)
    - Category selection
    - Integrated password generator
    - Password strength indicator
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("ctrl+g", "generate", "Generate"),
    ]

    def __init__(
        self,
        entry: Entry | None = None,
        categories: list[Category] | None = None,
        name: str | None = None,
    ) -> None:
        """Initialize the entry form.

        Args:
            entry: Entry to edit (None for new entry).
            categories: Available categories.
            name: Screen name.
        """
        super().__init__(name=name)
        self.entry = entry
        self._categories = categories or []
        self._is_edit = entry is not None
        self._generator = PasswordGenerator()

    def compose(self) -> ComposeResult:
        """Compose the form layout."""
        with Container(id="form-container"):
            title = "Edit Entry" if self._is_edit else "New Entry"
            yield Static(f"📝 {title}", id="form-title")

            # Name field
            yield Label("Name *", classes="form-label")
            yield Input(
                value=self.entry.name if self.entry else "",
                placeholder="e.g., GitHub, Netflix",
                id="name-input",
                classes="form-field",
            )

            # Username field
            yield Label("Username / Email", classes="form-label")
            yield Input(
                value=self.entry.username if self.entry else "",
                placeholder="Username or email address",
                id="username-input",
                classes="form-field",
            )

            # Password field with generator
            yield Label("Password", classes="form-label")
            with Horizontal(classes="form-field"):
                yield Input(
                    value=self.entry.password if self.entry else "",
                    placeholder="Password",
                    password=True,
                    id="password-input",
                )
                yield Button("👁", id="toggle-password", variant="default")
                yield Button("🎲", id="generate-button", variant="primary")

            # Password strength
            yield Static("", id="password-strength")

            # URL field
            yield Label("URL", classes="form-label")
            yield Input(
                value=self.entry.url if self.entry else "",
                placeholder="https://example.com",
                id="url-input",
                classes="form-field",
            )

            # Category selection
            yield Label("Category", classes="form-label")
            category_options = [(cat.name, str(cat.id)) for cat in self._categories]
            category_options.insert(0, ("None", "none"))
            current_cat = str(self.entry.category_id) if self.entry and self.entry.category_id else "none"
            yield Select(
                options=category_options,
                value=current_cat,
                id="category-select",
                classes="form-field",
            )

            # Favorite checkbox
            yield Checkbox(
                "Mark as Favorite",
                value=self.entry.favorite if self.entry else False,
                id="favorite-checkbox",
            )

            # Notes field
            yield Label("Notes", classes="form-label")
            yield TextArea(
                text=self.entry.notes if self.entry else "",
                id="notes-input",
                classes="form-field",
            )

            # Generator options (collapsible)
            with Container(id="generator-container"):
                yield Static("🔑 Password Generator", id="generator-title")
                with Horizontal():
                    yield Label("Length: ", classes="gen-label")
                    yield Input(value="16", id="gen-length", type="integer")
                with Horizontal():
                    yield Checkbox("Symbols (!@#$)", value=False, id="gen-symbols")
                    yield Checkbox("Exclude Ambiguous", value=True, id="gen-ambiguous")
                yield Static("", id="generated-password")

            # Action buttons
            with Horizontal(id="form-buttons"):
                yield Button("💾 Save", variant="success", id="save-button")
                yield Button("Cancel", variant="default", id="cancel-button")
                if self._is_edit:
                    yield Button("🗑 Delete", variant="error", id="delete-button")

    def on_mount(self) -> None:
        """Focus the name input on mount."""
        self.query_one("#name-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes."""
        if event.input.id == "password-input":
            self._update_password_strength(event.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id

        if button_id == "save-button":
            self._save_entry()
        elif button_id == "cancel-button":
            self.post_message(self.Cancelled())
        elif button_id == "delete-button":
            if self.entry:
                self.post_message(self.DeleteRequested(self.entry.id))
        elif button_id == "toggle-password":
            self._toggle_password_visibility()
        elif button_id == "generate-button":
            self._generate_and_fill_password()

    def action_save(self) -> None:
        """Save action."""
        self._save_entry()

    def action_cancel(self) -> None:
        """Cancel action."""
        self.post_message(self.Cancelled())

    def action_generate(self) -> None:
        """Generate password action."""
        self._generate_and_fill_password()

    def _toggle_password_visibility(self) -> None:
        """Toggle password field visibility."""
        password_input = self.query_one("#password-input", Input)
        password_input.password = not password_input.password

    def _generate_and_fill_password(self) -> None:
        """Generate a password and fill the field."""
        try:
            length = int(self.query_one("#gen-length", Input).value or "16")
        except ValueError:
            length = 16

        include_symbols = self.query_one("#gen-symbols", Checkbox).value
        exclude_ambiguous = self.query_one("#gen-ambiguous", Checkbox).value

        char_sets = CharacterSet.default()
        if include_symbols:
            char_sets |= CharacterSet.SYMBOLS

        config = PasswordConfig(
            length=max(8, min(length, 128)),
            character_sets=char_sets,
            exclude_ambiguous=exclude_ambiguous,
        )

        password = self._generator.generate(config)

        # Update fields
        password_input = self.query_one("#password-input", Input)
        password_input.value = password

        generated_display = self.query_one("#generated-password", Static)
        generated_display.update(f"Generated: {password}")

        self._update_password_strength(password)

    def _update_password_strength(self, password: str) -> None:
        """Update the password strength indicator."""
        strength_label = self.query_one("#password-strength", Static)

        if not password:
            strength_label.update("")
            return

        # Calculate simple strength
        length = len(password)
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        score = sum([has_lower, has_upper, has_digit, has_symbol])

        if length < 8:
            strength = "Weak"
            style_class = "strength-weak"
        elif length < 12 or score < 3:
            strength = "Fair"
            style_class = "strength-fair"
        elif length < 16 or score < 4:
            strength = "Strong"
            style_class = "strength-strong"
        else:
            strength = "Excellent"
            style_class = "strength-excellent"

        strength_label.update(f"Strength: {strength}")

    def _save_entry(self) -> None:
        """Save the entry."""
        name = self.query_one("#name-input", Input).value.strip()

        if not name:
            self.notify("Name is required", severity="error")
            return

        username = self.query_one("#username-input", Input).value.strip()
        password = self.query_one("#password-input", Input).value
        url = self.query_one("#url-input", Input).value.strip()
        notes = self.query_one("#notes-input", TextArea).text
        favorite = self.query_one("#favorite-checkbox", Checkbox).value

        category_select = self.query_one("#category-select", Select)
        category_value = category_select.value
        category_id = UUID(category_value) if category_value and category_value != "none" else None

        if self.entry:
            # Update existing
            self.entry.name = name
            self.entry.username = username
            self.entry.password = password
            self.entry.url = url
            self.entry.notes = notes
            self.entry.favorite = favorite
            self.entry.category_id = category_id
            self.entry.touch()
            self.post_message(self.EntrySaved(self.entry, is_new=False))
        else:
            # Create new
            entry = Entry(
                name=name,
                username=username,
                password=password,
                url=url,
                notes=notes,
                favorite=favorite,
                category_id=category_id,
                entry_type=EntryType.PASSWORD,
            )
            self.post_message(self.EntrySaved(entry, is_new=True))

    # Messages
    class EntrySaved(Message):
        """Entry was saved."""

        def __init__(self, entry: Entry, is_new: bool) -> None:
            super().__init__()
            self.entry = entry
            self.is_new = is_new

    class DeleteRequested(Message):
        """Delete was requested."""

        def __init__(self, entry_id: UUID) -> None:
            super().__init__()
            self.entry_id = entry_id

    class Cancelled(Message):
        """Form was cancelled."""

        pass

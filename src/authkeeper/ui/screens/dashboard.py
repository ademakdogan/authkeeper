"""Dashboard screen for AuthKeeper.

Main interface showing entries with search and category filtering.
"""

from uuid import UUID

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Button, Input, Label, ListItem, ListView, Static

from authkeeper.core.models import Category, Entry


class EntryListItem(ListItem):
    """Custom list item for displaying entries."""

    def __init__(self, entry: Entry, *args, **kwargs) -> None:
        """Initialize with an entry.

        Args:
            entry: The entry to display.
        """
        super().__init__(*args, **kwargs)
        self.entry = entry

    def compose(self) -> ComposeResult:
        """Compose the entry item layout."""
        with Vertical(classes="entry-item-content"):
            yield Static(
                f"{'⭐ ' if self.entry.favorite else ''}{self.entry.name}",
                classes="entry-name",
            )
            if self.entry.username:
                yield Static(self.entry.username, classes="entry-username")


class CategoryListItem(ListItem):
    """Custom list item for displaying categories."""

    def __init__(self, category: Category | None, label: str, *args, **kwargs) -> None:
        """Initialize with a category.

        Args:
            category: The category to display (None for "All").
            label: Display label.
        """
        super().__init__(*args, **kwargs)
        self.category = category
        self.label = label

    def compose(self) -> ComposeResult:
        """Compose the category item layout."""
        yield Static(self.label, classes="category-label")


class DashboardScreen(Screen):
    """Main dashboard screen showing entries.

    Features:
    - Category sidebar for filtering
    - Search bar with fuzzy search
    - Entry list with quick actions
    - Keyboard navigation
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("a", "add_entry", "Add", show=True),
        Binding("s", "focus_search", "Search", show=True),
        Binding("l", "lock", "Lock", show=True),
        Binding("g", "generate", "Generate", show=True),
        Binding("escape", "clear_search", "Clear"),
        Binding("enter", "view_entry", "View"),
        Binding("c", "copy_password", "Copy Password"),
        Binding("u", "copy_username", "Copy Username"),
        Binding("delete", "delete_entry", "Delete"),
    ]

    def __init__(
        self,
        entries: list[Entry] | None = None,
        categories: list[Category] | None = None,
        name: str | None = None,
    ) -> None:
        """Initialize the dashboard.

        Args:
            entries: Initial list of entries.
            categories: List of categories.
            name: Screen name.
        """
        super().__init__(name=name)
        self._entries = entries or []
        self._categories = categories or []
        self._filtered_entries = self._entries.copy()
        self._selected_category: UUID | None = None
        self._search_query = ""

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        with Horizontal():
            # Sidebar
            with Vertical(id="sidebar"):
                yield Static("📁 Categories", id="sidebar-title")
                yield ListView(
                    CategoryListItem(None, "📋 All Entries", id="cat-all"),
                    CategoryListItem(None, "⭐ Favorites", id="cat-favorites"),
                    *[
                        CategoryListItem(cat, f"  {cat.name}", id=f"cat-{cat.id}")
                        for cat in self._categories
                    ],
                    id="category-list",
                )

            # Main content
            with Vertical(id="main-content"):
                # Search bar
                with Container(id="search-container"):
                    yield Input(
                        placeholder="🔍 Search entries...",
                        id="search-input",
                    )

                # Entry list
                yield ListView(
                    *[EntryListItem(e, id=f"entry-{e.id}") for e in self._filtered_entries],
                    id="entry-list",
                )

                # Action buttons
                with Horizontal(id="action-bar"):
                    yield Button("➕ Add", variant="primary", id="add-button")
                    yield Button("📋 Copy", variant="default", id="copy-button")
                    yield Button("🔑 Generate", variant="default", id="generate-button")
                    yield Button("🔒 Lock", variant="warning", id="lock-button")

        # Status bar
        with Horizontal(id="status-bar"):
            yield Static(f"{len(self._entries)} entries", id="status-count")

    def on_mount(self) -> None:
        """Focus the search input on mount."""
        self.query_one("#search-input", Input).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle search input changes."""
        if event.input.id == "search-input":
            self._search_query = event.value
            self.post_message(self.SearchRequest(event.value))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle list selection."""
        if event.list_view.id == "category-list":
            item = event.item
            if isinstance(item, CategoryListItem):
                if item.id == "cat-all":
                    self._selected_category = None
                    self.post_message(self.CategorySelected(None))
                elif item.id == "cat-favorites":
                    self.post_message(self.FavoritesSelected())
                elif item.category:
                    self._selected_category = item.category.id
                    self.post_message(self.CategorySelected(item.category.id))

        elif event.list_view.id == "entry-list":
            item = event.item
            if isinstance(item, EntryListItem):
                self.post_message(self.EntrySelected(item.entry.id))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        button_id = event.button.id
        if button_id == "add-button":
            self.post_message(self.AddEntryRequest())
        elif button_id == "copy-button":
            self._copy_selected_password()
        elif button_id == "generate-button":
            self.post_message(self.GeneratePasswordRequest())
        elif button_id == "lock-button":
            self.post_message(self.LockRequest())

    def action_add_entry(self) -> None:
        """Action to add a new entry."""
        self.post_message(self.AddEntryRequest())

    def action_focus_search(self) -> None:
        """Action to focus the search input."""
        self.query_one("#search-input", Input).focus()

    def action_clear_search(self) -> None:
        """Action to clear the search."""
        search_input = self.query_one("#search-input", Input)
        search_input.value = ""
        search_input.focus()

    def action_lock(self) -> None:
        """Action to lock the vault."""
        self.post_message(self.LockRequest())

    def action_generate(self) -> None:
        """Action to show password generator."""
        self.post_message(self.GeneratePasswordRequest())

    def action_view_entry(self) -> None:
        """Action to view selected entry."""
        entry_list = self.query_one("#entry-list", ListView)
        if entry_list.highlighted_child:
            item = entry_list.highlighted_child
            if isinstance(item, EntryListItem):
                self.post_message(self.EntrySelected(item.entry.id))

    def action_copy_password(self) -> None:
        """Action to copy password of selected entry."""
        self._copy_selected_password()

    def action_copy_username(self) -> None:
        """Action to copy username of selected entry."""
        self._copy_selected_username()

    def action_delete_entry(self) -> None:
        """Action to delete selected entry."""
        entry_list = self.query_one("#entry-list", ListView)
        if entry_list.highlighted_child:
            item = entry_list.highlighted_child
            if isinstance(item, EntryListItem):
                self.post_message(self.DeleteEntryRequest(item.entry.id))

    def _copy_selected_password(self) -> None:
        """Copy password of currently selected entry."""
        entry_list = self.query_one("#entry-list", ListView)
        if entry_list.highlighted_child:
            item = entry_list.highlighted_child
            if isinstance(item, EntryListItem):
                self.post_message(self.CopyPasswordRequest(item.entry.id))

    def _copy_selected_username(self) -> None:
        """Copy username of currently selected entry."""
        entry_list = self.query_one("#entry-list", ListView)
        if entry_list.highlighted_child:
            item = entry_list.highlighted_child
            if isinstance(item, EntryListItem):
                self.post_message(self.CopyUsernameRequest(item.entry.id))

    def update_entries(self, entries: list[Entry]) -> None:
        """Update the displayed entries.

        Args:
            entries: New list of entries to display.
        """
        self._filtered_entries = entries
        entry_list = self.query_one("#entry-list", ListView)
        entry_list.clear()
        for entry in entries:
            entry_list.append(EntryListItem(entry, id=f"entry-{entry.id}"))

        status = self.query_one("#status-count", Static)
        status.update(f"{len(entries)} entries")

    # Messages
    class SearchRequest(Message):
        """Request to search entries."""

        def __init__(self, query: str) -> None:
            super().__init__()
            self.query = query

    class CategorySelected(Message):
        """Category was selected."""

        def __init__(self, category_id: UUID | None) -> None:
            super().__init__()
            self.category_id = category_id

    class FavoritesSelected(Message):
        """Favorites was selected."""

        pass

    class EntrySelected(Message):
        """Entry was selected."""

        def __init__(self, entry_id: UUID) -> None:
            super().__init__()
            self.entry_id = entry_id

    class AddEntryRequest(Message):
        """Request to add new entry."""

        pass

    class DeleteEntryRequest(Message):
        """Request to delete entry."""

        def __init__(self, entry_id: UUID) -> None:
            super().__init__()
            self.entry_id = entry_id

    class CopyPasswordRequest(Message):
        """Request to copy password."""

        def __init__(self, entry_id: UUID) -> None:
            super().__init__()
            self.entry_id = entry_id

    class CopyUsernameRequest(Message):
        """Request to copy username."""

        def __init__(self, entry_id: UUID) -> None:
            super().__init__()
            self.entry_id = entry_id

    class GeneratePasswordRequest(Message):
        """Request to show password generator."""

        pass

    class LockRequest(Message):
        """Request to lock vault."""

        pass

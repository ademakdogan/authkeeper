"""AuthKeeper CLI Interface.

Simple command-line interface using Rich for formatting.
Provides password management through a menu-driven interaction.
"""

import getpass
import sys
from typing import NoReturn

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from authkeeper.core.models import Entry, EntryType
from authkeeper.services.clipboard import copy_to_clipboard
from authkeeper.services.password_generator import (
    CharacterSet,
    PasswordConfig,
    PasswordGenerator,
    generate_passphrase,
)
from authkeeper.services.vault import InvalidPasswordError, Vault, VaultError
from authkeeper.utils.config import get_config


console = Console()


class CLI:
    """Command-line interface for AuthKeeper.

    Provides a simple, menu-driven interface for managing passwords
    with Rich formatting for better terminal output.

    Attributes:
        vault: The vault instance for password storage.
    """

    def __init__(self) -> None:
        """Initialize the CLI with vault and services."""
        config = get_config()
        self.vault = Vault(config.data_dir)
        self._generator = PasswordGenerator()
        self._running = True

    def run(self) -> None:
        """Run the CLI application."""
        self._show_header()

        if not self._authenticate():
            return

        self._main_loop()

    def _show_header(self) -> None:
        """Display the application header."""
        console.print()
        console.print(
            Panel.fit(
                "[bold cyan]🔐 AuthKeeper[/bold cyan]\n"
                "[dim]Secure Password Manager[/dim]",
                border_style="cyan",
            )
        )
        console.print()

    def _authenticate(self) -> bool:
        """Handle vault authentication (create or unlock).

        Returns:
            True if authentication successful, False otherwise.
        """
        if self.vault.exists():
            return self._unlock_vault()
        else:
            return self._create_vault()

    def _unlock_vault(self) -> bool:
        """Unlock an existing vault.

        Returns:
            True if unlocked successfully.
        """
        console.print("[dim]Enter your master password to unlock the vault.[/dim]")
        console.print()

        for attempt in range(3):
            try:
                password = getpass.getpass("Master Password: ")
                if not password:
                    console.print("[yellow]Password cannot be empty.[/yellow]")
                    continue

                self.vault.unlock(password)
                console.print()
                console.print("[green]✓ Vault unlocked successfully![/green]")
                return True

            except InvalidPasswordError:
                remaining = 2 - attempt
                if remaining > 0:
                    console.print(f"[red]✗ Invalid password. {remaining} attempts remaining.[/red]")
                else:
                    console.print("[red]✗ Too many failed attempts. Exiting.[/red]")
                    return False

        return False

    def _create_vault(self) -> bool:
        """Create a new vault.

        Returns:
            True if vault created successfully.
        """
        console.print("[dim]No vault found. Let's create one![/dim]")
        console.print()

        password = getpass.getpass("Create Master Password: ")
        if len(password) < 4:
            console.print("[red]✗ Password must be at least 4 characters.[/red]")
            return False

        confirm = getpass.getpass("Confirm Password: ")
        if password != confirm:
            console.print("[red]✗ Passwords do not match.[/red]")
            return False

        try:
            self.vault.create(password)
            console.print()
            console.print("[green]✓ Vault created successfully![/green]")
            return True
        except VaultError as e:
            console.print(f"[red]✗ Failed to create vault: {e}[/red]")
            return False

    def _main_loop(self) -> None:
        """Main command loop."""
        while self._running:
            self._show_menu()
            command = Prompt.ask("\n[bold cyan]>[/bold cyan]").strip().lower()

            if not command:
                continue

            self._handle_command(command)

    def _show_menu(self) -> None:
        """Display the main menu."""
        entry_count = self.vault.get_entry_count()
        console.print()
        console.print(f"[dim]─── Vault: {entry_count} entries ───[/dim]")
        console.print()
        console.print("[1] List entries")
        console.print("[2] Add entry")
        console.print("[3] Search [dim]<query>[/dim]")
        console.print("[4] Generate password")
        console.print("[5] Lock & Exit")
        console.print()
        console.print("[dim]c <n>  Copy password  |  v <n>  View entry  |  d <n>  Delete entry[/dim]")

    def _handle_command(self, command: str) -> None:
        """Handle a user command.

        Args:
            command: The command string entered by user.
        """
        parts = command.split(maxsplit=1)
        cmd = parts[0]
        arg = parts[1] if len(parts) > 1 else None

        if cmd == "1":
            self._list_entries()
        elif cmd == "2":
            self._add_entry()
        elif cmd == "3":
            self._search_entries(arg or "")
        elif cmd == "4":
            self._generate_password()
        elif cmd == "5":
            self._lock_and_exit()
        elif cmd == "c" and arg:
            self._copy_password(arg)
        elif cmd == "v" and arg:
            self._view_entry(arg)
        elif cmd == "d" and arg:
            self._delete_entry(arg)
        elif cmd in ("q", "quit", "exit"):
            self._lock_and_exit()
        else:
            console.print("[yellow]Unknown command. Try 1-5, c/v/d <n>, or q to quit.[/yellow]")

    def _list_entries(self, entries: list[Entry] | None = None) -> None:
        """Display entries in a table.

        Args:
            entries: Optional list of entries. Uses all entries if None.
        """
        if entries is None:
            entries = self.vault.get_all_entries()

        if not entries:
            console.print("[dim]No entries found.[/dim]")
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="bold")
        table.add_column("Username", style="dim")
        table.add_column("URL", style="dim", max_width=30)

        for i, entry in enumerate(entries, 1):
            fav = "⭐ " if entry.favorite else ""
            table.add_row(
                str(i),
                f"{fav}{entry.name}",
                entry.username or "-",
                entry.url[:30] if entry.url else "-",
            )

        console.print(table)
        self._current_entries = entries

    def _add_entry(self) -> None:
        """Add a new entry interactively."""
        console.print()
        console.print("[bold]Add New Entry[/bold]")
        console.print("[dim]Press Enter to skip optional fields.[/dim]")
        console.print()

        name = Prompt.ask("Name [dim](required)[/dim]")
        if not name:
            console.print("[yellow]Name is required.[/yellow]")
            return

        username = Prompt.ask("Username/Email", default="")
        password = Prompt.ask("Password [dim](or 'g' to generate)[/dim]", default="")

        if password.lower() == "g":
            password = self._generator.generate()
            console.print(f"[green]Generated: {password}[/green]")

        url = Prompt.ask("URL", default="")
        notes = Prompt.ask("Notes", default="")
        favorite = Confirm.ask("Mark as favorite?", default=False)

        entry = Entry(
            name=name,
            username=username,
            password=password,
            url=url,
            notes=notes,
            favorite=favorite,
            entry_type=EntryType.PASSWORD,
        )

        self.vault.add_entry(entry)
        console.print("[green]✓ Entry added successfully![/green]")

    def _search_entries(self, query: str) -> None:
        """Search entries by query.

        Args:
            query: Search query string.
        """
        if not query:
            query = Prompt.ask("Search query")

        if not query:
            return

        entries = self.vault.search(query, fuzzy=True)
        console.print(f"\n[dim]Results for '{query}':[/dim]")
        self._list_entries(entries)

    def _generate_password(self) -> None:
        """Generate a new password."""
        console.print()
        console.print("[bold]Generate Password[/bold]")

        length = Prompt.ask("Length", default="16")
        try:
            length_int = int(length)
        except ValueError:
            length_int = 16

        include_symbols = Confirm.ask("Include symbols (!@#$)?", default=False)
        passphrase_mode = Confirm.ask("Generate passphrase instead?", default=False)

        if passphrase_mode:
            password = generate_passphrase(word_count=4)
        else:
            char_sets = CharacterSet.default()
            if include_symbols:
                char_sets |= CharacterSet.SYMBOLS

            config = PasswordConfig(
                length=max(8, min(length_int, 128)),
                character_sets=char_sets,
                exclude_ambiguous=True,
            )
            password = self._generator.generate(config)

        console.print()
        console.print(Panel(password, title="Generated Password", border_style="green"))

        if Confirm.ask("Copy to clipboard?", default=True):
            copy_to_clipboard(password)
            console.print("[green]✓ Copied! (clears in 30 seconds)[/green]")

    def _copy_password(self, index_str: str) -> None:
        """Copy password of entry at index.

        Args:
            index_str: Entry index as string.
        """
        try:
            index = int(index_str) - 1
            entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

            if 0 <= index < len(entries):
                entry = entries[index]
                if entry.password:
                    copy_to_clipboard(entry.password)
                    console.print(f"[green]✓ Password for '{entry.name}' copied! (clears in 30s)[/green]")
                else:
                    console.print("[yellow]No password set for this entry.[/yellow]")
            else:
                console.print("[red]Invalid entry number.[/red]")
        except ValueError:
            console.print("[red]Please specify a valid number.[/red]")

    def _view_entry(self, index_str: str) -> None:
        """View entry details.

        Args:
            index_str: Entry index as string.
        """
        try:
            index = int(index_str) - 1
            entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

            if 0 <= index < len(entries):
                entry = entries[index]
                console.print()
                console.print(Panel(
                    f"[bold]{entry.name}[/bold]\n"
                    f"[dim]Username:[/dim] {entry.username or '-'}\n"
                    f"[dim]Password:[/dim] {'*' * 8} [dim](use 'c {index+1}' to copy)[/dim]\n"
                    f"[dim]URL:[/dim] {entry.url or '-'}\n"
                    f"[dim]Notes:[/dim] {entry.notes or '-'}\n"
                    f"[dim]Favorite:[/dim] {'Yes' if entry.favorite else 'No'}",
                    title="Entry Details",
                    border_style="cyan",
                ))
            else:
                console.print("[red]Invalid entry number.[/red]")
        except ValueError:
            console.print("[red]Please specify a valid number.[/red]")

    def _delete_entry(self, indices_str: str) -> None:
        """Delete one or more entries.

        Supports multiple indices like 'd 1 3 5' to delete entries 1, 3, and 5.

        Args:
            indices_str: Space-separated entry indices as string.
        """
        entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

        # Parse indices
        indices: list[int] = []
        for part in indices_str.split():
            try:
                idx = int(part) - 1  # Convert to 0-based
                if 0 <= idx < len(entries):
                    indices.append(idx)
                else:
                    console.print(f"[yellow]Skipping invalid number: {part}[/yellow]")
            except ValueError:
                console.print(f"[yellow]Skipping invalid input: {part}[/yellow]")

        if not indices:
            console.print("[red]No valid entry numbers provided.[/red]")
            return

        # Remove duplicates and sort in reverse (to delete from end first)
        indices = sorted(set(indices), reverse=True)

        # Get entries to delete
        entries_to_delete = [entries[i] for i in indices]
        names = ", ".join(f"'{e.name}'" for e in entries_to_delete)

        if len(entries_to_delete) == 1:
            prompt = f"Delete {names}?"
        else:
            prompt = f"Delete {len(entries_to_delete)} entries ({names})?"

        if Confirm.ask(prompt, default=False):
            for entry in entries_to_delete:
                self.vault.delete_entry(entry.id)
            console.print(f"[green]✓ {len(entries_to_delete)} entry(ies) deleted.[/green]")
            self._current_entries = None

    def _lock_and_exit(self) -> None:
        """Lock the vault and exit."""
        self.vault.lock()
        console.print()
        console.print("[cyan]🔒 Vault locked. Goodbye![/cyan]")
        self._running = False


def main() -> None:
    """Run the AuthKeeper CLI."""
    try:
        cli = CLI()
        cli.run()
    except KeyboardInterrupt:
        console.print("\n[cyan]🔒 Vault locked. Goodbye![/cyan]")
        sys.exit(0)


if __name__ == "__main__":
    main()

"""AuthKeeper CLI Interface.

Simple command-line interface using Rich for formatting.
Provides password management through a menu-driven interaction.
"""

import getpass
import json
import sys
from pathlib import Path
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
        console.print("[5] Export/Import")
        console.print("[6] Lock & Exit")
        console.print()
        console.print("[dim]c <n>  Copy password   |  v <n>  View    |  e <n>  Edit  |  d <n>  Delete[/dim]")
        console.print("[dim]p <n>  Preview password |  fav   Favorites only             [/dim]")

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
            self._export_import_menu()
        elif cmd == "6":
            self._lock_and_exit()
        elif cmd == "c" and arg:
            self._copy_password(arg)
        elif cmd == "v" and arg:
            self._view_entry(arg)
        elif cmd == "d" and arg:
            self._delete_entry(arg)
        elif cmd == "e" and arg:
            self._edit_entry(arg)
        elif cmd == "p" and arg:
            self._preview_password(arg)
        elif cmd in ("q", "quit", "exit"):
            self._lock_and_exit()
        elif cmd == "export":
            self._export_entries(arg)
        elif cmd == "import":
            self._import_entries(arg)
        elif cmd == "fav":
            self._list_favorites()
        else:
            console.print("[yellow]Unknown command. Try 1-6, fav, c/v/e/d <n>, or q to quit.[/yellow]")

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

    def _list_favorites(self) -> None:
        """List only favorite entries."""
        entries = self.vault.get_favorite_entries()
        console.print("\n[bold]⭐ Favorites[/bold]")
        self._list_entries(entries)

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

    def _export_import_menu(self) -> None:
        """Show export/import submenu."""
        console.print()
        console.print("[bold]Export/Import[/bold]")
        console.print("[1] Export entries to JSON")
        console.print("[2] Import entries from JSON")
        console.print("[3] Back to main menu")

        choice = Prompt.ask("\n[bold cyan]>[/bold cyan]", default="3")

        if choice == "1":
            self._export_entries(None)
        elif choice == "2":
            self._import_entries(None)

    def _export_entries(self, filepath: str | None) -> None:
        """Export all entries to a JSON file.

        Args:
            filepath: Optional file path. Prompts if not provided.
        """
        if not filepath:
            filepath = Prompt.ask(
                "Export file path",
                default="authkeeper_export.json",
            )

        entries = self.vault.get_all_entries()
        if not entries:
            console.print("[yellow]No entries to export.[/yellow]")
            return

        # Convert entries to dict format
        export_data = {
            "version": "1.0",
            "entries": [
                {
                    "name": e.name,
                    "username": e.username,
                    "password": e.password,
                    "url": e.url,
                    "notes": e.notes,
                    "favorite": e.favorite,
                    "entry_type": e.entry_type.value,
                }
                for e in entries
            ],
        }

        try:
            path = Path(filepath).expanduser()
            path.write_text(json.dumps(export_data, indent=2, ensure_ascii=False))
            console.print(f"[green]✓ Exported {len(entries)} entries to {path}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Export failed: {e}[/red]")

    def _import_entries(self, filepath: str | None) -> None:
        """Import entries from a JSON file.

        Args:
            filepath: Optional file path. Prompts if not provided.
        """
        if not filepath:
            filepath = Prompt.ask("Import file path")

        if not filepath:
            return

        path = Path(filepath).expanduser()
        if not path.exists():
            console.print(f"[red]✗ File not found: {path}[/red]")
            return

        try:
            data = json.loads(path.read_text())
            entries_data = data.get("entries", [])

            if not entries_data:
                console.print("[yellow]No entries found in file.[/yellow]")
                return

            console.print(f"[dim]Found {len(entries_data)} entries in file.[/dim]")

            if not Confirm.ask("Import all entries?", default=True):
                return

            imported = 0
            for entry_data in entries_data:
                try:
                    entry = Entry(
                        name=entry_data.get("name", "Unnamed"),
                        username=entry_data.get("username", ""),
                        password=entry_data.get("password", ""),
                        url=entry_data.get("url", ""),
                        notes=entry_data.get("notes", ""),
                        favorite=entry_data.get("favorite", False),
                        entry_type=EntryType(entry_data.get("entry_type", "password")),
                    )
                    self.vault.add_entry(entry)
                    imported += 1
                except Exception as e:
                    console.print(f"[yellow]Skipped entry: {e}[/yellow]")

            console.print(f"[green]✓ Imported {imported} entries.[/green]")
            self._current_entries = None

        except json.JSONDecodeError:
            console.print("[red]✗ Invalid JSON file.[/red]")
        except Exception as e:
            console.print(f"[red]✗ Import failed: {e}[/red]")

    def _copy_password(self, identifier: str) -> None:
        """Copy password of entry by index or name.

        Supports both number (c 1) and name (c github) for quick copy.

        Args:
            identifier: Entry index or name to search for.
        """
        entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

        # Try as number first
        try:
            index = int(identifier) - 1
            if 0 <= index < len(entries):
                entry = entries[index]
                if entry.password:
                    copy_to_clipboard(entry.password)
                    console.print(f"[green]✓ Password for '{entry.name}' copied! (clears in 30s)[/green]")
                else:
                    console.print("[yellow]No password set for this entry.[/yellow]")
                return
        except ValueError:
            pass

        # Try as name (fuzzy search)
        matches = self.vault.search(identifier, fuzzy=True, threshold=70)
        if not matches:
            console.print(f"[yellow]No entry found matching '{identifier}'.[/yellow]")
            return

        if len(matches) == 1:
            entry = matches[0]
            if entry.password:
                copy_to_clipboard(entry.password)
                console.print(f"[green]✓ Password for '{entry.name}' copied! (clears in 30s)[/green]")
            else:
                console.print("[yellow]No password set for this entry.[/yellow]")
        else:
            # Multiple matches - show options
            console.print(f"[dim]Multiple matches for '{identifier}':[/dim]")
            for i, e in enumerate(matches[:5], 1):
                console.print(f"  {i}. {e.name}")
            console.print("[dim]Use the entry number to copy.[/dim]")
            self._current_entries = matches

    def _preview_password(self, index_str: str) -> None:
        """Preview password with masked display and reveal option.

        Args:
            index_str: Entry index as string.
        """
        try:
            index = int(index_str) - 1
            entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

            if not (0 <= index < len(entries)):
                console.print("[red]Invalid entry number.[/red]")
                return

            entry = entries[index]
            if not entry.password:
                console.print("[yellow]No password set for this entry.[/yellow]")
                return

            # Show masked password
            password = entry.password
            masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)

            console.print()
            console.print(f"[bold]{entry.name}[/bold]")
            console.print(f"[dim]Masked:[/dim] {masked}")

            if Confirm.ask("Reveal full password?", default=False):
                console.print(f"[green]Password:[/green] {password}")

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

    def _edit_entry(self, index_str: str) -> None:
        """Edit an existing entry.

        Args:
            index_str: Entry index as string.
        """
        try:
            index = int(index_str) - 1
            entries = getattr(self, "_current_entries", None) or self.vault.get_all_entries()

            if not (0 <= index < len(entries)):
                console.print("[red]Invalid entry number.[/red]")
                return

            entry = entries[index]
            console.print()
            console.print(f"[bold]Edit Entry: {entry.name}[/bold]")
            console.print("[dim]Press Enter to keep current value.[/dim]")
            console.print()

            # Name
            new_name = Prompt.ask(
                f"Name [dim]({entry.name})[/dim]",
                default=entry.name,
            )

            # Username
            new_username = Prompt.ask(
                f"Username [dim]({entry.username or 'empty'})[/dim]",
                default=entry.username or "",
            )

            # Password
            password_prompt = "Password [dim](enter to keep, 'g' to generate)[/dim]"
            new_password = Prompt.ask(password_prompt, default="")
            if new_password.lower() == "g":
                new_password = self._generator.generate()
                console.print(f"[green]Generated: {new_password}[/green]")
            elif not new_password:
                new_password = entry.password

            # URL
            new_url = Prompt.ask(
                f"URL [dim]({entry.url or 'empty'})[/dim]",
                default=entry.url or "",
            )

            # Notes
            new_notes = Prompt.ask(
                f"Notes [dim]({(entry.notes[:20] + '...') if entry.notes and len(entry.notes) > 20 else entry.notes or 'empty'})[/dim]",
                default=entry.notes or "",
            )

            # Favorite
            new_favorite = Confirm.ask(
                "Mark as favorite?",
                default=entry.favorite,
            )

            # Update entry
            entry.name = new_name
            entry.username = new_username
            entry.password = new_password
            entry.url = new_url
            entry.notes = new_notes
            entry.favorite = new_favorite
            entry.touch()

            self.vault.update_entry(entry)
            console.print("[green]✓ Entry updated successfully![/green]")
            self._current_entries = None

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

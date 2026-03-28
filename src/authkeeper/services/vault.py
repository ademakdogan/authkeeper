"""Vault service for AuthKeeper.

High-level API for managing the encrypted vault, including
authentication, entry management, and search functionality.
"""

from pathlib import Path
from typing import Callable
from uuid import UUID

from platformdirs import user_data_dir
from thefuzz import fuzz

from authkeeper.core.crypto import DerivedKey, KeyDerivation, MasterPasswordHasher
from authkeeper.core.database import Database, DatabaseError
from authkeeper.core.models import Category, Entry, EntryType, SecureNote, Tag


# Default data directory
DEFAULT_DATA_DIR = Path(user_data_dir("authkeeper", "authkeeper"))
DEFAULT_DB_NAME = "vault.db"


class VaultError(Exception):
    """Base exception for vault errors."""

    pass


class VaultLockedError(VaultError):
    """Raised when vault operations are attempted while locked."""

    pass


class VaultAlreadyExistsError(VaultError):
    """Raised when trying to create a vault that already exists."""

    pass


class InvalidPasswordError(VaultError):
    """Raised when the master password is incorrect."""

    pass


class Vault:
    """High-level vault manager for AuthKeeper.

    Provides authentication, encryption key management, and a clean API
    for managing entries, categories, and tags.

    Example:
        >>> vault = Vault()
        >>> if vault.exists():
        ...     vault.unlock("master_password")
        ... else:
        ...     vault.create("master_password")
        >>> vault.add_entry(Entry(name="GitHub", username="user", password="pass"))
        >>> entries = vault.search("git")
        >>> vault.lock()

    Attributes:
        data_dir: Directory where vault data is stored.
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        """Initialize the vault manager.

        Args:
            data_dir: Custom data directory. Uses platform default if None.
        """
        self.data_dir = data_dir or DEFAULT_DATA_DIR
        self._db = Database(self.data_dir / DEFAULT_DB_NAME)
        self._key_derivation = KeyDerivation()
        self._password_hasher = MasterPasswordHasher()
        self._derived_key: DerivedKey | None = None
        self._on_lock_callbacks: list[Callable[[], None]] = []

    @property
    def is_unlocked(self) -> bool:
        """Check if the vault is currently unlocked."""
        return self._db.is_unlocked and self._derived_key is not None

    @property
    def is_locked(self) -> bool:
        """Check if the vault is currently locked."""
        return not self.is_unlocked

    def exists(self) -> bool:
        """Check if a vault exists at the data directory."""
        return self._db.exists()

    def _ensure_unlocked(self) -> None:
        """Ensure vault is unlocked before operations."""
        if not self.is_unlocked:
            raise VaultLockedError("Vault must be unlocked before this operation")

    def create(self, master_password: str) -> None:
        """Create a new vault with the given master password.

        Args:
            master_password: The master password to protect the vault.

        Raises:
            VaultAlreadyExistsError: If a vault already exists.
            ValueError: If the password is too weak.
        """
        if self.exists():
            raise VaultAlreadyExistsError("A vault already exists at this location")

        if len(master_password) < 4:
            raise ValueError("Master password must be at least 4 characters")

        # Derive key and hash password
        self._derived_key = self._key_derivation.derive_key(master_password)
        password_hash = self._password_hasher.hash_password(master_password)

        # Initialize database
        self._db.initialize(
            password_hash=password_hash,
            salt=self._derived_key.salt,
            key=self._derived_key.key,
        )

    def unlock(self, master_password: str) -> None:
        """Unlock the vault with the master password.

        Args:
            master_password: The master password.

        Raises:
            VaultError: If no vault exists.
            InvalidPasswordError: If the password is incorrect.
        """
        if not self.exists():
            raise VaultError("No vault exists. Create one first.")

        # Verify password
        stored_hash = self._db.get_password_hash()
        if not stored_hash or not self._password_hasher.verify_password(
            stored_hash, master_password
        ):
            raise InvalidPasswordError("Invalid master password")

        # Derive key with stored salt
        stored_salt = self._db.get_salt()
        if not stored_salt:
            raise VaultError("Invalid vault: missing salt")

        self._derived_key = self._key_derivation.derive_key(master_password, stored_salt)

        # Unlock database
        self._db.unlock(self._derived_key.key)

    def lock(self) -> None:
        """Lock the vault and clear sensitive data from memory."""
        # Notify callbacks
        for callback in self._on_lock_callbacks:
            try:
                callback()
            except Exception:
                pass  # Don't fail lock due to callback errors

        self._db.lock()
        self._derived_key = None

    def on_lock(self, callback: Callable[[], None]) -> None:
        """Register a callback to be called when vault is locked.

        Args:
            callback: Function to call on lock.
        """
        self._on_lock_callbacks.append(callback)

    def change_password(self, old_password: str, new_password: str) -> None:
        """Change the master password.

        Args:
            old_password: Current master password.
            new_password: New master password to set.

        Raises:
            InvalidPasswordError: If old password is incorrect.
            ValueError: If new password is too weak.
        """
        # Verify old password
        stored_hash = self._db.get_password_hash()
        if not stored_hash or not self._password_hasher.verify_password(
            stored_hash, old_password
        ):
            raise InvalidPasswordError("Current password is incorrect")

        if len(new_password) < 4:
            raise ValueError("New password must be at least 4 characters")

        # This would require re-encrypting all data with new key
        # For now, we just update the hash (password change without re-encryption)
        # TODO: Implement full re-encryption
        raise NotImplementedError("Password change with re-encryption not yet implemented")

    # Entry operations
    def add_entry(self, entry: Entry) -> Entry:
        """Add a new entry to the vault.

        Args:
            entry: The entry to add.

        Returns:
            The added entry with generated ID.
        """
        self._ensure_unlocked()
        self._db.add_entry(entry)
        return entry

    def get_entry(self, entry_id: UUID) -> Entry | None:
        """Get an entry by ID.

        Args:
            entry_id: The entry's UUID.

        Returns:
            The entry, or None if not found.
        """
        self._ensure_unlocked()
        return self._db.get_entry(entry_id)

    def get_all_entries(self) -> list[Entry]:
        """Get all entries from the vault.

        Returns:
            List of all entries, sorted by name.
        """
        self._ensure_unlocked()
        entries = self._db.get_all_entries()
        return sorted(entries, key=lambda e: e.name.lower())

    def update_entry(self, entry: Entry) -> None:
        """Update an existing entry.

        Args:
            entry: The entry with updated values.
        """
        self._ensure_unlocked()
        self._db.update_entry(entry)

    def delete_entry(self, entry_id: UUID) -> bool:
        """Delete an entry by ID.

        Args:
            entry_id: The entry's UUID.

        Returns:
            True if the entry was deleted.
        """
        self._ensure_unlocked()
        return self._db.delete_entry(entry_id)

    def get_entries_by_category(self, category_id: UUID | None) -> list[Entry]:
        """Get all entries in a category.

        Args:
            category_id: The category UUID, or None for uncategorized.

        Returns:
            List of entries in the category.
        """
        self._ensure_unlocked()
        entries = self.get_all_entries()
        return [e for e in entries if e.category_id == category_id]

    def get_favorite_entries(self) -> list[Entry]:
        """Get all favorite entries.

        Returns:
            List of favorite entries.
        """
        self._ensure_unlocked()
        entries = self.get_all_entries()
        return [e for e in entries if e.favorite]

    # Search
    def search(
        self,
        query: str,
        fuzzy: bool = True,
        threshold: int = 60,
        entry_type: EntryType | None = None,
    ) -> list[Entry]:
        """Search entries by name, username, or URL.

        Args:
            query: Search query string.
            fuzzy: Whether to use fuzzy matching.
            threshold: Minimum fuzzy match score (0-100).
            entry_type: Filter by entry type.

        Returns:
            List of matching entries, sorted by relevance.
        """
        self._ensure_unlocked()
        entries = self.get_all_entries()

        if entry_type:
            entries = [e for e in entries if e.entry_type == entry_type]

        if not query:
            return entries

        query_lower = query.lower()
        results: list[tuple[Entry, int]] = []

        for entry in entries:
            # Calculate match score
            if fuzzy:
                name_score = fuzz.partial_ratio(query_lower, entry.name.lower())
                username_score = fuzz.partial_ratio(query_lower, entry.username.lower())
                url_score = fuzz.partial_ratio(query_lower, entry.url.lower())
                score = max(name_score, username_score, url_score)
            else:
                # Exact substring match
                if (
                    query_lower in entry.name.lower()
                    or query_lower in entry.username.lower()
                    or query_lower in entry.url.lower()
                ):
                    score = 100
                else:
                    score = 0

            if score >= threshold:
                results.append((entry, score))

        # Sort by score descending, then by name
        results.sort(key=lambda x: (-x[1], x[0].name.lower()))
        return [entry for entry, _ in results]

    # Category operations
    def get_all_categories(self) -> list[Category]:
        """Get all categories.

        Returns:
            List of all categories.
        """
        self._ensure_unlocked()
        return self._db.get_all_categories()

    def add_category(self, category: Category) -> Category:
        """Add a new category.

        Args:
            category: The category to add.

        Returns:
            The added category.
        """
        self._ensure_unlocked()
        self._db.add_category(category)
        return category

    def delete_category(self, category_id: UUID) -> bool:
        """Delete a category by ID.

        Args:
            category_id: The category's UUID.

        Returns:
            True if deleted.
        """
        self._ensure_unlocked()
        return self._db.delete_category(category_id)

    # Tag operations
    def get_all_tags(self) -> list[Tag]:
        """Get all tags.

        Returns:
            List of all tags.
        """
        self._ensure_unlocked()
        return self._db.get_all_tags()

    def add_tag(self, tag: Tag) -> Tag:
        """Add a new tag.

        Args:
            tag: The tag to add.

        Returns:
            The added tag.
        """
        self._ensure_unlocked()
        self._db.add_tag(tag)
        return tag

    def delete_tag(self, tag_id: UUID) -> bool:
        """Delete a tag by ID.

        Args:
            tag_id: The tag's UUID.

        Returns:
            True if deleted.
        """
        self._ensure_unlocked()
        return self._db.delete_tag(tag_id)

    # Statistics
    def get_entry_count(self) -> int:
        """Get total number of entries.

        Returns:
            Count of entries in the vault.
        """
        self._ensure_unlocked()
        return self._db.get_entry_count()

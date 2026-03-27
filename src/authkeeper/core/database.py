"""Database module for AuthKeeper.

Provides encrypted SQLite database with application-level encryption.
All sensitive fields are encrypted using AES-256-GCM before storage.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator
from uuid import UUID

import apsw

from authkeeper.core.crypto import EncryptedData, EncryptionEngine
from authkeeper.core.models import Category, Entry, SecureNote, Tag, VaultMetadata


# Schema version for migrations
SCHEMA_VERSION = 1

CREATE_TABLES_SQL = """
-- Vault metadata table
CREATE TABLE IF NOT EXISTS vault_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    last_accessed TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt BLOB NOT NULL
);

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT NOT NULL DEFAULT 'folder',
    color TEXT NOT NULL DEFAULT '#6366f1',
    created_at TEXT NOT NULL
);

-- Tags table
CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- Entries table (passwords and secure notes)
CREATE TABLE IF NOT EXISTS entries (
    id TEXT PRIMARY KEY,
    entry_type TEXT NOT NULL DEFAULT 'password',
    name_encrypted BLOB NOT NULL,
    username_encrypted BLOB,
    password_encrypted BLOB,
    url_encrypted BLOB,
    notes_encrypted BLOB,
    category_id TEXT,
    favorite INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
);

-- Entry-Tag junction table
CREATE TABLE IF NOT EXISTS entry_tags (
    entry_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    PRIMARY KEY (entry_id, tag_id),
    FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category_id);
CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(favorite);
CREATE INDEX IF NOT EXISTS idx_entries_entry_type ON entries(entry_type);
CREATE INDEX IF NOT EXISTS idx_entry_tags_entry ON entry_tags(entry_id);
CREATE INDEX IF NOT EXISTS idx_entry_tags_tag ON entry_tags(tag_id);
"""


class DatabaseError(Exception):
    """Base exception for database errors."""

    pass


class DatabaseNotUnlockedError(DatabaseError):
    """Raised when database operations are attempted without unlocking."""

    pass


class Database:
    """Encrypted SQLite database for AuthKeeper.

    Uses APSW for SQLite access with application-level encryption
    for sensitive fields using AES-256-GCM.

    Attributes:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: Path) -> None:
        """Initialize database with the given path.

        Args:
            db_path: Path where the database file will be stored.
        """
        self.db_path = db_path
        self._connection: apsw.Connection | None = None
        self._encryption: EncryptionEngine | None = None

    @property
    def is_unlocked(self) -> bool:
        """Check if the database is unlocked and ready for operations."""
        return self._connection is not None and self._encryption is not None

    def _ensure_unlocked(self) -> None:
        """Ensure database is unlocked before operations."""
        if not self.is_unlocked:
            raise DatabaseNotUnlockedError("Database must be unlocked before operations")

    def exists(self) -> bool:
        """Check if the database file exists."""
        return self.db_path.exists()

    def initialize(self, password_hash: str, salt: bytes, key: bytes) -> None:
        """Initialize a new database with master password.

        Args:
            password_hash: Argon2id hash of the master password.
            salt: Salt used for key derivation.
            key: Derived encryption key.
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = apsw.Connection(str(self.db_path))
        self._encryption = EncryptionEngine(key)

        # Create tables
        self._connection.execute(CREATE_TABLES_SQL)

        # Insert metadata
        now = datetime.now().isoformat()
        self._connection.execute(
            """
            INSERT INTO vault_metadata (id, version, created_at, last_accessed, password_hash, salt)
            VALUES (1, ?, ?, ?, ?, ?)
            """,
            (SCHEMA_VERSION, now, now, password_hash, salt),
        )

        # Create default categories
        self._create_default_categories()

    def _create_default_categories(self) -> None:
        """Create default categories for new vaults."""
        default_categories = [
            ("Work", "briefcase", "#3b82f6"),
            ("Personal", "user", "#10b981"),
            ("Finance", "credit-card", "#f59e0b"),
            ("Social", "share-2", "#8b5cf6"),
            ("Development", "code", "#6366f1"),
        ]
        now = datetime.now().isoformat()
        for name, icon, color in default_categories:
            category = Category(name=name, icon=icon, color=color)
            self._connection.execute(
                """
                INSERT INTO categories (id, name, icon, color, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(category.id), category.name, category.icon, category.color, now),
            )

    def unlock(self, key: bytes) -> VaultMetadata:
        """Unlock the database with the derived key.

        Args:
            key: Derived encryption key.

        Returns:
            VaultMetadata from the database.

        Raises:
            DatabaseError: If the database cannot be opened.
        """
        if not self.exists():
            raise DatabaseError("Database does not exist")

        self._connection = apsw.Connection(str(self.db_path))
        self._encryption = EncryptionEngine(key)

        # Load and return metadata
        cursor = self._connection.execute("SELECT * FROM vault_metadata WHERE id = 1")
        row = cursor.fetchone()
        if not row:
            raise DatabaseError("Invalid database: missing metadata")

        # Update last accessed
        now = datetime.now().isoformat()
        self._connection.execute(
            "UPDATE vault_metadata SET last_accessed = ? WHERE id = 1", (now,)
        )

        return VaultMetadata(
            version=row[1],
            created_at=datetime.fromisoformat(row[2]),
            last_accessed=datetime.fromisoformat(row[3]),
            password_hash=row[4],
            salt=row[5],
        )

    def lock(self) -> None:
        """Lock the database and clear sensitive data."""
        if self._connection:
            self._connection.close()
        self._connection = None
        self._encryption = None

    def get_password_hash(self) -> str | None:
        """Get the stored password hash without unlocking.

        Returns:
            The stored Argon2id hash, or None if database doesn't exist.
        """
        if not self.exists():
            return None

        conn = apsw.Connection(str(self.db_path))
        try:
            cursor = conn.execute("SELECT password_hash FROM vault_metadata WHERE id = 1")
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def get_salt(self) -> bytes | None:
        """Get the stored salt without unlocking.

        Returns:
            The stored salt, or None if database doesn't exist.
        """
        if not self.exists():
            return None

        conn = apsw.Connection(str(self.db_path))
        try:
            cursor = conn.execute("SELECT salt FROM vault_metadata WHERE id = 1")
            row = cursor.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def _encrypt_field(self, value: str) -> bytes:
        """Encrypt a string field for storage."""
        if not self._encryption:
            raise DatabaseNotUnlockedError("No encryption engine available")
        encrypted = self._encryption.encrypt(value.encode("utf-8"))
        return encrypted.to_bytes()

    def _decrypt_field(self, data: bytes) -> str:
        """Decrypt a stored field."""
        if not self._encryption:
            raise DatabaseNotUnlockedError("No encryption engine available")
        encrypted = EncryptedData.from_bytes(data)
        return self._encryption.decrypt(encrypted).decode("utf-8")

    # Entry operations
    def add_entry(self, entry: Entry) -> None:
        """Add a new entry to the vault.

        Args:
            entry: The entry to add.
        """
        self._ensure_unlocked()

        self._connection.execute(
            """
            INSERT INTO entries (
                id, entry_type, name_encrypted, username_encrypted, password_encrypted,
                url_encrypted, notes_encrypted, category_id, favorite, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(entry.id),
                entry.entry_type.value,
                self._encrypt_field(entry.name),
                self._encrypt_field(entry.username) if entry.username else None,
                self._encrypt_field(entry.password) if entry.password else None,
                self._encrypt_field(entry.url) if entry.url else None,
                self._encrypt_field(entry.notes) if entry.notes else None,
                str(entry.category_id) if entry.category_id else None,
                1 if entry.favorite else 0,
                entry.created_at.isoformat(),
                entry.updated_at.isoformat(),
            ),
        )

        # Add tags
        for tag_id in entry.tag_ids:
            self._connection.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?, ?)",
                (str(entry.id), str(tag_id)),
            )

    def get_entry(self, entry_id: UUID) -> Entry | None:
        """Get an entry by ID.

        Args:
            entry_id: The entry's UUID.

        Returns:
            The entry, or None if not found.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute(
            "SELECT * FROM entries WHERE id = ?", (str(entry_id),)
        )
        row = cursor.fetchone()
        if not row:
            return None

        return self._row_to_entry(row)

    def _row_to_entry(self, row: tuple) -> Entry:
        """Convert a database row to an Entry object."""
        # Get tags for this entry
        tag_cursor = self._connection.execute(
            "SELECT tag_id FROM entry_tags WHERE entry_id = ?", (row[0],)
        )
        tag_ids = [UUID(r[0]) for r in tag_cursor.fetchall()]

        return Entry(
            id=UUID(row[0]),
            entry_type=row[1],
            name=self._decrypt_field(row[2]),
            username=self._decrypt_field(row[3]) if row[3] else "",
            password=self._decrypt_field(row[4]) if row[4] else "",
            url=self._decrypt_field(row[5]) if row[5] else "",
            notes=self._decrypt_field(row[6]) if row[6] else "",
            category_id=UUID(row[7]) if row[7] else None,
            favorite=bool(row[8]),
            created_at=datetime.fromisoformat(row[9]),
            updated_at=datetime.fromisoformat(row[10]),
            tag_ids=tag_ids,
        )

    def get_all_entries(self) -> list[Entry]:
        """Get all entries from the vault.

        Returns:
            List of all entries.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute("SELECT * FROM entries ORDER BY name_encrypted")
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    def update_entry(self, entry: Entry) -> None:
        """Update an existing entry.

        Args:
            entry: The entry with updated values.
        """
        self._ensure_unlocked()
        entry.touch()

        self._connection.execute(
            """
            UPDATE entries SET
                entry_type = ?, name_encrypted = ?, username_encrypted = ?,
                password_encrypted = ?, url_encrypted = ?, notes_encrypted = ?,
                category_id = ?, favorite = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                entry.entry_type.value,
                self._encrypt_field(entry.name),
                self._encrypt_field(entry.username) if entry.username else None,
                self._encrypt_field(entry.password) if entry.password else None,
                self._encrypt_field(entry.url) if entry.url else None,
                self._encrypt_field(entry.notes) if entry.notes else None,
                str(entry.category_id) if entry.category_id else None,
                1 if entry.favorite else 0,
                entry.updated_at.isoformat(),
                str(entry.id),
            ),
        )

        # Update tags
        self._connection.execute(
            "DELETE FROM entry_tags WHERE entry_id = ?", (str(entry.id),)
        )
        for tag_id in entry.tag_ids:
            self._connection.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?, ?)",
                (str(entry.id), str(tag_id)),
            )

    def delete_entry(self, entry_id: UUID) -> bool:
        """Delete an entry by ID.

        Args:
            entry_id: The entry's UUID.

        Returns:
            True if an entry was deleted, False otherwise.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute(
            "DELETE FROM entries WHERE id = ?", (str(entry_id),)
        )
        return self._connection.changes() > 0

    # Category operations
    def get_all_categories(self) -> list[Category]:
        """Get all categories.

        Returns:
            List of all categories.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute("SELECT * FROM categories ORDER BY name")
        return [
            Category(
                id=UUID(row[0]),
                name=row[1],
                icon=row[2],
                color=row[3],
                created_at=datetime.fromisoformat(row[4]),
            )
            for row in cursor.fetchall()
        ]

    def add_category(self, category: Category) -> None:
        """Add a new category.

        Args:
            category: The category to add.
        """
        self._ensure_unlocked()

        self._connection.execute(
            """
            INSERT INTO categories (id, name, icon, color, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(category.id),
                category.name,
                category.icon,
                category.color,
                category.created_at.isoformat(),
            ),
        )

    def delete_category(self, category_id: UUID) -> bool:
        """Delete a category by ID.

        Args:
            category_id: The category's UUID.

        Returns:
            True if a category was deleted.
        """
        self._ensure_unlocked()

        self._connection.execute(
            "DELETE FROM categories WHERE id = ?", (str(category_id),)
        )
        return self._connection.changes() > 0

    # Tag operations
    def get_all_tags(self) -> list[Tag]:
        """Get all tags.

        Returns:
            List of all tags.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute("SELECT * FROM tags ORDER BY name")
        return [
            Tag(
                id=UUID(row[0]),
                name=row[1],
                created_at=datetime.fromisoformat(row[2]),
            )
            for row in cursor.fetchall()
        ]

    def add_tag(self, tag: Tag) -> None:
        """Add a new tag.

        Args:
            tag: The tag to add.
        """
        self._ensure_unlocked()

        self._connection.execute(
            "INSERT INTO tags (id, name, created_at) VALUES (?, ?, ?)",
            (str(tag.id), tag.name, tag.created_at.isoformat()),
        )

    def delete_tag(self, tag_id: UUID) -> bool:
        """Delete a tag by ID.

        Args:
            tag_id: The tag's UUID.

        Returns:
            True if a tag was deleted.
        """
        self._ensure_unlocked()

        self._connection.execute("DELETE FROM tags WHERE id = ?", (str(tag_id),))
        return self._connection.changes() > 0

    def get_entry_count(self) -> int:
        """Get total number of entries.

        Returns:
            Count of entries in the vault.
        """
        self._ensure_unlocked()

        cursor = self._connection.execute("SELECT COUNT(*) FROM entries")
        return cursor.fetchone()[0]

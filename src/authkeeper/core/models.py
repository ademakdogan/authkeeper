"""Data models for AuthKeeper.

Defines the core entities: Entry, Category, Tag, and SecureNote
using Pydantic for validation and serialization.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class EntryType(str, Enum):
    """Type of vault entry."""

    PASSWORD = "password"
    SECURE_NOTE = "secure_note"


class CategoryIcon(str, Enum):
    """Predefined icons for categories."""

    FOLDER = "folder"
    WORK = "briefcase"
    PERSONAL = "user"
    FINANCE = "credit-card"
    SOCIAL = "share-2"
    EMAIL = "mail"
    SHOPPING = "shopping-cart"
    GAMING = "gamepad-2"
    DEVELOPMENT = "code"
    SERVER = "server"
    WIFI = "wifi"
    KEY = "key"


class Category(BaseModel):
    """Category for organizing entries.

    Attributes:
        id: Unique identifier.
        name: Display name of the category.
        icon: Icon identifier for UI display.
        color: Hex color code for the category.
        created_at: Timestamp of creation.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=50)
    icon: CategoryIcon = Field(default=CategoryIcon.FOLDER)
    color: str = Field(default="#6366f1")
    created_at: datetime = Field(default_factory=datetime.now)

    @field_validator("color")
    @classmethod
    def validate_color(cls, v: str) -> str:
        """Validate hex color format."""
        if not v.startswith("#") or len(v) != 7:
            raise ValueError("Color must be a valid hex code (e.g., #6366f1)")
        return v.lower()


class Tag(BaseModel):
    """Tag for flexible entry labeling.

    Attributes:
        id: Unique identifier.
        name: Tag name (lowercase, no spaces).
        created_at: Timestamp of creation.
    """

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., min_length=1, max_length=30)
    created_at: datetime = Field(default_factory=datetime.now)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        """Normalize tag name to lowercase without spaces."""
        return v.lower().strip().replace(" ", "-")


class Entry(BaseModel):
    """Password entry in the vault.

    Attributes:
        id: Unique identifier.
        entry_type: Type of entry (password or secure_note).
        name: Display name for the entry.
        username: Username or email.
        password: The password (stored encrypted in database).
        url: Associated website or service URL.
        notes: Additional notes.
        category_id: Optional category reference.
        tag_ids: List of associated tag IDs.
        favorite: Whether this entry is marked as favorite.
        created_at: Timestamp of creation.
        updated_at: Timestamp of last modification.
    """

    id: UUID = Field(default_factory=uuid4)
    entry_type: EntryType = Field(default=EntryType.PASSWORD)
    name: str = Field(..., min_length=1, max_length=100)
    username: str = Field(default="", max_length=200)
    password: str = Field(default="", max_length=500)
    url: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=5000)
    category_id: UUID | None = Field(default=None)
    tag_ids: list[UUID] = Field(default_factory=list)
    favorite: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def model_post_init(self, __context: Any) -> None:
        """Update the updated_at timestamp when model is modified."""
        pass

    def touch(self) -> None:
        """Update the updated_at timestamp to current time."""
        object.__setattr__(self, "updated_at", datetime.now())


class SecureNote(BaseModel):
    """Secure note for storing arbitrary encrypted text.

    Useful for SSH keys, API tokens, WiFi passwords, etc.

    Attributes:
        id: Unique identifier.
        title: Display title for the note.
        content: The encrypted content of the note.
        category_id: Optional category reference.
        tag_ids: List of associated tag IDs.
        favorite: Whether this note is marked as favorite.
        created_at: Timestamp of creation.
        updated_at: Timestamp of last modification.
    """

    id: UUID = Field(default_factory=uuid4)
    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(default="", max_length=50000)
    category_id: UUID | None = Field(default=None)
    tag_ids: list[UUID] = Field(default_factory=list)
    favorite: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def touch(self) -> None:
        """Update the updated_at timestamp to current time."""
        object.__setattr__(self, "updated_at", datetime.now())


class VaultMetadata(BaseModel):
    """Metadata about the vault itself.

    Attributes:
        version: Schema version for migrations.
        created_at: When the vault was created.
        last_accessed: Last access timestamp.
        password_hash: Argon2id hash of the master password.
        salt: Salt used for key derivation.
    """

    version: int = Field(default=1)
    created_at: datetime = Field(default_factory=datetime.now)
    last_accessed: datetime = Field(default_factory=datetime.now)
    password_hash: str = Field(...)
    salt: bytes = Field(...)

    class Config:
        """Pydantic configuration."""

        arbitrary_types_allowed = True

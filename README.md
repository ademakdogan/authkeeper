# 🔐 AuthKeeper

A secure terminal password manager with encrypted storage and modern CLI interface.

## Features

| Feature | Description |
|---------|-------------|
| 🔒 **AES-256-GCM Encryption** | Military-grade encryption for all sensitive data |
| 🔑 **Argon2id Key Derivation** | Memory-hard hashing resistant to brute-force attacks |
| 🔍 **Fuzzy Search** | Find entries even with typos |
| 📋 **Auto-Clear Clipboard** | Passwords cleared after 30 seconds |
| 📤 **Export/Import** | JSON backup and restore |
| 🎲 **Password Generator** | Secure random passwords and passphrases |
| 🐳 **Docker Support** | Run isolated in a container |

---

## Quick Start

### Local Installation

```bash
# Clone and install
git clone https://github.com/youruser/authkeeper.git
cd authkeeper

# Run with uv
uv run authkeeper

# Or install and run
uv pip install -e .
authkeeper
```

### Docker

```bash
# Build and run
docker compose run --rm authkeeper

# Or using make
make docker-run
```

---

## Commands

### Main Menu

| Command | Action |
|---------|--------|
| `1` | List all entries |
| `2` | Add new entry |
| `3 <query>` | Search entries (fuzzy) |
| `4` | Generate password |
| `5` | Export/Import menu |
| `6` | Lock vault & exit |

### Quick Commands

| Command | Description | Example |
|---------|-------------|---------|
| `c <n>` | Copy password by number | `c 1` |
| `c <name>` | Copy password by name (fuzzy) | `c github` |
| `v <n>` | View entry details | `v 1` |
| `e <n>` | Edit entry | `e 1` |
| `d <n...>` | Delete entry(ies) | `d 1 3 5` |
| `p <n>` | Preview password (masked) | `p 1` |
| `fav` | Show favorites only | `fav` |
| `export` | Export to JSON file | `export` |
| `import` | Import from JSON file | `import` |
| `q` | Quit (same as `6`) | `q` |

---

## Password Generator

Generate secure passwords interactively:

```
> 4

Generate Password
Length [16]: 24
Include symbols (!@#$)? [y/n]: y
Generate passphrase instead? [y/n]: n

╭─────────── Generated Password ────────────╮
│ K7#mP2x$Q9vL5n@R3wJt!2Xb                  │
╰───────────────────────────────────────────╯

Copy to clipboard? [Y/n]: y
✓ Copied! (clears in 30 seconds)
```

### Passphrase Mode

```
Coral-Brick-Dance-Tiger-42
```

---

## Security

### Encryption Architecture

```
Master Password
      │
      ▼ Argon2id (64MB RAM, 3 iterations)
      │
      ▼
Encryption Key (256-bit)
      │
      ▼ AES-256-GCM
      │
      ▼
Encrypted Vault
```

### Security Features

| Feature | Implementation |
|---------|----------------|
| **Key Derivation** | Argon2id with OWASP recommended parameters |
| **Encryption** | AES-256-GCM (authenticated encryption) |
| **Memory** | 64 MB memory cost (anti-GPU cracking) |
| **Salt** | 16 bytes random per vault |
| **Nonce** | 12 bytes random per field encryption |
| **Field-Level** | Passwords and notes encrypted separately |

### What's Encrypted?

| Field | Encrypted? |
|-------|------------|
| Entry name | ❌ No (for search) |
| Username | ❌ No (for search) |
| **Password** | ✅ **Yes** |
| URL | ❌ No (for search) |
| **Notes** | ✅ **Yes** |

### Data Location

```bash
# macOS
~/Library/Application Support/authkeeper/vault.db

# Linux
~/.local/share/authkeeper/vault.db

# Docker
/home/authkeeper/.local/share/authkeeper/vault.db
```

---

## Development

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager

### Setup

```bash
# Install dependencies
make install

# Run locally
make run

# Run tests
make test

# Lint code
make lint
```

### Project Structure

```
authkeeper/
├── src/authkeeper/
│   ├── cli.py           # CLI interface
│   ├── core/
│   │   ├── crypto.py    # Encryption (Argon2id + AES-GCM)
│   │   ├── database.py  # Encrypted SQLite
│   │   └── models.py    # Pydantic models
│   ├── services/
│   │   ├── vault.py     # Vault management
│   │   ├── clipboard.py # Auto-clear clipboard
│   │   └── password_generator.py
│   └── utils/
│       └── config.py    # Configuration
├── tests/
│   ├── test_crypto.py
│   └── test_password_generator.py
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── pyproject.toml
```

---

## Docker

### Build Image

```bash
make docker-build
```

### Run Container

```bash
# Interactive mode
make docker-run

# With custom data volume
docker run -it --rm \
  -v my-vault:/home/authkeeper/.local/share/authkeeper \
  authkeeper:latest
```

### Volume Management

```bash
# List volumes
docker volume ls | grep authkeeper

# Backup vault
docker run --rm -v authkeeper-vault:/data -v $(pwd):/backup alpine \
  cp /data/vault.db /backup/vault_backup.db

# Remove volume (WARNING: deletes all data!)
docker volume rm authkeeper-vault
```

---

## Backup & Restore

### Export (Unencrypted JSON)

```bash
> export
Export file path [authkeeper_export.json]: ~/backup/passwords.json
✓ Exported 15 entries to ~/backup/passwords.json
```

### Import

```bash
> import
Import file path: ~/backup/passwords.json
Found 15 entries in file.
Import all entries? [Y/n]: y
✓ Imported 15 entries.
```

⚠️ **Warning**: Export files contain plaintext passwords. Store securely!

---

## License

MIT License - See [LICENSE](LICENSE) for details.

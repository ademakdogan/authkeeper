# AuthKeeper

Secure terminal password manager with encrypted storage.

## Features

- 🔐 AES-256-GCM encryption with Argon2id key derivation
- 📋 Auto-clearing clipboard (30 seconds)
- 🔍 Fuzzy search
- 📤 JSON export/import
- 🎲 Password generator

## Quick Start

```bash
# Run with uv
uv run authkeeper

# Or with Docker
docker compose run --rm authkeeper
```

## Commands

| Command | Action |
|---------|--------|
| `1` | List entries |
| `2` | Add entry |
| `3 <query>` | Search |
| `4` | Generate password |
| `5` | Export/Import |
| `6` | Lock & Exit |
| `c <n>` | Copy password |
| `v <n>` | View entry |
| `e <n>` | Edit entry |
| `d <n>` | Delete entry |
| `p <n>` | Preview password |
| `fav` | Show favorites |

## License

MIT

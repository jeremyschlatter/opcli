# opcli

A fast, local 1Password CLI alternative. Reads directly from 1Password's local SQLite database instead of making network calls.

## Performance

~23x faster than the official `op` CLI:

```
opcli read: 47.8ms (mean)
op read:    1121ms (mean)
```

## How it works

1. Reads the local 1Password SQLite database
2. Derives the Account Unlock Key using 2SKD (HKDF + PBKDF2)
3. Decrypts the keyset chain (AES-256-GCM + RSA-OAEP)
4. Decrypts vault keys and item data

No network calls. No IPC with the desktop app. Just direct crypto.

## Installation

```bash
go install github.com/jeremyschlatter/opcli@latest
```

Or build from source:

```bash
go build -o opcli .
```

## Usage

```bash
# Read a field from an item
opcli read "op://VaultName/ItemName/fieldname"

# List all vaults
opcli list

# Dump an item as JSON
opcli get "op://VaultName/ItemName"

# Test unlock (verify credentials work)
opcli unlock

# Start credential daemon (for fast repeated access)
opcli daemon
```

### Credential Daemon

To avoid entering your master password on every command, run the daemon:

```bash
# Terminal 1: Start daemon (enter credentials once)
opcli daemon

# Terminal 2: Commands now work without prompts
opcli read "op://Personal/github.com/password"
```

## Configuration

Set these environment variables to avoid prompts:

- `OP_SECRET_KEY` - Your 1Password Secret Key (A3-XXXXX-...)
- `OP_MASTER_PASSWORD` - Your master password (not recommended for security)

## Security Warning

**The unlock UX is a work in progress.** The current daemon implementation:

- Stores your master password in memory (protected by [memguard](https://github.com/awnumar/memguard))
- Authenticates requests via a token file (`~/.opcli/opcli.token`)
- **Is NOT secure against malicious processes on your machine** - any process running as your user can read the token file and request your credentials

For high-security environments, enter credentials manually each time or use the official `op` CLI with biometric unlock.

## Requirements

- macOS (reads from `~/Library/Group Containers/2BUA8C4S2C.com.1password/`)
- 1Password 8 desktop app installed (creates the local database)
- Your 1Password Secret Key (from your Emergency Kit)

## Limitations

- macOS only (hardcoded database path)
- Some shared vaults from other accounts may not decrypt (missing keysets)
- Read-only (no write operations)

## License

MIT

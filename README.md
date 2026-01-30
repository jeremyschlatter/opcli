# opcli

A fast, local 1Password CLI alternative. Reads directly from 1Password's local SQLite database instead of making network calls.

## Performance

~10x faster than the official `op` CLI:

```
❯ hyperfine 'opcli read "op://Private/example/example"'
Benchmark 1: opcli read "op://Private/example/example"
  Time (mean ± σ):      90.9 ms ±   3.2 ms    [User: 34.6 ms, System: 9.2 ms]
  Range (min … max):    83.6 ms …  96.0 ms    34 runs

❯ hyperfine 'op read "op://Private/example/example"'
Benchmark 1: op read "op://Private/example/example"
  Time (mean ± σ):     979.6 ms ±  21.1 ms    [User: 159.4 ms, System: 53.0 ms]
  Range (min … max):   937.1 ms … 1016.9 ms    10 runs
```

## How it works

1. Reads the local 1Password SQLite database
2. Derives the Account Unlock Key using 2SKD (HKDF + PBKDF2)
3. Decrypts the keyset chain (AES-256-GCM + RSA-OAEP)
4. Decrypts vault keys and item data

No network calls. No IPC with the desktop app. Just direct crypto.

## Installation

Download the [latest release](https://github.com/jeremyschlatter/opcli/releases/latest) from GitHub.

Or build from source:

```bash
make
make sign SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

The build requires Xcode Command Line Tools and Go 1.21+.

### Code Signing (required for Touch ID)

For Touch ID support, the binary must be signed with a Developer ID certificate.

The release binary is signed with my certificate. To build from source you will need your own.

## Usage

```bash
# First time: sign in (stores credentials in Keychain)
opcli signin

# Read a field from an item (prompts Touch ID on first use per terminal)
opcli read "op://VaultName/ItemName/fieldname"

# List all vaults
opcli list

# Dump an item as JSON
opcli get "op://VaultName/ItemName"

# Remove credentials from Keychain
opcli signout
```

## Security

### Touch ID

We unfortunately cannot integrate with the 1Password Desktop App for account unlocking, so `opcli signin` will require you to enter both your 1Password Secret Key (from your Emergency Kit) and your Master Password.

These credentials are stored in the macOS Keychain with an app-only ACL. After this, `opcli` will only use TouchID to authenticate you. If any other app tries to read these credentials from the Keychain, macOS will give you a Keychain password prompt:

> `app` wants to use your confidential information stored in "opcli credentials" in your keychain.

...which you should deny.

### Sessions

Each terminal session requires Touch ID authentication on first access. After authenticating:
- The session lasts for **10 minutes of inactivity**
- Hard limit of **12 hours** before re-authentication is required
- Each terminal window/tab has its own session

This mirrors the UX of the official `op` CLI's desktop app integration.

## Requirements

- macOS (reads from `~/Library/Group Containers/2BUA8C4S2C.com.1password/`)
- 1Password 8 desktop app installed (creates the local database)
- Your 1Password Secret Key (from your Emergency Kit)

## Limitations

- macOS only
- Read-only (no write operations)

## Why Not Desktop App Integration?

The official `op` CLI can avoid password prompts by integrating with the 1Password desktop app (Touch ID).

Unfortunately for us, but fortunately for 1Password security in general, the desktop app requires a code signature from Agile Bits before accepting a connection from the CLI. If `opcli` does extremely well, maybe we can get Agile Bits to adopt it some day. Until then, we're stuck with managing the master password ourselves.

## License

MIT

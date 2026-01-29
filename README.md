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
make
make sign SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
```

The build requires Xcode Command Line Tools and Go 1.21+.

### Code Signing (required for Touch ID)

For Touch ID support, the binary must be signed with a Developer ID certificate.
Without code signing, you can still use environment variables or the daemon for authentication.

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

### Touch ID & Sessions

After running `opcli signin`, your credentials are stored in the macOS Keychain with an app-only ACL (only the signed `opcli` binary can read them).

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

- macOS only (hardcoded database path)
- Some shared vaults from other accounts may not decrypt (missing keysets)
- Read-only (no write operations)

## Why Not Desktop App Integration?

The official `op` CLI can avoid password prompts by integrating with the 1Password desktop app (Touch ID). We investigated both available paths:

### Path 1: XPC (used by `op` CLI)

The `op` CLI communicates via XPC (Apple's IPC mechanism) to `2BUA8C4S2C.com.1password.browser-helper`. XPC connections are validated by code signature:

```
verifySignatureOfSelfMatchesSignature(of:) Code signature team id of client == ourselves: true
```

The `op` binary is signed by AgileBits with Team ID `2BUA8C4S2C`. Third-party tools cannot pass this check.

### Path 2: Browser Native Messaging (used by browser extensions)

Browser extensions use Chrome/Firefox Native Messaging to spawn `1Password-BrowserSupport`, which then uses XPC to the main app. We investigated using this as an intermediary but found:

1. **Parent process validation**: BrowserSupport validates its parent process is an approved browser before processing any messages:
   ```
   failed to validate our guessed browser parent: no possible browser subprocesses matched the users approval list
   ```

2. **Browser enrollment**: Custom browsers can be added via `browsers.other-trusted-apps` in settings, but this requires cryptographic enrollment (`enrollmentUuid`, JWK keys), not a simple whitelist.

3. **Process tree inspection**: Validation checks the entire process tree, not just the immediate parent. BrowserSupport must be spawned by a browser's subprocess hierarchy.

### Conclusion

Both paths have strong caller validation:
- **XPC path**: Requires AgileBits Team ID signature
- **BrowserSupport path**: Requires parent process to be an approved browser

Third-party tools cannot integrate with the 1Password desktop app for Touch ID unlock.

### Our Solution

Instead of integrating with the 1Password app, opcli implements its own Touch ID flow:

1. `opcli signin` stores credentials in the macOS Keychain with an app-only ACL
2. On first access per terminal, Touch ID is triggered via LAContext
3. Sessions (10 min inactivity / 12 hr max) prevent repeated prompts

This provides a similar UX to the official `op` CLI without requiring desktop app integration.

## License

MIT

# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project uses semantic versioning where possible.

## [2.0.0] - 2025-12-07

### Added
- Interactive menu with language selection (EN/ID).
- Environment detection (Linux, macOS, Termux) + auto-install dependencies.
- Clipboard auto-copy with auto-clear (Termux, macOS, xclip, wl-copy).
- Password strength coaching (entropy, guess-time, hints in EN + ID).
- Recovery key pair (RSA) with `forgot` master password flow.
- Portable and save bundles including recovery files.
- `doctor` health / integrity check: vault format, recovery key, notes, etc.
- Secure notes: `notes-add`, `notes-list`, `notes-view`, `notes-delete`.

### Security
- Strong AES256 GPG symmetric encryption for the vault.
- Recovery public key embedded in vault metadata.
- `.gitignore` prevents vaults and private keys from being committed.

[2.0.0]: https://github.com/YOUR_USER/YOUR_REPO/releases/tag/v2.0.0

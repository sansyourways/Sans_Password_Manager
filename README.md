# Sans Password Manager (SPM)

[![Latest release](https://img.shields.io/github/v/release/sansyourways/Sans_Password_Manager?style=flat-square&color=4ade80)](https://github.com/sansyourways/Sans_Password_Manager/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/sansyourways/Sans_Password_Manager?style=flat-square&color=fbbf24)](https://github.com/sansyourways/Sans_Password_Manager/stargazers)
[![Release downloads](https://img.shields.io/github/downloads/sansyourways/Sans_Password_Manager/total?style=flat-square&color=60a5fa)](https://github.com/sansyourways/Sans_Password_Manager/releases)
[![CI](https://github.com/sansyourways/Sans_Password_Manager/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sansyourways/Sans_Password_Manager/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-7c3aed?style=flat-square)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/sansyourways/Sans_Password_Manager?style=flat-square)](https://github.com/sansyourways/Sans_Password_Manager/commits/main)

<p align="center">
  <img src="https://raw.githubusercontent.com/sansyourways/Sans_Password_Manager/main/docs/social-preview.png" alt="Sans Password Manager — Own the vault" width="1280">
</p>

An offline, portable password manager for people who want to own the vault,
understand the storage model, and keep cloud infrastructure out of the trust
boundary.

SPM is one executable Bash script backed by GnuPG. It provides a terminal
interface for automation and administration, plus an optional local web
interface for everyday browsing. There are no accounts, hosted APIs,
subscriptions, analytics, or vendor-operated recovery services.

Current release: **2.10.5**

---

## Table of Contents

- [Why use SPM?](#why-use-spm)
- [Product tour](#product-tour)
- [Capabilities](#capabilities)
- [Architecture & Security Model](#architecture--security-model)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Web Mode](#web-mode)
  - [CLI Commands](#cli-commands)
  - [Secure Notes](#secure-notes)
  - [Recovery: Forgot Master Password](#recovery-forgot-master-password)
  - [Doctor / Health Check](#doctor--health-check)
- [Password Strength Coaching](#password-strength-coaching)
- [Clipboard Auto-Clean](#clipboard-auto-clean)
- [Portable & Save Bundles](#portable--save-bundles)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Development & Versioning](#development--versioning)
- [Documentation & Legal](#documentation--legal)
- [License](#license)

---

## Why use SPM?

Most password managers ask you to trust an application, a browser extension,
an account system, a synchronization service, and the company operating all of
them. SPM deliberately keeps that trust boundary small.

| Reason | What it means in practice |
| --- | --- |
| Your vault stays yours | The encrypted vault, recovery material, backups, and sync target remain on storage you control. |
| No service dependency | Core vault operations work without an internet connection, hosted account, license server, or vendor API. |
| Auditable implementation | The primary application is one readable Bash file that delegates encryption to standard GnuPG and OpenSSL tools. |
| Terminal and browser workflows | Use deterministic CLI commands for administration and automation, or launch the optional web interface for a more visual workflow. |
| Portable by design | Create a self-contained encrypted bundle for removable media or move between Linux, macOS, and Termux environments. |
| Recovery without vendor custody | Generate your own RSA recovery key and store it offline; SPM never holds a copy. |
| More than passwords | Store notes, passphrases, backup codes, TOTP authenticators, attachments, and passkey metadata in the same encrypted vault. |
| Built-in operational safety | Atomic writes, advisory locking, encrypted history, verified backups, sync conflict detection, and health diagnostics reduce avoidable data loss. |

SPM is a strong fit for technically confident individuals, administrators,
small teams with local-first requirements, air-gapped systems, and anyone who
prefers transparent tools over opaque hosted custody. It is not intended to
protect a compromised operating system, malware-infected device, or an
attacker with root access.

## Product tour

All screenshots below were captured in Google Chrome from SPM 2.10.5 using a
disposable vault containing only synthetic documentation data. No personal
vault or real credential appears in these images.

![Animated tour of the SPM web interface using synthetic records](docs/product-demo.gif)

### Unlock and assess the vault

| Secure login | Security overview |
| --- | --- |
| ![SPM master-password login](docs/screenshots/web-v2.10.5/01-login.png) | ![SPM vault overview and security score](docs/screenshots/web-v2.10.5/02-overview.png) |

### Work with credentials and protected records

| Password records | Authenticator codes |
| --- | --- |
| ![SPM password list](docs/screenshots/web-v2.10.5/03-passwords.png) | ![SPM TOTP authenticator view](docs/screenshots/web-v2.10.5/16-authenticator-view.png) |

| Password generator | Import and export |
| --- | --- |
| ![SPM password generator](docs/screenshots/web-v2.10.5/22-generator.png) | ![SPM import and export workspace](docs/screenshots/web-v2.10.5/23-transfer.png) |

<details>
<summary><strong>Complete web interface gallery (23 pages)</strong></summary>

#### Passwords

| Add | View | Edit |
| --- | --- | --- |
| ![Add password](docs/screenshots/web-v2.10.5/04-password-add.png) | ![View password](docs/screenshots/web-v2.10.5/05-password-view.png) | ![Edit password](docs/screenshots/web-v2.10.5/06-password-edit.png) |

#### Secure notes

| List | Add | View |
| --- | --- | --- |
| ![Secure notes list](docs/screenshots/web-v2.10.5/07-notes.png) | ![Add secure note](docs/screenshots/web-v2.10.5/08-note-add.png) | ![View secure note](docs/screenshots/web-v2.10.5/09-note-view.png) |

#### Passphrases

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Passphrase list](docs/screenshots/web-v2.10.5/10-passphrases.png) | ![Add passphrase](docs/screenshots/web-v2.10.5/11-passphrase-add.png) | ![View passphrase](docs/screenshots/web-v2.10.5/12-passphrase-view.png) | ![Edit passphrase](docs/screenshots/web-v2.10.5/13-passphrase-edit.png) |

#### Authenticators

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Authenticator list](docs/screenshots/web-v2.10.5/14-authenticators.png) | ![Add authenticator](docs/screenshots/web-v2.10.5/15-authenticator-add.png) | ![View authenticator](docs/screenshots/web-v2.10.5/16-authenticator-view.png) | ![Edit authenticator](docs/screenshots/web-v2.10.5/17-authenticator-edit.png) |

#### Backup codes

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Backup-code list](docs/screenshots/web-v2.10.5/18-backup-codes.png) | ![Add backup codes](docs/screenshots/web-v2.10.5/19-backup-codes-add.png) | ![View backup codes](docs/screenshots/web-v2.10.5/20-backup-codes-view.png) | ![Edit backup codes](docs/screenshots/web-v2.10.5/21-backup-codes-edit.png) |

</details>

## Capabilities

- GnuPG AES-256 encrypted vault with atomic writes and advisory locking
- Interactive terminal interface with English, Indonesian, and Japanese modes
- Optional Console-style web interface with inactivity locking
- Password records, secure notes, passphrases, backup codes, and TOTP
  authenticators using SHA-1, SHA-256, or SHA-512
- Secure and memorable password generation with strength coaching
- Clipboard copy feedback and automatic clipboard clearing
- CLI and web import/export across CSV, JSON, TSV, NDJSON, Markdown, HTML,
  YAML, XML, SQL, INI, PSV, RST, TOML, Org, SCSV, JSONC, and related variants
- Vault-wide security score for weak, reused, old, incomplete, or malformed
  records
- Encrypted history, verified manual/automatic backups, and confirmed rollback
- Digest-verified encrypted attachments with a 1 MiB limit
- Named vault profiles and conflict-aware filesystem synchronization
- Recipient-encrypted emergency kits with authenticated contents
- Platform passkey metadata and an exact-domain native browser bridge
- Portable and SAVE bundles with recovery private keys excluded by default
- RSA-based self-custodied recovery and built-in doctor diagnostics

---

## Architecture & Security Model

### Encryption
- **Vault:** GnuPG symmetric AES-256  
- **Recovery:** RSA-2048 private/public key  
- **Notes:** Base64 + encrypted  
- **Metadata:** Stored inside encrypted vault

### Recovery Design
- `spm_recovery_private.pem` → your private key (store offline)  
- `<vault>.recovery` → recovery capsule encrypted with RSA public key

### SPM Assumes
- Host machine is secure  
- User protects master password & private key  
- GnuPG/OpenSSL are trusted binaries

### SPM Does NOT Resist
- Keyloggers / malware  
- Root attackers  
- RAM extraction  
- OS-level compromise  
- User mistakes (uploading vault, losing private key)

For more details, see [`SECURITY.md`](docs/SECURITY.md).

---

## Requirements
SPM automatically checks / installs:

- bash  
- gpg  
- openssl  
- curl  
- zip
- mktemp
- Clipboard helpers:
  - pbcopy (macOS)  
  - xclip / wl-copy (Linux)  
  - termux-clipboard-set (Termux)

---

## Installation

### Verified release installer

Download the installer first so you can inspect it, then install the latest
release. The installer downloads both the official ZIP and its matching
SHA-256 file, verifies the archive, checks Bash syntax, and installs `spm`.

```bash
curl -fsSLO https://raw.githubusercontent.com/sansyourways/Sans_Password_Manager/main/install.sh
bash install.sh
```

Install a specific release or a user-writable prefix:

```bash
bash install.sh --version 2.10.5
bash install.sh --prefix "$HOME/.local"
```

### From source

```bash
git clone https://github.com/sansyourways/Sans_Password_Manager.git
cd Sans_Password_Manager
chmod +x spm.sh
./spm.sh
```

---

## Usage

### Interactive Menu

```bash
./spm.sh
```

Includes:

- Add / list / get / delete entry  
- Edit vault  
- Change master password  
- Portable bundle  
- SAVE bundle  
- Secure notes  
- Recovery  
- Doctor diagnostics  

---

### Web Mode

```bash
./spm.sh web
```

- Runs on localhost by default; Global/custom binds require an explicit risk confirmation
- Background mode verifies that its PM2 process is online and reports startup errors
- SPM never changes firewall rules automatically; restrict any remote port to trusted clients
- Vault stays encrypted locally  
- Master password required  
- Features:
  - View entries  
  - View notes  
  - View passphrases  
  - View backup codes  
  - Edit entries  
  - Local copy-to-clipboard with inline toast feedback  
  - Language dropdown (EN/ID/JP) that translates the dashboard/import card and remembers your choice via cookie  
  - Detail pages (/view, /edit, authenticator viewer/editor, generator) inherit that language selection so every screen stays localized  
  - Dark-only Console presentation with a command-style vault status overview, visible keyboard focus, and mobile record layouts
  - Restrained motion for causal feedback—toast arrival, mobile navigation,
    import progress, and authenticator-code changes—with a fully static
    `prefers-reduced-motion` experience
  - A consistent inline SVG icon system for navigation, vault objects, status,
    and actions; the geometric assets inherit Console colors and work fully
    offline without icon fonts or third-party requests

Console deliberately favors dense, auditable rows over spacious cards. Very long
vault labels still wrap and can make mobile records tall; this is preferable to
shrinking text or forcing page-level horizontal scrolling.

---

### CLI Commands

```bash
./spm.sh init
./spm.sh add
./spm.sh list
./spm.sh get <id>
./spm.sh delete <id>
./spm.sh change-master
./spm.sh portable
./spm.sh save
./spm.sh restore
./spm.sh export [csv|json] [output-file]
./spm.sh import [csv|json] <input-file>
./spm.sh forgot
./spm.sh notes-add
./spm.sh notes-list
./spm.sh notes-view <id>
./spm.sh notes-delete <id>
./spm.sh passphrase-add
./spm.sh passphrase-list
./spm.sh passphrase-view <id>
./spm.sh passphrase-delete <id>
./spm.sh backup-codes-add
./spm.sh backup-codes-list
./spm.sh backup-codes-view <id>
./spm.sh backup-codes-delete <id>
./spm.sh doctor
./spm.sh web
```

---

## Secure Notes

```bash
./spm.sh notes-add
./spm.sh notes-list
./spm.sh notes-view 1
./spm.sh notes-delete 1
```

Stored inside encrypted vault.

---

## Export

```bash
./spm.sh export csv spm_export.csv
./spm.sh export json
```

Exports passwords, secure notes, passphrases, backup codes, and authenticators. Defaults to `spm_export_<timestamp>.csv` when no filename is provided; if you omit the extension on a custom name, it is auto-added. Advanced formats available: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc. Web mode also has an Export/Import card with the same formats and supports direct file upload for import. The format selector respects your EN/ID/JP language choice so menu text stays localized across sessions.

---

## Import

```bash
./spm.sh import csv my_export.csv
./spm.sh import json backup.json
```

Imports passwords, secure notes, passphrases, backup codes, and authenticators from supported export formats (csv/json primary; advanced formats accepted as listed above). Entries are appended and IDs auto-renumbered. Imports fail if no supported records are detected. Web mode overlays the entire Export/Import card with a loader during uploads, reports how many rows of each type were added, and automatically reloads the dashboard on success so the new rows appear immediately (errors show inline without redirect). Status messages and overlay text follow the selected language (EN/ID/JP) so users get consistent feedback during uploads.

---

## Passphrases

```bash
./spm.sh passphrase-add
./spm.sh passphrase-list
./spm.sh passphrase-view 1
./spm.sh passphrase-delete 1
```

Stored inside the encrypted vault. Viewing prompts a master password re-check.

---

## Backup Codes

```bash
./spm.sh backup-codes-add
./spm.sh backup-codes-list
./spm.sh backup-codes-view 1
./spm.sh backup-codes-delete 1
```

Stored inside encrypted vault. Viewing requires master password re-verification.

---

## Recovery: Forgot Master Password

Generated files:

- `spm_recovery_private.pem`  
- `<vault>.recovery`

To reset:

```bash
./spm.sh forgot
```

Process:

1. Decrypt recovery capsule  
2. Retrieve old master password  
3. Set new master password  
4. Rebuild vault + recovery files  

---

## Doctor / Health Check

```bash
./spm.sh doctor
```

Validates:

- Vault structure  
- GPG/AES decryption  
- Duplicate IDs  
- Secure notes integrity  
- Recovery metadata  
- RSA key pairing  
- File permissions on the vault, its `.bak`, the recovery file, and **every
  copy of the RSA private key** — each should be `600`. Anything readable by
  group or others is reported with a ready-to-run `chmod` command. Vaults last
  written by a web session before 2.9.1 were left at the umask default (usually
  `644`), and this is how you find and fix them.
  Because `init` generates the recovery key in whatever directory you run it
  from, copies tend to accumulate. The check looks in the current directory,
  beside the vault, next to the script, and up to four levels under `$HOME`,
  de-duplicating by real path. An exposed recovery key is worth fixing first:
  it unlocks the vault via `forgot` **without** the master password.

---

## Password Strength Coaching
SPM analyzes:

- Entropy  
- Crack-time estimates  
- Character class distribution  
- Repetition patterns  
- Suggestions (EN + ID)

---

## Clipboard Auto-Clean
Auto-clears clipboard in ~15 seconds using:

- pbcopy (macOS)  
- xclip / wl-copy (Linux)  
- termux-clipboard-set (Termux)

If unavailable → fallback warning only.

---

## Portable & Save Bundles

### Portable

```bash
./spm.sh portable
```

Bundle includes:

- spm.sh  
- spm_vault.gpg  
- spm_vault.gpg.recovery  
- Auto README file  

The RSA recovery private key is deliberately excluded. Keep it in a separate
offline location. To create a self-contained archive that can bypass the master
password, explicitly run `SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1 ./spm.sh portable`.
Treat that opt-in archive as plaintext-equivalent credential material.

### SAVE

```bash
./spm.sh save
```

Creates encrypted backup, wipes local vault.
The recovery private key remains separate unless
`SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1` is explicitly set.

---

## Contributing

Bug reports, focused improvements, and portability fixes are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Public issue
forms are available for bugs, feature requests, and non-sensitive security
design questions. Potential vulnerabilities must use the repository's private
security-advisory channel.

Contributions are accepted under Apache-2.0 and require a Developer Certificate
of Origin sign-off. Contributors retain copyright in their work; see
[the contributor license policy](docs/CONTRIBUTOR_LICENSE_POLICY.md).

Every change is checked with Bash syntax validation, ShellCheck, and a
disposable-vault regression suite covering all supported import/export formats,
web uploads, backups, synchronization, attachments, passkey metadata, emergency
kits, and password generation.

CI runs the regression suite on Linux and macOS, plus syntax, CLI-help, and
installer smoke checks in a pinned official Termux container. Pull requests
also require a DCO sign-off check.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for current reliability work, safer-integration
priorities, longer-term ecosystem ideas, and guidance for choosing a first
issue. Roadmap entries are directions, not promised delivery dates.

---

## Development & Versioning

Version: **2.10.5**
Web session cookies use `HttpOnly` and `SameSite=Strict`; `Secure` is added when the request arrives over HTTPS (`X-Forwarded-Proto`). Plain-HTTP non-loopback binds require an explicit `yes` confirmation: prefer localhost behind a TLS reverse proxy. `SPM_WEB_ALLOW_INSECURE_REMOTE=1` remains a non-interactive escape hatch for isolated trusted networks only.
The web login locks a client out for 60 seconds after 5 failed master-password attempts.
The 30-second idle auto-lock performs a single logout transition and tears down
its timer when the page is leaving, avoiding repeated navigation or refresh loops.
Returning to a page through the back/forward cache does not extend the idle
window: a page whose deadline already passed locks immediately on restore.
Authenticated web mutations also require an exact same-origin request and are serialized across threads/processes to prevent CSRF and lost vault writes. Decrypted web responses use `Cache-Control: no-store`.
All listed import formats are round-trip compatible with their matching CLI and web exports.
Vault writes are staged and atomically installed. CLI and web processes share an advisory vault lock when `flock` is available; avoid concurrent access on systems without it. `save` verifies the archived vault before removing the local copy.

### Local-first 2.10 commands

```bash
spm security
spm history-list
spm history-restore <snapshot-name>
spm backup-now [directory]
spm backup-auto enable [directory] [hours] [retention]
spm vault-profile list
spm vault-profile add <name> <vault-path>
spm vault-profile use <name>
spm attachment-add <file> [label]
spm attachment-list
spm attachment-extract <id> [output]
spm passkey-add <rp-id> <account> <credential-id> [notes]
spm passkey-list
spm sync status|push|pull <directory> [channel]
spm emergency-create <password-id> <recipient-public.pem> <YYYY-MM-DD> [archive]
spm emergency-open <archive> <recipient-private.pem> [output.json]
```

Automatic backups are opportunistic: SPM checks the configured interval after
successful vault writes. Filesystem sync stores only encrypted vault bytes and
refuses two-sided or mismatched first-time changes instead of selecting a last
writer. Use the same optional channel name on every device. Emergency dates
are enforced by `spm emergency-open` but remain advisory because a recipient
holding the private key can use lower-level cryptographic tools. Passkey private
keys remain non-exportable in the operating-system or hardware authenticator;
SPM stores only discovery and recovery metadata.

The unpacked Chrome/Chromium companion is in `browser-extension/`. Autofill
requires the record label, or an HTTP(S) URL in its notes, to exactly match the
active page hostname. See its README for native-host registration.
Uses **semantic versioning**.  
`./spm.sh update` fetches the latest GitHub ZIP, verifies its published SHA-256 and the extracted script syntax, then installs to `/usr/local/bin/spm` (sudo may be required).
See `CHANGELOG.md` for details.

---

## Documentation & Legal

SPM is open-source software licensed under the **Apache License 2.0**. The code
may be used, modified, and redistributed under that license. Project names and
logos remain subject to the separate trademark policy.

Refer to:

- [`LICENSE`](LICENSE)
- [`NOTICE`](NOTICE)
- [`DCO`](DCO)
- [`docs/CONTRIBUTOR_LICENSE_POLICY.md`](docs/CONTRIBUTOR_LICENSE_POLICY.md)
- [`docs/TRADEMARK_POLICY.md`](docs/TRADEMARK_POLICY.md)
- [`docs/PRIVACY_POLICY.md`](docs/PRIVACY_POLICY.md)
- [`docs/GDPR_NOTICE.md`](docs/GDPR_NOTICE.md)
- [`docs/TERMS_AND_CONDITIONS.md`](docs/TERMS_AND_CONDITIONS.md)
- [`docs/CODE_OF_CONDUCT.md`](docs/CODE_OF_CONDUCT.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)

---

## License

Licensed under the **Apache License 2.0**.
Copyright 2025–2026 Sansyourways and contributors.

See [`LICENSE`](LICENSE) for the full terms and [`NOTICE`](NOTICE) for
attribution. Releases before 2.10.3 remain governed by the license included in
their historical release artifacts.

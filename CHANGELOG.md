# Changelog

All notable changes to **Sans Password Manager (SPM)** are documented in this file.

This project loosely follows [Semantic Versioning](https://semver.org/) and a
Keep-a-Changelog style format.

## [2.7.9] - 2025-12-15

### Security
- **Hardened Update Command:** The `update` command now verifies the SHA-256 checksum of the downloaded release asset against a signed checksum file from the release. This prevents man-in-the-middle (MitM) attacks during the update process.
- **Secure Temporary Files:** The `make_tmp` function now exclusively uses `mktemp` to create temporary files, eliminating a race condition vulnerability that could have exposed sensitive data. The script will now fail if `mktemp` is not available.
- **TOTP Secret Protection:** The `_spm_totp_code` function no longer passes the TOTP secret as a command-line argument. It is now passed via standard input to the Python script, preventing it from being exposed in the system's process list.
- **Web Mode Warning:** Added a prominent warning to the `web` command, alerting users to the security implications of running a local web server and advising them to only use it on trusted networks.

## [2.7.8] - 2025-12-13

### Added
- Export gained 5 more formats: toml, org, scsv (semicolon), csv-noheader, and jsonc. The menu prompt now also lists all available formats for clarity while keeping csv/json as the primary suggestion.

### Changed
- Version bumped to 2.7.8.

## [2.7.8-import-update] - Unreleased

### Added
- Import command (menu + CLI) supports all export formats (csv/json primary; advanced formats accepted: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc). IDs auto-renumber; entries are appended to the existing vault.
- Authenticators now support SHA1/SHA256/SHA512 selection (CLI + web), stored per entry and preserved across export/import.
- Web mode adds an Export/Import card using the same formats; export downloads directly, import accepts pasted content and appends to the vault.
- Web import supports direct file uploads (multipart) in addition to paste.
- Import form in web mode now submits asynchronously with a card-wide loading overlay and inline success/error message (no redirect or forced logout).
- Removed the legacy `cgi` dependency in the web server; multipart uploads now use a boundary-aware email parser (no Python 3.13 warnings).
- Authenticator live view in web mode now includes a clipboard button for the current OTP code.
### Fixed
- Replaced deprecated `cgi` usage in the web server with `email.parser`-based multipart parsing to avoid deprecation issues on Python 3.13.
- Web import file uploads now use the correct multipart key, preventing hangs/timeouts on upload.
- Multipart import now short-circuits on >5MB payloads and falls back gracefully when parsing fails.
- Fixed missing `cgi` import in the web server so multipart upload parsing works consistently.
- Fixed missing `warnings` import in the web server, restoring multipart parsing path.
- Boundary-aware multipart parsing now defaults to email parser only (removed FieldStorage dependency to reduce upload failures).
- SQL export now escapes quotes correctly; import command is fully wired into CLI dispatch.
- Web export/import script no longer fails on SQL format generation (fixed quoting in generated Python).
- RST export in web server generation now uses proper quoting (no more syntax error in generated Python).
- Multipart import handler now prefers `cgi.FieldStorage` with warnings silenced and falls back to a lightweight parser, preventing hangs during uploads.
- Import endpoint now reuses the already-read request body instead of trying to read the stream twice, so uploads no longer stall on “load failed”.
- Fixed duplicate web import submissions triggered by both inline and scripted handlers, eliminating the phantom second upload that caused “load failed” UI states.
- Import now validates that the uploaded file contains at least one record and surfaces a clear error instead of silently doing nothing.
- Web import success now triggers an automatic page reload so newly imported entries are visible right away.

### Note
- Version intentionally left at 2.7.8 per policy; not a full release yet.

## [2.7.7] - 2025-12-13

### Added
- Export supports 8 more formats (yaml/yml, xml, sql, ini, psv, rst, plus jsonl alias) while prompts still show csv/json for simplicity.

### Changed
- Version bumped to 2.7.7.

## [2.7.6] - 2025-12-13

### Added
- Export now supports 5 additional formats: tsv, ndjson, markdown, html, and txt alongside csv/json. Interactive menu prompt updated.

### Changed
- Version bumped to 2.7.6.

## [2.7.5] - 2025-12-13

### Added
- Export command (`./spm.sh export <csv|json> [file]`) to dump all data types (passwords, notes, passphrases, authenticators, backup codes) to CSV or JSON; interactive menu includes Export.

### Changed
- Version bumped to 2.7.5. Export now auto-appends the correct extension when you provide a name without `.csv` or `.json`.

## [2.7.0] - 2025-12-13

### Added
- Web themes (Dark, AMOLED, Cyberpunk, Light) with a header picker; header now shows current version and auto-checks GitHub for updates on load.

### Changed
- Dashboard “Update” control now pairs with the version display and update check popup when a newer release is detected.

---

## [2.7.1] - 2025-12-13

### Changed
- Refined themes: AMOLED (solid/elegant black), Cyberpunk (neon palette), and Light (clean bright panels/cards). Theme variables now apply across the whole UI.
- Removed periodic auto-reload; rely on 30s idle auto-lock instead to avoid refresh churn.

---

## [2.7.2] - 2025-12-13

### Changed
- Tables and lists now use theme-aware backgrounds, borders, and text for better readability; Light theme tables/cards/panels adopt softer whites/grays instead of dark backgrounds.

---

## [2.7.3] - 2025-12-13

### Changed
- Light theme text and tables refined for readability; table wrappers now follow theme borders/background, and card headings/text use theme colors.
- Primary buttons softened (lighter shadow) to better match pastel tones.

---

## [2.7.4] - 2025-12-13

### Changed
- Primary/add buttons now use a pastel blue gradient with themed borders across password, passphrase, generator, TOTP, and backup sections, improving the light theme look.

---

## [2.7.4] - 2025-12-13

### Changed
- Primary/add buttons (password, passphrase, generator, TOTP, backup codes) now use a pastel blue gradient with themed borders to better fit the light palette.

## [2.6.1] - 2025-12-13

### Changed
- Easy password generator now produces human-memorable word-based passwords; secure mode remains random.
- Generator toggles cover uppercase, lowercase, numbers, and symbols for both CLI and web.

---

## [2.6.0] - 2025-12-13

### Added
- Password generator in CLI and web with mode toggles (secure/easy/numeric), optional symbols, length slider, and strength/crack-time estimate.

### Changed
- Main menu and web dashboard now link to the password generator; autofill bookmarklet remains removed.

---

## [2.5.7] - 2025-12-13

### Changed
- Removed the web autofill bookmarklet feature and related buttons/endpoints; copy helpers remain.

---

## [2.5.6] - 2025-12-13

### Fixed
- Session cookies now set both Lax and cross-site variants (SameSite=None; Secure) so bookmarklets can send credentials when accessed over HTTPS.

---

## [2.5.5] - 2025-12-13

### Changed
- Bookmarklet now targets broader username/email selectors (mail/email/account/identifier) and falls back to the first text field to improve autofill success.

---

## [2.5.4] - 2025-12-13

### Fixed
- Avoided shadowing the JSON module when serving autofill/authenticator JSON responses to resolve bookmarklet errors.

---

## [2.5.3] - 2025-12-13

### Fixed
- Added CORS headers and OPTIONS handling for JSON endpoints (autofill, authenticator codes) so bookmarklets work across sites when allowed by the browser.

---

## [2.5.2] - 2025-12-13

### Fixed
- Clipboard copy buttons now include fallback copying for browsers without `navigator.clipboard`, making bookmarklet and secret copies reliable.

---

## [2.5.1] - 2025-12-13

### Added
- Web autofill helper bookmarklet for password entries plus copy buttons on password, notes, passphrase, and backup views.

### Changed
- Web password view can copy username/password/notes and expose bookmarklet for quick form fill; backup/passphrase/note views now have copy helpers.

---

## [2.5.2] - 2025-12-13

### Fixed
- Clipboard copy buttons now include fallback copying for browsers without `navigator.clipboard`, making bookmarklet and secret copies reliable.

---

## [2.5.3] - 2025-12-13

### Fixed
- Added CORS headers and OPTIONS handling for JSON endpoints (autofill, authenticator codes) so bookmarklets work across sites when allowed by the browser.

---

## [2.5.4] - 2025-12-13

### Fixed
- Avoided shadowing the JSON module when serving autofill/authenticator JSON responses to resolve bookmarklet errors.

---

## [2.5.5] - 2025-12-13

### Changed
- Bookmarklet now targets broader username/email selectors (mail/email/account/identifier) and falls back to the first text field to improve autofill success.

---

## [2.5.6] - 2025-12-13

### Fixed
- Session cookies now set both Lax and cross-site variants (SameSite=None; Secure) so bookmarklets can send credentials when accessed over HTTPS.

---

## [2.5.7] - 2025-12-13

### Changed
- Removed the web autofill bookmarklet feature and related buttons/endpoints; copy helpers remain.

---

## [2.6.0] - 2025-12-13

### Added
- Password generator in CLI and web with mode toggles (secure/easy/numeric), optional symbols, length slider, and strength/crack-time estimate.

### Changed
- Main menu and web dashboard now link to the password generator; autofill bookmarklet remains removed.

---

## [2.6.1] - 2025-12-13

### Changed
- “Easy” generator now creates human-memorable word-based passwords; secure mode keeps full random.
- Generator toggles now cover uppercase, lowercase, numbers, and symbols for both CLI and web, with word-count mapping on easy mode.

---

## [2.5.0] - 2025-12-13

### Added
- Authenticator (TOTP) vault entries with configurable refresh interval, CLI CRUD, and live code display in web mode.

### Changed
- Main menu and doctor report now include authenticators; web dashboard adds a dedicated authenticator card.
- CLI authenticator view now streams live TOTP codes with a countdown.

---

## [2.4.1] - 2025-12-13

### Fixed
- Web dashboard now hides passphrases and backup codes from the password entries list, keeping each item type in its proper section.

---

## [2.4.0] - 2025-12-13

### Added
- **Passphrase Vault**
  - New CLI and menu flow for storing passphrases (`passphrase-add/list/view/delete`) with base64 storage in the encrypted vault.
  - Viewing a passphrase forces a master password prompt for re-verification.
- **Auto Updater**
  - `./spm.sh update` now downloads the latest GitHub ZIP release, extracts `spm.sh`, and installs it to `/usr/local/bin/spm` (uses `sudo` when available).
- **Web Mode: Passphrases & Backup Codes**
  - Web dashboard now lists passphrases and backup codes with add/edit/view/delete flows and base64 decoding for display.
  - Footer copyright + version and a right-aligned “Update” (refresh) action added.
  - Automatic page refresh every 5 seconds to avoid stale cached views.

### Changed
- Interactive menu now includes a dedicated Passphrases section and renumbered items.
- Doctor now reports counts for passwords, notes, passphrases, and backup codes.
- Help and editor format hints updated with the new `PASSPHRASE` row type.

### Fixed
- Master password re-verification now properly loads the cached master password before comparisons.
- Web mode now receives the running version via env (`SPM_VERSION`) to avoid undefined version display.

---

## [2.3.0] - 2025-12-12

### Added
- **Backup Codes Management**
  - New dedicated section in interactive menu (`13) Backup codes`).
  - CLI commands for full CRUD operations:
    - `./spm.sh backup-codes-add`: Add new backup codes with a user-defined label.
    - `./spm.sh backup-codes-list`: List all stored backup code entries.
    - `./spm.sh backup-codes-view <id>`: View the content of a specific backup code entry.
    - `./spm.sh backup-codes-delete <id>`: Delete a backup code entry.
  - Backup codes are stored securely within the encrypted vault, similar to secure notes.

### Security
- **Master Password Re-verification for Backup Codes View**
  - When attempting to view backup codes (via `backup-codes-view` command or interactive menu), the user is now prompted to re-enter their master password for an additional layer of security.

### Changed
- **Interactive Menu & Help Updates**
  - Main interactive menu options re-numbered to accommodate the new "Backup codes" feature.
  - `cmd_help` output updated to document new backup code commands.
  - `cmd_edit` vault format instructions updated to include `BACKUP_CODE` entry format.

## 2.2.1 – 2025-12-08

### Fixed
- Restored and updated `cmd_help` to match all current features (web mode, secure notes, doctor, clipboard coaching, etc.).

---

## [2.2.0] — 2025-12-10
### Added
- Mandatory **Terms & Conditions + Privacy Policy Consent** flow on first run.
- Persistent consent tracking stored in `~/.spm_consent`.
- Blocking logic: SPM cannot be used until the user agrees.
- Full support for **English & Indonesian** consent interface.
- Integrated policy URLs:
  - **Terms & Conditions:**  
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/TERMS_AND_CONDITIONS.md
  - **Privacy Policy:**  
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/PRIVACY_POLICY.md

### Improved
- Streamlined onboarding flow for first-time users.
- More secure startup-by-design: no menu access until consent is given.

### Notes
- Vault format remains fully compatible with all 2.x versions.
- Users from previous versions will be prompted once and remembered afterward.

---

## [2.1.0] – Web Mode, Secure Notes UI & PM2 Integration

### Added

- **Web Mode (Full Browser UI)**
  - New interactive menu entry and CLI command:
    - Menu option: `14) Web mode`
    - CLI: `./spm.sh web` or `./spm.sh web-mode`
  - Starts an embedded HTTP server so you can access your vault from a browser.
  - Login page protected by your **master password**.
  - Elegant “liquid glass” UI inspired by Apple-style glassmorphism:
    - Soft blurred background, rounded cards, subtle shadows.
    - Responsive layout that works on desktop and mobile (including iPhone).

- **Web Password Management (CRUD)**  
  - From the browser you can:
    - **Create** new password entries.
    - **View** existing entries (with controlled reveal of secrets).
    - **Edit** entries directly from the UI.
    - **Delete** entries.
  - Actions are exposed via **icon buttons** (not plain text) for a cleaner UI.
  - UI refined so buttons don’t get cut off on mobile viewport (e.g. iPhone).

- **Web Secure Notes (Separated from Passwords)**  
  - Dedicated secure-notes section in the web UI:
    - List all notes.
    - Add new note.
    - View / read note content.
    - Delete notes.
  - Notes reuse the same encrypted vault file, using `NOTE` records, and respect
    the same crypto as password entries.

- **Automatic Web Session Lock (Idle Timeout)**  
  - The web UI automatically **locks** after a period of inactivity
    (no user action) of ~30 seconds.
  - Once locked, the user must re-enter the **master password** to regain access.
  - Helps reduce exposure when the browser is left open.

- **Foreground / Background Web Mode**
  - When selecting Web Mode from the interactive menu, SPM now offers:
    - **Temporary (foreground)** mode: runs until Ctrl + C.
    - **Background (daemon)** mode: runs under **PM2**.
  - Background mode:
    - Checks if `pm2` is installed.
    - If not present, attempts to install **PM2** automatically, based on
      the detected environment (e.g. apt / yum / pkg / npm).
    - Registers a named SPM web process with PM2 so it can survive terminal
      closes or reboots (depending on PM2 configuration).

- **PM2 Web Process Management**
  - From the same Web Mode menu, you can:
    - **Start** a background SPM web instance (via PM2).
    - **Stop / clear** the existing SPM web PM2 process cleanly.
  - Prevents duplicate background servers and keeps Zero-Config feel for the user.

- **Automatic Firewall Configuration for Web Mode**
  - When binding to non-local addresses (e.g. `0.0.0.0` on a VPS),
    SPM attempts to:
    - Detect a firewall tool (`ufw`, `firewalld`, or basic `iptables`).
    - Install the firewall tool automatically if missing (when possible for
      the platform).
    - Open the selected **HTTP port** (e.g. 8080 / 8088) while keeping rules
      minimal and focused.
  - For localhost (`127.0.0.1`), no external ports are opened.
  - The external IP is detected and the URL presented as
    `http://YOUR_SERVER_IP:PORT/` so it’s clear what to open from remote.

### Changed

- **Interactive Menu**
  - Extended main TUI menu to include:
    - `14) Web mode` (previously experimental; now promoted to a first-class feature).
  - Updated Indonesian & English menu labels to reflect web capabilities.
  - Web Mode is no longer marked as “experimental” in the UI.

- **Help Output**
  - `./spm.sh help` now documents:
    - `web` / `web-mode` CLI usage.
    - The existence of Web Mode and its security notes.
  - Indonesian and English help sections both reference web and secure-notes commands.

### Security

- Web sessions are authenticated using the **same master password** as the CLI.
- Sessions auto-lock after inactivity, reducing the risk of shoulder-surfing or
  unattended browser tabs revealing sensitive information.
- Passwords are still **GPG-encrypted on disk**, and the web UI decrypts on-demand
  using the master password kept in memory only for the server lifetime.
- Firewall rules are automatically tuned when listening on public addresses, to
  expose only the required port while avoiding wide-open exposure by default.

---

## [2.0.0] – Major CLI/TUI Upgrade & Recovery Keys

> First fully structured release of SPM with strong crypto defaults, recovery
> flows, and portable bundles.

### Added

- **Cross-Platform Shell Application**
  - Pure `sh`/`bash` password manager designed to run on:
    - Linux distros
    - Termux (Android)
    - macOS
    - Most POSIX-friendly environments
  - Uses `gpg` symmetric encryption for the main vault file.

- **Master Password & Vault Initialization**
  - `./spm.sh init` guides the user to create a **master password**.
  - Vault is stored as an encrypted text file (`sans_vault.gpg`-style) with
    tab-separated records:
    - `id  service  username  password  notes  created_at`
  - Strong emphasis on long, unique master passwords.

- **Language Selection (EN / ID)**
  - On startup, SPM asks the user to pick language:
    - `en` – English
    - `id` – Indonesian
  - All interactive prompts, errors, and help texts respect the chosen language.

- **Recovery Key Pair (Forgot Password Flow)**
  - During `init`, SPM generates an **asymmetric key pair**:
    - **Public key** stored inside the vault metadata (`META_RECOVERY_PUBKEY`).
    - **Private key** exported as a separate file in the same directory.
  - The **private key** is shown exactly once in the terminal and saved as a
    recovery file next to the script so the user can back it up.
  - `./spm.sh forgot` allows resetting the master password using this private key,
    following a secure challenge-recovery flow.

- **Portable Bundles & SAVE Mode**
  - `./spm.sh portable [name]`:
    - Creates a ZIP bundle containing:
      - The script.
      - The encrypted vault.
      - Recovery/metadata files.
      - README / helper docs.
  - `./spm.sh save [name]`:
    - Creates a **SAVE bundle** (ZIP) and then securely **wipes the local vault**.
    - Useful for exporting vault off a machine while leaving no residue.
  - When saving / creating portable bundles, SPM also **cleans intermediate folders**
    to avoid leaving stray vault copies on disk.

- **Clipboard Integration + Auto Clear**
  - When retrieving a password with `get`, SPM attempts to copy it to the clipboard
    using platform-specific helpers (`xclip`, `pbcopy`, Termux clipboard, etc.).
  - After ~15 seconds, clipboard is **automatically cleared**:
    - `macOS`: `pbcopy < /dev/null`
    - `Linux`: `xclip` / equivalents with empty input.
    - `Termux`: `termux-clipboard-set ""`
  - If no helper is available, SPM clearly shows:
    - **EN**: `"No clipboard helper available"`  
    - **ID**: `"Tidak ada helper clipboard tersedia"`

- **Password Strength Coaching**
  - When creating a new password, SPM:
    - Computes **entropy**.
    - Estimates **guessing time**.
    - Analyses character classes (lower/upper/digits/symbols).
  - Provides suggestions to strengthen the password in both:
    - English, and
    - Indonesian.

- **Secure Notes (CLI)**
  - Dedicated commands for notes:
    - `notes-add`, `notes-list`, `notes-view`, `notes-delete`.
  - Notes are stored in-vault as `NOTE` entries:
    - `NOTE  note_id  title  base64_note  created_at  -`
  - Accessible via a **sub-menu** from the interactive TUI.

- **Doctor / Health Check**
  - `./spm.sh doctor`:
    - Runs a series of integrity and health checks:
      - Vault readability / decryption sanity.
      - Metadata presence (recovery key, etc.).
      - Basic structure validation for password and note records.
    - Reports findings in human-friendly English & Indonesian messages.

- **Auto Environment Detection & Requirements Installer**
  - On startup, SPM detects platform (Linux, macOS, Termux) and:
    - Checks for required tools (`gpg`, `zip`, `python3`, clipboard helpers, etc.).
    - Where possible, offers to install missing dependencies automatically using
      the appropriate package manager (`apt`, `dnf`, `yum`, `pkg`, `brew`, etc.).
  - Shows a **step-by-step check-list with checkmarks** for each requirement
    as it is verified / installed.

### Changed

- **Interactive Flow**
  - Introduced a clean, numbered menu-driven interface for all core operations:
    - List, add, get, delete, edit, change master, portable, save, help, update,
      forgot master, notes, doctor.
  - Master password is requested only once per session and re-used internally,
    until the user exits (or the process is terminated).

- **Language-Aware Help & Output**
  - Help text (`help`) and all major output strings are now fully localized
    for both English and Indonesian.

### Security

- Enforced consistent GPG usage and secure file permissions for vault files.
- Encouraged long, high-entropy master passwords and warned against reuse.
- Recovery key flow designed so that **only** holders of the private key can
  execute a master reset—no “backdoor” or central reset mechanism.

---

[2.1.0]: https://github.com/sansyourways/Sans_Password_Manager/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/sansyourways/Sans_Password_Manager/releases/tag/2.0.0

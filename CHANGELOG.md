# Changelog

All notable changes to **Sans Password Manager (SPM)** are documented in this file.

This project loosely follows [Semantic Versioning](https://semver.org/) and a
Keep-a-Changelog style format.

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

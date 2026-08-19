![IMG_1113](https://github.com/user-attachments/assets/3108e84d-a612-49fc-945e-dd38c35e19ae)
![IMG_1122](https://github.com/user-attachments/assets/37a78d2f-f3a8-4b7a-97aa-c80b6ff24642)
![IMG_1114](https://github.com/user-attachments/assets/acc62927-fc23-41b2-9664-35c40f22ecf6)


# Sans Password Manager (SPM)

> A fully offline, portable, terminal-based password manager  
> built in pure Bash + GnuPG, designed for **security-first**,  
> **minimalism**, and **complete user control**.

---

## Table of Contents
- [Overview](#overview)
- [Philosophy](#philosophy)
- [Features](#features)
  - [Fitur Utama (ID)](#fitur-utama-id)
  - [Key Features (EN)](#key-features-en)
- [Architecture & Security Model](#architecture--security-model)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Web Mode (Local Only)](#web-mode-local-only)
  - [CLI Commands](#cli-commands)
  - [Secure Notes](#secure-notes)
  - [Recovery: Forgot Master Password](#recovery-forgot-master-password)
  - [Doctor / Health Check](#doctor--health-check)
- [Password Strength Coaching](#password-strength-coaching)
- [Clipboard Auto-Clean](#clipboard-auto-clean)
- [Portable & Save Bundles](#portable--save-bundles)
- [Development & Versioning](#development--versioning)
- [Documentation & Legal](#documentation--legal)
- [License](#license)

---

## Overview

**SPM (Sans Password Manager)** is a **single-file**, **portable**,  
**offline-only**, **encrypted password manager** powered by:

- **GnuPG (AES-256, symmetric)**  
- **OpenSSL (RSA)** for optional recovery  
- **Pure Bash**, requiring no internet access

SPM is designed for users who want:

- full ownership of their vault  
- no cloud storage  
- no telemetry  
- no tracking  
- a clean UI (terminal + optional local web mode)

> ✔ SPM never transmits any data.  
> ✔ Fully offline.  
> ✔ You are the **sole data controller** (GDPR compliant).  
> ❗ The developer cannot recover your vault if you lose your master password.

---

## Philosophy
- **Privacy First:** No analytics, no logs, no tracking.  
- **Offline Forever:** Everything stored locally; no servers.  
- **Portable:** Carry your encrypted vault anywhere.  
- **Simplicity:** A single Bash script.  
- **Transparency:** Encryption handled by GnuPG/OpenSSL directly.  
- **User Ownership:** You control your keys, vaults, and backups.

---

## Features

### Fitur Utama (ID)

- 🔐 **Vault terenkripsi GPG (AES-256)**  
- 📟 **UI interaktif** (EN/ID/JP)  
- 🖥️ **Web Mode (Localhost)** — dashboard modern *offline-only*  
- 📦 **Portable bundle** (script + vault + recovery + private key when available)  
- 💾 **SAVE bundle** (backup + wipe vault lokal, menyertakan private key jika tersedia)  
- 🧠 **Password Strength Coaching**  
- 📝 **Secure Notes**  
- 🔑 **Passphrase Vault** (simpan passphrase, verifikasi ulang saat melihat)  
- 🔢 **Authenticator (TOTP)** dengan live code di web (plus tombol copy), interval kustom, dan pilihan algoritma SHA1/SHA256/SHA512  
- ⚡ **Copy cepat** (tombol copy di tampilan kata sandi, catatan, passphrase, kode backup) dengan notifikasi pop-up sukses yang ramah perangkat  
- 🔒 **Generator kata sandi** (mode mudah/aman, kata mudah diingat, panjang/slider, toggle huruf besar/kecil/angka/simbol, estimasi kekuatan)
- 🎨 **Tema web** (Dark, AMOLED, Cyberpunk, Light) + cek update di header
- 📤 **Export/Import vault** (CLI & Web) ke CSV/JSON + format lanjutan
- 📜 Kode Backup
- 🔑 **Lupa password** via RSA private key  
- 🩺 **Doctor mode** (diagnostik integritas vault & recovery)  
- 🧽 **Clear clipboard otomatis** (~15 detik)

---

### Key Features (EN)

- 🔐 Encrypted vault (GPG AES-256)  
- 🗂️ Clean interactive menu  
- 🌐 Local Web Mode (browser UI, offline only, EN/ID/JP toggle)  
- 📦 Portable bundle (ZIP; includes recovery + private key when present)  
- 💾 SAVE bundle (backup + wipe local; includes private key when present)  
- 🧠 Password strength analysis & coaching  
- 📝 Secure notes
- 🔑 Passphrase vault with re-verification on view  
- 🔢 Authenticator (TOTP) with live codes + copy button, configurable interval, and SHA1/SHA256/SHA512 algorithms  
- ⚡ Fast copy buttons on password, notes, passphrase, backup views with device-friendly toast confirmation  
- 🔒 Password generator (easy memorable words + secure random, slider length/words, toggles for upper/lower/digits/symbols, strength estimate)
- 🎨 Web themes (Dark, AMOLED, Cyberpunk, Light) with header update check/version display  
- 🇬🇧🇮🇩🇯🇵 Live language switcher (EN/ID/JP) in the web header with cookie persistence and instant translations across dashboard cards/import UI  
- 📤 Vault export/import (CLI & Web) to CSV/JSON + advanced formats
- 📜 Backup codes  
- 🔑 RSA-based recovery  
- 🩺 Doctor diagnostics  
- 🧽 Clipboard auto-clean  
- 🚫 No cloud, no telemetry, no data collection

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

### Web Mode (Local Only)

```bash
./spm.sh web
```

- Runs on localhost only  
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

Imports passwords, secure notes, passphrases, backup codes, and authenticators from supported export formats (csv/json primary; advanced formats accepted as listed above). Entries are appended and IDs auto-renumbered. Web mode overlays the entire Export/Import card with a loader during uploads, validates that at least one record was parsed, reports how many rows of each type were added, and automatically reloads the dashboard on success so the new rows appear immediately (errors show inline without redirect). Status messages and overlay text follow the selected language (EN/ID/JP) so users get consistent feedback during uploads.

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
- spm_recovery_private.pem (optional)  
- Auto README file  

### SAVE

```bash
./spm.sh save
```

Creates encrypted backup, wipes local vault.

---

## Development & Versioning

Version: **2.8.3**  
Web session cookies use `HttpOnly`, `Secure`, and `SameSite=Strict` attributes. Keep non-loopback web deployments behind HTTPS or a TLS reverse proxy.
Uses **semantic versioning**.  
`./spm.sh update` fetches the latest GitHub ZIP and installs to `/usr/local/bin/spm` (sudo may be required).  
See `CHANGELOG.md` for details.

---

## Documentation & Legal

SPM is closed-source and licensed under a **Private License**.

Refer to:

- [`LICENSE`](LICENSE)
- [`docs/PRIVACY_POLICY.md`](docs/PRIVACY_POLICY.md)
- [`docs/GDPR_PRIVACY_NOTICE.md`](docs/GDPR_PRIVACY_NOTICE.md)
- [`docs/TERMS_AND_CONDITIONS.md`](docs/TERMS_AND_CONDITIONS.md)
- [`docs/CODE_OF_CONDUCT.md`](docs/CODE_OF_CONDUCT.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)

---

## License

**Sans Password Manager — Private License**  
© 2025 Sansyourways. All Rights Reserved.

See [`LICENSE`](LICENSE) for full terms.

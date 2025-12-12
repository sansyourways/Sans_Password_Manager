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
- 📟 **UI interaktif** (EN/ID)  
- 🖥️ **Web Mode (Localhost)** — dashboard modern *offline-only*  
- 📦 **Portable bundle** (script + vault + recovery)  
- 💾 **SAVE bundle** (backup + wipe vault lokal)  
- 🧠 **Password Strength Coaching**  
- 📝 **Secure Notes**  
- 📜 Kode Backup
- 🔑 **Lupa password** via RSA private key  
- 🩺 **Doctor mode** (diagnostik integritas vault & recovery)  
- 🧽 **Clear clipboard otomatis** (~15 detik)

---

### Key Features (EN)

- 🔐 Encrypted vault (GPG AES-256)  
- 🗂️ Clean interactive menu  
- 🌐 Local Web Mode (browser UI, offline only)  
- 📦 Portable bundle (ZIP)  
- 💾 SAVE bundle (backup + wipe local)  
- 🧠 Password strength analysis & coaching  
- 📝 Secure notes
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
  - Edit entries  
  - Local copy-to-clipboard  

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
./spm.sh forgot
./spm.sh notes-add
./spm.sh notes-list
./spm.sh notes-view <id>
./spm.sh notes-delete <id>
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

Version: **2.3.0**  
Uses **semantic versioning**.  
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
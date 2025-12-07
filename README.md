# Sans Password Manager (SPM)

> Portable, terminal-based password manager in pure Bash + GPG,  
> designed to be **minimal**, **portable**, and **security-first**.

---

## Table of Contents

- [Overview](#overview)
- [Fitur Utama (ID)](#fitur-utama-id)
- [Key Features (EN)](#key-features-en)
- [Security Model](#security-model)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [CLI Commands](#cli-commands)
  - [Secure Notes](#secure-notes)
  - [Recovery: Forgot Master Password](#recovery-forgot-master-password)
  - [Doctor / Health Check](#doctor--health-check)
- [Password Strength Coaching](#password-strength-coaching)
- [Clipboard Auto-Clean](#clipboard-auto-clean)
- [Portable & Save Bundles](#portable--save-bundles)
- [Development & Versioning](#development--versioning)
- [Security Policy](#security-policy)
- [License](#license)

---

## Overview

**SPM** (Sans Password Manager) is a **single Bash script** password manager that:

- Encrypts your vault using **GPG (AES-256)**.
- Runs on **Linux, macOS, Termux** (Android) and most POSIX shells.
- Supports **portable bundles** so you can carry your vault between machines.
- Uses an **RSA key pair** for **“forgot master password”** recovery.

> ⚠️ This is a security-sensitive tool.  
> Use at your own risk and **never commit your real vault or private keys**.

---

## Fitur Utama (ID)

- 🔐 **Vault terenkripsi** dengan GPG (AES256, symmetric).
- 🌐 **Lintas platform**: Linux, macOS, Termux (Android).
- 🗂️ **Menu interaktif** dengan pilihan bahasa **Indonesia / English**.
- 📦 **Portable bundle**: ZIP dengan script + vault + file recovery.
- 💾 **SAVE bundle**: backup terenkripsi lalu hapus vault lokal (opsional).
- 🧠 **Password strength coaching**:
  - Entropy (bit)
  - Perkiraan waktu brute-force
  - Analisis jenis karakter
  - Saran (Bahasa Indonesia + Inggris)
- 📋 **Auto copy + auto clean clipboard** (15 detik) jika helper tersedia.
- 📝 **Secure notes**: catatan teks aman di dalam vault yang sama.
- 🔑 **Lupa password utama**: reset via **private key RSA** yang kamu simpan.
- 🩺 **`doctor` / health check**:
  - Cek format vault
  - Cek duplikasi ID
  - Validasi meta recovery key
  - Verifikasi pasangan recovery file + private key

---

## Key Features (EN)

- 🔐 **Encrypted vault** using GPG (AES256, symmetric mode).
- 🌐 **Cross-platform**: Linux, macOS, Termux (Android).
- 🗂️ **Interactive menu** with language selection (EN / ID).
- 📦 **Portable bundles**: ZIP with script + vault + recovery file.
- 💾 **SAVE bundles**: backup + wipe local vault (optional).
- 🧠 **Password strength coaching**:
  - Entropy (bits)
  - Rough crack-time estimate
  - Character type analysis
  - Suggestions (English + Indonesian)
- 📋 **Auto-copy & auto-clear clipboard** in ~15 seconds (if helper available).
- 📝 **Secure notes** stored inside the same encrypted vault.
- 🔑 **Forgot master password** flow using RSA private key + recovery file.
- 🩺 **`doctor` health check**:
  - Vault decryption check
  - Duplicate ID check
  - Recovery pubkey metadata validation
  - Recovery file + private key pairing test

---

## Security Model

### What SPM Does

- Uses **GPG symmetric encryption** (`AES256`) to protect your vault.
- Stores:
  - Password entries as tab-separated lines.
  - Secure notes as base64-encoded bodies inside vault.
  - Recovery public key metadata inside vault (`META_RECOVERY_PUBKEY`).
- Generates **RSA key pair** on `init`:
  - Private key: `spm_recovery_private.pem` (stored where you run `spm.sh`).
  - Public key: embedded into vault metadata + used to build recovery file.

### What SPM Assumes

- Your machine is **not compromised** (no malware / keylogger).
- You keep:
  - **Master password** secret.
  - **Private key** (`spm_recovery_private.pem`) in a **safe location** (ideally offline).
- GPG & OpenSSL are correctly installed and not tampered with.

### What SPM Does Not Protect Against

- Attackers with **root/admin** on your system while you are using SPM.
- Physical attacks on unencrypted disks or RAM dump.
- Mistakes like:
  - Pushing real vault / keys to GitHub.
  - Sharing recovery private key unintentionally.

For more details, see `SECURITY.md`.

---

## Requirements

SPM automatically checks & tries to install:

- `bash`
- `gpg`
- `openssl`
- `curl`
- `zip`
- Clipboard helpers (where possible):
  - Termux: `termux-clipboard-set`
  - Linux: `xclip` or `wl-copy`
  - macOS: `pbcopy` (built-in)

You may be asked for `sudo` when installing dependencies.

---

## Installation

```bash
git clone https://github.com/YOUR_USER/YOUR_REPO.git
cd YOUR_REPO
chmod +x spm.sh
./spm.sh
```

SPM will:

1. Detect your environment (Linux / macOS / Termux).
2. Check & install required tools.
3. Show a **language selection page** (EN / ID).
4. Present the interactive menu.

---

## Usage

### Interactive Menu

Run:

```bash
./spm.sh
```

Menu includes:

- List entries  
- Add entry  
- Get entry  
- Delete entry  
- Edit vault  
- Change master password  
- Portable bundle  
- Save bundle  
- Secure notes  
- Forgot password  
- Doctor / health check  

### CLI Examples

```bash
./spm.sh init
./spm.sh add
./spm.sh list
./spm.sh get 2
./spm.sh delete 4
./spm.sh change-master
./spm.sh update
./spm.sh forgot
./spm.sh doctor
```

---

## Secure Notes

```bash
./spm.sh notes-add
./spm.sh notes-list
./spm.sh notes-view 1
./spm.sh notes-delete 1
```

---

## Recovery: Forgot Master Password

SPM generates:

- `spm_recovery_private.pem` → **YOU must store safely**
- `<vault>.recovery` → included in portable/save bundles

Reset:

```bash
./spm.sh forgot
```

SPM will:

1. Decrypt recovery file using your private key  
2. Retrieve old master password  
3. Allow setting new master password  
4. Rebuild vault and recovery files  

---

## Doctor / Health Check

```bash
./spm.sh doctor
```

Checks:

- Vault format  
- Duplicate IDs  
- Recovery metadata  
- Matching private key  
- Secure notes structure  

---

## Password Strength Coaching

SPM shows:

- Entropy  
- Crack time estimates  
- Character class analysis  
- Suggestions (EN + ID)  

---

## Clipboard Auto-Clean

Auto-clears clipboard after ~15 seconds using:

- macOS: `pbcopy`  
- Linux: `xclip` / `wl-copy`  
- Termux: `termux-clipboard-set`  

If none available:

- EN: `No clipboard helper available.`  
- ID: `Tidak ada helper clipboard tersedia.`  

---

## Portable & Save Bundles

### Portable

```bash
./spm.sh portable
```

Includes:

- `spm.sh`
- `spm_vault.gpg`
- `spm_vault.gpg.recovery`
- `spm_recovery_private.pem` (if present)
- Language-based README

### Save (Backup + Wipe Local)

```bash
./spm.sh save
```

Creates bundle then wipes vault+backup locally.

---

## Development & Versioning

Version: **2.0.0**  
- Semantic versioning  
- See `CHANGELOG.md`  

---

## Security Policy

See `SECURITY.md`.

---

## License

**Proprietary – All Rights Reserved**  
© 2025 SansYourWays.

See `LICENSE` for details.

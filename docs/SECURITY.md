# Security Policy for Sans Password Manager (SPM)
Version 2.1 — © 2025–2026 Sansyourways
Last Updated: August 2026

SPM (Sans Password Manager) is a privacy-focused, offline, fully client-side encrypted application.  
This document contains the security policy for vulnerability reporting, responsible disclosure, and usage expectations.

---

## 1. Security Philosophy
SPM is designed around the following core principles:

- **Offline-first** — no servers, no cloud sync, no telemetry.  
- **Zero data collection** — all vault data stays on the user's device.  
- **Strong encryption** — GnuPG symmetric encryption with AES-256 protects stored vault data.
- **User-controlled keys** — the user is the sole owner of all keys and passwords.  
- **User-controlled recovery** — recovery requires the locally generated RSA private key and recovery blob; the developer cannot recover either.
- **Crash-safe writes** — ciphertext is staged and atomically installed, with a last-known-good encrypted backup.
- **Concurrent-write protection** — CLI and web mutations share an advisory file lock when `flock` is available.

Core vault operations are offline. The optional updater contacts GitHub Releases,
and web mode serves the local vault UI on the address selected by the user.

---

## 2. Supported Versions
Because SPM is distributed under a **Private License**, only the latest stable release is officially supported.

| Version | Status |
|--------|--------|
| Latest stable (current release) | Supported |
| Any modified, altered, or redistributed build | **Not supported** |
| Older versions | Not supported |

---

## 3. Reporting a Vulnerability (Responsible Disclosure)
If you discover a potential security issue, follow these rules:

### ✔️ DO:
- Report it privately and directly.
- Provide steps to reproduce.
- Provide your environment details (OS, version, architecture).
- Wait for confirmation before sharing further details.

### ❌ DO NOT:
- Publicly disclose the vulnerability.
- Post the issue in GitHub issues.
- Share vaults, passwords, or private keys.
- Upload sensitive data for testing.
- Attempt to reverse engineer or bypass protections (violates license).

### 📩 **Report via Email (only):**
**security@sansyourways.xyz**

You will receive acknowledgment within a reasonable timeframe.

---

## 4. What Information to Include
When reporting, attach:

- A clear description of the issue  
- Steps to reproduce  
- SPM version  
- Your OS and setup  
- Expected behavior vs actual behavior  
- Logs *only if safe* (no sensitive data)

Do **not** send:

- Real vaults  
- Real passwords  
- Master password  
- Private keys  
- Screenshots containing sensitive entries  

---

## 5. Scope of Security Support
The following are considered in-scope for reporting:

- Encryption implementation bugs  
- File corruption or integrity failures  
- Web mode security concerns  
- Local process access vulnerabilities  
- Cryptographic misuse  
- Privilege escalation inside SPM  
- Bundle/backup handling vulnerabilities  

The following are **out of scope**:

- Lost master passwords  
- User-caused key loss  
- Device compromise (malware/virus/root)  
- Modified or tampered versions of SPM  
- Vault recovery requests  
- Cloud leakage (SPM never uploads data)  
- Brute-forcing encrypted vaults  
- Unofficial extensions or scripts  

---

## 6. Handling of Reports
All valid security reports will be:

- Acknowledged
- Investigated privately
- Resolved in a future update where applicable
- Credited (if you wish)
- Kept confidential until fixed

Reports violating the Private License (reverse engineering, decompiling, etc.) may result in termination of your license.

---

## 7. User Security Responsibility
Users are fully responsible for:

- Protecting their master password  
- Storing backups securely  
- Managing encryption keys  
- Protecting their device from malware  
- Securing their filesystem permissions  

Because SPM does not collect data or hold keys, **the developer cannot restore lost vaults**.

---

## 8. Contact Information
Security issues: **security@sansyourways.xyz**  
General support: **support@sansyourways.xyz**  
Commercial licensing: **business@sansyourways.xyz**

© 2025 Sansyourways. All Rights Reserved.

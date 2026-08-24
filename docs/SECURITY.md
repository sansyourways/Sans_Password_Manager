# Security Policy for Sans Password Manager (SPM)
Version 2.2 — © 2025–2026 Sansyourways
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
- **Local-first extensions** — history, backups, attachments, and sync contain encrypted vault material; browser autofill is explicit and hostname-bound.
- **Platform-owned passkeys** — SPM stores passkey metadata, never private passkey key material.

Core vault operations are offline. The optional updater contacts GitHub Releases,
and web mode serves the local vault UI on the address selected by the user. The
startup release check is off unless the user enables it, and downloaded releases
are SHA-256 verified and syntax-checked before they replace the installed
script, which is swapped in by rename so a running instance is never rewritten
underneath itself.

---

## 2. Supported Versions
SPM is open-source under Apache-2.0. Security fixes are maintained for the
latest stable official release; forks and modified distributions should obtain
support from their respective maintainers.

| Version | Status |
|--------|--------|
| Latest stable (current release) | Supported |
| Forks or modified distributions | Supported by their distributor |
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
- Test systems, accounts, or data you do not own or lack authorization to
  assess.

### 📩 **Report via Email (only):**
**security@sansyourways.xyz**

You should receive acknowledgment within **3 business days**.

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
- Issues found only in an independently modified distribution
- Vault recovery requests
- Cloud leakage (SPM never uploads data)
- Brute-forcing encrypted vaults
- Unofficial extensions or scripts

---

## 6. Handling of Reports
The project uses the following best-effort response targets:

| Stage | Target |
| --- | --- |
| Initial acknowledgment | 3 business days |
| Preliminary severity and scope assessment | 7 business days |
| Critical-severity remediation target | 30 calendar days |
| High-severity remediation target | 60 calendar days |
| Coordinated disclosure | After a fix, or normally within 90 days |

Targets may change with complexity, maintainer availability, or coordination
needs. The reporter will receive material status updates when a target changes.
Lower-severity findings are prioritized into a planned release based on impact
and available maintenance capacity.

Valid reports are investigated privately, credited if requested, and kept
confidential until a fix or coordinated disclosure when reasonably possible.

Good-faith source review and security research are welcome. Do not access data,
devices, or services without authorization, and coordinate disclosure of
unfixed vulnerabilities that could put users at risk.

---

## 7. User Security Responsibility
Users are fully responsible for:

- Protecting their master password
- Storing backups securely
- Managing encryption keys
- Protecting their device from malware
- Securing their filesystem permissions
- Anything reachable from the internet, including a Web Mode instance published
  on a domain

Because SPM does not collect data or hold keys, **the developer cannot restore lost vaults**.

Publishing Web Mode on a domain widens the trust boundary considerably. The
vault stays bound to `127.0.0.1` behind nginx, so nginx and TLS are the only
things standing between the internet and a master-password prompt. Prefer a
DNS-only record: a CDN or reverse proxy that terminates TLS at its own edge can
read every request in plaintext, the login POST included. Certificates are
logged to public Certificate Transparency, so the hostname is discoverable —
obscurity is not part of the protection.

---

## 8. Contact Information
Security issues: **security@sansyourways.xyz**
General support: **support@sansyourways.xyz**
Trademark and partnership questions: **business@sansyourways.xyz**

Copyright 2025–2026 Sansyourways and contributors.

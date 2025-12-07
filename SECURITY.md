# Security Policy

## Supported Versions

This project is experimental and under active development.  
There is no formal LTS policy yet, but generally the **latest release / tag**
is considered the most secure version.

## Reporting a Vulnerability

If you find a security issue (logic bug, crypto misuse, info leak, etc.):

- **Do NOT** open a public GitHub issue with sensitive details.
- Contact the maintainer privately:

  - Email: `sansyourways@proton.me`
  - GitHub DM: via your GitHub profile (if enabled)

Please include:

- A short description of the issue
- Reproduction steps if possible
- Your environment (OS, shell, GPG/openssl version)

You will get:

- Acknowledgment of the report
- A plan (fix, mitigation, or explanation) if it’s a real issue

## Do Not Submit

- Your real vault files (`*.gpg`, `*.recovery`)
- Your real `spm_recovery_private.pem`
- Real passwords or master passwords
- Screenshots/logs that reveal secrets

## Threat Model (High Level)

Sans Password Manager (SPM) assumes:

- The host machine is **not compromised** (no active malware / keylogger).
- The user keeps the **master password** and **private key** secret.
- GPG and OpenSSL are correctly installed and not backdoored.

SPM **does NOT** protect against:

- Someone with full root access on your device while you are using SPM.
- Physical attacks on unencrypted disks / memory.
- Users who commit their vault or keys to GitHub by mistake.

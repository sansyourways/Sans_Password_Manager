# Privacy Policy for Sans Password Manager

Effective date: August 2026

Copyright 2025–2026 Sansyourways and contributors.

This policy describes official Sans Password Manager (`SPM`) releases. SPM is
an offline-first, self-hosted password manager. The project does not operate a
vault service and does not receive vault contents, master passwords, recovery
keys, usage analytics, crash reports, or device identifiers from the app.

## Local vault data

Passwords, notes, authenticators, backup codes, attachments, passkey metadata,
history, and configuration are processed on the user's device. Vault data is
stored in user-controlled files and encrypted locally. Maintainers cannot
access or recover a user's encrypted vault or master password.

Users control their vault location, backups, portable archives, filesystem sync
targets, and recovery material. Those files may contain sensitive information
and must be protected by the user.

## Network behavior

Core vault operations do not require an SPM-operated server. Network activity
occurs only for features or deployment choices initiated by the user:

- `spm update`, `install.sh`, and release checks contact GitHub to retrieve
  release metadata or artifacts.
- The startup release check is disabled by default. If the user turns it on
  (`spm auto-update notify|auto`, or the auto-update entry in the interactive
  menu), SPM requests the latest release metadata from GitHub when it starts,
  at most once every 24 hours. Only the request itself is sent; no vault
  contents, identifiers, or usage data accompany it. Turning it back off
  (`spm auto-update off`) stops the check.
- Web Mode communicates between the user's browser and the locally operated SPM
  web process. It defaults to loopback, but a user may explicitly bind it to a
  non-loopback address or place it behind a reverse proxy.
- Choosing the domain/HTTPS bind in Web Mode runs `certbot` against Let's
  Encrypt on the user's behalf. The domain names being certified, this host's
  IP address, and the contact email if one is supplied are sent to Let's
  Encrypt, and the issued certificate is published in public Certificate
  Transparency logs, where the hostname becomes permanently searchable by
  anyone. If the domain is proxied through Cloudflare, Cloudflare terminates
  TLS at its edge and can read every request in plaintext, including the login
  POST carrying the master password. Both are opt-in deployment choices, and
  the Cloudflare case requires an explicit typed confirmation.
- Filesystem synchronization reads and writes the directory selected by the
  user. If that directory is provided by third-party synchronization software,
  that provider's privacy terms apply independently.
- Opening project links, reporting issues, or contributing through GitHub
  sends information to GitHub under GitHub's own policies.

SPM has no advertising, telemetry, hosted account, remote license check,
maintainer-operated cloud sync, or analytics integration.

## Local web data

Web Mode uses a session cookie for authentication with the user-operated local
server. The cookie is not sent to Sansyourways. Decrypted responses are marked
`Cache-Control: no-store`. Users who expose Web Mode beyond loopback are
responsible for transport security, access controls, and network configuration.

## Support and project communications

If someone contacts the project by email, GitHub issue, pull request, or security
advisory, the maintainers receive the information that person deliberately
submits. Do not submit real vaults, passwords, recovery keys, tokens, or other
secrets. Email and GitHub process these communications under their respective
policies.

## Forks and commercial distributions

Apache-2.0 permits commercial use and modified distributions. Their operators
are responsible for documenting any behavior that differs from official SPM.
This policy does not make representations about third-party forks or services.

## Children

SPM is a general-purpose local tool and does not knowingly collect children's
personal information. Project communication services may apply their own age
requirements.

## Changes and contact

Material privacy changes will be documented in the repository and changelog.
Questions may be sent to support@sansyourways.xyz; security reports should be
sent to security@sansyourways.xyz.

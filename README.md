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

Sans Password Manager (SPM) is a local-first password manager for the terminal and browser. Your encrypted vault stays under your control; SPM does not require a hosted account or put a vendor cloud service in the trust boundary.

**[Read the full SPM documentation](https://spm-docs.silentprotocol.top/)** for installation variants, the complete command reference, dashboard deployment, browser extensions, synchronization, recovery, and troubleshooting.

## Why SPM?

- Local ownership: the encrypted vault lives on your device.
- Two interfaces: use the CLI/TUI or the offline web dashboard.
- Dashboard settings in one place, including four preview-before-apply themes
  (Sundial, Console, Cyberpunk, and Edgerunner), master-password changes, and
  optional biometric unlock. Applied themes also follow the login and lock screens.
- A theme-compatible **Organize passwords** section filters the password list by
  one or more folders and `#tags`; active filters remain in the URL for reloads,
  bookmarks, and back-button navigation.
- Portable recovery: backups and recovery material remain user-controlled.
- Broad import/export support for moving data without lock-in.
- A small, inspectable release artifact generated from the repository source.

## Product showcase

![Animated Sans Password Manager showcase covering every Dashboard page in Chromium with a disposable synthetic vault](docs/product-demo.gif)

The showcase is captured from every Dashboard page in Chromium on a disposable profile. Every name, hostname, password, token, recovery code, and vault record is synthetic; no personal vault or real credential is used.

## 60-second quick start

Install the latest signed release:

```bash
curl -fsSLO https://raw.githubusercontent.com/sansyourways/Sans_Password_Manager/main/install.sh
bash install.sh
```

Then create and use a vault:

```bash
spm init       # Create the encrypted vault and recovery material
spm add        # Add an entry
spm list       # List entries
spm get 1      # Retrieve entry 1
spm            # Open the interactive terminal interface
spm web        # Start the local dashboard
```

> [!CAUTION]
> `spm init` creates recovery material. Anyone who obtains both the recovery private key and the recovery capsule can recover the vault. Store the private key offline and separately from the vault, capsule, and backups. Losing the required recovery material can make recovery impossible.

See the [installation guide](https://spm-docs.silentprotocol.top/#installation) for Homebrew, source installs, pinned versions, release verification, PATH setup, and updates.

## Security at a glance

SPM seals vault data with AES-256-CTR under an HMAC-SHA256 tag, unlocked through scrypt, and keeps routine vault operations inside a shared Python trusted core. Vaults written before 4.0.0 remain readable and upgrade in place. The CLI invokes that core as a subprocess; the dashboard imports the same implementation. Sensitive operations are local by default.

SPM assumes the host operating system is trustworthy. It cannot protect secrets from malware, root compromise, memory inspection, a compromised browser, or an already-compromised endpoint. The project has **not received an independent professional security audit**; repository review and automated tests are not substitutes for one.

Optional breach review uses the Have I Been Pwned Pwned Passwords range API. Only a hash prefix is sent, but enabling it still creates a network request. It is off unless you invoke the feature.

Read the complete [architecture and security model](https://spm-docs.silentprotocol.top/#architecture-and-security-model) and [security event guidance](https://spm-docs.silentprotocol.top/#security-events). Please report vulnerabilities privately as described in [SECURITY.md](docs/SECURITY.md).

## Who SPM is for

SPM is a good fit when you want a local, scriptable password manager; are comfortable owning backups and recovery; or need both terminal and browser-based workflows without a hosted account.

SPM may not be a good fit when you need:

- Vendor-managed cloud sync and account recovery.
- Enterprise compliance certifications or a professionally audited product.
- Protection on an untrusted or compromised device.
- A fully managed native desktop or mobile application.
- A password manager that assumes responsibility for your backups.

## Features

- Encrypted password vault with history, health checks, backups, and recovery.
- Split recovery: Shamir t-of-n shares that reconstruct the vault key without the master password, and stay valid after it changes.
- Interactive terminal interface plus a local web dashboard in twelve languages, including right-to-left Arabic.
- Passphrases, backup codes, authenticator/TOTP entries, and biometric unlock where supported.
- Import and export across common and advanced text formats.
- Browser extensions for Chromium and Firefox with a local native host, including an in-field account picker rendered at the extension's own origin so the page cannot read your account list, and a session lock you set.
- Portable and save bundles for user-controlled transfer and recovery.
- Pluggable sync transports (directory, rsync, rclone) that move only encrypted bytes to infrastructure you already run.
- Bulk tidy for imported vaults: folders read from notes, package identifiers renamed, reviewed before anything is written.
- Optional breach review with privacy-preserving prefix queries.

## Supported platforms

| Platform | CLI/TUI | Dashboard | Clipboard | Browser extension | CI coverage |
|---|---:|---:|---:|---:|---:|
| Linux | Yes | Yes | Yes | Yes | Yes |
| macOS | Yes | Yes | Yes | Yes | Yes |
| Android / Termux | Yes | Available | Yes | No native host | CLI/install |
| Windows via WSL | Best effort | Best effort | Environment-dependent | Not supported | No |
| Native Windows | No | No | No | No | No |

For platform-specific requirements and limitations, see the [requirements](https://spm-docs.silentprotocol.top/#requirements) and [installation](https://spm-docs.silentprotocol.top/#installation) sections.

## Requirements

Runtime requirements:

- Bash
- GnuPG (`gpg`) — reads vaults written before 4.0.0; still required
- OpenSSL
- Python 3

The installer also uses `curl`, `sha256sum`, `unzip`, and `mktemp`. Clipboard integration is optional and uses the platform clipboard helper when available. The installer and CLI report missing dependencies; review the full documentation before installing on a minimal or unsupported system.

## Where SPM stores data

| Data | Default location |
|---|---|
| Encrypted vault | `~/.spm_vault.gpg` |
| Recovery capsule | `~/.spm_vault.gpg.recovery` |
| Configuration | `${XDG_CONFIG_HOME:-$HOME/.config}/spm` |
| Application data | `${XDG_DATA_HOME:-$HOME/.local/share}/spm` |
| Recovery private key created by `spm init` | `./spm_recovery_private.pem` in the current directory |

Paths can differ when you select another vault or override XDG directories. Treat every exported archive, portable bundle, and recovery key as sensitive.

## Common commands

| Command | Purpose |
|---|---|
| `spm` | Open the interactive terminal interface |
| `spm init` | Initialize a vault and recovery material |
| `spm add` | Add an entry |
| `spm list` | List entries |
| `spm get <id>` | Retrieve an entry |
| `spm web` | Start the local dashboard |
| `spm doctor` | Check vault health and structure |
| `spm portable` | Build a portable bundle |
| `spm save` | Build a save bundle |
| `spm restore` | Restore a bundle vault to the default location |
| `spm forgot` | Start recovery with test or owned recovery keys |
| `spm update` | Install the latest published release |
| `spm help` | Show the complete local command help |

The [usage guide](https://spm-docs.silentprotocol.top/#usage) is the source for detailed workflows and command examples.

## Backup and recovery

Keep at least one encrypted vault backup away from the primary device. Store the recovery private key separately from the vault, recovery capsule, portable/save bundles, and backup location. Test recovery only with disposable data before relying on the process.

Portable and save bundles exclude the recovery private key by default. Setting `SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1` explicitly includes it and creates a self-contained archive that can bypass the master password; handle that opt-in archive as credential-equivalent material. Read [recovery](https://spm-docs.silentprotocol.top/#recovery-forgot-master-password), [health checks](https://spm-docs.silentprotocol.top/#doctor-health-check), and [portable/save bundle guidance](https://spm-docs.silentprotocol.top/#portable-and-save-bundles) before an emergency.

## Architecture and development

SPM ships as a single executable Bash script, but it is developed from three owned sources:

- `src/spm_core.py` — trusted vault-byte operations.
- `src/spm_web_server.py` — the local dashboard.
- `src/spm.sh.in` — CLI commands, menus, and help.

`./build.sh` assembles those sources into the generated `spm.sh`. Contributors must edit the source files and commit the regenerated script in the same change. See [CONTRIBUTING.md](CONTRIBUTING.md) and the documentation's [contributing section](https://spm-docs.silentprotocol.top/#contributing).

## Uninstall

### Remove the application only

Use the command matching the installation method:

```bash
sudo rm -f /usr/local/bin/spm  # Default release installer
brew uninstall spm             # Homebrew formula
pkg uninstall spm              # Termux package
```

For a custom installer prefix, remove only `<prefix>/bin/spm`. If you manually added that directory to `PATH`, remove the matching line from your shell profile.

If the Dashboard runs through PM2, stop it and remove its saved startup entry:

```bash
pm2 delete spm-web
pm2 save
```

Remove the browser extension through the browser's extension manager. The native host is stored at `${XDG_DATA_HOME:-$HOME/.local/share}/spm/browser-extension`. Its registration is named `xyz.sansyourways.spm.json` in these platform locations:

- Linux Chromium browsers: the browser directory under `~/.config/`, followed by `NativeMessagingHosts/`.
- Linux Firefox: `~/.mozilla/native-messaging-hosts/`.
- macOS browsers: the browser directory under `~/Library/Application Support/`, followed by `NativeMessagingHosts/`.

Remove only the SPM-owned native-host directory and registration files.

If you published the Dashboard, remove only the Nginx vhost and `sites-enabled` link for the exact domain you configured, run `sudo nginx -t`, and reload Nginx. If Certbot created a certificate solely for that hostname, review it with `sudo certbot certificates` before removing it with `sudo certbot delete --cert-name <domain>`.

### Remove all SPM data

> [!DANGER]
> The following data can contain the only usable vault or recovery material. Verify an independent backup and inspect every path before deleting anything. Deletion is irreversible.

After completing the application-only removal, locate and individually remove only the data you intend to destroy:

- The active vault, normally `~/.spm_vault.gpg`, and its `<vault>.recovery` capsule.
- `${XDG_CONFIG_HOME:-$HOME/.config}/spm` and `${XDG_DATA_HOME:-$HOME/.local/share}/spm`.
- `spm_recovery_private.pem` from the directory where each vault was initialized.
- User-selected backups, history exports, portable/save bundles, synchronization targets, and emergency kits.
- The SPM browser extension, native-host directory, and `xyz.sansyourways.spm.json` manifests described above.
- The PM2 process, Nginx vhost, and dedicated TLS certificate described above.

SPM intentionally has no automatic “delete everything” command because vaults, recovery keys, custom profiles, backups, and deployment files may live in different user-selected locations.

## Known limitations

- Security depends on the endpoint, GnuPG, OpenSSL, Python, and correct recovery-key handling.
- Native Windows is not supported; WSL operation is best effort.
- Browser integration requires local native-host setup and is not available in Termux.
- The dashboard binds locally by default. Remote exposure changes the threat model and requires correctly configured TLS, authentication, proxy, and firewall controls.
- Sync transports can copy encrypted files but do not make an untrusted endpoint safe. SPM operates no service; every transport is infrastructure you already run.
- Nine of the twelve interface languages are unreviewed translations. They are marked in the language picker, and the English text is authoritative wherever a warning matters.

## Documentation and project links

- **Full manual:** [spm-docs.silentprotocol.top](https://spm-docs.silentprotocol.top/)
- **Latest release:** [GitHub Releases](https://github.com/sansyourways/Sans_Password_Manager/releases/latest)
- **Roadmap:** [ROADMAP.md](ROADMAP.md)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security policy:** [docs/SECURITY.md](docs/SECURITY.md)
- **Privacy policy:** [docs/PRIVACY_POLICY.md](docs/PRIVACY_POLICY.md)
- **License:** [Apache 2.0](LICENSE)

## License

Sans Password Manager is released under the [Apache License 2.0](LICENSE).

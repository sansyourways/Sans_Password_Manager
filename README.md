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

An offline, portable password manager for people who want to own the vault,
understand the storage model, and keep cloud infrastructure out of the trust
boundary.

SPM is one executable Bash script backed by GnuPG. It provides a terminal
interface for automation and administration, plus an optional local web
interface for everyday browsing. There are no accounts, hosted APIs,
subscriptions, analytics, or vendor-operated recovery services.

Current release: **3.3.0**

---

## Table of Contents

- [Why use SPM?](#why-use-spm)
- [Product tour](#product-tour)
- [Capabilities](#capabilities)
- [Architecture & Security Model](#architecture--security-model)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Running `spm` from anywhere](#running-spm-from-anywhere)
  - [Staying up to date](#staying-up-to-date)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [SPM Dashboard](#spm-dashboard)
  - [Publish the SPM Dashboard on a domain with HTTPS](#publish-the-spm-dashboard-on-a-domain-with-https)
  - [Install the SPM Dashboard as an iOS app](#install-the-spm-dashboard-as-an-ios-app)
  - [Install the browser extension](#install-the-browser-extension)
  - [CLI Commands](#cli-commands)
  - [Secure Notes](#secure-notes)
  - [Recovery: Forgot Master Password](#recovery-forgot-master-password)
  - [Doctor / Health Check](#doctor--health-check)
- [Password Strength Coaching](#password-strength-coaching)
- [Clipboard Auto-Clean](#clipboard-auto-clean)
- [Portable & Save Bundles](#portable--save-bundles)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Development & Versioning](#development--versioning)
- [Documentation & Legal](#documentation--legal)
- [License](#license)

---

## Why use SPM?

Most password managers ask you to trust an application, a browser extension,
an account system, a synchronization service, and the company operating all of
them. SPM deliberately keeps that trust boundary small.

| Reason | What it means in practice |
| --- | --- |
| Your vault stays yours | The encrypted vault, recovery material, backups, and sync target remain on storage you control. |
| No service dependency | Core vault operations work without an internet connection, hosted account, license server, or vendor API. |
| Auditable implementation | The primary application is one readable Bash file that delegates encryption to standard GnuPG and OpenSSL tools. |
| Terminal and browser workflows | Use deterministic CLI commands for administration and automation, or launch the optional web interface for a more visual workflow. |
| Portable by design | Create a self-contained encrypted bundle for removable media or move between Linux, macOS, and Termux environments. |
| Recovery without vendor custody | Generate your own RSA recovery key and store it offline; SPM never holds a copy. |
| More than passwords | Store notes, passphrases, backup codes, TOTP authenticators, attachments, and passkey metadata in the same encrypted vault. |
| Built-in operational safety | Atomic writes, advisory locking, encrypted history, verified backups, sync conflict detection, and health diagnostics reduce avoidable data loss. |

SPM is a strong fit for technically confident individuals, administrators,
small teams with local-first requirements, air-gapped systems, and anyone who
prefers transparent tools over opaque hosted custody. It is not intended to
protect a compromised operating system, malware-infected device, or an
attacker with root access.

## Product tour

Every web capture below was taken from the 2.13.0 build in headless Chromium at
1440x900, against a disposable vault holding only synthetic documentation data.
3.0.x changed how the vault is encrypted and nothing a user sees, so these
remain the current interface; they are not re-captured for a release that would
reproduce them pixel for pixel.
No personal vault or real credential appears in these images, and the sidebar
path is a placeholder. The locked-screen captures are from a real iPhone running
the Home Screen web app -- the release target for SPM Dashboard -- and were taken at
2.11.2, which is the last release that changed that screen.

![Animated tour of SPM Dashboard cycling through the overview, the tagged password
list, the security findings page, cross-type search, vault history and
biometric unlock, all using synthetic records](docs/product-demo.gif)

### Unlock and assess the vault

| Secure login | Security overview |
| --- | --- |
| ![SPM master-password login](docs/screenshots/web-v2.13.0/01-login.png) | ![SPM vault overview and security score](docs/screenshots/web-v2.13.0/02-overview.png) |

### Resume a locked session with Face ID or Touch ID

Registering a device lets the 30-second idle lock resume without retyping your
master password. Suspension is enforced by the server, so a locked session is
refused everywhere except the unlock endpoints — the browser cannot be talked
out of it. The master password is still required for the first sign-in, at the
12-hour session cap, and once a locked session has gone unresumed for longer
than `SPM_WEB_SUSPEND_MAX`.

| Registered devices | The locked screen, on the phone |
| --- | --- |
| ![SPM biometric unlock settings listing two registered devices](docs/screenshots/web-v2.13.0/06-biometric-unlock.png) | ![SPM locked screen on iOS offering biometric unlock with a master-password fallback](docs/screenshots/ios-v2.11.2/01-vault-locked-en.jpg) |

The locked screen is translated like the rest of the interface, and carries its
own language picker — it is the one page a user meets *after* being locked out,
so it cannot assume they can still reach the app's settings to change language.

| English | Indonesian | Japanese |
| --- | --- | --- |
| ![SPM locked screen in English](docs/screenshots/ios-v2.11.2/01-vault-locked-en.jpg) | ![SPM locked screen in Indonesian](docs/screenshots/ios-v2.11.2/02-vault-locked-id.jpg) | ![SPM locked screen in Japanese](docs/screenshots/ios-v2.11.2/03-vault-locked-ja.jpg) |

### Rotate the master password

The **Settings** group holds the vault's own credentials: the master password
and the registered unlock devices. Changing the master password re-encrypts the
whole vault, and rewrites the recovery file *first* — a vault re-encrypted under
a new password while its `.recovery` file still names the old one is the one
state `spm forgot` cannot recover from. Every other browser session is signed
out; the session that made the change carries on.

![SPM master password page showing current, new and confirmation fields and a
summary of what changing it does](docs/screenshots/web-v2.13.0/28-master-password.png)

### Audit, search and roll back

| Security findings | Vault history |
| --- | --- |
| ![SPM security page listing weak, reused and stale entries by ID](docs/screenshots/web-v2.13.0/03-security.png) | ![SPM history page listing encrypted vault snapshots](docs/screenshots/web-v2.13.0/05-history.png) |

**Cross-type search** — one query across passwords, notes, passphrases,
authenticators and backup codes. Results carry labels and IDs only: matching on
a secret field would turn the search box into an oracle that confirms a guessed
password by whether a row appears.

![SPM search results spanning passwords, backup codes and authenticators](docs/screenshots/web-v2.13.0/04-search.png)

### Work with credentials and protected records

Password rows carry `#hashtag` tags parsed from their notes, with a filter chip
row above the table and a `rotate` badge on anything past the rotation
threshold. Tags are a convention over existing plaintext fields, so they need no
schema change and survive export and import untouched.

Each record also has a **URL**, alongside the username / email, password and
notes. It is what binds a credential to a site: the browser bridge matches the
hostname from this field first, and the browser extension will use it to offer
the right entry without guessing from the record's name. Only `http://` and
`https://` are accepted -- the value is rendered as a link and handed to the
extension, so the scheme is an allowlist rather than free text. Vaults written
before 2.12.0 have no URL field and are read unchanged; the bridge still finds
a URL in the notes the way it always did, so nothing needs migrating.

| Password records | Authenticator codes |
| --- | --- |
| ![SPM password list](docs/screenshots/web-v2.13.0/07-passwords.png) | ![SPM TOTP authenticator view](docs/screenshots/web-v2.13.0/20-authenticator-view.png) |

| Password generator | Import and export |
| --- | --- |
| ![SPM password generator](docs/screenshots/web-v2.13.0/26-generator.png) | ![SPM import and export workspace](docs/screenshots/web-v2.13.0/27-transfer.png) |

<details>
<summary><strong>Complete web interface gallery (28 pages)</strong></summary>

#### Passwords

| Add | View | Edit |
| --- | --- | --- |
| ![Add password](docs/screenshots/web-v2.13.0/08-password-add.png) | ![View password](docs/screenshots/web-v2.13.0/09-password-view.png) | ![Edit password](docs/screenshots/web-v2.13.0/10-password-edit.png) |

#### Secure notes

| List | Add | View |
| --- | --- | --- |
| ![Secure notes list](docs/screenshots/web-v2.13.0/11-notes.png) | ![Add secure note](docs/screenshots/web-v2.13.0/12-note-add.png) | ![View secure note](docs/screenshots/web-v2.13.0/13-note-view.png) |

#### Passphrases

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Passphrase list](docs/screenshots/web-v2.13.0/14-passphrases.png) | ![Add passphrase](docs/screenshots/web-v2.13.0/15-passphrase-add.png) | ![View passphrase](docs/screenshots/web-v2.13.0/16-passphrase-view.png) | ![Edit passphrase](docs/screenshots/web-v2.13.0/17-passphrase-edit.png) |

#### Authenticators

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Authenticator list](docs/screenshots/web-v2.13.0/18-authenticators.png) | ![Add authenticator](docs/screenshots/web-v2.13.0/19-authenticator-add.png) | ![View authenticator](docs/screenshots/web-v2.13.0/20-authenticator-view.png) | ![Edit authenticator](docs/screenshots/web-v2.13.0/21-authenticator-edit.png) |

#### Backup codes

| List | Add | View | Edit |
| --- | --- | --- | --- |
| ![Backup-code list](docs/screenshots/web-v2.13.0/22-backup-codes.png) | ![Add backup codes](docs/screenshots/web-v2.13.0/23-backup-codes-add.png) | ![View backup codes](docs/screenshots/web-v2.13.0/24-backup-codes-view.png) | ![Edit backup codes](docs/screenshots/web-v2.13.0/25-backup-codes-edit.png) |

#### Settings

| Master password | Biometric unlock |
| --- | --- |
| ![Master password page](docs/screenshots/web-v2.13.0/28-master-password.png) | ![Biometric unlock settings](docs/screenshots/web-v2.13.0/06-biometric-unlock.png) |

</details>

## Capabilities

- GnuPG AES-256 encrypted vault with atomic writes and advisory locking
- Interactive terminal interface with English, Indonesian, and Japanese modes
- Optional Console-style web interface with inactivity locking
- Password records, secure notes, passphrases, backup codes, and TOTP
  authenticators using SHA-1, SHA-256, or SHA-512
- Secure and memorable password generation with strength coaching
- Clipboard copy feedback and automatic clipboard clearing
- CLI and web import/export across CSV, JSON, TSV, NDJSON, Markdown, HTML,
  YAML, XML, SQL, INI, PSV, RST, TOML, Org, SCSV, JSONC, and related variants
- Vault-wide security score for weak, reused, old, incomplete, or malformed
  records, with an SPM Dashboard page listing the entries behind each finding
- Cross-type search and `#hashtag` tags across every record type
- A URL on every password record, scheme-restricted to `http(s)`, used to bind
  a credential to a site for the browser extension
- Encrypted history, verified manual/automatic backups, and confirmed rollback,
  restorable from the interactive menu or SPM Dashboard
- Digest-verified encrypted attachments with a 1 MiB limit
- Named vault profiles and conflict-aware filesystem synchronization
- Recipient-encrypted emergency kits with authenticated contents
- Platform passkey metadata and an exact-domain native browser bridge
- Portable and SAVE bundles with recovery private keys excluded by default
- RSA-based self-custodied recovery and built-in doctor diagnostics

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

### SPM Dashboard safeguards
- Login failures are isolated by visitor behind the bundled loopback nginx
  configuration, synchronized across request threads, expired, and memory-bound.
- Vault mutations are serialized and protected by per-session CSRF tokens.
- Password generation refuses to continue without a cryptographically secure
  random source.

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

### Verified release installer

Download the installer first so you can inspect it, then install the latest
release. The installer downloads both the official ZIP and its matching
SHA-256 file, verifies the archive, checks Bash syntax, and installs `spm`.

```bash
curl -fsSLO https://raw.githubusercontent.com/sansyourways/Sans_Password_Manager/main/install.sh
bash install.sh
```

Install a specific release or a user-writable prefix:

```bash
bash install.sh --version 3.3.0
bash install.sh --prefix "$HOME/.local"
```

### Running `spm` from anywhere

The installer puts the CLI at `PREFIX/bin/spm` — `/usr/local/bin/spm` by
default, which is already on `PATH` on most systems. When it is not, the
installer says so and adds it to your shell profile for you, so a new terminal
can run `spm` from any directory:

```text
Installed SPM 3.3.0 at /home/you/.local/bin/spm
PATH        : added /home/you/.local/bin to /home/you/.bashrc
                run "exec /bin/bash" or open a new terminal to pick it up
```

The line it appends is marked with a comment and written only once, so
reinstalling or upgrading never duplicates it. The profile is chosen from your
login shell:

| Shell | File written |
|---|---|
| bash | `~/.bashrc`, or `~/.bash_profile` on macOS |
| zsh | `$ZDOTDIR/.zshrc`, else `~/.zshrc` |
| fish | `~/.config/fish/conf.d/spm.fish` (uses `fish_add_path`) |
| anything else | `~/.profile` |

Nothing is written when the directory is already on `PATH`, when you pass
`--no-modify-path`, when `SPM_NO_MODIFY_PATH=1` is set, or when the installer
runs as root — under `sudo`, `$HOME` may belong to root rather than to you, so
the installer prints the line to add instead of editing the wrong account's
profile.

To do it by hand, or if you installed from source, add the directory yourself:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
exec "$SHELL"
```

Confirm it worked:

```bash
command -v spm
spm help
```

### Staying up to date

`spm update` checks GitHub Releases and installs the latest version on demand.
The download is SHA-256 verified and syntax-checked before it replaces the
installed script.

SPM can also check on its own at startup. This is **off by default** and never
enabled implicitly, because the privacy policy limits network activity to things
the user chooses to switch on:

```bash
spm auto-update status    # show the current mode
spm auto-update notify    # check daily, ask before installing
spm auto-update auto      # check daily, install without asking
spm auto-update off       # never check on its own
```

The same three modes are available from the interactive menu under
**Auto-update settings**, which also shows when the last check ran and offers a
one-off *Check now*.

| Mode | Behaviour |
|---|---|
| `off` *(default)* | SPM never contacts GitHub unless you run `spm update` |
| `notify` | Checks at startup, at most once a day, and asks before installing |
| `auto` | Checks at startup, at most once a day, and installs without asking |

The check is deliberately unobtrusive: it runs only on an interactive terminal,
never during scripted use, times out after a few seconds, and is silently
skipped when you are offline or GitHub is unreachable — being unable to reach
the network never delays access to your vault. Set `SPM_UPDATE_TIMEOUT` to
change the timeout.

### From source

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
- Vault history (pick an encrypted snapshot by number and restore it)  

---

### SPM Dashboard

```bash
./spm.sh web
```

- Runs on localhost by default; Global/custom binds require an explicit risk confirmation
- Background mode verifies that its PM2 process is online and reports startup errors
- SPM never changes firewall rules automatically; restrict any remote port to trusted clients
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
  - A **Settings** group holding the gear-marked **Master Password** page and
    **Biometric Unlock**. Changing the master password re-encrypts the vault,
    rewrites the recovery file first so `spm forgot` keeps working, and signs
    out every other browser session  
  - Dark-only Console presentation with a command-style vault status overview, visible keyboard focus, and mobile record layouts
  - Restrained motion for causal feedback—toast arrival, mobile navigation,
    import progress, and authenticator-code changes—with a fully static
    `prefers-reduced-motion` experience
  - A consistent inline SVG icon system for navigation, vault objects, status,
    and actions; the geometric assets inherit Console colors and work fully
    offline without icon fonts or third-party requests

Console deliberately favors dense, auditable rows over spacious cards. Very long
vault labels still wrap and can make mobile records tall; this is preferable to
shrinking text or forcing page-level horizontal scrolling.

---

### Publish the SPM Dashboard on a domain with HTTPS

Choosing bind option **4) Domain/subdomain with HTTPS** puts nginx in front of
the vault: nginx terminates TLS on the public interface, and the vault itself is
bound to `127.0.0.1` where nothing on the network can reach it directly. SPM
writes the vhost, obtains a Lets Encrypt certificate, and reloads nginx for you.

```
./spm.sh web
  → 2) Run in background using PM2
  → 4) Domain/subdomain with HTTPS (nginx + Lets Encrypt)
```

You are asked for:

| Prompt | Notes |
| --- | --- |
| Domain or subdomain | e.g. `vault.example.com`. A scheme or trailing path is stripped. |
| Also cover `www.`? | Both names go on one certificate. |
| Proxied through Cloudflare? | Answer honestly — it changes the generated config, not just a message. |
| How to prove ownership | HTTP file on port 80, or a DNS TXT record via the Cloudflare API. |
| Contact email | Passed to Lets Encrypt for expiry notices. Blank registers without one. |
| Port | The loopback port nginx proxies to. |

#### Choosing the validation method

**HTTP (default for a plain DNS record)** answers a challenge file on port 80.
It needs port 80 reachable from the internet and nothing in front rewriting or
challenging that request.

**DNS (default behind Cloudflare)** writes a TXT record through the Cloudflare
API instead. Nothing has to be reachable on port 80, and the CDN cannot
interfere because no HTTP request is involved — which makes it the only method
that reliably works behind a proxy. It also certifies a name whose A record
does not exist yet, and it never touches your existing site: no HTTP vhost is
installed until the certificate is already in hand.

DNS validation asks once for a Cloudflare API token needing exactly:

| Group | Access |
| --- | --- |
| Zone → Zone | Read |
| Zone → DNS | Edit |

Nothing broader is required, and a broader token would let anything holding
that file repoint your entire domain. The token is read with hidden input and
written straight to `~/.config/spm/cloudflare.ini` at mode `0600` — it never
appears on screen, in shell history, or in the process list. **Keep that file:**
certbot reads it again at every renewal, so deleting it breaks unattended
renewal. Renewals then work regardless of your CDN settings.

Only Cloudflare is wired up today. Other DNS providers have certbot plugins,
but SPM does not drive them yet.

**Before you start**, the DNS record for every name must already resolve to this
host (or to Cloudflare, if proxied), and ports 80 and 443 must be reachable from
the internet. Port 80 is required even though the site ends up on 443: it is how
the ACME HTTP-01 challenge is answered. SPM prints what each name resolves to
and compares it against this host's address before it asks Lets Encrypt for
anything.

With HTTP validation, setup runs in three phases, because nginx must already
answer on port 80 to serve the challenge, while a TLS server block naming a
certificate that does not exist yet fails `nginx -t`:

1. an HTTP-only vhost serving `/.well-known/acme-challenge/`
2. `certbot certonly --webroot` for every name
3. the real vhost — HTTP redirects to HTTPS, HTTPS reverse-proxies to the vault

With DNS validation there are only two, because nothing needs to be served for
the challenge: the certificate is obtained first, then the finished vhost goes
in. Your existing site stays untouched until the certificate exists.

Every install is validated with `nginx -t` before the reload, and a
configuration that fails validation is rolled back to whatever was there before,
so a bad generate can never take down other sites on the same host.
HTTP challenge and certificate failures also restore the prior vhost and
enabled-site link. If the target belongs to another application, SPM requires
the literal confirmation `replace` before staging any change.

Set `SPM_ACME_DRY_RUN=1` to exercise the whole challenge path against Lets
Encrypt's staging behaviour without spending a certificate against the rate
limit. A dry run stops before enabling TLS and restores the previous vhost.

#### If the domain is behind Cloudflare

Answering yes has consequences worth stating plainly, and SPM asks you to
confirm them:

- **Cloudflare can read every request in plaintext.** It terminates TLS at its
  edge and re-encrypts to your host, so the login POST carrying your master
  password and every secret the vault renders pass through it decrypted.
  End-to-end encryption between your browser and your host requires DNS-only
  mode (grey cloud).
- SPM installs a real-IP snippet so nginx logs and rate limits see the visitor's
  address from `CF-Connecting-IP` rather than a Cloudflare edge address.
- Set your zone's SSL/TLS mode to **Full (strict)** afterwards so the edge
  verifies the certificate SPM just issued instead of accepting any origin.
- **Universal SSL does not cover `www.vault.example.com`.** Cloudflare's free
  certificate covers the apex and *one* level of subdomain, so a `www.` alias on
  an already-nested subdomain has no certificate at the edge and browsers fail
  the handshake. SPM detects this and offers to drop the alias. Advanced
  Certificate Manager or a custom certificate lifts the limit.
- If Bot Fight Mode or a managed challenge is enabled on the zone, the edge
  answers with a challenge page before the vault is reached. Exempt the hostname
  if logins stall.

**Two Cloudflare settings break *HTTP* issuance outright**, and both are on by
default in many zones. Neither affects DNS validation, which is the simplest
reason to choose it behind a proxy. SPM fetches the challenge file through the public
internet before calling certbot and names whichever one it hits, rather than
leaving you with certbot's bare `unauthorized`:

- **Always Use HTTPS** redirects the plain-HTTP ACME challenge to HTTPS — but
  the certificate does not exist yet, so that request cannot succeed. Turn it
  off until issuance completes.
- **Bot Fight Mode / Browser Integrity Check / WAF** answer Let's Encrypt's
  validator with a challenge page, which it cannot solve. Add a Configuration
  Rule disabling them for `/.well-known/acme-challenge/*`, or set the record to
  DNS-only (grey cloud) until the certificate is issued.

Because the check runs before the request, a zone misconfiguration costs you
nothing against the Let's Encrypt rate limit.

The choice is saved, so the next run offers the same domain again.

---

### Install the SPM Dashboard as an iOS app

SPM Dashboard ships an app icon and a web app manifest, so iPhone and iPad can add it
to the Home Screen and launch it like a native app — full screen, with no Safari
address bar. Nothing is installed from an app store and nothing leaves your host;
the icon simply opens the same local server that is already running.

**1. Start SPM Dashboard in background mode — this is not optional.**

```bash
./spm.sh web
```

```text
Choose mode:
  1) Temporary (foreground, Ctrl+C to stop)
  2) Run in background using PM2      <- choose this
  3) Stop background web server (PM2)
  0) Back
```

Choose **2**. The Home Screen icon is only a bookmark: it opens the server, it
does not start it. Option 1 runs the server in the foreground, tied to the shell
you launched it from, so it stops on `Ctrl+C` and dies the moment you close the
terminal or drop an SSH session — and the icon would then open a page that fails
to load. Option 2 hands the server to PM2, which keeps it running after you log
out. Use option 3 when you want to stop it.

Note the address it prints; that is what you open in Safari.

If you want the server to come back after a reboot, tell PM2 to remember it —
SPM starts the process but does not persist it for you:

```bash
pm2 save
pm2 startup   # prints a command to run once, as root
```

**2. Open the vault in Safari, then tap the address bar menu and choose Share.**

Safari is required. Chrome, Firefox, and other iOS browsers cannot add a web app
to the Home Screen.

![Safari menu with the Share item highlighted](docs/screenshots/ios-install/1-share.jpg)

**3. Scroll the share sheet and tap _Add to Home Screen_.**

![iOS share sheet showing the Add to Home Screen action](docs/screenshots/ios-install/2-add-to-home-screen.jpg)

**4. Leave _Open as Web App_ enabled, then tap _Add_.**

The icon and the name `SPM` are filled in automatically from the manifest. Keep
the toggle on: it is what makes the vault open full screen instead of in a Safari
tab. The address shown here is your own host — the example below is redacted.

![Add to Home Screen sheet with the Open as Web App toggle enabled](docs/screenshots/ios-install/3-open-as-web-app.jpg)

**5. The vault now has an icon on your Home Screen.**

![SPM icon on an iOS Home Screen](docs/screenshots/ios-install/4-home-screen-icon.jpg)

#### Notes

- **You will be asked to unlock again on first launch.** iOS gives Home Screen
  web apps their own cookie storage, separate from Safari, so the app does not
  inherit an existing Safari session.
- **There is no address bar in the installed app**, so you cannot visually
  confirm the origin the way you can in a tab. Only install from an address you
  trust.
- **The icon does not start the server.** If SPM Dashboard is not running when you
  tap the icon, the page simply fails to load. This is why step 1 uses PM2
  background mode rather than the foreground option.
- **The icon is cached when you add it.** If you upgrade SPM and the artwork
  changes, remove the Home Screen icon and add it again to pick up the new one.
- **Serving outside localhost is your decision to make.** `./spm.sh web` binds to
  localhost by default and requires an explicit confirmation to bind elsewhere.
  SPM speaks plain HTTP and never edits firewall rules, so anything reachable
  beyond your own machine should be restricted to trusted clients — ideally over
  a VPN or an SSH tunnel rather than an open port.
- Android and desktop Chrome read the same manifest and offer an equivalent
  *Install app* / *Add to Home screen* action.

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

Imports passwords, secure notes, passphrases, backup codes, and authenticators from supported export formats (csv/json primary; advanced formats accepted as listed above). Entries are appended and IDs auto-renumbered. Imports fail if no supported records are detected. Web mode overlays the entire Export/Import card with a loader during uploads, reports how many rows of each type were added, and automatically reloads the dashboard on success so the new rows appear immediately (errors show inline without redirect). Status messages and overlay text follow the selected language (EN/ID/JP) so users get consistent feedback during uploads.

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
- **Split records** — entries containing a character that Python's
  `splitlines()` treats as a line break (`U+000B`, `U+000C`, `U+001C`–`U+001E`,
  `U+0085`, `U+2028`, `U+2029`). Such an entry was written as one record but is
  read back as two, so it vanishes from SPM Dashboard while still listing correctly
  in the CLI — the CLI splits on newline only. Releases before 2.10.12 could
  create these; the scan finds any you already have.

  The scan is read-only. It prints the record type, id, label and the character
  by Unicode name, never the secret field, and leaves the vault untouched. To
  repair one, re-save it from the CLI (`spm edit <id>`, or the matching
  `*-edit` command for notes, passphrases, backup codes and authenticators) so
  the field passes through the current sanitiser:

  ```
  [!] 1 record(s) contain a line-break character; 0 leftover fragment(s):
        line 3     PASSWORD      id=2     My␣Bank            U+2028 LINE SEPARATOR
      These entries are invisible in SPM Dashboard. The vault was NOT changed.
  ```

- File permissions on the vault, its `.bak`, the recovery file, and **every
  copy of the RSA private key** — each should be `600`. Anything readable by
  group or others is reported with a ready-to-run `chmod` command. Vaults last
  written by a web session before 2.9.1 were left at the umask default (usually
  `644`), and this is how you find and fix them.
  Because `init` generates the recovery key in whatever directory you run it
  from, copies tend to accumulate. The check looks in the current directory,
  beside the vault, next to the script, and up to four levels under `$HOME`,
  de-duplicating by real path. An exposed recovery key is worth fixing first:
  it unlocks the vault via `forgot` **without** the master password.

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
- Auto README file  

The RSA recovery private key is deliberately excluded. Keep it in a separate
offline location. To create a self-contained archive that can bypass the master
password, explicitly run `SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1 ./spm.sh portable`.
Treat that opt-in archive as plaintext-equivalent credential material.

### SAVE

```bash
./spm.sh save
```

Creates encrypted backup, wipes local vault.
The recovery private key remains separate unless
`SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1` is explicitly set.

---

## Contributing

Bug reports, focused improvements, and portability fixes are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Public issue
forms are available for bugs, feature requests, and non-sensitive security
design questions. Potential vulnerabilities must use the repository's private
security-advisory channel.

Contributions are accepted under Apache-2.0 and require a Developer Certificate
of Origin sign-off. Contributors retain copyright in their work; see
[the contributor license policy](docs/CONTRIBUTOR_LICENSE_POLICY.md).

Every change is checked with Bash syntax validation, ShellCheck, and a
disposable-vault regression suite covering all supported import/export formats,
web uploads, backups, synchronization, attachments, passkey metadata, emergency
kits, and password generation.

CI runs the regression suite on Linux and macOS, plus syntax, CLI-help, and
installer smoke checks in a pinned official Termux container. Pull requests
also require a DCO sign-off check.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for current reliability work, safer-integration
priorities, longer-term ecosystem ideas, and guidance for choosing a first
issue. Roadmap entries are directions, not promised delivery dates.

---

## Development & Versioning

Version: **3.3.0**
Web session cookies use `HttpOnly` and `SameSite=Strict`; `Secure` is added when the request arrives over HTTPS (`X-Forwarded-Proto`). Plain-HTTP non-loopback binds require an explicit `yes` confirmation: prefer localhost behind a TLS reverse proxy. `SPM_WEB_ALLOW_INSECURE_REMOTE=1` remains a non-interactive escape hatch for isolated trusted networks only.
The web login locks a client out for 60 seconds after 5 failed master-password attempts.
The 30-second idle auto-lock performs a single logout transition and tears down
its timer when the page is leaving, avoiding repeated navigation or refresh loops.
Returning to a page through the back/forward cache does not extend the idle
window: a page whose deadline already passed locks immediately on restore.
That lock runs in the browser, so it resets on mouse and touch activity that
reaches no server — and it cannot protect a client whose scripts do not run.
The server independently expires an idle session after 5 minutes and any
session after 12 hours, regardless of what the browser does. Every `<script>`
is served with `data-cfasync="false"` beside its CSP nonce so a CDN cannot
rewrite it out of existence; if you front the SPM Dashboard with Cloudflare, disable
Rocket Loader for the hostname as well.

Set a relying-party id (`SPM_WEB_RP_ID`, or let SPM's own domain setup supply
it) and SPM Dashboard offers **biometric unlock**: register a device from the
Biometric Unlock page and the idle lock resumes with Face ID or Touch ID
instead of a retyped master password. Suspension is enforced by the server, not
the browser — a locked session is refused everywhere except the unlock
endpoints, so disabling JavaScript walks past nothing. The master password is
still required for the first sign-in, once the 12-hour session cap is reached,
and whenever a locked session goes unresumed for longer than
`SPM_WEB_SUSPEND_MAX` (default 8 hours), which is how long the master password
stays in server memory after the screen locks. Registration needs a browser
that can export the credential key (`getPublicKey()`, Safari 16+), assertions
are verified with `openssl` against ES256, and user verification is required —
a bare presence tap is refused. No relying-party id means the feature and its
endpoints do not exist at all. Failed unlocks share the login lockout budget.

The origin that assertions are checked against follows the relying-party id,
not the address SPM binds: `localhost` implies `http://localhost:<port>` (the one host
browsers treat as a secure context without TLS) and any other name implies
`https://<name>`. That is what makes the documented deployment — loopback bind
behind a TLS reverse proxy — work. Set `SPM_WEB_ORIGIN` to override it
explicitly if your proxy publishes a non-default port.
Authenticated web mutations also require an exact same-origin request and are serialized across threads/processes to prevent CSRF and lost vault writes. Decrypted web responses use `Cache-Control: no-store`.
All listed import formats are round-trip compatible with their matching CLI and web exports.
Vault writes are staged and atomically installed. CLI and web processes share an advisory vault lock when `flock` is available; avoid concurrent access on systems without it. `save` verifies the archived vault before removing the local copy.

### Local-first 2.10 commands

```bash
spm security
spm history-list
spm history-restore <snapshot-name>
spm backup-now [directory]
spm backup-auto enable [directory] [hours] [retention]
spm vault-profile list
spm vault-profile add <name> <vault-path>
spm vault-profile use <name>
spm attachment-add <file> [label]
spm attachment-list
spm attachment-extract <id> [output]
spm passkey-add <rp-id> <account> <credential-id> [notes]
spm passkey-list
spm sync status|push|pull <directory> [channel]
spm emergency-create <password-id> <recipient-public.pem> <YYYY-MM-DD> [archive]
spm emergency-open <archive> <recipient-private.pem> [output.json]
```

Automatic backups are opportunistic: SPM checks the configured interval after
successful vault writes. Filesystem sync stores only encrypted vault bytes and
refuses two-sided or mismatched first-time changes instead of selecting a last
writer. Use the same optional channel name on every device. Emergency dates
are enforced by `spm emergency-open` but remain advisory because a recipient
holding the private key can use lower-level cryptographic tools. Passkey private
keys remain non-exportable in the operating-system or hardware authenticator;
SPM stores only discovery and recovery metadata.

### Install the browser extension

The universal extension is in `browser-extension-universal/` and supports
Chrome, Chromium, Edge, Brave, Opera, Vivaldi, and Firefox desktop from one
source tree. First install SPM 3.3.0 or later, then unpack the release archive.

### One-command guided setup

```bash
./browser-extension-universal/setup.sh
```

This detects an installed browser, builds the correct package, registers the
native host, opens the browser extension page and prepared folder, and prints
the final three clicks. Choose a browser explicitly when needed:

```bash
./browser-extension-universal/setup.sh --browser chrome
./browser-extension-universal/setup.sh --browser firefox
```

For Chromium-family browsers, enable **Developer mode** at the top right, click
**Load unpacked** at the top left, and select the folder printed by the setup
command. For Firefox, click **Load Temporary Add-on** and select the printed
`manifest.json`.

![Chrome Extensions showing Developer mode enabled and Load unpacked ready](docs/screenshots/browser-extension-setup/chrome-load-unpacked.png)

The screenshot uses a disposable empty Chrome profile and contains no account,
browsing, vault, or credential data.

For remote or scripted preparation without opening windows:

```bash
./browser-extension-universal/setup.sh --browser chromium --no-open
```

The unpacked Chromium build now carries a public development key, so every copy
loads under the same extension ID and nothing has to be pasted back into the
terminal. If you already had the extension loaded from an earlier build, remove
that entry from the extensions page first: its ID changes, so the browser would
otherwise keep the stale copy alongside the new one. The manual `build.sh` and
`install-host.sh` flow, and the full upgrade note, are in
[`browser-extension-universal/README.md`](browser-extension-universal/README.md).
Temporary Firefox add-ons must still be loaded again after restart unless
installed through a signed distribution.

Open an HTTP(S) login page and select the SPM toolbar icon. Unlock once, then
choose one of the accounts bound to that exact hostname. The master password is
kept only in the native host process and is discarded on explicit lock, idle
timeout, native-port disconnect, or browser exit. The hostname is verified
again before the selected password is returned. A record for `example.com`
does not match `login.example.com`.

Safari and iOS browsers cannot use this native-messaging package. Safari needs
a separately signed Xcode application wrapper; on iOS, use the installable SPM
Dashboard web app. See
[`browser-extension-universal/README.md`](browser-extension-universal/README.md)
for browser-specific paths, behavior, and troubleshooting. The older
`browser-extension/` remains in the archive only as a compatibility client for
existing installations.
Uses **semantic versioning**.  
`./spm.sh update` fetches the latest GitHub ZIP, verifies its published SHA-256 and the extracted script syntax, then installs to `/usr/local/bin/spm` (sudo may be required).
See `CHANGELOG.md` for details.

---

## Documentation & Legal

SPM is open-source software licensed under the **Apache License 2.0**. The code
may be used, modified, and redistributed under that license. Project names and
logos remain subject to the separate trademark policy.

Refer to:

- [`LICENSE`](LICENSE)
- [`NOTICE`](NOTICE)
- [`DCO`](DCO)
- [`docs/CONTRIBUTOR_LICENSE_POLICY.md`](docs/CONTRIBUTOR_LICENSE_POLICY.md)
- [`docs/TRADEMARK_POLICY.md`](docs/TRADEMARK_POLICY.md)
- [`docs/PRIVACY_POLICY.md`](docs/PRIVACY_POLICY.md)
- [`docs/GDPR_NOTICE.md`](docs/GDPR_NOTICE.md)
- [`docs/TERMS_AND_CONDITIONS.md`](docs/TERMS_AND_CONDITIONS.md)
- [`docs/CODE_OF_CONDUCT.md`](docs/CODE_OF_CONDUCT.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)

---

## License

Licensed under the **Apache License 2.0**.
Copyright 2025–2026 Sansyourways and contributors.

See [`LICENSE`](LICENSE) for the full terms and [`NOTICE`](NOTICE) for
attribution. Releases before 2.10.3 remain governed by the license included in
their historical release artifacts.

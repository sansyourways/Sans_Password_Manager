# Changelog

All notable changes to **Sans Password Manager (SPM)** are documented in this file.

This project loosely follows [Semantic Versioning](https://semver.org/) and a
Keep-a-Changelog style format.

## [2.10.9] - 2026-08-23

### Added
- The domain flow can prove ownership with a DNS TXT record through the
  Cloudflare API instead of a file served over HTTP. Behind a CDN the HTTP
  challenge has to survive the edge's redirects and bot rules; a DNS lookup
  cannot be interfered with, which makes this the only method that reliably
  works for a proxied domain. It is the default when the domain is proxied,
  and it also certifies a name whose A record does not exist yet. Renewals
  are unattended and unaffected by CDN settings.
- DNS validation runs in two phases rather than three: no HTTP vhost is
  installed at all, so an existing live site is untouched until the
  certificate is in hand.
- The Cloudflare API token is read with hidden input and written straight to
  `~/.config/spm/cloudflare.ini` at mode `0600`, so it never reaches the
  terminal, the shell history, or the process list. SPM asks for a token
  scoped to `Zone:Read` and `DNS:Edit` only.

## [2.10.8] - 2026-08-23

### Fixed
- The domain flow now checks that the ACME challenge file is actually
  reachable from the internet before calling certbot, and names the cause when
  it is not. Cloudflare's "Always Use HTTPS" redirects the plain-HTTP challenge
  to a certificate that does not exist yet, and its bot protection answers
  Let's Encrypt's validator with a challenge page it cannot solve; both
  previously surfaced only as certbot's bare `unauthorized`, after the attempt
  had already been spent against the rate limit. The probe retries, because
  `systemctl reload` returns before the new nginx workers are serving.
- A domain whose name has no A record no longer marches into a doomed
  certificate request. The flow reports the missing record and stops, since a
  failed validation counts against the rate limit.
- Guarded a `dig | grep` pipeline that exits non-zero when a name does not
  resolve. Under `pipefail` that failed the assignment; every current call site
  runs with `errexit` suppressed, so it hid rather than crashed, but it would
  have taken down any caller that did not.

## [2.10.7] - 2026-08-23

### Added
- Web Mode can publish itself on a domain or subdomain over HTTPS. A fourth
  bind option writes an nginx vhost, obtains a Let's Encrypt certificate with
  `certbot --webroot`, and reloads nginx, leaving the vault bound to
  `127.0.0.1` behind the proxy rather than exposed on the network. Setup runs
  in three phases because nginx must answer on port 80 for the ACME challenge
  before a TLS block naming the certificate can pass `nginx -t`; every install
  is validated and rolled back on failure, so a bad generate cannot take down
  other sites on the host. `SPM_ACME_DRY_RUN=1` exercises the challenge path
  without spending a certificate and restores the previous vhost afterwards.
- The domain flow asks whether the name is proxied through Cloudflare. Saying
  yes requires confirming that Cloudflare can read every request in plaintext,
  including the login POST carrying the master password, and installs a
  `set_real_ip_from` snippet so nginx sees the visitor address from
  `CF-Connecting-IP`. It also detects that Cloudflare's Universal SSL does not
  cover a `www.` alias one level below an already-nested subdomain and offers
  to drop the alias rather than publish a name the edge cannot serve.
- Opt-in automatic update checking. `spm auto-update [status|off|notify|auto]`
  and an `Auto-update settings` entry in the interactive menu let SPM check
  GitHub Releases at startup, at most once every 24 hours, and either report a
  newer release or install it without asking. It is **off by default** and never
  enabled implicitly: the privacy policy limits network activity to features the
  user initiates, so enabling it is what makes the check user-initiated. The
  check only runs on an interactive terminal, times out after a few seconds, and
  is skipped silently when offline, so it can never delay reaching a vault.
- `install.sh` now checks whether `PREFIX/bin` is on `PATH` and, when it is not,
  appends it to the shell profile that matches your login shell so `spm` runs
  from any directory. The line is marked and written once, so reinstalling never
  duplicates it. Skipped when already on `PATH`, under `--no-modify-path` or
  `SPM_NO_MODIFY_PATH=1`, and when running as root, where `$HOME` may belong to
  root rather than to the person installing.
- README section covering `PATH` setup, the profile chosen per shell, and the
  manual equivalent for source installs.
- README walkthrough for installing Web Mode as an iOS app: the Safari share
  sheet, `Add to Home Screen`, the `Open as Web App` toggle, and the resulting
  Home Screen icon, with notes on the separate cookie jar, the missing address
  bar, and restricting any non-localhost bind.

### Fixed
- The updater no longer overwrites the installed script in place. Bash reads a
  script lazily as it runs, so replacing the bytes underneath a live instance
  could make it execute garbage; automatic updates would have made that the
  common case. The new build is staged alongside the target and renamed over it,
  leaving any running process on the old inode.
- Update checks compare versions by version order rather than string equality,
  so a release such as 2.10.10 is correctly seen as newer than 2.10.9.

### Changed
- The iOS walkthrough now requires PM2 background mode at step 1 and explains
  why: the Home Screen icon only opens the server, it does not start one, so the
  foreground option dies with the terminal and leaves the icon opening a dead
  page. Also covers `pm2 save` / `pm2 startup` for surviving a reboot.

## [2.10.6] - 2026-08-23

### Added
- Web Mode now serves an app icon, a favicon, and a web app manifest, so adding
  the vault to an iOS home screen shows the login page brand mark instead of a
  screenshot of the page. The artwork is that mark reproduced from the CSS: a
  52x52 box with a 14px radius and a 1px `#5fd095` border holding the `i-brand`
  glyph, drawn at 70% of the canvas so Apple's icon mask and Android's maskable
  safe zone both leave the border intact. Regenerate with
  `tools/make-app-icon.sh`.
- Launching from the home screen opens standalone, with no browser chrome, and
  page content is inset from the status bar and home indicator.

### Fixed
- `/apple-touch-icon.png`, `/favicon.ico`, `/favicon.svg`, and
  `/manifest.webmanifest` are answered before the login gate. Unknown paths fall
  through to that gate, which replies with the login page as HTTP 200 rather
  than redirecting, so these requests were previously served HTML with a
  `text/html` content type.
- The mobile navigation drawer no longer cuts off its footer. It is
  `position: fixed`, so padding on `body` never reached it, and `height: 100vh`
  measures the largest possible viewport on iOS rather than the visible one,
  which pushed the vault chip and the logout button below the bottom of the
  screen when launched from the home screen. It now uses `100dvh` and carries
  its own safe-area insets.
- The vault path is shown again in the drawer footer. A `max-width: 620px` rule
  hid it, but the chip lives in the drawer, which is a fixed 272px panel whose
  width does not follow the viewport, so the rule left an empty box holding a
  lone status dot. The path now ellipsises instead.

## [2.10.5] - 2026-08-19

### Changed
- Web Mode now uses restrained, reduced-motion-aware effects for toast feedback,
  the mobile navigation scrim, import progress, and changed authenticator codes.
  The Console layout, palette, typography, and component structure are unchanged.
- Replaced mixed emoji and text-glyph Web Mode icons with a deterministic inline
  SVG set built on the Console 24-unit grid. Icons use square stroke terminals,
  `currentColor`, accessible control names, and no external asset requests.

### Fixed
- Web auto-lock now performs one logout navigation, stops its interval before
  leaving the page, and tears the timer down on `pagehide`, preventing the
  repeated refresh/navigation loop.
- Returning to a vault page through the back/forward cache no longer grants a
  fresh idle window. Timers are frozen while a page is cached, so the restored
  interval cannot observe the idle time that passed; the surviving deadline is
  now honoured and an expired page locks immediately on restore instead of
  resetting to a full 30 seconds.
- The `pagehide` teardown is no longer one-shot, so the timer is still stopped
  on a second navigation away after a back/forward-cache round trip.
- Cleared the existing ShellCheck warning in the regression-suite format count.
- The authenticator countdown no longer renders its raw i18n placeholder. The
  catalogue strings carry `{n}` (`Refreshes in {n}s`, `{n}秒で更新`) but the
  countdown appended the seconds instead of substituting, so every language
  showed the literal placeholder next to a stray count (`Refreshes in {n}s 4s`).

### Documentation
- Regenerated the 23 Web Mode product-tour screenshots against 2.10.5 so they
  show the inline SVG icon set rather than the replaced emoji glyphs, using a
  larger synthetic documentation vault. Screenshots now live in
  `docs/screenshots/web-v2.10.5/`.
- Rebuilt the animated product tour (`docs/product-demo.gif`) from the same
  2.10.5 captures, preserving its six-screen sequence, 960x638 size, and
  1.8-second cadence.
- Redrew the social preview card (`docs/social-preview.png`) so its brand mark
  is the shipped terminal glyph rather than the retired letterform, and its
  palette is taken from the Console tokens the product actually renders.

## [2.10.4] - 2026-08-19

### Added
- Enforced Developer Certificate of Origin sign-offs with a dedicated pull
  request check and a reusable local verifier.
- Added Linux/macOS CI matrix coverage plus syntax, CLI-help, and installer
  smoke checks in a pinned official Termux container.
- Added a public roadmap, contributor-task issue form, and curated onboarding
  path for `good first issue` work.

### Changed
- Updated GitHub Actions checkout steps to the Node.js 24-based v6 runtime.
- Replaced absolute offline/GDPR claims with precise documentation of local
  processing, user-initiated GitHub traffic, Web Mode exposure, filesystem sync,
  and project communications.
- Standardized all active support, security, and partnership contacts on the
  `sansyourways.xyz` domain.
- Defined best-effort vulnerability acknowledgment, triage, remediation, and
  coordinated-disclosure targets.

### Fixed
- Regression tests load SPM functions from a temporary file instead of process
  substitution, preventing Bash 3/BSD sed truncation on macOS.
- Regression tests use a short isolated GnuPG home and explicitly manage their
  agent, avoiding macOS runner socket failures without touching user keyrings.
- Termux dependency installation now uses `pkg` instead of incorrectly invoking
  Debian's `apt-get`; PM2 setup uses the same detected environment contract.
- CLI help is available before dependency installation and policy prompts,
  allowing users to inspect SPM safely on a fresh platform.

### Security
- Release checks now include the DCO verifier, and repository rules require its
  successful pull-request status before contributor changes can merge.

## [2.10.3] - 2026-08-19

### Changed
- Relicensed SPM as open-source software under the Apache License 2.0; releases
  before 2.10.3 retain the license shipped in their historical artifacts.
- Replaced private-source contribution restrictions with Apache-2.0 inbound
  licensing, Developer Certificate of Origin 1.1 sign-offs, and an optional
  written contributor agreement for unusually substantial contributions.
- Aligned the Code of Conduct, security policy, terms, README, issue forms, and
  pull-request guidance with open-source forks and collaboration.
- Preserved executable permissions for `spm.sh` in Git and the release archive.

### Documentation
- Fixed the README hero artwork to use a stable absolute raw-content URL so it
  renders reliably on GitHub and external Markdown viewers.
- Reframed the README around SPM's local ownership, auditable implementation,
  portability, recovery, and operational-safety benefits.
- Added a Chrome-verified visual tour covering all 23 web interface pages with
  synthetic documentation data only.
- Added a concise badge row for the latest release, stars, downloads,
  Apache-2.0 license, CI status, and repository activity.
- Added branded social-preview artwork and an animated, synthetic-data product
  demonstration derived from the verified Chrome captures.

### Added
- Apache-2.0 `NOTICE`, the DCO 1.1 text, a contributor-license policy, and a
  trademark policy separating code rights from project identity.
- Reusable disposable-vault regression tests and a GitHub Actions CI workflow
  covering syntax, ShellCheck, imports/exports, web uploads, and advanced
  local-first features.
- A tag-driven GitHub release workflow that enforces version consistency,
  rebuilds and verifies the ZIP/checksum, refuses release overwrites, and
  verifies downloaded published assets while excluding local backup files.
- A checksum-verifying release installer with version, prefix, and dry-run
  options.
- Contribution guidance, structured bug/feature/security issue forms, private
  vulnerability-report links, and a pull-request verification template.

## [2.10.2] - 2026-08-19

### Fixed
- Choosing background Web Mode with the Global bind now presents an explicit
  risk confirmation and, after acceptance, passes that decision to both PM2
  and the generated server instead of silently returning to the main menu.
- Background startup now replaces only the existing `spm-web` process, checks
  that PM2 assigned a live PID, and exposes actionable startup logs instead of
  discarding failures while claiming success.
- Global Web Mode derives its displayed LAN address locally instead of calling
  public IP-discovery services, preserving the offline/privacy contract.

### Security
- Remote HTTP exposure remains fail-closed until the user types `yes` or sets
  the documented environment override. Web startup no longer installs,
  enables, or changes host firewall rules automatically.

## [2.10.1] - 2026-08-19

### Security
- History restore authenticates and decrypts a snapshot before replacing the
  live vault, and emergency kits authenticate both manifest and ciphertext with
  HMAC-SHA-256 before decryption.
- First-time sync refuses mismatched local/remote vaults unless the user sets
  the explicit `SPM_SYNC_FORCE_INITIAL=1` override after verification.
- Vault profile paths reject control characters that could inject configuration
  rows.

### Fixed
- Sync now uses a portable channel name (`default` unless supplied), allowing
  the same encrypted vault to synchronize across different absolute paths.
  Push/pull staging and device-local base-state updates are verified and atomic.
- Automatic-backup failure no longer reports the preceding successful vault
  mutation as failed, which could cause duplicate retries.
- History listing and emergency-date parsing no longer depend on GNU-only
  `find -printf` or `date -d` behavior.
- The browser popup clears its retained master-password variable after native
  messaging dispatch.

## [2.10.0] - 2026-08-19

### Added
- Encrypted vault history with bounded retention and confirmed restoration.
- A CLI security dashboard covering weak, reused, old, incomplete, and malformed
  records; web overview now displays the same security score.
- Verified manual and opportunistic automatic encrypted backups.
- Recipient-encrypted emergency kits with an advisory activation date and a
  matching local decrypt workflow.
- A Chrome/Chromium native-messaging extension for explicit, exact-domain-bound
  autofill without persistent browser-side master-password storage.
- Encrypted attachments up to 1 MiB with digest-verified, no-overwrite extraction.
- Named vault profiles, conflict-safe filesystem synchronization, and local
  passkey metadata whose private key remains in the platform authenticator.

### Changed
- The vault schema recognizes backward-compatible `ATTACHMENT` and `PASSKEY`
  records. Older SPM versions continue to ignore these tagged lines.

## [2.9.6] - 2026-08-19

### Security
- CLI and interactive vault operations now take the same mode-`600` advisory
  file lock as web mode, preventing concurrent CLI/web lost updates when
  `flock` is available.
- CLI encryption now writes a unique mode-`600` ciphertext and atomically
  replaces the live vault only after GnuPG succeeds. Failed encryption leaves
  the current vault unchanged.
- `save` verifies the archived vault digest before wiping local data, and
  restore stages mode-`600` files before atomically replacing destinations.

### Fixed
- Markdown, Org, RST, TOML, and INI exports now preserve pipes, quotes,
  backslashes, literal escape text, and multiline secrets during import; YAML
  exports preserve real newlines.
- CLI import now fails when no records or no supported record types are found,
  instead of reporting a misleading success.
- Numeric password-generator mode now emits digits only. Missing, unknown, and
  invalid generator options fail with an actionable error.
- Portable/save commands refuse to overwrite an existing archive.
- The updater now resolves a checksum named for the ZIP it verifies (while
  retaining legacy compatibility) and rejects an extracted `spm.sh` that does
  not pass `bash -n` before installation.

## [2.9.5] - 2026-08-19

### Fixed
- Every advertised advanced import format now accepts the output produced by
  its matching exporter in both CLI and web mode. HTML, YAML/YML, XML, SQL,
  INI, TOML, TXT, PSV, RST, Markdown/Org tables, and headerless CSV no longer
  fall through to an incompatible table parser or shift fields by one column.
- YAML and INI exports now escape quoted and multiline values consistently,
  and the RST web exporter no longer raises an exception while rendering rows.

## [2.9.4] - 2026-08-19

### Security
- Authenticated web writes now require an exact same-origin `Origin` header.
  This closes cross-port localhost and same-site form CSRF paths that could add,
  edit, delete, or import vault records using an existing browser session.
- Password-view copy controls no longer interpolate usernames inside inline
  JavaScript. A crafted imported username could previously terminate the HTML
  event attribute and create a stored script-injection boundary.
- Every web response now sends `Cache-Control: no-store` plus CSP, frame,
  MIME-sniffing, referrer, and permissions-policy headers so decrypted secrets,
  TOTP codes, and exports are not retained by browser or proxy caches.
- Plain-HTTP web mode now refuses non-loopback binds by default. Remote access
  should terminate TLS at a reverse proxy bound to localhost; the explicit
  `SPM_WEB_ALLOW_INSECURE_REMOTE=1` escape hatch is reserved for isolated,
  trusted networks where transport interception is accepted.
- Portable/save bundles no longer include the RSA recovery private key by
  default. Combining that key with the recovery blob and vault in one
  unencrypted archive made possession of the archive equivalent to knowing the
  master password. `SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1` is the explicit opt-in.

### Fixed
- Web mutations are serialized across threads and server processes for the full
  decrypt-modify-encrypt transaction. Parallel requests previously reused one
  `.webtmp` path, returned empty responses, generated duplicate IDs, and silently
  discarded successful writes. Temporary ciphertext paths are now unique,
  atomically installed, and removed on every exit path.
- Web writes now preserve a mode-`600` last-known-good `.bak`, matching CLI
  writes. Import payloads consistently enforce the declared 1 MiB ceiling and
  asynchronous failures return their actual HTTP status.
- Portable/save bundle names now reject slashes, leading dashes, dot-directory
  targets, and control characters before creating or recursively removing paths.

## [2.9.3] - 2026-08-19

### Changed
- Web mode now uses the Console (CNS-18) design system: a dark operational
  transcript with square ruled surfaces, monospace typography, green actions,
  and amber vault-produced values. The overview opens with a live vault-status
  command and emitted session facts instead of a generic dashboard header.
- The four-theme picker was retired so every route follows Console's deliberate
  dark-only ground. EN/ID/JP switching, search, responsive navigation, auto-lock,
  CRUD, generator, and export/import behavior remain available.
- Web tables replace their column layout with stacked records on narrow screens;
  skip links now reach the authenticated content and unlock form directly.

### Fixed
- **`doctor`'s permission check could report a world-readable recovery private
  key as fine.** The key path it audited was `./spm_recovery_private.pem` -
  relative to the current directory, because that is where `init` generates it.
  So the check tested whichever copy happened to sit in the directory you ran
  `doctor` from, and found nothing at all when run from somewhere else. Run
  from `$HOME` on a machine whose exposed copy lived in a project folder, it
  printed a clean bill of health. This matters more than a loose vault file:
  the recovery key decrypts the vault through `forgot` *without* the master
  password, so an exposed copy is a master-password bypass rather than one more
  encrypted blob to crack.
- `doctor` now audits every copy of the key it can reasonably find - in the
  current directory, beside the vault, next to the script, and anywhere within
  four levels of `$HOME` - and matches `spm_recovery_private*.pem`, the same
  glob `.gitignore` uses, so renamed and spare keys are caught too. Results are
  de-duplicated by canonical path, so one key reached by several paths (or via
  a symlink) is reported once. The `chmod 600` hint still names only the files
  that are actually exposed.
- The cwd-relative default itself is unchanged: `init`, `portable`, `save`, and
  `forgot` all still generate and look for the key in the working directory.
  Only the audit got wider.

## [2.9.2] - 2026-08-19

### Added
- `./spm.sh doctor` now checks the on-disk permissions of the vault, its
  `.bak`, the recovery file, and the RSA recovery private key. Each should be
  `600`; anything granting group or other access is reported with its actual
  mode and a ready-to-run `chmod 600` command naming only the offending files.
  2.9.1 stopped web-mode writes from loosening the vault to `644`, but it could
  not repair vaults already written that way - this makes those findable.
  Modes like `400` are accepted; only group/other bits are flagged. The check
  reads modes through both GNU (`stat -c`) and BSD/macOS (`stat -f`) syntax.

## [2.9.1] - 2026-08-19

### Security
- **The master password was exposed to every other user on the machine.** The
  web server invoked GnuPG as `gpg --passphrase <master> ...`, putting the
  plaintext password in the process argument list, where any local user could
  read it from `ps` or `/proc/<pid>/cmdline` for the duration of every vault
  read and write. It is now passed over a pipe with `--passphrase-fd`, matching
  what the shell side already did.
- **Every web-mode write made the vault world-readable.** `encrypt_vault` wrote
  a temp file and `os.replace`d it over the vault without setting a mode; since
  `os.replace` swaps the inode, the vault silently dropped from `0600` to
  whatever the umask allowed (typically `0644`). The temp file is now chmod'd
  to `0600` before the swap, and vault backups (`*.gpg.bak`), which `cp`
  likewise created under the umask, are chmod'd too.
- **The web login had no brute-force protection.** Since 2.8.4 allowed binding
  beyond loopback, anyone who could reach the port could guess the master
  password without limit. A client is now locked out for 60 seconds after 5
  failed attempts, and failures are logged.
- Web sessions are swept on every request and capped at an absolute 12-hour
  lifetime. Previously an expired session was discarded only if that exact
  token was presented again, so an abandoned session kept its plaintext master
  password in memory for as long as the server ran.

### Fixed
- **Passwords containing a TAB were silently corrupted.** Vault records are
  TAB-delimited, and the CLI wrote user input verbatim, so a password pasted
  with a TAB was stored whole but read back truncated at the TAB - with the
  remainder bleeding into the notes column. The original was unrecoverable.
  All fields are now sanitized on write, in both the CLI and the web UI.
- **Importing an ordinary CSV could corrupt the vault.** Nothing stripped
  newlines, so a quoted multi-line field - routine in exports from other
  password managers - split one entry into two malformed records. Compounding
  it, the web importer fed `content.splitlines()` to the `csv` module, which
  strips the very newlines needed to reassemble quoted fields; it now parses
  from a `StringIO` so multi-line values arrive intact.
- The CLI importer sanitized the label, username, and notes but not the
  `secret` field, leaving the most important value exposed to the same
  splitting bug.
- **TSV import always failed.** The delimiter was written as `"\\t"`, a literal
  two-character backslash-t rather than a tab, so `csv` raised
  `TypeError: "delimiter" must be a 1-character string`. TSV *export* used a
  real tab, so a TSV export could never be imported back.

## [2.9.0] - 2026-08-19

### Changed - web interface redesign
- The web UI is rebuilt around a persistent **app shell**: a sidebar with live
  item counts, a sticky top bar, and a real navigation flow. The old design put
  every section on one long scrolling page with no way to navigate between them.
- Each vault type now has its **own page** - `/passwords`, `/notes`,
  `/passphrases`, `/authenticators`, `/backup-codes` - plus a `/transfer` page
  for export/import. `/` is now an **Overview** with per-type stat tiles and a
  recently-added list.
- **Instant search** filters the current table as you type; press `/` to jump to
  it and `Esc` to clear.
- Secrets on view pages start masked with explicit **reveal** and **copy**
  buttons, instead of being printed in the page.
- The 30-second idle auto-lock now shows a **live countdown** that turns amber in
  the last 10 seconds, rather than logging you out with no warning.
- Nine separate stylesheets were replaced by **one design system** (tokens,
  components, four themes). All four themes - Dark, AMOLED, Cyberpunk, Light -
  and all three languages are preserved; the embedded web script shrank from
  5,183 to 4,196 lines.
- The layout is now responsive: the sidebar collapses to a drawer under 900px,
  and `prefers-reduced-motion` and print styles are honoured.

### Fixed
- **Editing an authenticator always failed with a 500 and silently discarded the
  change.** `algo_in` was assigned only in the `/authenticator-add` branch but
  read in `/authenticator-edit`; because Python scopes it to the whole `do_POST`
  function, every edit raised `UnboundLocalError` before the vault was written.
- The generator's strength readout never updated. Inside `crackTime()` the local
  accumulator was named `t`, shadowing the `t()` translation helper, so calling
  `t(...)` threw `TypeError: t is not a function` on every keystroke.

### Security
- The web generator drew passwords from `Math.random()`, a non-cryptographic
  PRNG. It now uses `crypto.getRandomValues()` with rejection sampling, matching
  the CSPRNG fix applied to the CLI generator in 2.8.3.

### Added
- 39 new translation keys covering the new navigation, empty states, and login
  screen, in all three languages (181 keys each, full parity).

---

## [2.8.4] - 2026-08-19

### Fixed
- **Web login was impossible on non-loopback binds.** The session cookie was
  always sent with the `Secure` attribute, but web mode serves plain HTTP and
  has no TLS support. Browsers withhold `Secure` cookies from insecure origins,
  so anyone using the "Global (0.0.0.0)" or custom-IP bind logged in, had the
  cookie silently dropped, and was bounced straight back to the login form with
  no error. `Secure` is now set only when the request really arrives over HTTPS
  (`X-Forwarded-Proto: https`, i.e. behind a TLS reverse proxy). `HttpOnly` and
  `SameSite=Strict` are unchanged and still always applied.

---

## [2.8.3] - 2026-08-19

### Fixed
- **Authenticator codes were completely wrong.** `_spm_totp_code` piped its Python
  program in on stdin and then called `sys.stdin.read()` to get the secret, so the
  secret was always empty and every TOTP code was derived from an empty HMAC key.
  All accounts produced the same incorrect code. The secret is now read from
  `sys.argv[1]`, and codes match RFC 6238 test vectors.
- Adding an authenticator now actually rejects invalid Base32 secrets. The
  validation check could never fail before, because an empty secret always decoded
  cleanly, so malformed secrets were written to the vault.
- The web `/authenticator-code` endpoint no longer raises on a malformed stored
  secret; it returns `------` instead of failing the request.
- `doctor` no longer reports a phantom "entries with EMPTY password field" warning
  with a blank count on healthy vaults. The awk counters returned an empty string
  rather than `0` when nothing matched.
- `doctor` now prints the duplicate-ID verdict in English when running in English;
  it previously printed "tidak ada"/"ADA" in both languages.
- `update` can find its release assets again. The GitHub asset lookups used
  `grep -E '\\.zip"'`, which in ERE matches a literal backslash that release JSON
  never contains, so auto-update always reported "Could not find ZIP asset".

### Security
- Decrypted vault material is no longer left on disk when a command is interrupted.
  `Ctrl-C` previously wiped the master password and let execution continue into a
  failing re-encrypt, which exited before the temp file was wiped. Temp files are
  now tracked in a per-process registry and wiped by the exit handler, and
  `INT`/`TERM`/`HUP` abort cleanly instead of falling through.
- Generated passwords now come from a CSPRNG (`openssl rand`, falling back to
  `/dev/urandom`) instead of `$RANDOM`, a predictable 15-bit LCG. Character
  selection uses rejection sampling, so the charset is sampled uniformly rather
  than biased toward its first characters.
- The terminal no longer stays in `-echo` when a hidden password prompt is
  interrupted or hits EOF, which previously left the shell unable to display typed
  input.

---

## [2.8.2] - 2025-12-16

### Security and maintenance
- Hardened web session cookies with `Secure` and `SameSite=Strict` attributes.
- Removed unused recovery-check and record-parser variables.
- Improved portable case normalization for user input and export/import formats.

### Added
- Web-mode interactive prompt now lets you choose localhost, 0.0.0.0, or a custom bind IP after selecting temporary/background mode.

---

## [2.8.1] - 2025-12-16

### Fixed
- Web-mode firewall detection now recognizes UFW even when it lives in `/usr/sbin`, avoids false “ufw not found” messages, and no longer tries to install firewalld automatically.

---

## [2.8.0] - 2025-12-16

### Added
- Web mode now speaks Japanese: the header dropdown offers EN/ID/JP, and all dashboard panels, table headers, session copy, and the Export/Import workflow translate instantly while remembering the selection via cookies.

### Fixed
- Detail pages (view/edit screens, authenticator live view/edit, and the generator) now honor the selected EN/ID/JP language so translations persist after leaving the dashboard.

### Changed
- Version bumped to 2.8.0.

---

## [2.7.9] - 2025-12-15

### Added
- All copy buttons across password, secure note, passphrase, backup code, and authenticator views now show device-friendly toast notifications so users immediately see when clipboard actions succeed (or fail) on desktop and mobile browsers alike.
- Web mode now includes a persistent EN/ID language switcher in the header; dashboard panels, table headers, and the entire Export/Import card translate instantly and remember your preference via a cookie.
- Save bundles now include your RSA private key (when present) alongside the vault and recovery file, making off-device restores self-contained.
- Portable bundles now copy the RSA private key as well whenever it sits beside the script, so both bundle types are self-contained.
- New `./spm.sh restore` command + menu option detects when you run SPM from a portable/save folder and moves `spm_vault.gpg` (and its recovery file) back to `~/.spm_vault.gpg`.
- Restore now retargets the running session to the relocated vault so subsequent actions operate on the restored data immediately.
- Restored vaults are now always written as hidden dotfiles (`~/.spm_vault.gpg` + `.recovery`) so they match the normal layout after leaving a bundle folder.

### Security
- **Hardened Update Command:** The `update` command now verifies the SHA-256 checksum of the downloaded release asset against a signed checksum file from the release. This prevents man-in-the-middle (MitM) attacks during the update process.
- **Secure Temporary Files:** The `make_tmp` function now exclusively uses `mktemp` to create temporary files, eliminating a race condition vulnerability that could have exposed sensitive data. The script will now fail if `mktemp` is not available.
- **TOTP Secret Protection:** The `_spm_totp_code` function no longer passes the TOTP secret as a command-line argument. It is now passed via standard input to the Python script, preventing it from being exposed in the system's process list.
- **Web Mode Warning:** Added a prominent warning to the `web` command, alerting users to the security implications of running a local web server and advising them to only use it on trusted networks.

## [2.7.8] - 2025-12-13

### Added
- Export gained 5 more formats: toml, org, scsv (semicolon), csv-noheader, and jsonc. The menu prompt now also lists all available formats for clarity while keeping csv/json as the primary suggestion.

### Changed
- Version bumped to 2.7.8.

## [2.7.8-import-update] - Unreleased

### Added
- Import command (menu + CLI) supports all export formats (csv/json primary; advanced formats accepted: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc). IDs auto-renumber; entries are appended to the existing vault.
- Authenticators now support SHA1/SHA256/SHA512 selection (CLI + web), stored per entry and preserved across export/import.
- Web mode adds an Export/Import card using the same formats; export downloads directly, import accepts pasted content and appends to the vault.
- Web import supports direct file uploads (multipart) in addition to paste.
- Import form in web mode now submits asynchronously with a card-wide loading overlay and inline success/error message (no redirect or forced logout).
- Removed the legacy `cgi` dependency in the web server; multipart uploads now use a boundary-aware email parser (no Python 3.13 warnings).
- Authenticator live view in web mode now includes a clipboard button for the current OTP code.
### Fixed
- Replaced deprecated `cgi` usage in the web server with `email.parser`-based multipart parsing to avoid deprecation issues on Python 3.13.
- Web import file uploads now use the correct multipart key, preventing hangs/timeouts on upload.
- Multipart import now short-circuits on >5MB payloads and falls back gracefully when parsing fails.
- Fixed missing `cgi` import in the web server so multipart upload parsing works consistently.
- Fixed missing `warnings` import in the web server, restoring multipart parsing path.
- Boundary-aware multipart parsing now defaults to email parser only (removed FieldStorage dependency to reduce upload failures).
- SQL export now escapes quotes correctly; import command is fully wired into CLI dispatch.
- Web export/import script no longer fails on SQL format generation (fixed quoting in generated Python).
- RST export in web server generation now uses proper quoting (no more syntax error in generated Python).
- Multipart import handler now prefers `cgi.FieldStorage` with warnings silenced and falls back to a lightweight parser, preventing hangs during uploads.
- Import endpoint now reuses the already-read request body instead of trying to read the stream twice, so uploads no longer stall on “load failed”.
- Fixed duplicate web import submissions triggered by both inline and scripted handlers, eliminating the phantom second upload that caused “load failed” UI states.
- Import now validates that the uploaded file contains at least one record and surfaces a clear error instead of silently doing nothing.
- Web import success now triggers an automatic page reload so newly imported entries are visible right away.
- Success responses now include per-type counts (passwords, notes, passphrases, backups, authenticators) so the UI and logs confirm what was imported.
- Fixed the importer writing literal `\t`/`\n` sequences, so appended rows now use real tabs/newlines and show up in CLI + web lists immediately.

### Note
- Version intentionally left at 2.7.8 per policy; not a full release yet.

## [2.7.7] - 2025-12-13

### Added
- Export supports 8 more formats (yaml/yml, xml, sql, ini, psv, rst, plus jsonl alias) while prompts still show csv/json for simplicity.

### Changed
- Version bumped to 2.7.7.

## [2.7.6] - 2025-12-13

### Added
- Export now supports 5 additional formats: tsv, ndjson, markdown, html, and txt alongside csv/json. Interactive menu prompt updated.

### Changed
- Version bumped to 2.7.6.

## [2.7.5] - 2025-12-13

### Added
- Export command (`./spm.sh export <csv|json> [file]`) to dump all data types (passwords, notes, passphrases, authenticators, backup codes) to CSV or JSON; interactive menu includes Export.

### Changed
- Version bumped to 2.7.5. Export now auto-appends the correct extension when you provide a name without `.csv` or `.json`.

## [2.7.0] - 2025-12-13

### Added
- Web themes (Dark, AMOLED, Cyberpunk, Light) with a header picker; header now shows current version and auto-checks GitHub for updates on load.

### Changed
- Dashboard “Update” control now pairs with the version display and update check popup when a newer release is detected.

---

## [2.7.1] - 2025-12-13

### Changed
- Refined themes: AMOLED (solid/elegant black), Cyberpunk (neon palette), and Light (clean bright panels/cards). Theme variables now apply across the whole UI.
- Removed periodic auto-reload; rely on 30s idle auto-lock instead to avoid refresh churn.

---

## [2.7.2] - 2025-12-13

### Changed
- Tables and lists now use theme-aware backgrounds, borders, and text for better readability; Light theme tables/cards/panels adopt softer whites/grays instead of dark backgrounds.

---

## [2.7.3] - 2025-12-13

### Changed
- Light theme text and tables refined for readability; table wrappers now follow theme borders/background, and card headings/text use theme colors.
- Primary buttons softened (lighter shadow) to better match pastel tones.

---

## [2.7.4] - 2025-12-13

### Changed
- Primary/add buttons now use a pastel blue gradient with themed borders across password, passphrase, generator, TOTP, and backup sections, improving the light theme look.

---

## [2.7.4] - 2025-12-13

### Changed
- Primary/add buttons (password, passphrase, generator, TOTP, backup codes) now use a pastel blue gradient with themed borders to better fit the light palette.

## [2.6.1] - 2025-12-13

### Changed
- Easy password generator now produces human-memorable word-based passwords; secure mode remains random.
- Generator toggles cover uppercase, lowercase, numbers, and symbols for both CLI and web.

---

## [2.6.0] - 2025-12-13

### Added
- Password generator in CLI and web with mode toggles (secure/easy/numeric), optional symbols, length slider, and strength/crack-time estimate.

### Changed
- Main menu and web dashboard now link to the password generator; autofill bookmarklet remains removed.

---

## [2.5.7] - 2025-12-13

### Changed
- Removed the web autofill bookmarklet feature and related buttons/endpoints; copy helpers remain.

---

## [2.5.6] - 2025-12-13

### Fixed
- Session cookies now set both Lax and cross-site variants (SameSite=None; Secure) so bookmarklets can send credentials when accessed over HTTPS.

---

## [2.5.5] - 2025-12-13

### Changed
- Bookmarklet now targets broader username/email selectors (mail/email/account/identifier) and falls back to the first text field to improve autofill success.

---

## [2.5.4] - 2025-12-13

### Fixed
- Avoided shadowing the JSON module when serving autofill/authenticator JSON responses to resolve bookmarklet errors.

---

## [2.5.3] - 2025-12-13

### Fixed
- Added CORS headers and OPTIONS handling for JSON endpoints (autofill, authenticator codes) so bookmarklets work across sites when allowed by the browser.

---

## [2.5.2] - 2025-12-13

### Fixed
- Clipboard copy buttons now include fallback copying for browsers without `navigator.clipboard`, making bookmarklet and secret copies reliable.

---

## [2.5.1] - 2025-12-13

### Added
- Web autofill helper bookmarklet for password entries plus copy buttons on password, notes, passphrase, and backup views.

### Changed
- Web password view can copy username/password/notes and expose bookmarklet for quick form fill; backup/passphrase/note views now have copy helpers.

---

## [2.5.2] - 2025-12-13

### Fixed
- Clipboard copy buttons now include fallback copying for browsers without `navigator.clipboard`, making bookmarklet and secret copies reliable.

---

## [2.5.3] - 2025-12-13

### Fixed
- Added CORS headers and OPTIONS handling for JSON endpoints (autofill, authenticator codes) so bookmarklets work across sites when allowed by the browser.

---

## [2.5.4] - 2025-12-13

### Fixed
- Avoided shadowing the JSON module when serving autofill/authenticator JSON responses to resolve bookmarklet errors.

---

## [2.5.5] - 2025-12-13

### Changed
- Bookmarklet now targets broader username/email selectors (mail/email/account/identifier) and falls back to the first text field to improve autofill success.

---

## [2.5.6] - 2025-12-13

### Fixed
- Session cookies now set both Lax and cross-site variants (SameSite=None; Secure) so bookmarklets can send credentials when accessed over HTTPS.

---

## [2.5.7] - 2025-12-13

### Changed
- Removed the web autofill bookmarklet feature and related buttons/endpoints; copy helpers remain.

---

## [2.6.0] - 2025-12-13

### Added
- Password generator in CLI and web with mode toggles (secure/easy/numeric), optional symbols, length slider, and strength/crack-time estimate.

### Changed
- Main menu and web dashboard now link to the password generator; autofill bookmarklet remains removed.

---

## [2.6.1] - 2025-12-13

### Changed
- “Easy” generator now creates human-memorable word-based passwords; secure mode keeps full random.
- Generator toggles now cover uppercase, lowercase, numbers, and symbols for both CLI and web, with word-count mapping on easy mode.

---

## [2.5.0] - 2025-12-13

### Added
- Authenticator (TOTP) vault entries with configurable refresh interval, CLI CRUD, and live code display in web mode.

### Changed
- Main menu and doctor report now include authenticators; web dashboard adds a dedicated authenticator card.
- CLI authenticator view now streams live TOTP codes with a countdown.

---

## [2.4.1] - 2025-12-13

### Fixed
- Web dashboard now hides passphrases and backup codes from the password entries list, keeping each item type in its proper section.

---

## [2.4.0] - 2025-12-13

### Added
- **Passphrase Vault**
  - New CLI and menu flow for storing passphrases (`passphrase-add/list/view/delete`) with base64 storage in the encrypted vault.
  - Viewing a passphrase forces a master password prompt for re-verification.
- **Auto Updater**
  - `./spm.sh update` now downloads the latest GitHub ZIP release, extracts `spm.sh`, and installs it to `/usr/local/bin/spm` (uses `sudo` when available).
- **Web Mode: Passphrases & Backup Codes**
  - Web dashboard now lists passphrases and backup codes with add/edit/view/delete flows and base64 decoding for display.
  - Footer copyright + version and a right-aligned “Update” (refresh) action added.
  - Automatic page refresh every 5 seconds to avoid stale cached views.

### Changed
- Interactive menu now includes a dedicated Passphrases section and renumbered items.
- Doctor now reports counts for passwords, notes, passphrases, and backup codes.
- Help and editor format hints updated with the new `PASSPHRASE` row type.

### Fixed
- Master password re-verification now properly loads the cached master password before comparisons.
- Web mode now receives the running version via env (`SPM_VERSION`) to avoid undefined version display.

---

## [2.3.0] - 2025-12-12

### Added
- **Backup Codes Management**
  - New dedicated section in interactive menu (`13) Backup codes`).
  - CLI commands for full CRUD operations:
    - `./spm.sh backup-codes-add`: Add new backup codes with a user-defined label.
    - `./spm.sh backup-codes-list`: List all stored backup code entries.
    - `./spm.sh backup-codes-view <id>`: View the content of a specific backup code entry.
    - `./spm.sh backup-codes-delete <id>`: Delete a backup code entry.
  - Backup codes are stored securely within the encrypted vault, similar to secure notes.

### Security
- **Master Password Re-verification for Backup Codes View**
  - When attempting to view backup codes (via `backup-codes-view` command or interactive menu), the user is now prompted to re-enter their master password for an additional layer of security.

### Changed
- **Interactive Menu & Help Updates**
  - Main interactive menu options re-numbered to accommodate the new "Backup codes" feature.
  - `cmd_help` output updated to document new backup code commands.
  - `cmd_edit` vault format instructions updated to include `BACKUP_CODE` entry format.

## 2.2.1 – 2025-12-08

### Fixed
- Restored and updated `cmd_help` to match all current features (web mode, secure notes, doctor, clipboard coaching, etc.).

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

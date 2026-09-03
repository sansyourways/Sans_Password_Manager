# Sans Password Manager Roadmap

This roadmap communicates direction rather than fixed delivery dates. Security,
data integrity, portability, and backward compatibility take priority over
feature volume. Proposals should begin with an issue and use synthetic data.

The architectural direction below comes from the system-design review in
[`docs/system-design.html`](docs/system-design.html). Its thesis: keep secrets
and cryptography in the smallest auditable component, and make the CLI, the SPM
Dashboard, sync and the browser extension clients of that core rather than
co-owners of it. That review is a design concept, not a formal security audit.

## Now — reliability and contributor foundations

- **Cross-platform coverage — shipped in 3.4.0.** Version ordering used
  `sort -V`, a GNU extension BSD sort does not have, so on macOS the comparison
  failed and a lexical fallback ordered 2.10.10 before 2.10.9 — in the function
  the auto-updater uses to decide whether a newer release exists. Replaced with
  a POSIX awk comparison, and a guard now fails the build on `sort -V`,
  `date -d`, `base64 -w`, `grep -P`, `sed -i` or `mktemp -p` reaching shipped
  code without a BSD fallback beside it.
- **A portable vault lock — shipped in 3.4.1.** The lock was `flock(1)`, which
  macOS does not ship, so the CLI took no lock there while the dashboard did:
  one side believed it was protected. The CLI now takes the same lock through
  python3's `fcntl` where `flock` is absent — the primitive the dashboard
  already used, so the two genuinely exclude each other. `mkdir` was the
  obvious answer and the wrong one: it would have needed stale-lock detection,
  and an advisory lock the kernel drops when its holder dies needs none.
- ~~Fault injection around restore failures, interrupted writes and concurrent
  mutations — disk-full, process killed mid-write, corrupted vault, competing
  writers.~~ **Shipped in 3.4.0** for the write path and the lock, and
  completed in **4.0.1** for restore and import.

  What the restore half found was worse than the coverage gap that prompted
  it. `spm restore` was the one write in SPM that could not be undone: it
  copied whatever the bundle held over the live vault with no archive, no
  `.bak` and no check that the bundle even opened, so restoring a truncated
  copy destroyed a working vault and reported success. It also held the
  *bundle's* advisory lock while overwriting the destination, and consumed the
  bundle before the recovery file was installed.

  `restore`, `history-restore` and `sync pull` now share one install path in
  the trusted core — archive, `.bak`, optional digest check, fsync, atomic
  rename, fsync the directory — where each previously carried its own
  `cp`/`chmod`/`mv` and none of them fsynced.

  The import half was smaller and the same shape: a web import cleared the
  reviewed rows before writing the vault, so a failed write cost the user the
  whole upload for a failure that had nothing to do with the confirmation
  token. Consumption moved after the write; replay, guessing and expiry are
  refused exactly as before.
- **Dashboard accessibility — shipped in 3.6.0.** Fifty-two issues across the
  eleven pages, found through the browser's real accessibility tree rather than
  by reading source: 22 inputs whose labels were attached to nothing, 19
  unnamed controls, no navigation landmark anywhere, a table with no header
  cells. The focus ring was the worst of them — present in the DOM at 1.15:1
  against the field it surrounded, where WCAG 1.4.11 asks 3.0:1. Now 9.7:1,
  with the suite failing if it drops again.
- ~~Keep import/export fixtures synchronized across every documented format.~~
  **Shipped in 4.1.0.** The Bitwarden readers added in 3.4.3 still have
  fixtures but no round trip, because SPM does not export to Bitwarden and
  never will.

  The item read as nearly done: twenty formats already round-tripped against
  their own exports. What they round-tripped was the record *count*. Compared
  field by field, all twenty lost the folder and the custom fields, because the
  CLI export never wrote those columns and its import never read them -- while
  the dashboard did both. Two surfaces, two answers about the same file.

  `spm export sql` was worse: the column list named eight columns while each
  row wrote nine, so sqlite refused every statement it produced. SPM's own
  reader parses the tuple positionally and ignores the column list, so the
  round trip passed -- SPM read back exactly what SPM wrote, and only SPM
  could. The suite now loads that export with a real SQL parser.

  Five places each kept their own copy of the column order and each stopped
  somewhere different. There is now one ordered definition in the core, and the
  exported header is asserted against it.

## Shipped integrations

- **Universal browser-extension popup picker — shipped in 3.1.0.** Chrome,
  Chromium, Edge, Brave, Opera, Vivaldi, and Firefox desktop share one source
  tree. The secret-free account-list protocol, memory-only native-host session,
  and exact-host selection are delivered.

- **Guided extension setup — shipped in 3.2.0.** 3.1.0's installation was a
  loop: load the extension unpacked, read the ID the browser generated from the
  install directory, paste it into a second command, restart. The ID differed
  per machine, so it could not be documented. A public development key now
  gives every unpacked copy one stable identity, `extension-id.sh` derives it
  from the manifest key the way the browser does so the two cannot drift, and
  `setup.sh` performs the build, registration, and browser hand-off in one
  command. Existing installs must remove the previously loaded extension, since
  its ID changes.

- **A stable extension boundary — shipped in 3.7.0.** The native-messaging
  host checked what came in and forwarded whatever the CLI printed on the way
  out, which meant the extension's view of the vault was not a contract but
  whatever `bridge-get` happened to emit that release. Responses are now
  projected onto the fields each action declares, and errors come from a fixed
  set rather than being echoed — an unexpected message like
  `gpg: /home/you/.spm_vault.gpg: decryption failed` carried a filesystem path
  across a boundary whose purpose is that nothing crosses unnamed.

  What the boundary does not do is written down rather than implicit: the
  original one-shot extension sends the master password with every request and
  holds no session, so Lock and both timeouts do not constrain it.

- **Bitwarden vault imports — shipped in 3.4.3.** All three of its export files
  are read: JSON, CSV, and password-protected JSON. Before this a Bitwarden CSV
  imported as one empty note and silently dropped every login while the
  dashboard reported success. Argon2id-protected exports are refused by name,
  the same wall described below for SPM's own vaults.

  The in-field picker and optional WebAuthn unlock remain phased in
  [`docs/BROWSER-EXTENSION-ROADMAP.md`](docs/BROWSER-EXTENSION-ROADMAP.md).
  Both need a browser's extension UI driven for real to be worth trusting,
  which is the gap that decides when they ship rather than the code.

## Next — safer integrations

- Continue the browser-extension work with an origin-isolated in-field picker.
  Not shipped, and not for want of effort — see *What is left, and what decides
  when* below. **4.4.0 removed the blocker that section named** -- the
  extension now runs under headless Chromium in the regression suite, the
  verification route this item was waiting on -- and **4.4.1 extended it to
  the fill**, which is the part an in-field picker actually performs.
- ~~Design pluggable, encrypted synchronization transports without introducing a
  maintainer-operated cloud service.~~ **Shipped in 3.15.0.** A transport
  answers three questions -- can I reach this target, put the remote object in
  this file, make this file the remote object -- and nothing else. Conflict
  detection, digest verification, archiving before replacement and the refusal
  to install a remote that will not decrypt all live above it, so a transport
  added later cannot skip a safety check: it is never asked to perform one.
  `dir`, `rsync` and `rclone` ship, none of them operated by this project.

  Digests are measured locally over a fetched copy, because a remote-side
  digest is a claim rather than a measurement. The genuinely new hazard was
  that over a network "the remote file is not there" can also mean nothing was
  reachable -- which is exactly the state in which pushing over someone else's
  newer vault feels safe -- so every transport must prove it can reach the
  target before any decision is taken.
- **Machine-readable doctor output — shipped in 3.4.0**, corrected in 3.4.2.
  `spm doctor --json` emits the same checks as a document with stable ids and
  an exit status that follows the verdict. It shipped emitting a banner and a
  password prompt on stdout, because the tests called the function after
  sourcing the library and never ran the command.
- **Reproducible release provenance and artifact attestations — shipped in
  3.9.0.** Every release archive carries a signed statement, in Sigstore's
  public transparency log, that it came from this repository's release
  workflow, and the installer checks it. Before this the installer compared an
  archive against a checksum fetched from the same host, which proves the
  transfer was intact and nothing about its origin.

  The archive is also reproducible now — sorted entry order, timestamps from
  the commit rather than the clock, machine-specific fields stripped — so the
  published checksum is one a third party can arrive at independently instead
  of one they have to accept.

  Hardware-backed signing, listed under *Later*, is a separate question and
  still open: this ties a release to a workflow in a repository, not to a key
  a person holds.

## Later — ecosystem growth

- **Package-manager distribution for Homebrew and Termux — shipped in
  3.12.0.** Each release carries a reproducible Termux `.deb` and a Homebrew
  formula, both installable today.

  The formula is generated per release rather than checked in: it pins the
  sha256 of one archive, so a committed one is either stale or wrong, and a
  wrong checksum fails for every user at once.

  What the evaluation concluded, and the part worth stating: neither is
  published to a package index. Homebrew core has notability requirements a
  single-maintainer project does not meet, and Termux's repository has its own
  submission process. Both are decisions to take deliberately rather than side
  effects of a build.

  It also found that `spm --version` did not exist — the flag fell through to
  the interactive banner, so a packager asking which version this is got a menu
  and a wait. Added in the same release.
- **Explored in 4.3.0: hardware-backed signing for release provenance.**
  Hardware-backed protection of the vault itself is covered under Architecture
  below and is unaffected by this.

  The conclusion is that hardware *in* the release is not reachable on this
  project's terms, and that the exploration found something more useful than
  the thing it went looking for.

  **Hardware in CI: no.** The artifact is built by the release workflow from
  the tag, and a GitHub-hosted runner exposes no TPM and no smartcard. A
  self-hosted runner with a token plugged into it would work and would mean a
  maintainer-operated machine in the release path, which is the shape this
  project avoids everywhere else.

  **Building locally and uploading: no.** It would put the published bytes
  outside the workflow the attestation describes, trading a stronger claim
  about *who* for a weaker one about *what*.

  **What is reachable, and why it is not urgent.** Because 3.9.0 made the
  archive reproducible, a maintainer holding a token can rebuild the published
  archive byte for byte and sign *that*, after the fact, without the build
  moving anywhere. Signing the tag with a hardware-held key is reachable today
  too. Neither needs anything from this repository to change; both need a key
  a person holds, which is the part that is not code.

  **What the exploration actually found.** The installer verified attestations
  with `--repo` alone, which asserts only that *some* workflow in this
  repository attested those bytes. Only `release.yml` holds
  `attestations: write`, so nothing was exploitable -- but that is a one-line
  change away from being untrue, and a check should not rest on a permission
  staying where it is. The installer now pins the signing workflow where the
  GitHub CLI supports it, and says which of the two checks it performed when
  it cannot. Tightening what the existing signature proves was worth more than
  adding a second one.
- ~~Add optional localization contributions beyond English, Indonesian, and
  Japanese.~~ Delivered in 3.13.0, though not the way the item was written.
  The obstacle was never that translations were missing: it was that
  contributing one meant hand-editing a JavaScript object literal inside a
  Python string inside a generated shell script, and getting two levels of
  escaping right. The regression suite carried a test whose only job was to
  catch that escaping going wrong, which said plainly enough where the problem
  was. Catalogues now live in `locales/<code>.json`, a generator folds them in,
  and `tools/i18n-lint.py` is the check a contributor runs. Nine languages
  followed, each marked unreviewed in the picker and in the docs, because none
  has been read by a speaker and several strings warn about actions nothing can
  undo.

  Arabic forced the part that was actual engineering: right-to-left. Physical
  margins, paddings and borders became logical properties, positioned
  decorations became insets, and the fixed-width type the Console theme is
  built on is dropped for cursive scripts. Two defects survived every
  assertion and were found only by screenshotting the running app -- the
  unreviewed notice rendered on maintained languages because a styled class
  outranks `[hidden]`, and the search icon sat on top of its own placeholder
  because a four-value `padding` shorthand does not mirror. Both now have
  guards; neither would have been caught by reading the diff.

## Architecture — shrinking the trusted core

Sequenced ahead of new features, because each is progressively harder to
retrofit as more surface comes to depend on the current shape. Every item here
changes how a vault is protected, so each needs a migration path that leaves
existing vaults readable.

The foundation is now delivered, and the sequencing turned out to be the point:
the vault-key change needed the format version to migrate through, and both
needed the core extracted before the crypto backend could be touched at all.
What remains is listed below in the order that dependency imposes.

### Foundation — make the core auditable — **shipped in 3.0.0**

All three items are implemented and released. 3.0.0 is a major version because
the vault format changed and a vault it writes cannot be opened by 2.13.0 or
earlier — not because the feature list is long; it carries this section and
nothing else, so that backing out a format migration would not also back out
unrelated work. One clause of the second item is carried forward, and is stated
as such below rather than quietly dropped.

- **Version the vault format and state the KDF policy explicitly.** *(#36)*
  Vaults carry a `META_VAULT_VERSION` row written on every write, and a vault
  without one is recognised as format 1 and upgraded in place, so there is no
  flag day. Key derivation is pinned rather than inherited: both writers pass
  `--s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712`, which stops a
  user's `gpg.conf` from changing a security parameter underneath the
  application. Measured rather than assumed — GnuPG already defaults to mode 3
  at the maximum count, so the concrete change is the digest, which defaults to
  **SHA1**.

  **Argon2id was not adopted, and is not reachable on any platform SPM
  supports.** Two separate walls, and the second was found only after the
  first was blamed for everything. GnuPG cannot express it: OpenPGP
  string-to-key is hash-iteration by construction, `gpg --symmetric` offers
  only `--s2k-mode`, `--s2k-digest-algo`, `--s2k-cipher-algo` and
  `--s2k-count`, and GnuPG's own Argon2id support covers its private keys from
  2.4 onward, never symmetric messages. But replacing gpg does not deliver it
  either — Argon2 arrived in **OpenSSL 3.2**, and the platforms SPM targets are
  behind it: OpenSSL 3.0 on current Debian and Ubuntu, LibreSSL with no
  `openssl kdf` at all on macOS. Python's `hashlib` offers scrypt and PBKDF2
  and no Argon2. Every remaining route is a third-party dependency, which is
  the portability rule SPM is built on.

  So the honest statement is that the clause names a primitive the ecosystem
  does not yet hand us on the terms this project accepts. The reachable
  memory-hard KDF is **scrypt**, and it arrived in **4.0.0** with the
  data-layer replacement below. What that release also added is the part that
  makes the rest cheap: the vault records its KDF **by name and parameters**,
  and the unwrap uses the vault's numbers rather than the running build's. So
  Argon2id is no longer a format change waiting on a platform floor -- it is a
  value the reader dispatches on, once a floor makes it testable rather than
  merely writable.

- **Wrap a vault key rather than the master password.** *(#37)* Format 3 seals
  the vault under a random 256-bit vault key and seals only that key under the
  master password, both in one file — so nothing that copies, backs up, syncs
  or bundles a vault had to change. A password change now rewraps a few hundred
  bytes instead of re-encrypting the whole vault, and the recovery file holds a
  key that no password change invalidates, rather than a second copy of the
  password itself.

- **Split the trusted core out of the single script.** *(#38, #39)* Everything
  that touches the vault's bytes lives in `src/spm_core.py`: key wrapping,
  read, write, rewrap, format stamping, recovery, history. The CLI runs it as a
  subprocess with secrets on stdin, the SPM Dashboard imports it, and the
  browser bridge reaches it through the same wrappers — three clients of one
  core, none of them a co-owner. The regression suite asserts the arrangement
  structurally: it parses the dashboard's AST and fails any of those functions
  that grows a body of its own instead of delegating.

  `spm.sh` is now generated by `./build.sh` from `src/`, byte-identically, and
  CI fails a change where the two disagree. SPM still ships as one file; it is
  no longer written as one.

### Foundation — the work this unblocks — **complete as of 4.0.0**

Both items below have shipped. The sequencing held: the vault-key change
needed the format version to migrate through, both needed the core extracted
before the crypto backend could be touched, and the backend replacement was a
single-file change by the time it was reached.


- ~~**Replace the gpg data layer.**~~ **Shipped in 4.0.0.** A vault is sealed
  with AES-256-CTR and authenticated with HMAC-SHA256; the master password is
  stretched with scrypt at n=32768, r=8, p=1 and the vault key is not stretched
  at all, because it never had anything to stretch. Measured on a 200-record
  vault, a cold read went from **663 ms to 168 ms** and a read with the vault
  key already held from **248 ms to 11 ms**.

  Three things are worth recording beyond the numbers. The vault names its KDF
  and its parameters, which is what turns Argon2id from another format change
  into a value the reader dispatches on. The data is authenticated for the
  first time, so a damaged vault and a wrong master password stopped being the
  same refusal -- they have opposite remedies and now read differently. And
  the vault key does not change during the upgrade, which is what let a format
  change ship without touching recovery files, Shamir share sets, or any .bak
  written before it.

  What decided the shape was openssl's command line, not the design. Keys go
  in on a file descriptor because `-K` puts them in argv; they go in as base64
  because a passphrase is read as a line and a raw key holding an 0x0A byte
  would be truncated in silence, sealing the vault under a fraction of itself
  with nothing reporting anything. And `openssl enc` carries no AEAD tag, so
  encrypt-then-MAC is written out here rather than delegated.

  Argon2id remains out of reach on the terms below, unchanged: what shipped is
  the reachable memory-hard KDF, plus the header field that makes adopting the
  other one cheap.

  The original measurement that motivated this, kept for the record. On a
  format-3 vault a read cost **452 ms**, of which 280 ms is the key unwrap
  and 172 ms the data layer — two gpg invocations, and gpg's symmetric path
  carries a fixed cost that payload size barely moves. Against that,
  `openssl aes-256-ctr` with an HMAC-SHA256 tag costs **~30 ms**, and
  `hashlib.scrypt` costs **69 ms at n=2^14** (16 MiB) or **183 ms at n=2^15**
  (32 MiB).

  The gain is therefore about **2× on a cold read and ~15× once a derived key
  is held**, because the KDF runs on the key envelope only — the data layer is
  keyed by a random 256-bit value that needs no stretching, which is precisely
  what format 3 established and gpg squanders by stretching both layers.

  Three constraints the implementation does not get to choose. Keys must reach
  openssl on a file descriptor: `openssl enc -K` places the key in `argv`, and
  while OpenSSL 3 scrubs it moments after startup there is a race, and
  LibreSSL is not known to scrub at all. Authentication must be explicit and
  encrypt-then-MAC, since `openssl enc` has no AEAD mode that carries a tag.
  And `hashlib.scrypt` must be given an explicit `maxmem`, or it refuses
  anything past its default with `memory limit exceeded`.

  The vault must record the KDF it used, by name and parameters. That is what
  turns Argon2id from another format change into a value the reader already
  knows how to dispatch on. It must also keep reading format-3 vaults, which is
  what the version row exists for.

  All three constraints held. Keys reach openssl on a descriptor, the MAC is
  explicit and encrypt-then-MAC, `hashlib.scrypt` is given an explicit
  `maxmem`, and gpg-sealed vaults still open.
- **Cache the dashboard session key — shipped in 3.4.0.** Two gpg invocations
  per request became one, counted through a shim in front of the real binary:
  10 calls for 5 page loads before, 5 after. The key lives in the session
  record and dies with it, which is deliberately not a process-wide cache — one
  would survive logout, and a test now fails the build if one appears.

### User power — daily capability

- **Per-record password history — shipped in 3.5.0.** A rotated credential
  keeps its predecessors, so the common accident is recoverable without
  restoring a whole vault generation and taking every other record with it.
  Recorded at the write boundary rather than at the twenty-one CLI and nineteen
  dashboard edit paths, so a new one cannot forget. History never reaches an
  export and is never counted as a password.
- **Duplicate and breach review — shipped in 3.12.1.**
  Duplicate grouping remains completely local. The breach check is explicit
  opt-in and uses Pwned Passwords' k-anonymous range API: SHA-1 is computed on
  the device and only five prefix characters leave it, with padded responses
  requested. Passwords and full hashes are never sent, printed, logged or
  persisted; a failed request reports unavailable rather than a false clean
  result. CLI and Dashboard now consume one trusted-core report.
- **Folders and custom fields — shipped in 3.11.0.** A password record carries
  a folder and any number of named fields, on the Add and Edit forms, masked on
  the view page like the password itself, and travelling through export and
  import as readable columns.

  Format 4 appends one optional column; a record using neither is written
  exactly as format 3 wrote it. The release also adds the guard that had to
  come with it: SPM now refuses to *write* a vault stamped newer than it
  understands. Without that an older build would open a format-4 vault, keep
  only the columns it knew, and write it back stamped as format 3 -- readable
  afterwards, which is what would have made it dangerous.
- **Import preview — shipped in 3.8.0.** A web-mode upload is parsed and shown
  before anything is written: every record the file would add, with its type,
  service, username and a masked secret, plus a named list of rows SPM has no
  record type for. The vault is untouched until the review is confirmed, the
  confirmation is single-use so a refresh cannot import twice, and the parsed
  rows stay on the server rather than being round-tripped through the browser,
  which would hand a decrypted password-protected export back to the page that
  uploaded it.

  3.4.3 had made this sharper rather than answering it: a Bitwarden export
  imported correctly but went straight in, and the failure it replaced — a CSV
  that produced one empty note and dropped every login while reporting success
  — is exactly the kind the review now shows first. Correcting an export
  before importing it is still done in the file; the review says what will
  happen, not which rows to keep.

### What is left, and what decides when

Two items on this board are written but not shipped, and in both cases the
blocker is verification rather than code.

- **The in-field picker** needed a browser's extension UI driven for real.
  **4.4.0 built the harness that does it and 4.4.1 finished the half that can
  be built**, so this is no longer waiting on a way to run it -- only on being
  written. What the harness proves today: the packed extension loads and its
  service worker starts under headless Chromium, the identity the browser
  assigns is the identity `extension-id.sh` derives, one fill-path rule holds,
  nothing reaches the popup that should not, and the fill itself writes to the
  right fields, skips the wrong ones, and reaches a framework that owns the
  property. That last one found a shipped defect: the compatibility
  extension's copy of the fill had drifted to a plain `element.value`
  assignment, which such a framework ignores.

  What the harness does not reach is the native-messaging round trip through a
  live popup, and that is now a recorded boundary rather than pending work.
  `chrome.action.openPopup()` opens the popup headlessly, but the popup cannot
  obtain `activeTab`: Chromium grants it on a genuine user gesture on the
  toolbar action, and a synthesised call is not one. The hostname
  verification keeps its CLI-level coverage, which tests the decision rather
  than the plumbing.
- **Hardware-backed key wrapping** needs a FIDO2 key or a TPM to test against.
  Unchanged, and 4.3.0's exploration of hardware-backed *signing* did not move
  it: neither has a known answer to pin or a second implementation in CI to
  disagree with.

That distinction is worth stating because of what the 3.2.0–3.7.0 run showed.
Five defects reached a release and were then found only when something was
rendered or executed rather than unit-tested: a language picker whose whole
dictionary failed to parse, `doctor --json` emitting a banner before its
document, the Bitwarden formats attached to the export form instead of the
import one, a focus ring at 1.15:1, and an error path that stringified a
filesystem path instead of refusing it. Each passed a test that exercised the
function underneath it.

Crypto and extension UI are the two worst places to accept that gap, so these
two wait for a way to run them rather than for someone to write them.

4.0.0 is the counter-example that shows what "a way to run them" means, and it
is why replacing the whole data layer shipped while hardware-backed wrapping
did not. A round trip proves nothing about a cipher: a build whose openssl
derived a different key would encrypt and decrypt perfectly against itself and
produce vaults no other machine could open. What made it shippable was that the
derivation is reproducible outside the tool performing it -- fixed key, salt,
IV and plaintext against fixed ciphertext, and openssl's `-pbkdf2 -iter 1`
asserted byte-for-byte against `hashlib.pbkdf2_hmac` -- plus a macOS runner
whose LibreSSL is a genuinely different implementation to disagree with.

A FIDO2 key or a TPM offers no equivalent. There is no known answer to pin and
no second implementation in CI to disagree, so the item stays where it is.

3.8.0 is the first item on this board built the other way round, and the
result argues for the rule. Its review page passed the suite — ten mutants
across the token, the expiry, the classification and the masking were all
killed — and was then opened in a browser, where four defects were visible
immediately: "1 passwords · 1 notes", "1 row(s)", a five-column table header
over no rows in the empty state, and the secret column headed "Password" for
note bodies and backup codes. None of them could have failed a test of the
function underneath; all four were fixed before the release rather than after
it. The tally above stays at five because rendering happened first this time,
which is the whole point.

### Trust expansion — hardware and recovery

- Hardware-backed key wrapping via FIDO2, TPM or a platform secure enclave.
  Distinct from the biometric unlock shipped in 2.11.0, which resumes a
  suspended dashboard session and never holds the vault key.
- ~~Split recovery — Shamir-style shares — so recovery does not depend on one
  file and one private key remaining simultaneously available and secret.~~
  **Shipped in 3.14.0.** `spm shares split` mints a t-of-n set over GF(2**8);
  any `t` reconstruct the vault key and any `t - 1` reveal nothing.

  Three decisions carry it. What is split is the *vault key*, not the RSA
  private key, because the vault key is stable — `rewrap` changes only the
  envelope around it — so shares written on paper keep working after any
  number of master-password changes. Every share carries a checksum over its
  own text, because Shamir has no integrity of its own and three shares with
  one character wrong reconstruct a different key silently. And the share
  format carries no digest of the secret: reconstruction is proved by opening
  the vault, since a digest would be the one thing an attacker holding `t - 1`
  shares could attack offline.

  Minting is CLI-only. At threshold the shares are the vault, and rendering
  them through a browser would put them in a page, a scrollback and possibly a
  proxy log on the way to the person meant to write them down.
- **A security-event log — shipped in 3.10.0.** Unlocks, writes and
  master-password changes are recorded so a user can notice what they did not
  do. `spm events` reads it and the dashboard shows it under Tools.

  Two decisions carry it. It lives *outside* the vault, in plaintext, because a
  failed unlock is the event most worth recording and the one that cannot be
  written into a vault nobody could open — which is only safe because it holds
  no record names, usernames, URLs, passwords or paths, and its details are
  validated against a closed vocabulary rather than being free text. And
  repeated successes coalesce while failures never do, because the dashboard
  reads the vault on nearly every page view and one line per read buried the
  handful of lines anyone came to see.

## Choosing work

New contributors should start with issues labeled
[`good first issue`](https://github.com/sansyourways/Sans_Password_Manager/labels/good%20first%20issue).
Larger proposals should include security impact, CLI/Web parity, migration,
tests, and rollback considerations. See `CONTRIBUTING.md` before implementation.

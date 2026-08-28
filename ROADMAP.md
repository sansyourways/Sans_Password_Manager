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

- Expand Linux, macOS, and Termux regression coverage for platform-specific
  command behavior.
- Add focused tests around restore failures, interrupted writes, and concurrent
  CLI/Web mutations. The next step beyond this is deliberate fault injection —
  disk-full, process killed mid-write, corrupted vault, competing writers.
- Improve accessibility and keyboard-only verification for every SPM Dashboard page.
- Keep import/export fixtures synchronized across every documented format.

## Shipped integrations

- **Universal browser-extension popup picker — shipped in 3.1.0.** Chrome,
  Chromium, Edge, Brave, Opera, Vivaldi, and Firefox desktop share one source
  tree. The secret-free account-list protocol, memory-only native-host session,
  exact-host selection, installers, and installation tutorials are delivered.
  The in-field picker and optional WebAuthn unlock remain phased in
  [`docs/BROWSER-EXTENSION-ROADMAP.md`](docs/BROWSER-EXTENSION-ROADMAP.md).

## Next — safer integrations

- Continue the browser-extension work with an origin-isolated in-field picker.
- Design pluggable, encrypted synchronization transports without introducing a
  maintainer-operated cloud service.
- Add machine-readable doctor output for support and automation.
- Improve reproducible release provenance and artifact attestations.

## Later — ecosystem growth

- Evaluate package-manager distribution for Homebrew and Termux.
- Define a stable extension boundary that cannot bypass vault authorization.
- Explore hardware-backed signing for release provenance. Hardware-backed
  protection of the vault itself is covered under Architecture below.
- Add optional localization contributions beyond English, Indonesian, and
  Japanese.

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
  memory-hard KDF is **scrypt**, and it arrives with the data-layer
  replacement below. Argon2id follows it when a platform floor makes it
  testable rather than merely writable.

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

### Foundation — the work this unblocks

- **Replace the gpg data layer.** Now the single-file change it was not
  before, and the one that brings a memory-hard KDF with it. Measured on a
  format-3 vault: a read costs **452 ms**, of which 280 ms is the key unwrap
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
- **Cache the dashboard session key.** Two gpg invocations per request become
  one. Roughly half the latency, for a change confined to the core's callers.

### User power — daily capability

- Per-record password history, so a rotated credential keeps its predecessors.
  This is distinct from the existing vault-level snapshots, which capture whole
  generations rather than the history of one entry.
- Duplicate and breach review that performs its analysis without disclosing a
  secret to any third party.
- Folders and custom fields for records that do not fit the current shape.
- Import preview, so a Bitwarden, 1Password, KeePass or browser export can be
  inspected and corrected before it is committed to the vault.

### Trust expansion — hardware and recovery

- Hardware-backed key wrapping via FIDO2, TPM or a platform secure enclave.
  Distinct from the biometric unlock shipped in 2.11.0, which resumes a
  suspended dashboard session and never holds the vault key.
- Split recovery — Shamir-style shares — so recovery does not depend on one
  file and one private key remaining simultaneously available and secret.
- A security-event log that records sensitive operations without recording the
  secrets involved.

## Choosing work

New contributors should start with issues labeled
[`good first issue`](https://github.com/sansyourways/Sans_Password_Manager/labels/good%20first%20issue).
Larger proposals should include security impact, CLI/Web parity, migration,
tests, and rollback considerations. See `CONTRIBUTING.md` before implementation.

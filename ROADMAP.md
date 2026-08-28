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

## Next — safer integrations

- Harden and document browser-extension installation on each supported platform.
  A detailed plan for URL auto-bind and an in-field account picker, including
  the browsers this can and cannot reach, is in
  [`docs/BROWSER-EXTENSION-ROADMAP.md`](docs/BROWSER-EXTENSION-ROADMAP.md).
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

### Foundation — make the core auditable

- **Wrap a vault key rather than the master password.** Recovery currently
  RSA-encrypts the master password itself, so the recovery file is a second
  copy of that password rather than a wrapped key. Introducing a random vault
  key, wrapped separately by the master password and by each recovery factor,
  would let a password change rewrap a key instead of re-encrypting the whole
  vault, and would stop a recovery file from being password-equivalent.
- **Version the vault format and state the KDF policy explicitly.** The vault
  carries a single metadata row (`META_RECOVERY_PUBKEY`) and no format version,
  and encryption states only `--cipher-algo AES256` while leaving key derivation
  to GnuPG's defaults. Recording format version, KDF choice and its parameters
  in the vault — Argon2id where available — makes migrations possible and makes
  a security decision reviewable instead of implicit.
- **Split the trusted core out of the single script.** Crypto, key handling and
  vault mutation belong in the smallest component that can be reviewed on its
  own, with the CLI, dashboard and bridge reaching it through a narrow contract.
  This is the precondition for most of the rest of this section.

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

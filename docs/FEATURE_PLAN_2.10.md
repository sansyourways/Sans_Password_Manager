# SPM 2.10 Local-First Feature Plan

## Goal

Add the ten requested capabilities without moving decrypted vault data to a
service or weakening the existing single-file Bash/GnuPG trust boundary.

## Scope and acceptance criteria

1. **History:** retain encrypted pre-write generations, list them, and restore
   only after confirmation. Retention is bounded.
2. **Reuse detection:** compare password fingerprints only inside the decrypted
   audit process and never print secrets or hashes.
3. **Security dashboard:** score weak, reused, old, incomplete, and malformed
   records and provide record IDs for remediation.
4. **Automatic backups:** opportunistically create encrypted snapshots after a
   configured interval, verify their digest, and enforce retention.
5. **Emergency access:** package selected records using recipient RSA-OAEP plus
   AES encryption. The activation date is advisory because an offline archive
   cannot enforce a clock against its private-key owner.
6. **Browser bridge:** ship a least-privilege native-messaging host and extension
   scaffold. It exposes health and explicit record lookup, never vault dumps.
7. **Attachments:** store bounded files as encrypted vault records, verify SHA-256
   on extraction, and refuse destination overwrite.
8. **Multiple vaults:** named profiles resolve to explicit paths; switching takes
   effect on the next process and never migrates data implicitly.
9. **Synchronization:** start with a user-controlled filesystem target and a
   portable channel name, track a device-local base digest, and refuse two-sided
   changes rather than last-write-wins.
10. **Passkeys:** manage relying-party, account, credential-ID, and notes metadata.
    Private passkey material remains in the platform authenticator.

## Data model

New line tags remain backward-compatible with existing vaults:

- `ATTACHMENT<TAB>id<TAB>label<TAB>filename_b64<TAB>mime<TAB>data_b64<TAB>sha256<TAB>created`
- `PASSKEY<TAB>id<TAB>rp_id<TAB>account<TAB>credential_id<TAB>notes_b64<TAB>created`

History, backups, sync state, and profile configuration contain ciphertext,
digests, paths, and timestamps only. They never contain master passwords.

## Security boundaries and tradeoffs

- Browser requests still require an interactive SPM process and master-password
  verification; the extension cannot request all credentials.
- Filesystem sync is deliberately the first adapter. WebDAV/S3/Git credentials
  and network retry semantics are deferred rather than embedded insecurely.
- Emergency dates communicate intent but are not cryptographic time locks.
- Passkey private keys are intentionally non-exportable and are not copied into
  SPM.

## Validation

- Syntax and ShellCheck.
- Disposable encrypted-vault tests for every new command.
- Corruption, conflict, overwrite, size-limit, and wrong-key failure tests.
- Existing 21-format CLI/web import/export regression matrix.
- Secret-pattern scan, ZIP validation, and clean scoped commits.

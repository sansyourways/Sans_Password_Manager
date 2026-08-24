# SPM 2.10.12

A data-integrity release. Everything here came out of a full sweep of the
codebase; each defect was reproduced before it was fixed, and each has a
regression guarding it.

## Why this release exists

Three bugs in this set could destroy or corrupt secrets without saying anything.
That is the worst failure mode a password manager has, because the damage is
discovered later — usually at the moment the credential is needed.

## Security

- **Vault fields collapse every line-break character.** `_vf()` stripped tab,
  carriage return and newline; `str.splitlines()`, which every parser uses to
  read the vault back, breaks on eleven characters. The other eight passed
  through, split the record in two on read, and the entry disappeared — the next
  write then made the loss permanent. The failure was asymmetric and so
  especially confusing: Bash reads with `read -r` and split only on newline, so
  an entry added from the CLI still listed in the CLI while being invisible in
  Web Mode.
- **Imports fail closed on non-UTF-8 input.** Readers used `errors="ignore"`, so
  a cp1252 export — the common case from Windows password managers — imported
  as *success* with characters silently missing from the stored secrets.
  `dummy-pw-Größe` was stored as `dummy-pw-Gre`. SPM now names the byte and line
  and suggests an `iconv` conversion, and writes nothing.
- **The temporary-file registry is unpredictable.** It lived at a `$$`-derived
  path in a world-writable directory, and `cleanup()` feeds every line of it to
  `shred`. A local user who pre-created that file chose which files SPM
  destroyed. It is now created with `mktemp`.
- **The self-updater no longer falls back to a predictable directory.** When
  `mktemp -d` fails it aborts, because `mkdir -p` succeeds on a directory
  somebody else already owns — and verifying the ZIP's checksum does not help
  once the extraction directory is attacker-controlled.
- **Web Mode dropped `'unsafe-inline'` from its script policy.** The nine inline
  handlers became one delegated listener, and every remaining script block
  carries a per-response nonce.

## Fixed

- **Blank backup-code edits preserve the stored codes.** This was the same
  defect as the 2.10.11 passphrase fix, with a worse payload: recovery codes
  cannot be regenerated from anything, and a blank submit erased them while
  returning success. An unreadable stored value now stops without modifying the
  vault.
- **Web Mode writes record encrypted history.** All three callers of the
  archival routine were in Bash, so `history-list` and `history-restore` were
  blind to every change made from the browser — leaving one `.bak` generation as
  the only undo for the primary client.
- **Vault writes are durable.** Both writers staged to a temporary file and
  renamed with no flush. The rename is atomic but not durable; a crash could
  leave the vault pointing at unwritten blocks.
- **Imports report what they skipped.** Unrecognised record types — `login`,
  `credential`, `card` and friends — were discarded in silence. Four rows in,
  one stored, success reported. SPM now prints the stored count and names every
  type it did not understand.
- **`spm update` recognises the current version.** It compared the release tag
  `v2.10.12` against the version string `2.10.12`, so it always offered to
  reinstall what was already running.
- **`EDITOR` values with arguments work.** `EDITOR="code --wait"` was run as one
  executable name.

## Upgrade note

Web Mode runs a *generated* Python file. Installing the new `spm.sh` and
restarting the service is not enough — regenerate the web script, restart with
`SPM_VERSION` set, then confirm a marker from this release is present:

```
grep -c _VAULT_BREAKS ~/.local/share/spm/spm_web_server.py   # must be non-zero
```

## Verification

`bash -n`, `shellcheck -x -S warning` and `git diff --check` clean on all
scripts; the generated web server compiles; the full regression suite passes
across all 20 import/export formats plus the new integrity tests. Each new test
was confirmed to fail when its fix is reverted.

# SPM 2.10.14

Surfaces the parts of SPM that only the CLI could reach, and fixes two ways
Web Mode disagreed with the CLI about your vault.

## Why

SPM has around 48 CLI commands. Web Mode's navigation exposed eight
destinations. Web Mode is the daily driver — the iPhone Home Screen app is the
release target — so features that were already built, tested and shipped were
invisible exactly where they were most useful.

Two of them were not merely missing but half-built: the overview computed a
security score and drew it as a tile, but the tile linked to `/` and no detail
page existed, so the number could not be acted on; and the attachment and
passkey counts were recomputed on every request and never displayed.

## What was added

- **`/security`** — the findings behind the score. Weak, reused, due for
  rotation, missing details, malformed authenticators, each listing the entry
  IDs as links. IDs and labels only; secret fields are never rendered, so the
  page stays safe to open on a phone in public.
- **`/history`** — the encrypted snapshots SPM takes before every change, with
  a Restore button. Restore proves the snapshot opens with the current master
  password *before* touching the live vault, archives the current vault first,
  and writes through the same fsync-then-rename path as any other vault write.
  The snapshot name is validated against an allowlist rather than screened for
  traversal.
- **`spm` menu item 23** — the same history, chosen by number. A generated
  filename never has to be typed. The confirmation before overwriting a vault
  is unchanged.
- **`/search?q=`** — one query across passwords, notes, passphrases, backup
  codes and authenticators. Labels, names, usernames and IDs only: a query can
  never match a secret, so the result count cannot confirm a guessed password.
- **Tags** — a `#hashtag` convention inside fields that already exist. No
  schema change, no migration, export and import untouched. Secret fields and
  base64 bodies are never scanned, so a tag can never be a secret.
- **Rotation badges** — entries older than `SPM_ROTATION_DAYS` (default 365).

## What was fixed

- `ATTACHMENT` and `PASSKEY` rows were listed as passwords in Web Mode, with
  their base64 payload in the password column, and were counted in the security
  score. Web Mode identified a password row by listing every *other* row type
  by prefix — a denylist that had fallen behind the record types SPM has gained
  since it was written. A password row is now identified the way the CLI does
  it: field 1 is a number, so anything added later is excluded by default.
- The CLI dashboard and Web Mode were two independent copies of the same
  scoring formula and had drifted: the CLI penalised malformed authenticators
  and Web Mode did not, so the same vault scored differently depending on where
  you looked. One implementation now, with the suite asserting they agree.
- `spm doctor` printed its duplicate-ID verdict with the empty `[ ]` marker
  used by in-progress steps, so a passing check read as unfinished.

## Upgrading

Web Mode changed in this release, so a PM2 restart alone is not enough — the
generated `spm_web_server.py` must be rewritten from the new `spm.sh` before
restarting, or the old server keeps running.

No vault migration. Nothing in this release changes how records are written.

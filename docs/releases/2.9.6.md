# Sans Password Manager 2.9.6

This patch release completes a full import/export and vault-durability audit.

## Highlights

- Lossless round trips across all 21 advertised CLI and web format identifiers, including
  pipes, quotes, backslashes, commas, and multiline secret material.
- Fail-closed imports when an upload contains no supported records.
- Shared CLI/web vault locking and atomic encrypted vault replacement.
- Verified save archives before local wipe, plus atomic mode-`600` restores.
- Correct digits-only numeric password generation and strict option errors.
- Archive-specific updater checksums and a pre-install Bash syntax gate.

## Verification

- `bash -n spm.sh`
- `shellcheck spm.sh`
- Exact multi-record round-trip matrix for all supported formats in CLI and web
- Real multipart and pasted CSV web imports with encrypted readback
- Forced encryption and archive-corruption failure tests
- Cross-process lock contention, save, restore, doctor, TOTP, and generator tests
- Release ZIP integrity, permissions, checksum, and clean extraction checks

The recovery private key remains excluded from release and portable/save
archives unless the explicit insecure opt-in is selected for a portable bundle.

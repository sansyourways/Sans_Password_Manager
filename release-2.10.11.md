# Sans Password Manager 2.10.11

This patch release resolves every high- and medium-severity defect identified
by the 2026-08-24 deep audit. It does not change the vault format.

## Security and reliability

- Blank passphrase edits preserve the correct stored secret and fail without a
  write when the stored value cannot be decoded.
- HTTP certificate setup restores the complete previous nginx state after a
  failed preflight, certificate request, dry run, missing certificate, or TLS
  install. Replacing a non-SPM vhost requires explicit confirmation.
- Web login throttling is thread-safe, bounded, expires stale clients, and uses
  a validated visitor address when requests arrive through loopback nginx.
- Password generation no longer falls back to predictable Bash `$RANDOM`.
- Installer profile changes safely quote paths, allow multiple installation
  prefixes, and select `.bash_profile` for macOS Bash login shells.
- TOML import remains available on Python 3.10 and older without downloading a
  dependency.

## Verification

- `bash -n spm.sh install.sh tests/regression.sh`
- ShellCheck reviewed; no warning-or-higher findings in changed application code
- Full regression suite: 20 import/export formats, Web Mode, passphrase edit,
  proxy-aware login isolation, installer PATH behavior, and advanced features
- Release ZIP syntax and SHA-256 verified after packaging

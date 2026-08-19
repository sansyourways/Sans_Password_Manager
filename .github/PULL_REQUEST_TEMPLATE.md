## Purpose

Describe the problem and why this change is needed.

## Changes

Describe the focused implementation changes.

## Verification

- [ ] `bash -n spm.sh install.sh tests/regression.sh tests/dco-check.sh`
- [ ] `shellcheck -x -S warning spm.sh install.sh tests/regression.sh tests/dco-check.sh`
- [ ] `./tests/regression.sh`
- [ ] User-visible documentation is updated when behavior changes
- [ ] Release ZIP/checksum requirements are satisfied when applicable
- [ ] Every commit includes a DCO sign-off (`Signed-off-by:`)

## Security and data handling

- [ ] Tests use disposable vaults and synthetic credentials only
- [ ] No vault, recovery key, token, session, backup, or private environment file is included
- [ ] File permissions, atomic writes, migrations, and rollback implications were reviewed

## Release and rollback

State the intended version, deployment impact, and safe rollback revision or procedure.

By submitting this pull request, I agree that my contributions are licensed
under Apache-2.0 and certify them under the Developer Certificate of Origin 1.1.

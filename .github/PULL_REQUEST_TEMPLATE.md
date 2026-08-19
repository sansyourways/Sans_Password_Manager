## Purpose

Describe the problem and why this change is needed.

## Changes

Describe the focused implementation changes.

## Verification

- [ ] `bash -n spm.sh install.sh tests/regression.sh`
- [ ] `shellcheck -x -S warning spm.sh install.sh tests/regression.sh`
- [ ] `./tests/regression.sh`
- [ ] User-visible documentation is updated when behavior changes
- [ ] Release ZIP/checksum requirements are satisfied when applicable

## Security and data handling

- [ ] Tests use disposable vaults and synthetic credentials only
- [ ] No vault, recovery key, token, session, backup, or private environment file is included
- [ ] File permissions, atomic writes, migrations, and rollback implications were reviewed

## Release and rollback

State the intended version, deployment impact, and safe rollback revision or procedure.

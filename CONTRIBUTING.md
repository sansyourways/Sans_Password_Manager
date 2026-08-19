# Contributing to Sans Password Manager

Thank you for helping improve SPM. Contributions should preserve its
local-first model, single-file core, portability, and conservative handling of
credential data.

## Before opening a change

1. Check existing issues and releases for related work.
2. Keep the change focused; avoid unrelated formatting or banner rewrites.
3. Never use or attach a real vault, password, recovery key, token, cookie,
   backup, or private host detail. Use obviously synthetic fixtures.
4. For vulnerabilities, follow [the private disclosure process](docs/SECURITY.md)
   instead of opening a public issue.

## Development expectations

- Keep core behavior in `spm.sh` and match its Bash style, tab indentation,
  `snake_case` functions, and explicit command flags.
- Keep direct CLI, interactive menus, help text, and web behavior aligned.
- Preserve compatibility with standard utilities across Linux, macOS, and
  Termux where practical.
- Update `README.md` and `CHANGELOG.md` for user-visible behavior.
- Do not overwrite historical release bundles.

## Required verification

```bash
bash -n spm.sh install.sh tests/regression.sh
shellcheck -x -S warning spm.sh install.sh tests/regression.sh
./tests/regression.sh
```

Add a targeted disposable-vault regression when fixing a behavior that the
suite does not already cover. Web import changes must exercise both a real
multipart CSV upload and pasted form data.

## Pull requests

Explain the problem, behavioral change, validation evidence, security impact,
and rollback path. Small, reviewable changes are preferred. Submission does not
change the repository's private license; acceptance and redistribution remain
subject to the terms in [LICENSE](LICENSE).

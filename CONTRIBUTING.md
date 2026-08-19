# Contributing to Sans Password Manager

Thank you for helping improve SPM. Contributions should preserve its
local-first model, single-file core, portability, and conservative handling of
credential data.

## Before opening a change

1. Check existing issues and releases for related work.
2. Keep the change focused; avoid unrelated formatting or banner rewrites.
3. Never use or attach a real vault, password, recovery key, token, cookie,
   backup, or private host detail. Use obviously synthetic fixtures.
4. Report vulnerabilities through the private process in `docs/SECURITY.md`,
   not a public issue or pull request.
5. Confirm that you can license every part of the contribution under
   Apache-2.0.

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

Add a targeted disposable-vault regression when fixing behavior that the suite
does not already cover. Web import changes must exercise both a real multipart
CSV upload and pasted form data.

## Developer Certificate of Origin

Every commit must be signed off under the Developer Certificate of Origin 1.1:

```bash
git commit --signoff
```

The resulting `Signed-off-by:` trailer certifies the statements in `DCO`. It is
not a copyright assignment. See `docs/CONTRIBUTOR_LICENSE_POLICY.md` for the
inbound licensing policy and the limited circumstances in which maintainers may
request a separate contributor agreement.

## Pull requests

Explain the problem, behavioral change, validation evidence, security impact,
and rollback path. Small, reviewable changes are preferred. Maintainers may
request changes and are not obligated to merge a submission.

Unless explicitly marked `Not a Contribution`, intentional submissions are
licensed under Apache-2.0 as provided by section 5 of `LICENSE`. Contributors
retain copyright in their original work.

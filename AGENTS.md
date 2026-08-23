# Repository Guidelines

## Project Structure & Modules
- Core logic lives in `spm.sh` (single-file Bash password manager). Keep changes self-contained and portable.
- Legal and policy docs sit in `docs/` (`SECURITY.md`, `PRIVACY_POLICY.md`, etc.). Update them when behavior or data handling changes.
- Release artifacts are the versioned `Sans_Password_Manager_v*.zip` bundles and notes like `release-2.3.0.md`; do not overwrite historical bundles.
- `.github/` holds Gemini automation configs; avoid breaking workflow inputs.
- Ignore and never commit vaults, recovery keys, or save/portable bundles listed in `.gitignore`.

## Build, Test, and Development Commands
- Make executable once: `chmod +x spm.sh`
- Run interactive TUI: `./spm.sh`
- Start local web UI (offline): `./spm.sh web`
- Health check on a dummy vault: `./spm.sh doctor`
- Quick lint/sanity for edits:
  ```bash
  bash -n spm.sh
  shellcheck spm.sh   # if available
  ```
- For recovery flow tests, generate throwaway keys only (never real secrets).

## Coding Style & Naming Conventions
- Language: Bash with `set -euo pipefail`; prefer POSIX-compatible utilities.
- Indentation uses tabs in existing code; match surrounding style. Place `local` declarations at the top of functions.
- Functions are `snake_case()`, constants upper snake (`VERSION`, `REPO_NAME`), and user-facing strings kept in-line for menu translations.
- Favor small helper functions over inline pipelines; keep command flags explicit for readability.
- When adding features, also extend help text and interactive menus to keep CLI/Web modes aligned.

## Testing Guidelines
- No formal test suite; rely on scripted checks plus manual flows.
- Use `bash -n` and `shellcheck` to catch syntax issues. Run `./spm.sh doctor` after edits to validate vault structure handling.
- Smoke-test critical commands with disposable vaults: `./spm.sh init`, `./spm.sh add`, `./spm.sh get <id>`, `./spm.sh portable`, `./spm.sh save`, and `./spm.sh forgot` (with test RSA keys).
- Avoid copying real secrets into the clipboard during tests; use dummy data and clear with the built-in auto-clean.

## Commit & Pull Request Guidelines
- Follow the existing Conventional Commit style: `feat: ...`, `fix: ...`, optional scoped tags (e.g., `feat(2.3.0): ...`) when bumping versions.
- Release delivery is PR-only for every contributor and automation agent,
  including Claude: create a release branch and reviewed pull request; never
  push a release commit or tag directly to the protected default branch.
- Update `CHANGELOG.md` and `README.md` for user-visible changes; note new release artifacts when applicable.
- PRs should include: purpose, key changes, test notes (`bash -n`, `shellcheck`, manual flows run), and any security considerations (key handling, vault migrations).
- Keep diffs minimal; avoid reformatting the ASCII banner or existing translations unless intentional.
- Versioning policy reminder: keep patch bumps (`x.x.n`) for fixes/small tweaks; add new features without bumping when already on current minor. Accumulate ~5+ new features before bumping the minor (`x.n.0`), and bump major only for overhauls/breaking changes. Current version is 2.8.0 and every future change must keep this semantic versioning policy in mind.
- Release hygiene: every change set must update `CHANGELOG.md` + `README.md` and regenerate the ZIP (`Sans_Password_Manager_v<version>.zip`) before commit; don’t skip the zip rebuild.
- Web import stability: always verify `/import` handles both multipart uploads and pasted data with clear logging and redirects; test with a real CSV upload in temporary web mode to confirm success feedback.

## Current Snapshot (v2.8.0)
- Version in `spm.sh` is `2.8.0`; README shows the same. Export supports csv/json prompts plus advanced formats: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc. Menu prompt now lists all available formats while still highlighting csv/json.
- Web dashboard now includes an EN/ID/JP language selector in the header that persists via cookie; dashboard cards, table headers, and the export/import UI rerender in the selected language without reloading.
- Web themes introduced 2.7.x; auto-reload removed in 2.7.1. Tables/cards/theme colors refined through 2.7.2–2.7.3. Buttons pastelized in 2.7.4.
- Web mode has passphrase, backup codes, authenticator cards; version passed via `SPM_VERSION` env. CLI includes passphrase and authenticator commands. Copy buttons in all view pages now emit toast notifications so users always know when clipboard actions succeed/fail on any device. New `restore` command/menu relocates bundle vaults back to `~/.spm_vault.gpg`.
- Portable and save bundles now package the RSA private key (`spm_recovery_private.pem`) alongside the vault and recovery file; handle archives carefully. Auto-updater (`./spm.sh update`) downloads the latest ZIP and installs to `/usr/local/bin/spm` (may need sudo). Rebuild the release ZIP (`Sans_Password_Manager_v2.8.0.zip`) before publishing.

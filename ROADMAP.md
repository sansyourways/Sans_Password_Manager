# Sans Password Manager Roadmap

This roadmap communicates direction rather than fixed delivery dates. Security,
data integrity, portability, and backward compatibility take priority over
feature volume. Proposals should begin with an issue and use synthetic data.

## Now — reliability and contributor foundations

- Expand Linux, macOS, and Termux regression coverage for platform-specific
  command behavior.
- Add focused tests around restore failures, interrupted writes, and concurrent
  CLI/Web mutations.
- Improve accessibility and keyboard-only verification for every Web Mode page.
- Keep import/export fixtures synchronized across every documented format.

## Next — safer integrations

- Harden and document browser-extension installation on each supported platform.
- Design pluggable, encrypted synchronization transports without introducing a
  maintainer-operated cloud service.
- Add machine-readable doctor output for support and automation.
- Improve reproducible release provenance and artifact attestations.

## Later — ecosystem growth

- Evaluate package-manager distribution for Homebrew and Termux.
- Define a stable extension boundary that cannot bypass vault authorization.
- Explore hardware-backed recovery and signing integrations.
- Add optional localization contributions beyond English, Indonesian, and
  Japanese.

## Choosing work

New contributors should start with issues labeled
[`good first issue`](https://github.com/sansyourways/Sans_Password_Manager/labels/good%20first%20issue).
Larger proposals should include security impact, CLI/Web parity, migration,
tests, and rollback considerations. See `CONTRIBUTING.md` before implementation.

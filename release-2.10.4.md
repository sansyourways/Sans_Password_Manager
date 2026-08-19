# Sans Password Manager 2.10.4

This patch completes SPM's open-source contributor and portability foundation.

- Enforced DCO 1.1 sign-offs for every pull-request commit
- Added full Linux and macOS regression jobs
- Added compatibility smoke testing in a pinned official Termux container
- Fixed Termux dependency installation to use `pkg` and made CLI help available
  before environment setup prompts
- Isolated GnuPG test-agent state for reliable macOS regression execution
- Updated GitHub Actions to the Node.js 24 checkout runtime
- Corrected privacy and GDPR documentation for optional network behavior
- Standardized public contact domains and added security response targets
- Added a public roadmap and newcomer-oriented issue workflow

There are no vault-format, encryption, CLI, or Web Mode behavior changes.

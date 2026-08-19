# GDPR Privacy Notice for Sans Password Manager

Effective date: August 2026

Copyright 2025–2026 Sansyourways and contributors.

This notice explains the data roles associated with official SPM releases. It
is informational and does not determine the legal obligations of every user,
organization, fork, or deployment.

## Application data

SPM processes vault records locally on behalf of the person operating it. The
SPM project does not provide a hosted vault service and does not receive vault
contents, master passwords, recovery keys, device identifiers, telemetry, or
analytics from official releases.

Depending on how SPM is used, the person or organization controlling the vault
may be a controller for personal data stored in it. That operator is responsible
for establishing an appropriate legal basis, retention policy, security
controls, and response process for affected individuals. Running open-source
software does not transfer those responsibilities to project maintainers.

## Data location and transfers

Vaults, backups, history, attachments, recovery material, and filesystem sync
targets remain in locations selected by the user. SPM maintainers do not choose
those locations or receive that data.

The following user-initiated activity can involve third-party infrastructure:

- update and installation commands retrieve metadata or files from GitHub;
- GitHub issues, pull requests, releases, and security advisories are processed
  by GitHub;
- support or security emails are processed by the sender's and recipient's mail
  providers;
- non-loopback Web Mode and externally synchronized directories use networks or
  providers configured by the operator.

Users and organizations must assess any international-transfer requirements
created by their chosen GitHub, email, hosting, proxy, storage, or sync setup.

## Project communications

When someone deliberately contacts the project, maintainers process the
submitted name, address, message, and related technical information to respond,
maintain security, and operate the open-source project. Do not include vaults,
passwords, keys, tokens, or unrelated personal data.

Requests concerning information submitted directly to project-maintained
channels may be sent to support@sansyourways.xyz. Requests about data held by
GitHub, an email provider, a fork, or an independent deployment should be sent
to that operator.

## Security and retention

Official SPM releases use local encryption and do not give maintainers a means
to recover vault data. Public GitHub contribution records and DCO sign-offs are
retained as part of the project's permanent licensing and authorship history.
Security reports are retained as needed to investigate, remediate, and document
the vulnerability.

## Changes

This notice will be updated when relevant application or project communication
practices change. Security reports should be sent to
security@sansyourways.xyz.

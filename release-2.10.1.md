# Sans Password Manager 2.10.1

This audit patch hardens the local-first features introduced in 2.10.0.

- Authenticated history restoration
- HMAC-authenticated emergency manifests and payloads
- Portable sync channels and fail-closed first-time conflict handling
- Safe profile configuration fields
- Non-fatal automatic-backup reporting after successful vault writes
- Portable history/date handling
- Shorter browser-side master-password lifetime

All 2.10 feature and legacy import/export regression tests were rerun against
the patched build.

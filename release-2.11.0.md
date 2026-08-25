# SPM 2.11.0 — biometric unlock for Web Mode

## What this release is for

2.10.14 repaired the 30-second idle auto-lock, which had been silently dead on
the phone. Repairing it created a new problem: a lock that genuinely fires
every 30 seconds means typing a long master password on a phone keyboard dozens
of times a day, and the predictable response to that is to raise the timeout
until the control stops meaning anything.

This release makes resuming a locked session cheap without making it weak.

## What was added

- **Biometric unlock.** Register a device from the new Biometric Unlock page,
  and the idle lock resumes with Face ID or Touch ID instead of a retyped
  master password. The master password is still required for the first sign-in
  of the session, once the 12-hour cap is reached, and whenever a locked
  session has gone unresumed past its suspension window.

- **`spm webauthn-list` / `spm webauthn-delete <id>`** to see and revoke unlock
  credentials from the CLI. Registration is a browser ceremony by nature, so
  there is no matching add command.

## The design decision that matters

Suspension is **server-side state**, not a browser redirect.

This is the direct lesson of the bug 2.10.14 fixed. The old lock was
`window.location.replace("/logout")` in a script — and when a CDN rewrote that
script out of existence, the lock silently ceased to exist. If suspension were
built the same way, anyone holding the phone could disable JavaScript, or type
`/passwords` into the address bar, and walk straight past it.

Instead, a suspended session is refused everywhere except the unlock endpoints.
`_get_cookie_session` reports it as *no session at all*, so every route written
before this feature existed — and every route added after it — fails closed
without having to opt in.

## What the server checks

Refusing on the first failure: ceremony type, a single-use server-issued
challenge, exact origin match, relying-party id hash, user presence **and user
verification**, a registered credential id, and an ES256 signature over
`authenticatorData || sha256(clientDataJSON)`.

User verification is checked separately from user presence on purpose. Without
it a bare tap on the authenticator satisfies the ceremony and Face ID is
decoration on top of an unlock anyone holding the phone can perform.

Failed unlocks share the existing login lockout budget. An assertion that
reaches the server having failed is attack-shaped: a real Face ID mismatch
never leaves the phone.

## No new dependencies

Signatures are verified with `openssl`, already required by the recovery-key
flow. Registration reads the credential key from the browser's `getPublicKey()`
rather than decoding a CBOR attestation object, so the generated server stays
on the Python standard library exactly as before.

## The honest trade

A suspended session keeps the plaintext master password in server memory so a
biometric can resume it. That residency is the entire cost of the feature, and
it is bounded by `SPM_WEB_SUSPEND_MAX` — **8 hours by default**. The bound does
not slide, and an unlock never resets the session's `created` time, so
biometric resumes cannot chain into an unbounded session.

If eight hours is longer than you want the master password resident after your
screen locks, set `SPM_WEB_SUSPEND_MAX` lower; one hour is a reasonable
tightening at the cost of retyping the password a few times a day.

Signature counters are held per process rather than written back to the vault:
persisting one would mean a full read-modify-write of the encrypted vault on
every unlock, and Apple's platform authenticator reports 0 forever regardless.
Cloned-authenticator detection is correspondingly weaker across a restart.

## Configuration

- `SPM_WEB_RP_ID` — the WebAuthn relying party. SPM's own domain setup supplies
  it automatically. It is never inferred from the `Host` header, and with no
  value configured the feature and its endpoints do not exist at all.
- `SPM_WEB_SUSPEND_MAX` — seconds a locked session stays resumable (default
  28800).

Registration needs a browser that can export the credential key
(`getPublicKey()`, Safari 16+). Everything degrades cleanly: with no
relying-party id, no registered credential, or no `PublicKeyCredential`, the
idle lock behaves exactly as it did in 2.10.14.

## Upgrading

Nothing to migrate. Existing vaults gain a new `WEBAUTHN` row type only once
you register a device, and that row is invisible to password parsing and to the
security score.

**Deploying:** reinstall `/usr/local/bin/spm` from the new `spm.sh` *before*
regenerating `spm_web_server.py`. Web Mode regenerates the server from the
installed CLI, not from a repo checkout, so a restart alone ships the old code.

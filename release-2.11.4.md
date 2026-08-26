# SPM 2.11.4 — the idle lock can no longer strand you

Two defects in biometric unlock, both found by probing the state machine rather
than by anything failing in normal use. Neither put a vault at risk; both ended
with the user unexpectedly logged out, retyping the master password — the exact
friction the feature exists to remove.

## The lock could suspend into a page that could not let you back in

`/unlock/suspend` trusted a flag cached on the session at login instead of
checking the vault. A browser already open when the last credential was
deleted — or when `SPM_WEB_RP_ID` changed — still believed a credential
existed. Its lock would fire, the session would suspend, and `/unlock/challenge`
would then answer "no credential registered". The only working control left on
the locked page was **Use master password instead**, which logs out.

Suspending now asks the vault, which is the only authority, and refuses when no
usable credential exists. The lock bar treats a refusal as a reason to log
out — exactly what it did before 2.11.0 — and the stale flag is corrected so
later pages stop advertising unlock.

## A second tab could log out the session the first had just locked

Two tabs share one session, and both lock bars fire. The second
`/unlock/suspend` was answered "no session", and because the lock bar treats
any refusal as a reason to log out, the tab that lost the race destroyed the
suspended session the other tab was about to resume with Face ID.

Suspending an already-suspended session is now idempotent. It deliberately does
**not** refresh `suspended_at` — doing that every time a tab reported in would
let an idle browser hold the master password in memory past
`SPM_WEB_SUSPEND_MAX` indefinitely.

## Nothing else changed

No behaviour outside the unlock state machine was touched. Registration, the
ceremony checks, session expiry, the CSRF paths, and every other page are
unchanged.

Both fixes carry regression assertions, and each assertion was reverted against
the 2.11.2 behaviour and confirmed to fail for the right reason before being
accepted.

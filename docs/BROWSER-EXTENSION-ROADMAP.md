# Browser extension roadmap — URL auto-bind and the account picker

Status: **3.1.0 protocol and popup picker shipped; 3.2.0 guided setup and
stable extension identity shipped**. The origin-isolated in-field picker is
next, for 3.4.0.

Phases were rebased onto 3.1.0 after 3.0.0 took the major version for the
vault-format change, and shifted one release again when 3.2.0 went to the
guided installer. That is the third rebase -- 2.13.0 shipped the dashboard
master-password change ahead of this work, 3.0.0 shipped the trusted core ahead
of it again, and 3.2.0 fixed the installation loop that 3.1.0 left behind. The
sequence is unchanged every time; only the version each phase targets moved.

That has now happened four times, which is enough to say plainly: **the version
numbers below are the next free minor at the time of writing, not a
reservation.** The order is the part worth trusting.

This is an implementation plan with target versions, so it lives here rather
than in [`ROADMAP.md`](../ROADMAP.md), which deliberately communicates direction
without delivery dates.

## Goal

Autofill that behaves like a mainstream password manager: focus a login field,
get a dropdown of the accounts bound to that site, pick one, and it fills —
without typing a record ID or a master password every time.

## Where we are

`browser-extension-universal/` now ships one Chromium-family/Firefox source
tree. Its popup unlocks a memory-only native-host session, lists accounts for
the active tab's exact hostname, and fills the account the user chooses. The
original `browser-extension/` remains for compatibility.

It works, and it is deliberately explicit. It is also not usable as a daily
autofill tool, for two reasons that decide the rest of this plan.

### Gap 1 — there is no discovery verb

`bridge-get` takes an ID you must already know. Nothing can answer *"which
records match this host?"*, so a picker has nothing to populate itself from.

Adding that is the single most security-sensitive change in this plan: it is an
endpoint that enumerates which accounts exist for a site.

### Gap 2 — the master password is typed per fill

Acceptable for one explicit action. Impossible for a dropdown that appears on
focus.

## Browser support — what is actually achievable

The request was "all browsers". The honest scope is *every browser with a
native-messaging extension model*.

| Target | Status | Notes |
| --- | --- | --- |
| Chrome, Edge, Brave, Opera, Vivaldi | Supported | One MV3 build; native messaging as today |
| Firefox (desktop) | Supported | Same code plus a `browser.*` polyfill. Different native-host manifest: `allowed_extensions` rather than `allowed_origins`, installed under `~/.mozilla/native-messaging-hosts/` |
| Firefox for Android | Partial | Extensions run; the in-field overlay needs its own testing pass |
| **Safari** | **Out of scope** | See below |
| Chrome/Safari on iOS | Not possible | No extension model of this kind |

### Why Safari cannot ship from this repository

Safari Web Extensions must be wrapped in a signed macOS/iOS **application
bundle** built with Xcode (`safari-web-extension-converter`) and distributed
through the App Store or as a signed developer build. They also do not speak
Chrome's native-messaging protocol — communication goes through an app
extension, so `native_host.py` does not port.

A single-file Bash project cannot carry an Xcode project, a signing identity, or
an Apple Developer membership, and none of it can be "included in the bundle" as
loadable source. This is a platform constraint rather than a scoping decision.

iOS is already covered by the SPM Dashboard installed as a Home Screen web app,
which is the release target for that platform.

## Protocol

The shipped boundary keeps both vault operations as CLI verbs and session
state inside the persistent native host. The master password reaches the CLI
only on stdin, exactly as `bridge-get` took it previously.

```
spm bridge-list  <host>      master on stdin -> { ok, matches: [ {id, label, username, url} ] }
spm bridge-get   <id> <host> master on stdin -> { ok, username, password }
```

`bridge-list` **never returns a secret field**. That is the property to assert
in the regression suite and to mutation-test, in the same way the search page's
oracle guard is tested.

Like `bridge-get`, these dispatch before any language or consent prompt in
`main()` — native messaging is a machine-readable protocol and must emit exactly
one JSON document.

## Session model

The native host holds the master password in memory, and the extension holds a
**persistent port** (`chrome.runtime.connectNative`). When the port drops, the
host exits and the session is gone.

This is fail-closed and needs no new long-lived daemon: closing the browser
locks the vault.

Limits mirror the Dashboard's, which are already proven in production: an idle
expiry plus an absolute cap, both overridable by environment variable.

**Known cost, stated up front.** MV3 service workers are torn down aggressively.
A connected native port extends a worker's life but does not pin it forever, so
re-unlocking will happen more often than in a manager with a persistent
background page. The mitigation is not a longer session — it is making unlock
cheap, by reusing the WebAuthn ceremony the Dashboard already implements so
re-unlocking is a Touch ID tap. That is phase 3 rather than a blocker.

## The in-field dropdown

Render the menu in an **iframe served from the extension origin**
(`chrome-extension://<id>/menu.html`), not an injected `<div>`.

A closed shadow root still lives in the page's document and is reachable by page
script through layout and DOM traversal. An extension-origin iframe is a genuine
origin boundary the page cannot read into. This is what Bitwarden and 1Password
do, and it is the difference between "the page cannot see your account list" and
"the page probably cannot see your account list".

Cost: the iframe must be listed in `web_accessible_resources`, which exposes the
extension ID to the page and allows fingerprinting. This is universal among
password managers. MV3's `use_dynamic_url` reduces it and should be evaluated.

### Fill-path rules

These are the properties that separate autofill from a credential leak.

- **No silent autofill.** A fill always requires a user gesture. This is the
  anti-phishing property; a manager that fills automatically will fill a
  look-alike page automatically.
- **Re-verify the hostname at fill time**, not only when the list was built. The
  page can navigate between the dropdown opening and the click landing.
- **Never fill inside a cross-origin iframe** by default. An embedded login form
  from another origin is a standard credential-theft pattern.
- **Refuse to fill an `http://` page from a record whose URL is `https://`.**
  Downgrade protection.
- The `http(s)`-only scheme allowlist added in 2.12.0 already prevents a
  `javascript:` URL from reaching the extension as a match target.

## Matching rules

Exact hostname, as today.

Subdomain matching is deliberately **not** inferred. Without a public suffix
list, "also match the parent domain" turns a record for `foo.co.uk` into a match
for everything under `.co.uk`. Bundling and maintaining a PSL is a large data
dependency for a project with no third-party dependencies at all.

Instead, subdomain scope is **opt in per record**, written into the URL field:

```
https://example.com        exact host only
https://*.example.com      host and any subdomain
```

The wildcard is expanded by the bridge, never inferred from a bare hostname.

## Phasing

One release for all of this would be too large to review or bisect.

### 3.1.0 — protocol and popup picker — **shipped**

- Secret-free `bridge-list`; `bridge-get` remains hostname-bound
- Unlock and lock are native-host messages, so no reusable token or daemon is exposed
- Session in the native host behind a persistent port
- Popup lists matching accounts for the current tab and fills the chosen one
- Firefox build: polyfill, second native-host manifest, install docs

Fully testable headlessly: the whole protocol is CLI-level.

### 3.2.0 — guided setup and stable identity — **shipped**

- `setup.sh` detects the browser, builds the right package, registers the
  native host, and opens the extensions page and prepared folder
- A public development key gives every unpacked Chromium copy one stable ID,
  removing the copy-the-generated-ID-and-rerun-the-installer loop
- `extension-id.sh` derives that ID from the manifest key the way the browser
  does, so the registration cannot drift from the loaded extension

Not a picker phase. It removes the installation friction that 3.1.0 shipped
with, and it is separated from the in-field work so that the identity change,
which requires existing users to reload the extension, lands on its own.

### 3.4.0 — in-field dropdown

- Content script, field detection, extension-origin iframe menu
- Keyboard navigation (arrows, Enter, Escape), focus handling
- The fill-path rules above, each with a test
- Firefox for Android verification pass

### 3.5.0 — cheap unlock and scoping

- WebAuthn unlock in the popup, reusing the Dashboard's ceremony
- Opt-in `*.` subdomain scoping
- Optional: save-on-submit prompt for new credentials

## Testing

**In the regression suite** — the entire bridge protocol, because it is
CLI-level and needs no browser:

- `bridge-list` returns matches for a bound host and an empty list otherwise
- `bridge-list` output contains **no** secret, under mutation
- the native host refuses `list` and `get` without an unlocked session
- native-host `lock` makes a previously working session fail
- unlock, list, get, and lock work over native-messaging framing

Wildcard scope and HTTPS downgrade refusal belong to the 3.5.0 scoping phase
and receive their regression assertions with that implementation.

**Manual matrix** — the browser UI. Driving an extension under headless Chromium
with `--load-extension` is possible and worth revisiting, but it is its own
project and should not gate 3.1.0.

## Packaging

Both `browser-extension/` (compatibility) and `browser-extension-universal/`
are zipped recursively into the release archive. Generated `dist/` builds and
local `*.bak` files are excluded.

## Open questions

1. Should `bridge-list` include the username, or only the label? Usernames make
   the picker useful and are already visible on any list page, but they are the
   most sensitive thing the endpoint returns.
2. Should an unlocked bridge session and an unlocked Dashboard session be the
   same session? Sharing state would be convenient and is a larger blast radius.
3. Does save-on-submit belong in this extension at all, given SPM's explicit,
   non-magical posture elsewhere?

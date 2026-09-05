# Browser extension roadmap — URL auto-bind and the account picker

Status: **3.1.0 protocol and popup picker shipped; 3.2.0 guided setup and
stable extension identity shipped; 3.7.0 declared the boundary the host
enforces; 4.5.0 shipped opt-in subdomain scope and downgrade protection;
4.6.0 shipped the origin-isolated in-field picker.** What remains of this plan
is WebAuthn unlock in the popup, which is waiting on a design decision, and an
optional save-on-submit prompt.

Phases were rebased onto 3.1.0 after 3.0.0 took the major version for the
vault-format change, and shifted one release again when 3.2.0 went to the
guided installer. That is the third rebase -- 2.13.0 shipped the dashboard
master-password change ahead of this work, 3.0.0 shipped the trusted core ahead
of it again, and 3.2.0 fixed the installation loop that 3.1.0 left behind. The
sequence is unchanged every time; only the version each phase targets moved.

That happened four times, and each time the number was wrong within a day, so
the unstarted phases below no longer name one. 3.3.0 went to the dashboard's
dead controls, 3.4.0 to diagnostics, 3.5.0 to per-record history — none of them
this plan. **The order is the part worth trusting; the version each phase lands
in is decided when it is ready, not here.**

For these two that was not a scheduling question. Both needed a browser's
extension UI driven for real before they were worth trusting, and that is what
decided when they shipped: 4.4.0 built that harness, 4.4.1 extended it to the
fill, and 4.6.0 used it to ship the picker with every fill-path rule asserted
in a browser rather than argued for on paper.

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

## The in-field dropdown — **shipped in 4.6.0**

Render the menu in an **iframe served from the extension origin**
(`chrome-extension://<id>/menu.html`), not an injected `<div>`.

A closed shadow root still lives in the page's document and is reachable by page
script through layout and DOM traversal. An extension-origin iframe is a genuine
origin boundary the page cannot read into. This is what Bitwarden and 1Password
do, and it is the difference between "the page cannot see your account list" and
"the page probably cannot see your account list".

Cost: the iframe must be listed in `web_accessible_resources`, which exposes the
extension ID to the page and allows fingerprinting. This is universal among
password managers.

`use_dynamic_url` was evaluated in 4.6.0 and not adopted. It rotates the
resource URL, which genuinely reduces fingerprinting; it also moves the origin
the background recognises its own menu frame by, and Firefox's MV3 does not
implement it, so adopting it means a Chromium-only change to a boundary check.
That is worth doing deliberately rather than as a side effect.

A second cost is smaller and real: the overlay has a height, and the height
follows the number of rows up to four, so a page can infer roughly how many
accounts matched. It cannot infer which. Sizing to a fixed height would close
that and would make a one-account menu look broken; the leak is recorded here
rather than traded for the worse interface.

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
  Downgrade protection. **Shipped in 4.5.0**, and it fails closed: a caller
  that does not say what scheme the page uses is refused for https-bound
  records, because an unknown scheme cannot be shown to be secure. The list and
  the fill agree, so an account the fill will refuse is never offered.
- The `http(s)`-only scheme allowlist added in 2.12.0 already prevents a
  `javascript:` URL from reaching the extension as a match target.

**All of these shipped in 4.6.0, each with a test that fails when the code
enforcing it is removed.** Two are stricter than written above. "Never fill
inside a cross-origin iframe" is enforced as *never fill inside any subframe*:
telling a same-origin embed from a hostile one needs the tab's own URL, which
needs a permission worth more than the case it would enable, so the whole class
is refused. And the picker will not fill a record it did not offer, which is
what keeps the downgrade rule true at the fill and not only in the list.

The gesture rule rests on `isTrusted`. A page can focus a field and can
dispatch a `KeyboardEvent` identical to Enter in every other respect; it cannot
set that flag, because the browser sets it and only for real input. Opening the
menu is deliberately not gated on it, since an open menu reveals nothing.

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

**Shipped in 4.5.0.** One guard needs no PSL and is a floor rather than a
substitute: `https://*.com` is refused, because nothing legitimately covers a
whole top-level domain. `*.co.uk` still parses -- SPM cannot tell it from
`*.example.com` -- which is the cost of having no PSL and the reason scope is
opt in per record. Matching stops at a dot, so `*.example.com` does not match
`notexample.com`; the form refuses a scope the matcher will not honour, and the
view page renders a scope as a scope rather than as an href that cannot
resolve.

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

### 4.6.0 — in-field dropdown — **shipped**

- Content script, field detection, extension-origin iframe menu
- Keyboard navigation (arrows, Enter, Escape), focus handling
- The fill-path rules above, each with a test that kills its own mutant
- Driven end to end in Chromium, including the native-messaging round trip

Not done in this phase: the **Firefox for Android verification pass**. The code
is shared and the manifest carries the same content script, but "extensions run
there" is not the same statement as "this overlay behaves on a touch keyboard
at that viewport", and this repository has no way to run that. It is listed as
an unverified target rather than a supported one.

### After that — cheap unlock

- ~~Opt-in `*.` subdomain scoping~~ **Shipped in 4.5.0**, together with
  downgrade protection and one matcher in the trusted core: `bridge-list` and
  `bridge-get` each carried their own copy of the rule that decides whether a
  page may see a credential.
- WebAuthn unlock in the popup, reusing the Dashboard's ceremony. **Needs a
  design decision before it needs code.** The popup reaches SPM through the
  native host, which takes no part in the Dashboard's WebAuthn ceremony and
  holds no session for an assertion to attach to. Where a verified assertion is
  redeemed is the open question; answering it badly puts a second unlock path
  beside the one that already exists.
- Optional: save-on-submit prompt for new credentials

## Testing

**In the regression suite** — the entire bridge protocol, because it is
CLI-level and needs no browser:

- `bridge-list` returns matches for a bound host and an empty list otherwise
- `bridge-list` output contains **no** secret, under mutation
- the native host refuses `list` and `get` without an unlocked session
- native-host `lock` makes a previously working session fail
- unlock, list, get, and lock work over native-messaging framing

**Scope and downgrade, from 4.5.0** -- driven through the CLI's own bridge
commands rather than the matcher alone, because the shell is where the argument
order and the exit status live:

- an opt-in wildcard covers the parent host and every depth beneath it
- it stops at a dot, so `*.example.com` does not match `notexample.com`
- a bare hostname is never treated as a wildcard
- `*.com` is refused as a scope
- an https-bound record is neither offered to nor filled on an http page
- a missing page scheme is not treated as secure
- a refusal exits non-zero, and a list stays secret-free whatever it matches
- every refusal the core can produce is declared in the native host's error
  table, so a downgrade refusal does not reach the extension as the generic one

Five mutations of the matcher were each killed by the assertion written for it.

**In a browser, from 4.4.0** — `tests/extension-ui.mjs`, run by the regression
suite when Chromium and puppeteer are both present and skipped loudly when they
are not:

- the packed extension loads and its **service worker starts**, which is the
  difference between running and merely sitting unpacked on disk
- the id the browser assigns equals the one `extension-id.sh` derives. That was
  previously checked by re-deriving it the same way the script does, which
  proves the script agrees with itself; this asks the browser. A single flipped
  bit in the manifest key is caught.
- a non-web page is refused, which is the fill-path rule that keeps autofill off
  the extension's own pages, PDF viewers and devtools tabs
- nothing secret reaches the popup DOM

**The fill, from 4.4.1** — `tests/extension-fill.mjs` drives `fill.js`, the
function both popups inject, against a real login form:

- the visible username and password fields are filled
- a hidden honeypot, a disabled field and a readonly field are not
- the value is written through `HTMLInputElement.prototype`'s setter, so a
  framework that owns the property receives it rather than swallowing it
- `input` and `change` both fire

The fixture puts the honeypot first in document order and gives the real field
an own-property `value` accessor that discards writes, so dropping the
visibility filter and reverting to `element.value =` each fail the test. Both
survived an earlier fixture, which is how 4.4.1's defect reached a release.

The suite also `cmp`s the two `fill.js` copies and requires each popup to
inject the shared function by name, because a fill duplicated inline in two
popups is exactly what drifted.

**The picker, from 4.6.0** — `tests/extension-menu.mjs` drives the whole
feature in Chromium: a real login form served over http, the real content
script, the real extension-origin iframe, the real native host, and a real
vault. Including the native-messaging round trip, which is new.

- the menu opens on focus and is served from `chrome-extension://…/menu.html`
- the account list is not in the page's DOM, and the picker's shadow host stays
  closed to page script
- a synthetic Enter fills nothing; a real one fills
- arrow keys and Enter fill; Escape dismisses
- an https-bound record is not offered on an http page, and cannot be chosen
  through the menu's own channel either
- a login field in a cross-origin iframe is offered nothing, and is not filled
- page script cannot reach the extension's message channel at all
- a menu loaded with a nonce the background never issued lists nothing

Six mutants, each killed by its own assertion: the trusted-event gate removed,
the top-frame refusal removed, the list rendered into the page, an unoffered
record made choosable, the fill-time hostname re-read dropped, the shadow root
opened. The cross-origin refusal was mutated in two steps on purpose — first
with the content script allowed into every frame and the background check
intact, which still refused, and then with both removed, which did not. A guard
that is only ever shadowed by another guard is not known to work.

That pass also corrected the test rather than the code once. The check that the
page cannot read the list read `outerHTML`, which does not see into a closed
shadow root, so a list rendered into one would have passed a test claiming to
prove the opposite. The replacement is the real attack — a page that patches
`attachShadow` before anything else runs — and it comes back empty, because a
content script runs in an isolated world with its own `Element.prototype`.

**Still not reached, and still not pending.** The native-messaging round trip
through *the popup*. `chrome.action.openPopup()` works under headless Chromium
and the popup can be attached to and driven, but it cannot obtain `activeTab`:
that permission is granted by a genuine user gesture on the toolbar action, and
a debugger-synthesised call is not one, so `tabs.query` returns a tab with an id
and no URL. This is a Chromium design decision, not a gap to engineer around.
The popup's hostname verification therefore keeps its CLI-level coverage —
which tests the decision, the part that can be wrong — and the fill it guards
is covered in a browser.

The picker reaches the host in the test above precisely because it does not use
`activeTab`: a content script and an extension-origin iframe need no such
grant. So the round trip is now covered for the path that could carry it, and
the popup's remains a recorded boundary rather than a hole that was quietly
worked around.

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

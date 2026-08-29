# Sans Password Manager browser extension

This folder contains one extension codebase for Chrome, Chromium, Edge, Brave,
Opera, Vivaldi, and Firefox desktop. It lists only accounts bound to the active
tab's exact hostname and fills only the account you explicitly choose.

## Recommended: guided one-command setup

```bash
./browser-extension-universal/setup.sh
```

The setup command detects your browser, builds the correct extension, registers
the native host, opens the browser's extension page and the prepared folder,
and prints the final three clicks. Nothing needs to be copied back into the
terminal.

To select a browser explicitly:

```bash
./browser-extension-universal/setup.sh --browser chrome
./browser-extension-universal/setup.sh --browser firefox
```

Use `--no-open` on a remote machine or when you only want to prepare the files.
Run `setup.sh --help` for the supported browser names.

The command leaves the browser on its extensions page. In Chrome, turn on
**Developer mode** at the top right, then choose **Load unpacked** at the top
left and select the folder the command printed:

![Chrome Extensions with Developer mode enabled and the Load unpacked button visible](../docs/screenshots/browser-extension-setup/chrome-load-unpacked.png)

This screenshot was captured in Chrome 151 with a disposable empty profile. It
contains no account, browsing, vault, or credential data.

The Chromium build carries a public development key that gives unpacked copies
the stable ID `infdncbkefpjncplegccokcfpiicadlo`. This is not a secret or a
signing credential; it only removes the old copy-ID-and-run-another-command
loop. Browser store signing remains separate. `extension-id.sh` derives that ID
from the manifest key exactly as the browser does, so the registration can
never drift from the identity the browser actually assigns.

### Upgrading from an earlier unpacked install

Earlier unpacked builds carried no key, so the browser derived the ID from the
directory path and every machine got a different one. Adding the key changes
that ID, and the browser treats the result as a separate extension. Remove the
previously loaded SPM entry from the extensions page before loading the new
one; otherwise the stale copy stays installed and its native-host registration
no longer matches. Re-running `install-host.sh` also rewrites any Chromium
manifest that was registered against an old ID.

## Manual installation

The guided flow is recommended. These steps remain available for
troubleshooting. Both variants are produced by `build.sh`, which writes the
generated `dist/chromium/` and `dist/firefox/` directories. That output is
local and is not committed.

```bash
./browser-extension-universal/build.sh chromium
./browser-extension-universal/build.sh firefox
```

### Chromium-family installation

1. Build the Chromium variant.
2. Open the browser's extensions page (`chrome://extensions`,
   `edge://extensions`, `brave://extensions`, or the equivalent).
3. Enable Developer mode and choose **Load unpacked**. Select
   `browser-extension-universal/dist/chromium`.
4. Register the native host, then fully restart the browser:

   ```bash
   ./browser-extension-universal/install-host.sh
   ```

### Firefox desktop installation

1. Build the Firefox variant.
2. Open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
   Add-on**, and select `dist/firefox/manifest.json`.
3. Register the Firefox native host:

   ```bash
   ./browser-extension-universal/install-host.sh
   ```
4. Fully restart Firefox. Temporary add-ons must be loaded again after a
   Firefox restart; signed distribution is required for permanent installation.

## The boundary

The extension talks to SPM through one native-messaging host, and that host is
a contract rather than a pipe. Two halves:

**Inbound.** Four actions exist — `unlock`, `lock`, `list`, `get` — and an
action not named in the host's table is refused. The extension never chooses
what SPM command runs: each branch names a literal `bridge-*` command, so
there is no path from a message to an arbitrary CLI invocation. A hostname is
validated against a pattern and a record id must be digits.

**Outbound.** A response is *projected* onto the fields the action declares,
never forwarded:

| Action | Returns |
|---|---|
| `unlock` | `ok` only — the verdict, not the list used to reach it |
| `lock` | `ok` |
| `list` | `matches`, each row reduced to `id`, `label`, `username`, `url` |
| `get` | `username`, `password` |

This is the half worth having. `bridge-get` returns a username and a password
today; if it ever returns a note, a URL or a TOTP seed, that field cannot reach
the extension without someone editing the table — which is the review the
boundary exists to force. Forwarding whatever the CLI printed made the
extension's view of the vault whatever the CLI happened to print, which is not
a contract.

Failures are chosen from a fixed set of messages rather than echoed. An
unexpected error becomes a generic refusal, because a message like
`gpg: /home/you/.spm_vault.gpg: decryption failed` carries a filesystem path
across a boundary whose entire purpose is that nothing crosses unnamed.

**What the boundary does not do.** The original one-shot extension, still in
this repository, sends the master password with every `get` and holds no
session. That path is kept so it does not break, and it is not constrained by
**Lock** or by either timeout — a caller supplying the password directly has no
session for them to act on. That is a property of a one-shot protocol, not
something this table can close. The popup in this folder never sends the master
password except to `unlock`.

## Use

Open an HTTP(S) login page, select the SPM toolbar icon, enter the master
password once, and choose a matching account. The native host keeps the master
password only in process memory. **Lock SPM** discards it immediately. It is
also discarded after five idle minutes, after twelve total hours, when the
native connection ends, or when the browser closes.

Matching is exact. `example.com` does not match `login.example.com`. The CLI
re-verifies the hostname again when the chosen credential is retrieved.

Safari and iOS browsers are not supported: Safari requires a signed Xcode app
wrapper and iOS browsers do not expose this native-messaging extension model.
Use the installable SPM Dashboard web app on iOS.

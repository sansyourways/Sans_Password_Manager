# Sans Password Manager browser extension

This folder contains one extension codebase for Chrome, Chromium, Edge, Brave,
Opera, Vivaldi, and Firefox desktop. It lists only accounts bound to the active
tab's exact hostname and fills only the account you explicitly choose.

## Build the unpacked extension

```bash
./browser-extension-universal/build.sh chromium
./browser-extension-universal/build.sh firefox
```

The commands create `dist/chromium/` and `dist/firefox/`. These generated
directories are local build output and are not committed.

## Chromium-family installation

1. Build the Chromium variant.
2. Open the browser's extensions page (`chrome://extensions`,
   `edge://extensions`, `brave://extensions`, or the equivalent).
3. Enable Developer mode and choose **Load unpacked**. Select
   `browser-extension-universal/dist/chromium`.
4. Copy the extension ID shown by the browser.
5. Register the native host, then fully restart the browser:

   ```bash
   ./browser-extension-universal/install-host.sh YOUR_32_CHARACTER_EXTENSION_ID
   ```

## Firefox desktop installation

1. Build the Firefox variant.
2. Open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
   Add-on**, and select `dist/firefox/manifest.json`.
3. Register the Firefox native host without a Chromium ID:

   ```bash
   ./browser-extension-universal/install-host.sh
   ```
4. Fully restart Firefox. Temporary add-ons must be loaded again after a
   Firefox restart; signed distribution is required for permanent installation.

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

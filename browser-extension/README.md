# Browser bridge

Load this directory as an unpacked Chrome/Chromium extension, copy the generated
extension ID into `xyz.sansyourways.spm.json`, replace the native-host path with
an absolute path, and install that manifest in the browser's native-messaging
host directory.

Autofill is deliberately explicit: the popup asks for a record ID and master
password for each request. `spm bridge-get` releases a credential only when the
current hostname exactly matches the record label or an `http(s)` hostname in
its notes. The bridge cannot list or dump the vault and does not retain the
master password between requests.

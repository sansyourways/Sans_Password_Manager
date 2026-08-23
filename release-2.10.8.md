# Sans Password Manager 2.10.8

A fix release for the domain/HTTPS bind added in 2.10.7, found by running it
against a Cloudflare-proxied subdomain.

Certificate issuance now fails fast and says why. Before calling certbot, SPM
fetches the challenge file through the public internet exactly the way Let's
Encrypt will, and reports what actually came back:

- **Cloudflare's "Always Use HTTPS"** redirects the plain-HTTP ACME challenge to
  HTTPS, where the certificate does not exist yet, so the request cannot
  succeed
- **Bot Fight Mode, Browser Integrity Check and WAF** answer the validator with
  a challenge page it cannot solve

Both previously surfaced only as certbot's bare `unauthorized`, after the
attempt had already been spent against the Let's Encrypt rate limit. SPM now
names the setting and the fix — a Configuration Rule exempting
`/.well-known/acme-challenge/*`, or DNS-only mode during issuance.

Also fixed:

- A name with no A record no longer marches into a doomed certificate request;
  the flow reports the missing record and stops
- The reachability probe retries, because `systemctl reload` returns before the
  new nginx workers are serving and a single probe can be answered by the old
  configuration
- Guarded a `dig | grep` pipeline that exits non-zero when a name does not
  resolve. Under `pipefail` that failed the assignment; every current call site
  runs with `errexit` suppressed, so it hid rather than crashed, but it would
  have taken down any caller that did not.

There are no vault-format, encryption, or CLI behavior changes.

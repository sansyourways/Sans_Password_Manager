# Sans Password Manager 2.10.9

The domain flow can now prove ownership with a **DNS TXT record** through the
Cloudflare API instead of a file served over HTTP.

This is what makes the feature work behind a CDN. An HTTP-01 challenge has to
survive whatever sits in front of your origin — "Always Use HTTPS" redirects it
to a certificate that does not exist yet, and bot protection or a WAF rule
answers Let's Encrypt's validator with a challenge page it cannot solve. A DNS
lookup cannot be interfered with by any of that.

- DNS validation is the **default when the domain is proxied through
  Cloudflare**; HTTP stays the default for a plain DNS record
- It runs in **two phases instead of three**: no HTTP vhost is installed at
  all, so an existing live site is untouched until the certificate is in hand
- It certifies a name whose **A record does not exist yet** — only the TXT
  record matters for validation
- **Renewals are unattended** and unaffected by any later CDN setting change

The Cloudflare API token is read with hidden input and written straight to
`~/.config/spm/cloudflare.ini` at mode `0600`. It never reaches the terminal,
the shell history, or the process list. SPM asks for a token scoped to exactly
`Zone → Zone → Read` and `Zone → DNS → Edit`; anything broader would let
whatever holds that file repoint your entire domain.

Keep that file — certbot reads it again at every renewal.

Only Cloudflare is wired up. Other DNS providers have certbot plugins, but SPM
does not drive them yet.

There are no vault-format, encryption, or CLI behavior changes.

# Sans Password Manager 2.10.7

Web Mode can now publish itself on your own domain over HTTPS.

Choosing bind option **4) Domain/subdomain with HTTPS** puts nginx in front of
the vault: SPM writes the vhost, obtains a Let's Encrypt certificate with
`certbot --webroot`, reloads nginx, and binds the vault to `127.0.0.1` so the
network can only reach it through the proxy.

- Setup runs in three phases, because nginx must already answer on port 80 to
  serve the ACME challenge while a TLS server block naming a certificate that
  does not exist yet fails `nginx -t`
- Every install is validated with `nginx -t` and rolled back to whatever was
  there before on failure, so a bad generate cannot take down other sites
  sharing the host
- `SPM_ACME_DRY_RUN=1` exercises the whole challenge path without spending a
  certificate against the rate limit, and restores the previous vhost afterwards
- The generated vhost adds HSTS only; the vault already sends
  `X-Frame-Options`, `nosniff`, `Referrer-Policy` and a CSP on every response,
  and browsers may ignore a duplicated `X-Frame-Options` rather than honour it
- `listen ... http2` was deprecated in nginx 1.25.1, so the separate directive
  is emitted when the running nginx is new enough

If the domain is proxied through Cloudflare, saying so changes the generated
configuration rather than only printing a message, and requires typing a
confirmation first:

- Cloudflare terminates TLS at its edge and can read every request in
  plaintext, including the login POST carrying your master password.
  End-to-end encryption requires DNS-only mode (grey cloud).
- A `set_real_ip_from` snippet is installed so nginx sees the visitor address
  from `CF-Connecting-IP` rather than a Cloudflare edge address
- Cloudflare's Universal SSL covers the apex and one subdomain level only, so a
  `www.` alias on an already-nested subdomain has no certificate at the edge.
  SPM detects this and offers to drop the alias instead of publishing a name
  browsers cannot reach.

`docs/PRIVACY_POLICY.md` and `docs/SECURITY.md` record what the flow sends to
Let's Encrypt, that issued certificates make the hostname permanently
searchable in Certificate Transparency logs, and what publishing on a domain
does to the trust boundary.

There are no vault-format, encryption, or CLI behavior changes.

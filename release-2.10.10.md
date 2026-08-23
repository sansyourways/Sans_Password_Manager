# Sans Password Manager 2.10.10

A follow-up fix to 2.10.9: writes from an iPhone **home-screen web app** still
failed with `403 Cross-origin write rejected`.

Safari sends `Origin: null` for a standalone web app's own same-origin form
posts. The check added in 2.10.9 treated any non-empty `Origin` as a real
origin to compare against `Host`, so it took the strict path and refused before
ever looking at the CSRF token.

`null` is an **opaque** origin. It means the browser will not name the sender —
not that the sender is foreign. It is now treated like an absent origin, so the
per-session CSRF token decides. That is safe: a sandboxed or cross-origin
context cannot read the token, which is the whole reason the token exists.

Confirmed from the live request that failed:

```
POST spm.example.com/add origin="null" ua="...iPhone...Safari/604.1" -> 403
```

Verified after the fix, against a throwaway vault:

| Case | Result |
| --- | --- |
| `Origin: null` + valid token (the web app) | accepted |
| `Origin: null` + no token | rejected |
| `Origin: null` + wrong token | rejected |
| no `Origin` + valid token | accepted |
| foreign `Origin` + valid token | rejected |
| matching `Origin`, no token | accepted |

There are no vault-format, encryption, or CLI behavior changes.

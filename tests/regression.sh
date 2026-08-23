#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spm-regression.XXXXXX")"
GPG_TEST_HOME="$(mktemp -d /tmp/spm-gnupg.XXXXXX)"
WEB_PID=""
WEB_PORT=$((18000 + ($$ % 10000)))

cleanup() {
	if [ -n "$WEB_PID" ]; then
		kill "$WEB_PID" 2>/dev/null || true
		wait "$WEB_PID" 2>/dev/null || true
	fi
	gpgconf --kill gpg-agent >/dev/null 2>&1 || true
	rm -rf "$TEST_ROOT"
	rm -rf "$GPG_TEST_HOME"
}
trap cleanup EXIT INT TERM

export HOME="$TEST_ROOT/home"
export XDG_CONFIG_HOME="$TEST_ROOT/config"
export XDG_DATA_HOME="$TEST_ROOT/data"
export PASSWORD_VAULT="$TEST_ROOT/vault.gpg"
export GNUPGHOME="$GPG_TEST_HOME"
mkdir -p "$HOME" "$XDG_CONFIG_HOME/spm" "$XDG_DATA_HOME"
chmod 700 "$GNUPGHOME"
gpgconf --launch gpg-agent

AUDIT_PASSWORD="SPM-Regression-Only-42"
PLAIN="$TEST_ROOT/plain"
printf 'META_RECOVERY_PUBKEY\tdGVzdA==\t-\t-\t-\t-\n1\tExample\tuser@example.invalid\tDemoSecret42\thttps://example.invalid\t2025-01-01T00:00:00Z\nNOTE\t1\tMemo\taGVsbG8gbm90ZQ==\t2025-01-01T00:00:00Z\t-\nPASSPHRASE\t1\tWords\taG9yc2UtYmF0dGVyeQ==\t2025-01-01T00:00:00Z\t-\nBACKUP_CODE\t1\tCodes\tY29kZTEKY29kZTI=\t2025-01-01T00:00:00Z\t-\nAUTH\t1\tOTP\tJBSWY3DPEHPK3PXP\t30\t2025-01-01T00:00:00Z\tsha1\n' > "$PLAIN"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$PASSWORD_VAULT" "$PLAIN"

# Load functions without executing main. A real temporary file avoids the
# process-substitution truncation seen with Bash 3 and BSD sed on macOS.
SPM_LIBRARY="$TEST_ROOT/spm-library.sh"
sed '$d' "$ROOT_DIR/spm.sh" > "$SPM_LIBRARY"
# shellcheck source=/dev/null
source "$SPM_LIBRARY"
export MASTER_PW="$AUDIT_PASSWORD"
export SPM_LANG="en"

TERMUX_VERSION="regression" detect_env
[ "$ENV_FLAVOR" = "termux" ]
[ "$PKG_TYPE" = "pkg" ]
unset TERMUX_VERSION
detect_env

numeric="$(generate_password 24 numeric 1 1 1 1)"
printf '%s' "$numeric" | grep -Eq '^[0-9]{24}$'
secure="$(generate_password 24 secure 1 1 1 1)"
[ "$(printf '%s' "$secure" | wc -c)" -eq 24 ]
cmd_security_dashboard | grep -q '^Score:'

formats='csv json tsv ndjson jsonl md html txt yaml yml xml sql ini psv rst toml org scsv csv-noheader jsonc'
for format in $formats; do
	export_file="$TEST_ROOT/export.$format"
	cmd_export "$format" "$export_file" >/dev/null
	cp "$PASSWORD_VAULT" "$TEST_ROOT/import-$format.gpg"
	export VAULT_FILE="$TEST_ROOT/import-$format.gpg"
	export RECOVERY_FILE="$VAULT_FILE.recovery"
	cmd_import "$format" "$export_file" >/dev/null
	verify_file="$TEST_ROOT/verify-$format"
	decrypt_vault_to_file "$verify_file"
	count="$(awk -F '\t' '$1~/^[0-9]+$/||$1=="NOTE"||$1=="PASSPHRASE"||$1=="BACKUP_CODE"||$1=="AUTH"{n++}END{print n+0}' "$verify_file")"
	[ "$count" -eq 10 ]
	secure_wipe "$verify_file"
	export VAULT_FILE="$PASSWORD_VAULT"
	export RECOVERY_FILE="$VAULT_FILE.recovery"
done

printf 'synthetic attachment\n' > "$TEST_ROOT/attachment.txt"
cmd_attachment_add "$TEST_ROOT/attachment.txt" Regression >/dev/null
cmd_attachment_extract 1 "$TEST_ROOT/extracted.txt" >/dev/null
cmp "$TEST_ROOT/attachment.txt" "$TEST_ROOT/extracted.txt"
cmd_passkey_add example.invalid demo credential-id synthetic >/dev/null
cmd_passkey_list | grep -q 'example.invalid'
backup_path="$(cmd_backup_now "$TEST_ROOT/backups")"
cmp "$PASSWORD_VAULT" "$backup_path"
cmd_sync push "$TEST_ROOT/sync" regression >/dev/null
cmp "$PASSWORD_VAULT" "$TEST_ROOT/sync/spm-regression.gpg"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out "$TEST_ROOT/private.pem" >/dev/null 2>&1
openssl pkey -in "$TEST_ROOT/private.pem" -pubout \
	-out "$TEST_ROOT/public.pem" >/dev/null 2>&1
cmd_emergency_create 1 "$TEST_ROOT/public.pem" 2020-01-01 \
	"$TEST_ROOT/emergency.tar.gz" >/dev/null
cmd_emergency_open "$TEST_ROOT/emergency.tar.gz" "$TEST_ROOT/private.pem" \
	"$TEST_ROOT/emergency.json" >/dev/null
grep -q 'DemoSecret42' "$TEST_ROOT/emergency.json"

# Auto-update preference. It must stay opt-in: the privacy policy states that
# network activity happens only for features the user initiates, so a default
# of anything but "off" would make that claim untrue.
[ "$(autoupdate_mode)" = "off" ]
autoupdate_put MODE notify
[ "$(autoupdate_mode)" = "notify" ]
autoupdate_put MODE auto
[ "$(autoupdate_mode)" = "auto" ]
autoupdate_put MODE nonsense
[ "$(autoupdate_mode)" = "off" ]
autoupdate_put MODE off

# Installer PATH mutation must be path-specific and macOS Bash must use the
# login-shell profile even when it does not exist yet.
INSTALL_LIBRARY="$TEST_ROOT/install-library.sh"
sed -n '1,111p' "$ROOT_DIR/install.sh" > "$INSTALL_LIBRARY"
# shellcheck source=/dev/null
source "$INSTALL_LIBRARY"
SHELL=/bin/bash
uname() { printf 'Darwin\n'; }
[ "$(profile_for_shell)" = "$HOME/.bash_profile" ]
uname() { printf 'Linux\n'; }
PATH=/usr/bin:/bin
ensure_on_path "$TEST_ROOT/first prefix/bin" >/dev/null
ensure_on_path "$TEST_ROOT/second-prefix/bin" >/dev/null
grep -Fqx "export PATH='$TEST_ROOT/first prefix/bin':\$PATH" "$HOME/.bashrc"
grep -Fqx "export PATH='$TEST_ROOT/second-prefix/bin':\$PATH" "$HOME/.bashrc"
unset -f uname

# Password generation must fail closed instead of falling back to Bash's small,
# predictable $RANDOM generator.
if sed -n '/_spm_rand_below()/,/^}/p' "$ROOT_DIR/spm.sh" | grep -q 'RANDOM %'; then
	printf 'password generation still falls back to predictable $RANDOM\n' >&2
	exit 1
fi
# Python before 3.11 has no tomllib; the importer must carry a local fallback.
grep -q 'except ModuleNotFoundError:' "$ROOT_DIR/spm.sh"
grep -q 'Invalid TOML key' "$ROOT_DIR/spm.sh"
[ "$(stat -c '%a' "$SPM_AUTOUPDATE_FILE" 2>/dev/null || stat -f '%Lp' "$SPM_AUTOUPDATE_FILE")" = "600" ]

# String comparison is not enough here: 2.10.10 sorts before 2.10.9 lexically,
# so a lexical check would stop offering updates after the ninth patch.
version_is_newer 2.10.7 2.10.6
version_is_newer 2.10.10 2.10.9
version_is_newer 2.11.0 2.10.99
if version_is_newer 2.10.6 2.10.6; then
	printf 'version_is_newer reported an equal version as newer\n' >&2
	exit 1
fi
if version_is_newer 2.9.6 2.10.0; then
	printf 'version_is_newer mis-ordered a minor bump\n' >&2
	exit 1
fi

# Being off, non-interactive, or offline must never block access to the vault.
autoupdate_put MODE off
autoupdate_startup_check </dev/null
autoupdate_put MODE notify
autoupdate_put LAST_CHECK 0
autoupdate_startup_check </dev/null
autoupdate_put LAST_CHECK not-a-number
autoupdate_put INTERVAL garbage
autoupdate_startup_check </dev/null
autoupdate_put MODE off

# The updater must never overwrite its target in place: Bash reads a script
# lazily, so replacing bytes under a running instance can execute garbage.
if grep -qE '(sudo )?cp "\$new_spm" "\$target"' "$ROOT_DIR/spm.sh"; then
	printf 'cmd_update still writes over the install target in place\n' >&2
	exit 1
fi
grep -q 'mv -f "$staged" "$target"' "$ROOT_DIR/spm.sh"

# Web Mode domain/TLS binding. These exercise the generators only -- nothing
# here touches /etc/nginx, runs certbot, or reaches the network.
domain_is_valid vault.example.com
domain_is_valid example.co.uk
if domain_is_valid "not a domain"; then
	printf 'domain_is_valid accepted a string with spaces\n' >&2
	exit 1
fi
if domain_is_valid "http://example.com/path"; then
	printf 'domain_is_valid accepted a URL\n' >&2
	exit 1
fi

vhost_http="$(domain_render_vhost "vault.example.com www.vault.example.com" 8777 0 http)"
printf '%s' "$vhost_http" | grep -q 'server_name vault.example.com www.vault.example.com;'
printf '%s' "$vhost_http" | grep -q 'location /.well-known/acme-challenge/'
# Phase one runs before any certificate exists, so a TLS block here would make
# "nginx -t" fail and take the whole reload down with it.
if printf '%s' "$vhost_http" | grep -q 'listen 443'; then
	printf 'the pre-certificate vhost already references TLS\n' >&2
	exit 1
fi
if printf '%s' "$vhost_http" | grep -q 'ssl_certificate'; then
	printf 'the pre-certificate vhost references a certificate that cannot exist yet\n' >&2
	exit 1
fi

vhost_tls="$(domain_render_vhost "vault.example.com www.vault.example.com" 8777 0 https)"
printf '%s' "$vhost_tls" | grep -q 'ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;'
printf '%s' "$vhost_tls" | grep -q 'return 301 https://\$host\$request_uri;'
printf '%s' "$vhost_tls" | grep -q 'add_header Strict-Transport-Security'
# The vault must stay on loopback behind the proxy; a public bind here would
# expose it beside nginx rather than behind it.
printf '%s' "$vhost_tls" | grep -q 'proxy_pass http://127.0.0.1:8777;'
# Without this the server cannot tell it is behind TLS and drops the Secure
# flag from the session cookie.
printf '%s' "$vhost_tls" | grep -q 'proxy_set_header X-Forwarded-Proto \$scheme;'
# The vault already sends these on every response. Sending them again from
# nginx duplicates the header, and browsers may then ignore X-Frame-Options
# outright instead of honouring it.
for header in X-Frame-Options X-Content-Type-Options Referrer-Policy; do
	if printf '%s' "$vhost_tls" | grep -q "add_header $header"; then
		printf 'vhost duplicates the %s header the vault already sends\n' "$header" >&2
		exit 1
	fi
done
if printf '%s' "$vhost_tls" | grep -q 'spm-cloudflare-realip'; then
	printf 'a DNS-only vhost trusts Cloudflare forwarded addresses\n' >&2
	exit 1
fi

# dig|grep exits 1 when a name has no A record. Under pipefail that failed the
# assignment, and every real call site happens to run with errexit suppressed,
# so the bug hid rather than crashed. Keep the guard.
grep -qE 'dig \+short A .* \|\| true' "$ROOT_DIR/spm.sh"
# A name that does not resolve cannot be certified, and failed validations
# count against the rate limit, so the flow must stop rather than call certbot.
grep -q 'That name cannot be certified until it resolves' "$ROOT_DIR/spm.sh"
# Cloudflare's "Always Use HTTPS" redirects the HTTP-01 challenge to a
# certificate that does not exist yet, and its bot challenge answers the
# validator with an interstitial. Both must be named, not left to certbot's
# "unauthorized".
grep -q 'domain_preflight_challenge' "$ROOT_DIR/spm.sh"
grep -q 'Always Use HTTPS' "$ROOT_DIR/spm.sh"
grep -q '/.well-known/acme-challenge/\*' "$ROOT_DIR/spm.sh"
# "systemctl reload" returns before the new workers serve, so a single probe
# can be answered by the old configuration and report a false failure.
grep -q 'for attempt in 1 2 3 4 5; do' "$ROOT_DIR/spm.sh"
# Failure to stage the probe is a failed preflight, never permission to spend an
# ACME attempt without evidence that the challenge path works.
if grep -q 'sudo mkdir -p "\$dir" || return 0' "$ROOT_DIR/spm.sh" ||
	grep -q 'sudo tee "\$dir/\$token" >/dev/null || return 0' "$ROOT_DIR/spm.sh"; then
	printf 'ACME probe setup still fails open\n' >&2
	exit 1
fi
grep -q 'domain_restore_vhost "\$domain" "\$prior" "\$had_available" "\$enabled_target"' "$ROOT_DIR/spm.sh"
grep -q "Type 'replace' to continue" "$ROOT_DIR/spm.sh"

# DNS-01. Behind a CDN the HTTP challenge has to survive the edge's redirect
# and bot rules; a TXT record bypasses all of it, so the generator must be able
# to ask certbot for DNS validation instead.
grep -q 'domain_dns01_available' "$ROOT_DIR/spm.sh"
grep -q -- '--dns-cloudflare-credentials' "$ROOT_DIR/spm.sh"
# The token must never reach the terminal, the shell history or the process
# list, so it is read with -s and written straight to a 0600 file.
grep -q 'read -rs token' "$ROOT_DIR/spm.sh"
grep -qF 'chmod 0600 "$SPM_CF_CREDENTIALS"' "$ROOT_DIR/spm.sh"
# DNS validation needs no reachable port 80, so it must not install the
# phase-one HTTP vhost -- that is what makes it safe against a live domain.
grep -q 'Phase 1/2: proving ownership with a DNS TXT record' "$ROOT_DIR/spm.sh"
grep -q 'Phase 2/2: enabling TLS and the reverse proxy' "$ROOT_DIR/spm.sh"
# A name with no A record can still be certified over DNS-01.
grep -q 'DNS validation does not need an A record' "$ROOT_DIR/spm.sh"

# certbot picks the lineage directory from the name set unless it is pinned, so
# an unpinned request can land in <domain>-0001 while the vhost still points at
# <domain> and nginx then fails to start.
grep -q -- '--cert-name "\${names%% \*}"' "$ROOT_DIR/spm.sh"
# A dry run must stop before the TLS rewrite: no certificate exists after one,
# and phase three would fail validation.
grep -q 'Dry run complete: the %s challenge works' "$ROOT_DIR/spm.sh"
# /etc/letsencrypt/live is mode 0700, so an unprivileged -f test reports every
# certificate as missing.
grep -q 'sudo test -f "/etc/letsencrypt/live/\$domain/fullchain.pem"' "$ROOT_DIR/spm.sh"

web_script="$(write_spm_web_script)"
grep -q 'locking = false' "$web_script"
grep -q 'window.location.replace("/logout")' "$web_script"
grep -q '!event.persisted || locking' "$web_script"
# A restore from the back/forward cache must honour the surviving deadline
# rather than resetting it, or Back would hand back an unlocked vault.
grep -q 'Date.now() >= deadline' "$web_script"
if grep -q 'window.location.href = "/logout"' "$web_script"; then
	printf 'legacy repeating auto-lock navigation is still present\n' >&2
	exit 1
fi
if grep -q 'pagehide".*once: true' "$web_script"; then
	printf 'pagehide teardown is one-shot and will leak after a bfcache round trip\n' >&2
	exit 1
fi
grep -q -- '--motion-base: 200ms' "$web_script"
grep -q 'rel="apple-touch-icon"' "$web_script"
grep -q 'rel="manifest" href="/manifest.webmanifest"' "$web_script"
grep -q 'APP_ICON_PNG = base64.b64decode' "$web_script"
# The mobile sidebar is position:fixed, so it needs its own safe-area inset,
# and height:100vh measures the largest viewport on iOS rather than the visible
# one, which pushed the vault chip and logout button off the bottom.
grep -q 'height: 100dvh' "$web_script"
grep -q 'padding-bottom: calc(var(--sp-4) + env(safe-area-inset-bottom))' "$web_script"
grep -q 'prefers-reduced-motion:reduce' "$web_script"
# Safari omits Origin on same-origin form submissions, so an Origin-only check
# rejected every authenticated write from an iPhone with a 403. Referer cannot
# cover the gap because this server sends Referrer-Policy: no-referrer, so a
# per-session CSRF token carries the check and Origin is the second layer.
grep -q '"csrf": secrets.token_hex(32)' "$web_script"
grep -q 'def _write_authorized' "$web_script"
grep -q 'hmac.compare_digest' "$web_script"
# Stamped centrally in _send_html so a form added later cannot ship untokenised.
grep -q '_POST_FORM_RE' "$web_script"
# "null" is an opaque origin, not a foreign one. iOS home-screen web apps send
# it for their own same-origin form posts, so treating it as present-and-wrong
# rejected every write from an installed web app even with a valid token.
grep -q 'origin.lower() != "null"' "$web_script"
if grep -q 'if not self._same_origin_post():' "$web_script"; then
	printf 'authenticated writes still gate on Origin alone\n' >&2
	exit 1
fi
grep -q 'self.auth_lock = threading.RLock()' "$web_script"
grep -q 'X-Real-IP' "$web_script"
grep -q '_sweep_login_failures_locked' "$web_script"
grep -q 'Stored passphrase cannot be decoded; vault was not changed' "$web_script"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 -m py_compile \
	"$web_script" "$ROOT_DIR/browser-extension/native_host.py"
SPM_VAULT_PATH="$PASSWORD_VAULT" SPM_WEB_BIND=127.0.0.1 \
	SPM_WEB_PORT="$WEB_PORT" SPM_VERSION="$VERSION" python3 "$web_script" \
	>"$TEST_ROOT/web.log" 2>&1 &
WEB_PID="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	curl -fsS -o "$TEST_ROOT/login.html" "http://127.0.0.1:$WEB_PORT/login" 2>/dev/null && break
	sleep 0.25
done
grep -q 'Sans Password Manager' "$TEST_ROOT/login.html"
grep -q 'rel="apple-touch-icon"' "$TEST_ROOT/login.html"

# The icon routes are deliberately fetched with no session cookie. Unknown
# paths fall through to the login gate, which answers HTTP 200 with the login
# page, so a misplaced route would serve HTML to iOS and it would go back to
# screenshotting the page instead of showing the mark.
for icon_path in /apple-touch-icon.png /apple-touch-icon-precomposed.png /favicon.ico; do
	curl -fsS -D "$TEST_ROOT/icon.headers" -o "$TEST_ROOT/icon.png" \
		"http://127.0.0.1:$WEB_PORT$icon_path"
	if ! grep -qi '^Content-Type: image/png' "$TEST_ROOT/icon.headers"; then
		printf '%s is not served as image/png (login gate leak?)\n' "$icon_path" >&2
		exit 1
	fi
	if [ "$(head -c 4 "$TEST_ROOT/icon.png" | od -An -tx1 | tr -d ' \n')" != "89504e47" ]; then
		printf '%s did not return PNG data\n' "$icon_path" >&2
		exit 1
	fi
done

curl -fsS -D "$TEST_ROOT/favicon.headers" -o "$TEST_ROOT/favicon.svg" \
	"http://127.0.0.1:$WEB_PORT/favicon.svg"
grep -qi '^Content-Type: image/svg+xml' "$TEST_ROOT/favicon.headers"
grep -q '#5fd095' "$TEST_ROOT/favicon.svg"

curl -fsS -D "$TEST_ROOT/manifest.headers" -o "$TEST_ROOT/manifest.json" \
	"http://127.0.0.1:$WEB_PORT/manifest.webmanifest"
grep -qi '^Content-Type: application/manifest+json' "$TEST_ROOT/manifest.headers"
python3 -c 'import json,sys; m=json.load(open(sys.argv[1])); assert m["display"]=="standalone", m["display"]; assert m["icons"][0]["src"]=="/apple-touch-icon.png"' \
	"$TEST_ROOT/manifest.json"

for _ in 1 2 3 4 5; do
	curl -sS -o /dev/null -X POST -H 'X-Real-IP: 198.51.100.10' \
		--data-urlencode 'password=definitely-wrong' "http://127.0.0.1:$WEB_PORT/login"
done
curl -fsS -D "$TEST_ROOT/login.headers" -c "$TEST_ROOT/cookies" -o /dev/null \
	-H 'X-Real-IP: 198.51.100.11' \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "password=$AUDIT_PASSWORD" "http://127.0.0.1:$WEB_PORT/login"
grep -q '302 Found' "$TEST_ROOT/login.headers"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/dashboard.html" \
	"http://127.0.0.1:$WEB_PORT/"
grep -q '<symbol id="i-brand"' "$TEST_ROOT/dashboard.html"
grep -q 'rel="apple-touch-icon"' "$TEST_ROOT/dashboard.html"
grep -q '<use href="#i-key"' "$TEST_ROOT/dashboard.html"
grep -q '<use href="#i-shield"' "$TEST_ROOT/dashboard.html"
grep -q '<use href="#i-logout"' "$TEST_ROOT/dashboard.html"
if grep -Eq '🔑|🗒|📝|⏱|🧯|✨|🗑|👁|📋' "$TEST_ROOT/dashboard.html"; then
	printf 'legacy emoji icon found in generated Web Mode dashboard\n' >&2
	exit 1
fi
# A blank secret on edit means preserve the existing passphrase. The prior bug
# indexed the filtered passphrase array with the absolute vault line number and
# silently replaced the secret with a random value.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/passphrase-edit.html" \
	"http://127.0.0.1:$WEB_PORT/passphrase-edit?id=1"
csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$TEST_ROOT/passphrase-edit.html" | head -n1)"
[ "${#csrf}" -eq 64 ]
curl -fsS -D "$TEST_ROOT/passphrase-edit.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST --data-urlencode "csrf=$csrf" --data-urlencode 'label=Renamed words' \
	--data-urlencode 'secret=' "http://127.0.0.1:$WEB_PORT/passphrase-edit?id=1"
grep -q '302 Found' "$TEST_ROOT/passphrase-edit.headers"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --quiet --pinentry-mode loopback \
	--passphrase-fd 0 --decrypt "$PASSWORD_VAULT" > "$TEST_ROOT/passphrase-after"
[ "$(awk -F '\t' '$1=="PASSPHRASE"&&$2==1{print $4}' "$TEST_ROOT/passphrase-after" | base64 -d)" = 'horse-battery' ]
printf 'type,id,label,username,secret,notes,created,extra\npassword,,Web import,demo,WebSecret42,synthetic,2026-01-01T00:00:00Z,\n' \
	> "$TEST_ROOT/import.csv"
curl -fsS -D "$TEST_ROOT/import.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" -F 'fmt=csv' \
	-F "file=@$TEST_ROOT/import.csv;type=text/csv" "http://127.0.0.1:$WEB_PORT/import"
grep -qi '^Location: /?msg=import-ok' "$TEST_ROOT/import.headers"

printf 'SPM regression suite passed (%s formats plus web and advanced features).\n' \
	"$(printf '%s\n' "$formats" | awk '{ print NF }')"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/spm-regression.XXXXXX")"
GPG_TEST_HOME="$(mktemp -d /tmp/spm-gnupg.XXXXXX)"
WEB_PID=""
WEB_PORT=$((18000 + ($$ % 10000)))

harness_cleanup() {
	local status="${1:-0}"
	if [ "$status" -ne 0 ] && [ -f "$TEST_ROOT/web.log" ]; then
		printf '\n--- SPM Dashboard regression log ---\n' >&2
		sed -n '1,240p' "$TEST_ROOT/web.log" >&2
	fi
	if [ -n "$WEB_PID" ]; then
		kill "$WEB_PID" 2>/dev/null || true
		wait "$WEB_PID" 2>/dev/null || true
	fi
	gpgconf --kill gpg-agent >/dev/null 2>&1 || true
	rm -rf "$TEST_ROOT"
	rm -rf "$GPG_TEST_HOME"
}
trap 'status=$?; harness_cleanup "$status"; exit "$status"' EXIT INT TERM

export HOME="$TEST_ROOT/home"
export XDG_CONFIG_HOME="$TEST_ROOT/config"
export XDG_DATA_HOME="$TEST_ROOT/data"
export PASSWORD_VAULT="$TEST_ROOT/vault.gpg"
export GNUPGHOME="$GPG_TEST_HOME"
mkdir -p "$HOME" "$XDG_CONFIG_HOME/spm" "$XDG_DATA_HOME"
chmod 700 "$GNUPGHOME"
gpgconf --launch gpg-agent

AUDIT_PASSWORD="SPM-Regression-Only-42"
TEST_RECOVERY_PRIVATE="$TEST_ROOT/recovery-private.pem"
TEST_RECOVERY_PUBLIC="$TEST_ROOT/recovery-public.pem"
openssl genrsa -out "$TEST_RECOVERY_PRIVATE" 2048 >/dev/null 2>&1
openssl rsa -in "$TEST_RECOVERY_PRIVATE" -pubout -out "$TEST_RECOVERY_PUBLIC" >/dev/null 2>&1
TEST_RECOVERY_B64="$(base64 <"$TEST_RECOVERY_PUBLIC" | tr -d '\n')"
PLAIN="$TEST_ROOT/plain"
printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n1\tExample\tuser@example.invalid\tDemoSecret42\thttps://example.invalid\t2025-01-01T00:00:00Z\nNOTE\t1\tMemo\taGVsbG8gbm90ZQ==\t2025-01-01T00:00:00Z\t-\nPASSPHRASE\t1\tWords\taG9yc2UtYmF0dGVyeQ==\t2025-01-01T00:00:00Z\t-\nBACKUP_CODE\t1\tCodes\tY29kZTEKY29kZTI=\t2025-01-01T00:00:00Z\t-\nAUTH\t1\tOTP\tJBSWY3DPEHPK3PXP\t30\t2025-01-01T00:00:00Z\tsha1\n' "$TEST_RECOVERY_B64" > "$PLAIN"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$PASSWORD_VAULT" "$PLAIN"

# Load the functions without executing main. The script guards its own entry
# point now, so this sources it directly -- no copy, and no `sed '$d'` that
# would silently start including real code the day anything follows the call
# to main.
export SPM_LIBRARY="$ROOT_DIR/spm.sh"
# shellcheck source=/dev/null
source "$SPM_LIBRARY"

# The application library installs its own cleanup traps. Restore the harness
# trap so failures retain the generated SPM Dashboard server log before disposal.
trap 'status=$?; harness_cleanup "$status"; exit "$status"' EXIT INT TERM

# The harness must not be able to reach a real vault. Everything above
# redirects HOME, XDG and PASSWORD_VAULT into $TEST_ROOT; assert that it
# actually took, because the failure mode here is not a failing test but an
# exclusive lock held on the operator's live vault.
case "$VAULT_FILE" in
	"$TEST_ROOT"/*) ;;
	*)
		printf 'harness isolation failed: VAULT_FILE=%s is outside %s\n' \
			"$VAULT_FILE" "$TEST_ROOT" >&2
		exit 1
		;;
esac
export MASTER_PW="$AUDIT_PASSWORD"
export SPM_LANG="en"

test_decrypt_vault() {
	local path="$1" password="$2" output="$3"
	(
		export VAULT_FILE="$path" MASTER_PW="$password" VAULT_KEY=""
		decrypt_vault_to_file "$output"
	)
}

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
original_path="$PATH"
PATH=/usr/bin:/bin
ensure_on_path "$TEST_ROOT/first prefix/bin" >/dev/null
ensure_on_path "$TEST_ROOT/second-prefix/bin" >/dev/null
grep -Fqx "export PATH='$TEST_ROOT/first prefix/bin':\$PATH" "$HOME/.bashrc"
grep -Fqx "export PATH='$TEST_ROOT/second-prefix/bin':\$PATH" "$HOME/.bashrc"
PATH="$original_path"
unset -f uname

# The installer must not assume the release tag equals the version string.
# Releases through 2.9.6 are tagged bare; everything from 2.10.11 on carries a
# leading "v". Reusing the v-stripped version as the tag made every download
# 404, including the default "latest" path, because tag_name comes back as
# "v2.11.2" and was stripped straight back to "2.11.2".
grep -q 'release_tag()' "$ROOT_DIR/install.sh"
grep -q 'for candidate in "v\$1" "\$1"' "$ROOT_DIR/install.sh"
if grep -q 'base_url="https://github.com/\$REPO/releases/download/\$VERSION"' "$ROOT_DIR/install.sh"; then
	printf 'install.sh still builds the download URL from the version rather than the tag\n' >&2
	exit 1
fi
grep -q 'No release asset found for' "$ROOT_DIR/install.sh"

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

# SPM Dashboard domain/TLS binding. These exercise the generators only -- nothing
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
# The iOS installed app can surface the SVG <use> as the tap target. Mobile
# navigation must therefore have direct listeners instead of depending on a
# delegated ev.target.closest() call reaching the surrounding button.
grep -q 'function wireMobileNav()' "$web_script"
grep -q 'trigger.addEventListener("click"' "$web_script"
grep -q 'scrim.addEventListener("click"' "$web_script"
grep -q 'aria-controls="mobile-navigation"' "$web_script"
if grep -q 'data-act="nav"' "$web_script"; then
	printf 'mobile navigation still depends on delegated data-act handling\n' >&2
	exit 1
fi
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

# The dashboard ships its three translation dictionaries as one inline
# <script>. They are written inside a plain Python triple-quoted string, so an
# escape intended for JavaScript is consumed by Python first: `\"` in the
# source reaches the browser as a bare quote, ends the JS string early, and
# takes the whole dictionary down with a SyntaxError. Nothing observable
# fails -- the page still renders, because every element carries an English
# fallback in its markup -- so the only symptom is that the language picker
# silently does nothing. That shipped, in every release that carried the
# string, and no test noticed. This parses what the browser is actually
# handed and checks the three languages against each other while it is there.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" <<'I18NPY'
import ast
import json
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()

# The dictionaries live inside a Python string literal, so the file on disk is
# one escaping level away from what the browser is handed: `\\"` in the source
# is correct Python for an emitted `\"`. Decoding the literal first is the
# whole point -- checking the raw source instead would pass the broken version
# and fail the fixed one.
literal = re.search(r'I18N_SCRIPT = (""".*?""")', source, re.S)
if not literal:
    sys.exit("I18N_SCRIPT literal was not found")
emitted = ast.literal_eval(literal.group(1))

match = re.search(r"const DICT = (\{.*?\n  \});", emitted, re.S)
if not match:
    sys.exit("the dashboard's DICT literal was not found")

# The literal is JavaScript, and it uses trailing commas, which JSON rejects.
# Dropping a comma only where the next line closes its object keeps this a
# check on quoting and escaping rather than on punctuation style -- and it
# cannot touch the inside of a value, because every value line ends `",`.
lines = match.group(1).split("\n")
for index in range(len(lines) - 1):
    if lines[index].rstrip().endswith(",") and lines[index + 1].lstrip()[:1] in "}]":
        lines[index] = lines[index].rstrip()[:-1]
try:
    dictionaries = json.loads("\n".join(lines))
except ValueError as exc:
    sys.exit("the dictionary the browser receives is not parseable: %s" % exc)

missing = {"en", "id", "ja"} - set(dictionaries)
if missing:
    sys.exit("translation dictionary is missing %s" % ", ".join(sorted(missing)))

english = set(dictionaries["en"])
for language in ("id", "ja"):
    absent = english - set(dictionaries[language])
    extra = set(dictionaries[language]) - english
    if absent:
        sys.exit("%s is missing %d key(s), e.g. %s"
                 % (language, len(absent), sorted(absent)[0]))
    if extra:
        sys.exit("%s has %d key(s) English does not, e.g. %s"
                 % (language, len(extra), sorted(extra)[0]))
print("  i18n: 3 languages, %d keys each, dictionary parses as delivered" % len(english))
I18NPY

# The hamburger exists at every width: under 900px it opens the drawer, above
# it collapses the sidebar to an icon rail. It was display:none until 900px,
# which left a desktop user pressing a control that was not there.
grep -q '\.menu-btn { display: inline-grid; }' "$web_script"
grep -q 'body\.rail' "$web_script"
if grep -qE 'transition:[^;]*\bwidth\b' "$web_script"; then
	printf 'a stylesheet transition still animates width; it relayouts every frame\n' >&2
	exit 1
fi
grep -q 'X-Real-IP' "$web_script"
grep -q '_sweep_login_failures_locked' "$web_script"
grep -q 'Stored passphrase cannot be decoded; vault was not changed' "$web_script"
# The 30-second auto-lock users see runs in the browser, so it protects nobody
# whose scripts fail to execute. The server-side idle expiry is the control
# that still holds in that case, and it silently used to be half an hour.
# [0-9][0-9]* rather than [0-9]\+ -- BSD sed has no \+ in a basic regex, and
# this suite runs on macOS in CI.
web_ttl="$(sed -n 's/^SESSION_TTL = \([0-9][0-9]*\)$/\1/p' "$web_script" | head -n1)"
[ -n "$web_ttl" ] || { printf 'SESSION_TTL not found in generated web script\n' >&2; exit 1; }
if [ "$web_ttl" -gt 300 ]; then
	printf 'server-side idle expiry is %ss; the browser lock cannot be the only fast one\n' \
		"$web_ttl" >&2
	exit 1
fi
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 -m py_compile \
	"$web_script" "$ROOT_DIR/browser-extension/native_host.py"
SPM_VAULT_PATH="$PASSWORD_VAULT" SPM_WEB_BIND=127.0.0.1 \
	SPM_WEB_PORT="$WEB_PORT" SPM_VERSION="$VERSION" \
	SPM_WEB_RP_ID=localhost python3 "$web_script" \
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

printf 'Web regression: proxy-aware login isolation\n'
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
	printf 'legacy emoji icon found in generated SPM Dashboard dashboard\n' >&2
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
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/passphrase-after"
[ "$(awk -F '\t' '$1=="PASSPHRASE"&&$2==1{print $4}' "$TEST_ROOT/passphrase-after" | base64 -d)" = 'horse-battery' ]
printf 'type,id,label,username,secret,notes,created,extra\npassword,,Web import,demo,WebSecret42,synthetic,2026-01-01T00:00:00Z,\n' \
	> "$TEST_ROOT/import.csv"
curl -fsS -D "$TEST_ROOT/import.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" -F 'fmt=csv' \
	-F "file=@$TEST_ROOT/import.csv;type=text/csv" "http://127.0.0.1:$WEB_PORT/import"
grep -qi '^Location: /?msg=import-ok' "$TEST_ROOT/import.headers"

# --- 2.12.0 URL field --------------------------------------------------------

# Password rows gained a seventh field. Everything below is about the two ways
# that can go wrong: the value not surviving a round trip, and the value being
# trusted when it reaches an href or the browser extension.

vault_plain() {
	# To a file, then cat: the core returns the vault key on its stdout, so
	# decrypting straight into a pipe would interleave the two.
	test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/vault-plain.tmp"
	cat "$TEST_ROOT/vault-plain.tmp"
}

curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/add.html" \
	"http://127.0.0.1:$WEB_PORT/add"
grep -q 'name="url"' "$TEST_ROOT/add.html" \
	|| { printf 'the add form has no url input\n' >&2; exit 1; }
add_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$TEST_ROOT/add.html" | head -n1)"

curl -fsS -D "$TEST_ROOT/url-add.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST --data-urlencode "csrf=$add_csrf" --data-urlencode 'name=Bound Site' \
	--data-urlencode 'user=avery@example.invalid' --data-urlencode 'password=UrlBound42!x' \
	--data-urlencode 'notes=synthetic' --data-urlencode 'url=https://bound.example.invalid/login' \
	"http://127.0.0.1:$WEB_PORT/add"
grep -q '302 Found' "$TEST_ROOT/url-add.headers"
vault_plain > "$TEST_ROOT/url-after"
bound_id="$(awk -F '\t' '$2=="Bound Site"{print $1}' "$TEST_ROOT/url-after" | head -n1)"
[ -n "$bound_id" ] || { printf 'the url entry was not stored\n' >&2; exit 1; }
[ "$(awk -F '\t' -v id="$bound_id" '$1==id{print $7}' "$TEST_ROOT/url-after")" \
	= 'https://bound.example.invalid/login' ] \
	|| { printf 'the url did not reach field 7\n' >&2; exit 1; }

# A javascript: url would become an href on the view page and a match target
# for the extension. The form must refuse it rather than store it.
before_rows="$(awk -F '\t' '$1 ~ /^[0-9]+$/' "$TEST_ROOT/url-after" | wc -l)"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/url-bad.html" \
	-X POST --data-urlencode "csrf=$add_csrf" --data-urlencode 'name=Hostile' \
	--data-urlencode 'user=x' --data-urlencode 'password=y' \
	--data-urlencode 'url=javascript:alert(1)' \
	"http://127.0.0.1:$WEB_PORT/add"
grep -qi 'http:// or https://' "$TEST_ROOT/url-bad.html" \
	|| { printf 'a javascript: url was not rejected with a reason\n' >&2; exit 1; }
vault_plain > "$TEST_ROOT/url-bad-after"
after_rows="$(awk -F '\t' '$1 ~ /^[0-9]+$/' "$TEST_ROOT/url-bad-after" | wc -l)"
[ "$before_rows" = "$after_rows" ] \
	|| { printf 'a rejected url still wrote a row\n' >&2; exit 1; }
if grep -q 'javascript:' "$TEST_ROOT/url-bad-after"; then
	printf 'a javascript: scheme reached the vault\n' >&2; exit 1
fi

# The view page renders it as a link, and never as a javascript: href even if
# a hand-edited vault smuggles one past the form.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/url-view.html" \
	"http://127.0.0.1:$WEB_PORT/view?id=$bound_id"
grep -q 'href="https://bound.example.invalid/login"' "$TEST_ROOT/url-view.html" \
	|| { printf 'the view page did not render the url as a link\n' >&2; exit 1; }
grep -q 'rel="noopener noreferrer nofollow"' "$TEST_ROOT/url-view.html" \
	|| { printf 'the url link is missing its rel guard\n' >&2; exit 1; }

# Search finds an entry by its url -- the whole point of storing one.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/url-search.html" \
	"http://127.0.0.1:$WEB_PORT/search?q=bound.example.invalid"
grep -q 'Bound Site' "$TEST_ROOT/url-search.html" \
	|| { printf 'search does not match on the url field\n' >&2; exit 1; }

# `get` splits a row with a fixed read list, where the last named variable
# absorbs every remaining field. On a SEVEN-field row a missing `url` in that
# list silently appends the URL to the timestamp, so the assertion has to run
# against a row that actually has one -- a six-field row cannot show the bug.
bound_created="$(awk -F '\t' -v id="$bound_id" '$1==id{print $6}' "$TEST_ROOT/url-after")"
bound_url="$(awk -F '\t' -v id="$bound_id" '$1==id{print $7}' "$TEST_ROOT/url-after")"
[ -n "$bound_created" ] && [ -n "$bound_url" ]
MASTER_PW="$AUDIT_PASSWORD" cmd_get "$bound_id" > "$TEST_ROOT/url-get.txt" 2>/dev/null || true
grep -qx "Created: *$bound_created" "$TEST_ROOT/url-get.txt" \
	|| { printf 'the url field bled into the Created value in get\n' >&2
	     sed -n '1,12p' "$TEST_ROOT/url-get.txt" >&2; exit 1; }
grep -qx "URL: *$bound_url" "$TEST_ROOT/url-get.txt" \
	|| { printf 'get did not print the stored URL\n' >&2
	     sed -n '1,12p' "$TEST_ROOT/url-get.txt" >&2; exit 1; }

# A vault written before 2.12.0 has six fields and must still read cleanly.
legacy_created="$(awk -F '\t' '$1=="1"{print $6}' "$TEST_ROOT/url-after")"
[ -n "$legacy_created" ]
MASTER_PW="$AUDIT_PASSWORD" cmd_get 1 > "$TEST_ROOT/legacy-get.txt" 2>/dev/null || true
grep -qx "Created: *$legacy_created" "$TEST_ROOT/legacy-get.txt" \
	|| { printf 'a six-field row corrupted the Created value in get\n' >&2
	     sed -n '1,12p' "$TEST_ROOT/legacy-get.txt" >&2; exit 1; }
grep -qx "URL: *" "$TEST_ROOT/legacy-get.txt" \
	|| { printf 'get does not print an empty URL line for a legacy row\n' >&2; exit 1; }

# The browser bridge binds on the url field, and still honours a URL that only
# exists in the notes -- that is how every vault written before 2.12.0 works.
printf '%s\n' "$AUDIT_PASSWORD" | cmd_bridge_get "$bound_id" bound.example.invalid \
	> "$TEST_ROOT/bridge-url.json" || true
grep -q '"ok": *true' "$TEST_ROOT/bridge-url.json" \
	|| { printf 'the bridge did not bind on the url field\n' >&2
	     cat "$TEST_ROOT/bridge-url.json" >&2; exit 1; }
if printf '%s\n' "$AUDIT_PASSWORD" | cmd_bridge_get "$bound_id" other.example.invalid \
	> "$TEST_ROOT/bridge-wrong.json" 2>/dev/null; then
	printf 'the bridge bound a record to a hostname it does not carry\n' >&2; exit 1
fi
printf '%s\n' "$AUDIT_PASSWORD" | cmd_bridge_get 1 example.invalid \
	> "$TEST_ROOT/bridge-notes.json" || true
grep -q '"ok": *true' "$TEST_ROOT/bridge-notes.json" \
	|| { printf 'a pre-2.12.0 notes-embedded URL stopped binding\n' >&2
	     cat "$TEST_ROOT/bridge-notes.json" >&2; exit 1; }
printf '%s\n' "$AUDIT_PASSWORD" | cmd_bridge_list bound.example.invalid \
	> "$TEST_ROOT/bridge-list.json" || true
grep -q '"ok": *true' "$TEST_ROOT/bridge-list.json"
grep -q '"id": *"'"$bound_id"'"' "$TEST_ROOT/bridge-list.json"
if grep -q "$AUDIT_PASSWORD\|url-secret" "$TEST_ROOT/bridge-list.json"; then
	printf 'bridge-list exposed secret material\n' >&2; exit 1
fi
printf '%s\n' "$AUDIT_PASSWORD" | cmd_bridge_list no-match.example.invalid \
	> "$TEST_ROOT/bridge-list-empty.json" || true
grep -q '"matches": *\[\]' "$TEST_ROOT/bridge-list-empty.json"
printf '%s\n' "$AUDIT_PASSWORD" | "$ROOT_DIR/spm.sh" bridge-list bound.example.invalid \
	> "$TEST_ROOT/bridge-list-dispatch.json"
grep -q '"ok": *true' "$TEST_ROOT/bridge-list-dispatch.json"
[ "$(wc -l < "$TEST_ROOT/bridge-list-dispatch.json" | tr -d ' ')" = 1 ] \
	|| { printf 'bridge-list dispatch emitted prompts around its JSON response\n' >&2; exit 1; }

printf 'Web regression: url field, scheme allowlist and bridge binding\n'
python3 "$ROOT_DIR/tests/native_host_protocol.py"
setup_home="$TEST_ROOT/extension-setup-home"
mkdir -p "$setup_home"
HOME="$setup_home" XDG_DATA_HOME="$setup_home/data" \
	"$ROOT_DIR/browser-extension-universal/setup.sh" --browser firefox --no-open \
	> "$TEST_ROOT/extension-setup.txt"
grep -q 'Finish in Firefox' "$TEST_ROOT/extension-setup.txt"
case "$(uname -s)" in
	Darwin)
		firefox_manifest="$setup_home/Library/Application Support/Mozilla/NativeMessagingHosts/xyz.sansyourways.spm.json"
		chromium_manifest="$setup_home/Library/Application Support/Google/Chrome/NativeMessagingHosts/xyz.sansyourways.spm.json"
		;;
	*)
		firefox_manifest="$setup_home/.mozilla/native-messaging-hosts/xyz.sansyourways.spm.json"
		chromium_manifest="$setup_home/.config/google-chrome/NativeMessagingHosts/xyz.sansyourways.spm.json"
		;;
esac
grep -q 'browser-extension@sansyourways.xyz' "$firefox_manifest"
grep -q 'infdncbkefpjncplegccokcfpiicadlo' "$chromium_manifest"

# --- 2.10.12 integrity regressions -------------------------------------------

# A blank backup-codes field means preserve, never erase. Recovery codes cannot
# be regenerated from the vault, so this had a worse payload than the
# passphrase bug above and shipped without the same guard.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/backup-edit.html" \
	"http://127.0.0.1:$WEB_PORT/backup-codes-edit?id=1"
csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$TEST_ROOT/backup-edit.html" | head -n1)"
curl -fsS -D "$TEST_ROOT/backup-edit.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST --data-urlencode "csrf=$csrf" --data-urlencode 'label=Renamed codes' \
	--data-urlencode 'codes=' "http://127.0.0.1:$WEB_PORT/backup-codes-edit?id=1"
grep -q '302 Found' "$TEST_ROOT/backup-edit.headers"
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/backup-after"
awk -F '\t' '$1=="BACKUP_CODE"{print $4}' "$TEST_ROOT/backup-after" | head -n1 | base64 -d \
	| grep -q . || { printf 'blank backup-code edit erased the stored codes\n' >&2; exit 1; }

# Inline handlers are gone and every script carries this response's nonce, so
# the CSP no longer needs 'unsafe-inline'.
curl -fsS -D "$TEST_ROOT/csp.headers" -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/csp.html" \
	"http://127.0.0.1:$WEB_PORT/"
grep -i 'content-security-policy' "$TEST_ROOT/csp.headers" | grep -q "script-src 'self' 'nonce-"
if grep -i 'content-security-policy' "$TEST_ROOT/csp.headers" | grep -q "script-src[^;]*unsafe-inline"; then
	printf "CSP still allows inline script\n" >&2; exit 1
fi
if grep -Eq 'onclick=|onsubmit=' "$TEST_ROOT/csp.html"; then
	printf 'inline event handler found in generated markup\n' >&2; exit 1
fi
csp_nonce="$(sed -n "s/.*script-src 'self' 'nonce-\([A-Za-z0-9_-]*\)'.*/\1/p" "$TEST_ROOT/csp.headers" | head -n1)"
[ -n "$csp_nonce" ]
grep -q "<script nonce=\"$csp_nonce\"" "$TEST_ROOT/csp.html"

# A CDN in front of this server must not be able to strip the page's scripts.
# Cloudflare's Rocket Loader rewrites the type of every inline <script> it is
# not told to skip and re-injects the code itself; the re-injected copy carries
# no nonce, so this server's own CSP then refuses it. The page ends up with no
# JavaScript at all -- which silently disables the idle auto-lock, because that
# lock lives entirely in the browser. Every script needs the opt-out, so strip
# the guarded form and assert nothing resembling a script tag survives.
sed "s/<script nonce=\"$csp_nonce\" data-cfasync=\"false\"/<SCRIPTOK/g" \
	"$TEST_ROOT/csp.html" > "$TEST_ROOT/csp.stripped"
if grep -q '<script' "$TEST_ROOT/csp.stripped"; then
	printf 'script tag without the nonce + data-cfasync opt-out\n' >&2
	exit 1
fi
if ! grep -q '<SCRIPTOK' "$TEST_ROOT/csp.stripped"; then
	printf 'no guarded script tags found in served page\n' >&2
	exit 1
fi

# SPM Dashboard writes must land in the encrypted history the CLI exposes, not only
# in the single .bak generation.
find "$XDG_DATA_HOME/spm/history" -name '*.gpg' 2>/dev/null | grep -q . \
	|| { printf 'SPM Dashboard write produced no history snapshot\n' >&2; exit 1; }

# Import must refuse a non-UTF-8 source instead of dropping the bytes it cannot
# decode, and must leave the vault untouched when it refuses.
printf 'type,label,username,secret,notes\n' > "$TEST_ROOT/latin1.csv"
printf 'password,Caf\xe9,jos\xe9,dummy-pw-Gr\xf6\xdfe,notes\n' >> "$TEST_ROOT/latin1.csv"
cp "$PASSWORD_VAULT" "$TEST_ROOT/vault-before-import.gpg"
if printf '%s\n' "$AUDIT_PASSWORD" | cmd_import csv "$TEST_ROOT/latin1.csv" >"$TEST_ROOT/import-latin1.log" 2>&1; then
	printf 'import accepted a non-UTF-8 file\n' >&2; exit 1
fi
grep -q 'not valid UTF-8' "$TEST_ROOT/import-latin1.log"
cmp -s "$PASSWORD_VAULT" "$TEST_ROOT/vault-before-import.gpg" \
	|| { printf 'refused import still modified the vault\n' >&2; exit 1; }

# Unrecognised record types must be reported, not silently discarded.
printf 'type,label,username,secret,notes\npassword,Kept,alice,dummy-1,ok\nlogin,Dropped,bob,dummy-2,x\n' \
	> "$TEST_ROOT/mixed.csv"
printf '%s\n' "$AUDIT_PASSWORD" | cmd_import csv "$TEST_ROOT/mixed.csv" >"$TEST_ROOT/import-mixed.log" 2>&1
grep -q 'Skipped 1 record' "$TEST_ROOT/import-mixed.log"
grep -q 'login' "$TEST_ROOT/import-mixed.log"

# Every character str.splitlines() breaks on has to be collapsed, or the record
# splits when it is read back and the entry disappears.
python3 - "$web_script" <<'PYCHK'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'_VAULT_BREAKS = "([^"]*)"', src)
assert m, "_VAULT_BREAKS missing from the generated web server"
breaks = m.group(1).encode().decode("unicode_escape")
missing = [c for c in "\t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029" if c not in breaks]
assert not missing, "unhandled line-break characters: %r" % missing
PYCHK

# The manual updater compared "v2.10.12" with "2.10.12" and so never reported
# that the running version was current.
grep -cF 's/.*"tag_name": *"v?([^"]+)".*/\1/' "$ROOT_DIR/spm.sh" | grep -qx 2

# doctor's split-record scan: it must find a record carrying a line-break
# character, name the character, never print the secret field, and leave the
# vault byte-identical.
printf 'META_RECOVERY_PUBKEY\tdGVzdA==\t-\t-\t-\t-\n' > "$TEST_ROOT/broken-plain"
printf '1\tHealthy\talice\tCleanSecret1\tnotes\t2026-01-01T00:00:00Z\n' >> "$TEST_ROOT/broken-plain"
printf '2\tMy\342\200\250Bank\tbob\tHiddenSecret2\tnotes\t2026-01-01T00:00:00Z\n' >> "$TEST_ROOT/broken-plain"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
	--symmetric --cipher-algo AES256 -o "$TEST_ROOT/broken.gpg" "$TEST_ROOT/broken-plain"
chmod 600 "$TEST_ROOT/broken.gpg"
broken_before="$(sha256sum "$TEST_ROOT/broken.gpg" | cut -d' ' -f1)"
doctor_scan_broken_records "$TEST_ROOT/broken-plain" > "$TEST_ROOT/scan.out"
grep -q '^BROKEN' "$TEST_ROOT/scan.out"
grep -q 'U+2028' "$TEST_ROOT/scan.out"
# Built with awk rather than a \t escape: the pattern must match a literal tab
# whichever grep implementation is on PATH.
awk -F '\t' '$1=="SUMMARY" && $2==1 && $3==0 { found=1 } END { exit found?0:1 }' \
	"$TEST_ROOT/scan.out"
# The clean record must not be reported, and no secret may appear in the output.
# Written as `if !`, not `grep ... && { exit 1; }`: under errexit the latter
# aborts the suite when grep simply finds nothing.
if grep -q 'Healthy' "$TEST_ROOT/scan.out"; then
	printf 'scan flagged a clean record\n' >&2; exit 1
fi
if grep -qE 'HiddenSecret2|CleanSecret1' "$TEST_ROOT/scan.out"; then
	printf 'doctor scan leaked a secret field\n' >&2; exit 1
fi
[ "$(sha256sum "$TEST_ROOT/broken.gpg" | cut -d' ' -f1)" = "$broken_before" ] \
	|| { printf 'doctor scan modified the vault\n' >&2; exit 1; }
# a vault with no break characters reports nothing
doctor_scan_broken_records "$PLAIN" > "$TEST_ROOT/scan-clean.out"
awk -F '\t' '$1=="SUMMARY" && $2==0 && $3==0 { found=1 } END { exit found?0:1 }' \
	"$TEST_ROOT/scan-clean.out"

# ---- 2.10.14: security page, history, global search, tags, rotation --------

# The CLI dashboard and SPM Dashboard must score the same vault identically. They
# were two independent copies of the same weighting and had already drifted:
# the CLI penalised malformed authenticators and the web did not.
# Seed one malformed authenticator so the comparison actually exercises the
# term that had drifted. Without a row in that category both formulas agree
# trivially and the assertion proves nothing.
malformed_tmp="$(make_tmp)"
decrypt_vault_to_file "$malformed_tmp"
printf 'AUTH\t9\tBrokenAlgo\t\t30\t2025-01-01T00:00:00Z\tmd5\n' >> "$malformed_tmp"
encrypt_file_to_vault "$malformed_tmp"
secure_wipe "$malformed_tmp"
cmd_security_dashboard | grep -q 'Malformed protected records: authenticator:9'

cli_score="$(cmd_security_dashboard | sed -n 's#^Score: \([0-9]*\)/100$#\1#p')"
[ -n "$cli_score" ]
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/security.html" \
	"http://127.0.0.1:$WEB_PORT/security"
web_score="$(sed -n 's/.*<span class="stat-n score-[a-z]*">\([0-9]*\)<\/span>.*/\1/p' \
	"$TEST_ROOT/security.html" | head -1)"
[ "$cli_score" = "$web_score" ] || {
	printf 'security score differs: CLI %s, web %s\n' "$cli_score" "$web_score" >&2
	exit 1
}

# The security page names IDs. It must never echo a secret: this page is meant
# to be safe to open on a phone in public.
if grep -qF 'DemoSecret42' "$TEST_ROOT/security.html"; then
	printf 'security page leaked a password\n' >&2; exit 1
fi

# Global search covers every record type by label, and must NOT search secret
# fields -- a query that could match a password turns the result count into a
# confirmation oracle.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/search-hit.html" \
	"http://127.0.0.1:$WEB_PORT/search?q=Memo"
grep -q '/notes-view?id=1' "$TEST_ROOT/search-hit.html"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/search-secret.html" \
	"http://127.0.0.1:$WEB_PORT/search?q=DemoSecret42"
if grep -q 'btn-sm" href="/view?id=' "$TEST_ROOT/search-secret.html"; then
	printf 'search matched a secret field\n' >&2; exit 1
fi

# History lists the snapshots the CLI writes, and rejects anything that is not
# a generated snapshot name. The allowlist is checked with both a plain and a
# percent-encoded traversal.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/history.html" \
	"http://127.0.0.1:$WEB_PORT/history"
grep -q 'action="/history-restore"' "$TEST_ROOT/history.html"
hist_csrf="$(grep -o 'name="csrf" value="[^"]*"' "$TEST_ROOT/history.html" \
	| head -1 | sed 's/.*value="//; s/"$//')"
[ -n "$hist_csrf" ]
vault_before="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
for bad_name in '../../../../etc/passwd' '..%2f..%2fvault.gpg' 'not-a-snapshot.gpg'; do
	code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$TEST_ROOT/cookies" \
		-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
		--data-urlencode "csrf=$hist_csrf" --data-urlencode "name=$bad_name" \
		"http://127.0.0.1:$WEB_PORT/history-restore")"
	[ "$code" = "400" ] || {
		printf 'history-restore accepted %s (HTTP %s)\n' "$bad_name" "$code" >&2
		exit 1
	}
done
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_before" ] || {
	printf 'a rejected restore still modified the vault\n' >&2; exit 1
}

# Restoring a snapshot sealed with a different master password would lock the
# user out of their own vault, so it must be refused before anything is
# written.
hist_dir="$XDG_DATA_HOME/spm/history/$(printf '%s' "$PASSWORD_VAULT" \
	| python3 -c 'import hashlib,os,sys; print(hashlib.sha256(os.path.abspath(sys.stdin.read().strip()).encode()).hexdigest()[:16])')"
mkdir -p "$hist_dir"
printf 'META_X\tx\t-\t-\t-\t-\n' > "$TEST_ROOT/foreign-plain"
printf 'A-Completely-Different-Master' | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$hist_dir/20200101T000000.9999.abcdef123456.gpg" "$TEST_ROOT/foreign-plain"
code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$TEST_ROOT/cookies" \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hist_csrf" \
	--data-urlencode 'name=20200101T000000.9999.abcdef123456.gpg' \
	"http://127.0.0.1:$WEB_PORT/history-restore")"
[ "$code" = "409" ] || {
	printf 'restore of a foreign-password snapshot returned %s, expected 409\n' "$code" >&2
	exit 1
}
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_before" ] || {
	printf 'a refused restore still modified the vault\n' >&2; exit 1
}
# Remove the decoy so it cannot be picked as "newest" by the round-trip below.
rm -f "$hist_dir/20200101T000000.9999.abcdef123456.gpg"

# A real restore round-trip must return the vault to its earlier bytes. The
# snapshot is located by content, not by position: the sourced CLI library and
# the web server both archive into this directory during the run, so "newest"
# is not a stable way to name the one we want.
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hist_csrf" --data-urlencode 'name=Roundtrip' \
	--data-urlencode 'user=rt' --data-urlencode 'password=Rt9!qqqqqqqqqq' \
	--data-urlencode 'notes=' "http://127.0.0.1:$WEB_PORT/add"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" != "$vault_before" ]
snap=""
for candidate in "$hist_dir"/*.gpg; do
	if [ "$(sha256sum "$candidate" | cut -d' ' -f1)" = "$vault_before" ]; then
		snap="$(basename "$candidate")"
		break
	fi
done
[ -n "$snap" ] || { printf 'the web write did not archive the previous vault\n' >&2; exit 1; }
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/history2.html" \
	"http://127.0.0.1:$WEB_PORT/history"
hist_csrf2="$(grep -o 'name="csrf" value="[^"]*"' "$TEST_ROOT/history2.html" \
	| head -1 | sed 's/.*value="//; s/"$//')"
grep -qF "value=\"$snap\"" "$TEST_ROOT/history2.html"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hist_csrf2" --data-urlencode "name=$snap" \
	"http://127.0.0.1:$WEB_PORT/history-restore"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_before" ] || {
	printf 'history restore did not return the vault to its earlier bytes\n' >&2
	exit 1
}

# Snapshots are listed newest-first. They are copied with copy2, which
# preserves the source mtime, so ordering has to come from the generated name
# rather than the filesystem or an older snapshot sorts to the top.
python3 - "$TEST_ROOT/history2.html" <<'PYORDER'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
names = re.findall(r'name="name" value="([^"]+)"', html)
assert names, "history page listed no snapshots"
assert names == sorted(names, reverse=True), "snapshots are not newest-first: %r" % names
PYORDER

# Tags are a convention inside existing plaintext fields. "C#" and a URL
# fragment must not become tags, or every note with a link would sprout one.
python3 - "$web_script" <<'PYTAG'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'_TAG_RE = re\.compile\(r"([^"]+)"\)', src)
assert m, "_TAG_RE missing from the generated web server"
rx = re.compile(m.group(1))
assert rx.findall("work #dev #ops-2") == ["dev", "ops-2"], "tag parsing broke"
assert rx.findall("write C# daily") == [], "C# became a tag"
assert rx.findall("see http://host/page#anchor") == [], "a URL fragment became a tag"
PYTAG

# The rotation badge must be driven by the configured threshold, not a constant.
grep -q 'SPM_ROTATION_DAYS' "$web_script"
grep -q 'data-i18n="badge.aging"' "$web_script"

# Every new UI string must exist in all three shipped languages, or switching
# language blanks the element.
python3 - "$web_script" <<'PYI18N'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
need = ["nav.security", "nav.history", "nav.unlock", "security.weak",
        "security.reused",
        "security.aging", "security.incomplete", "security.malformed",
        "history.when", "btn.restore", "confirm.restore_snapshot",
        "search.kind", "badge.aging", "tags.all",
        "page.unlock.desc", "unlock.registered", "unlock.empty",
        "unlock.empty_sub", "unlock.field.label", "unlock.register",
        "unlock.note", "unlock.title", "unlock.sub", "unlock.btn",
        "unlock.fallback", "unlock.waiting", "unlock.failed",
        "unlock.nosupport", "register.waiting", "register.failed"]
for lang in ('"en"', '"id"', '"ja"'):
    start = src.index(lang + ": {")
    end = src.index("\n    }", start)
    block = src[start:end]
    missing = [k for k in need if '"%s":' % k not in block]
    assert not missing, "%s is missing %r" % (lang, missing)
PYI18N

# Biometric unlock. A throwaway P-256 key stands in for a platform
# authenticator: the ceremony below builds real authenticatorData and
# clientDataJSON and signs them with openssl, so the server's verification path
# is exercised for real rather than mocked.
#
# The RP id is "localhost" and the origin is http://localhost:PORT, because the
# server derives the expected origin from the RP id and a browser will not
# accept an IP address as a relying party.
printf 'Web regression: biometric unlock ceremonies\n'
openssl ecparam -name prime256v1 -genkey -noout -out "$TEST_ROOT/authn.key" 2>/dev/null
openssl ec -in "$TEST_ROOT/authn.key" -pubout -outform DER \
	-out "$TEST_ROOT/authn.pub.der" 2>/dev/null
python3 - "$WEB_PORT" "$AUDIT_PASSWORD" "$TEST_ROOT/authn.key" \
	"$TEST_ROOT/authn.pub.der" <<'PYWEBAUTHN'
import base64, hashlib, http.cookiejar, json, re, subprocess, sys
import urllib.error, urllib.parse, urllib.request

port, password, key_path, pub_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
BASE = "http://localhost:%s" % port
RP_ID = "localhost"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def post_json(path, payload, origin=BASE):
    """origin=None omits the header, reproducing an iOS home-screen web app.

    _write_authorized accepts a request whose Origin header matches the host
    without consulting the token at all, so a CSRF test that sends a good
    Origin can never fail. Omitting it is both the honest test and the real
    case: a standalone iOS web app sends Origin: null for its own posts, which
    that function treats as absent, and the token is then the only defence.
    """
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/json")
    if origin is not None:
        req.add_header("Origin", origin)
    try:
        r = opener.open(req, timeout=20)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}

def get(path):
    try:
        r = opener.open(urllib.request.Request(BASE + path), timeout=20)
        return r.status, r.read().decode("utf-8", "replace"), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), BASE + path

def bootstrap():
    _, body, _ = get("/")
    m = re.search(r"window\.SPM_UNLOCK = (\{.*?\});", body)
    assert m, "the unlock bootstrap is missing from the app shell"
    return json.loads(m.group(1)), body

def auth_data(rp_id=RP_ID, flags=0x05, count=0):
    return (hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags]) + count.to_bytes(4, "big"))

def client_data(kind, challenge, origin=BASE):
    return json.dumps({"type": kind, "challenge": challenge, "origin": origin,
                       "crossOrigin": False}, separators=(",", ":")).encode()

def sign(message):
    p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path],
                       input=message, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert p.returncode == 0, p.stderr
    return p.stdout

req = urllib.request.Request(
    BASE + "/login",
    data=urllib.parse.urlencode({"password": password}).encode(), method="POST")
req.add_header("Content-Type", "application/x-www-form-urlencoded")
req.add_header("Origin", BASE)
opener.open(req, timeout=20)

boot, _ = bootstrap()
assert boot["available"] is False, "unlock advertised before any credential exists"
csrf = boot["csrf"]
assert csrf, "no CSRF token reached the client"

# CSRF on the JSON ceremonies, checked here while the session is still active.
# _body_csrf grew a JSON branch for these and it is the function every
# authenticated write depends on. It has to be tested against a session that
# would otherwise be authorised: a suspended session is refused on its state
# before the token is ever examined, so the same assertions there would pass
# without proving anything.
for bad in ({}, {"csrf": ""}, {"csrf": "wrong"}, {"csrf": ["not", "a", "string"]},
            {"csrf": {"nested": "object"}}):
    code, res = post_json("/unlock/register/challenge", bad, origin=None)
    assert code == 403, ("a JSON post with csrf=%r was authorised" % bad, code, res)
    code, res = post_json("/unlock/register/challenge", bad, origin="null")
    assert code == 403, ("an opaque-origin post with csrf=%r was authorised" % bad,
                         code, res)
# The same request with the right token must still succeed, or the assertions
# above would pass for a server that simply refuses every JSON post.
for opaque in (None, "null"):
    code, res = post_json("/unlock/register/challenge", {"csrf": csrf}, origin=opaque)
    assert code == 200, ("a correctly signed JSON post was refused", opaque, code, res)
# A genuinely cross-origin post is refused whatever token it carries.
code, res = post_json("/unlock/register/challenge", {"csrf": csrf},
                      origin="https://evil.invalid")
assert code == 403, ("a cross-origin post was authorised", code, res)

# Suspending without a registered credential must be refused. A suspended
# session can be resumed by nothing except a credential, so allowing it strands
# the user on a page that cannot let them back in -- they can only log out and
# retype the master password, which is the friction this feature exists to
# remove. The lock bar treats a refusal as a reason to log out, which is
# exactly the pre-2.11.0 behaviour.
code, res = post_json("/unlock/suspend", {"csrf": csrf})
assert code == 409, ("suspend was allowed with no credential registered", code, res)

code, ch = post_json("/unlock/register/challenge", {"csrf": csrf})
assert code == 200 and ch.get("challenge"), ("register challenge", code, ch)
code, res = post_json("/unlock/register/verify", {
    "csrf": csrf, "credential_id": b64u(b"regression-cred"),
    "client_data": b64u(client_data("webauthn.create", ch["challenge"])),
    "auth_data": b64u(auth_data()),
    "public_key": b64u(open(pub_path, "rb").read()), "label": "Regression"})
assert code == 200, ("registration refused", code, res)

boot, body = bootstrap()
assert boot["available"] is True, "unlock still not advertised after registering"
assert "/unlock/settings" in body, "no nav entry for the unlock settings page"
csrf = boot["csrf"]

# Revocation, on a second credential so the first stays available to unlock
# with. The delete form must be spelled method="post" in double quotes, because
# that is what _POST_FORM_RE stamps the CSRF token onto. A single-quoted form
# receives no token and still works on desktop -- the Origin check carries it --
# so the failure would surface only on iOS, where a home-screen web app sends
# Origin: null and the token is all that is left.
code, ch2 = post_json("/unlock/register/challenge", {"csrf": csrf})
code, res = post_json("/unlock/register/verify", {
    "csrf": csrf, "credential_id": b64u(b"regression-spare"),
    "client_data": b64u(client_data("webauthn.create", ch2["challenge"])),
    "auth_data": b64u(auth_data()),
    "public_key": b64u(open(pub_path, "rb").read()), "label": "Disposable"})
assert code == 200, ("second registration refused", code, res)

_, settings, _ = get("/unlock/settings")
assert "Disposable" in settings, "the settings page did not list the credential"
m = re.search(r'name="csrf" value="([^"]+)"', settings)
assert m, "the delete form was not stamped with a CSRF token"
form_csrf = m.group(1)

def post_form(path, fields, origin=None):
    req = urllib.request.Request(path if path.startswith("http") else BASE + path,
                                 data=urllib.parse.urlencode(fields).encode(),
                                 method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if origin is not None:
        req.add_header("Origin", origin)
    try:
        return opener.open(req, timeout=20).status
    except urllib.error.HTTPError as e:
        return e.code

ids = re.findall(r'name="id" value="(\d+)"', settings)
assert len(ids) == 2, ("expected two credentials, saw %r" % ids)
target = ids[-1]
for bad in ("../etc", "abc", "99999"):
    code = post_form("/unlock/delete", {"csrf": form_csrf, "id": bad}, origin=None)
    assert code in (400, 404), ("delete accepted id=%r" % bad, code)
assert post_form("/unlock/delete", {"id": target}, origin=None) == 403, \
    "an unstamped delete was accepted"
assert post_form("/unlock/delete", {"csrf": form_csrf, "id": target},
                 origin=None) == 200, "a stamped delete with no Origin was refused"
_, settings, _ = get("/unlock/settings")
assert "Disposable" not in settings, "the credential survived deletion"
assert "Regression" in settings, "deletion removed the wrong credential"

boot, _ = bootstrap()
assert boot["available"] is True, "unlock stopped being offered while a credential remains"
csrf = boot["csrf"]

assert post_json("/unlock/suspend", {"csrf": csrf})[0] == 200, "suspend refused"

# Two tabs share one session and both lock bars fire. The second must not be
# told "no session": the lock bar treats any refusal as a reason to log out,
# which destroyed the suspended session the first tab was about to resume.
code, res = post_json("/unlock/suspend", {"csrf": csrf})
assert code == 200 and res.get("already_suspended") is True, \
    ("suspending an already-suspended session is not idempotent", code, res)
code, res = post_json("/unlock/challenge", {"csrf": csrf})
assert code == 200, ("the session stopped being resumable after a second suspend", code, res)

# The property this whole feature rests on. The 2.10.14 bug was a control that
# lived only in the browser; if suspension were a client-side redirect, a
# visitor could simply ask for the page.
code, body, url = get("/passwords")
assert "DemoSecret42" not in body, "a suspended session served vault secrets"
assert url.endswith("/unlock") or "Vault locked" in body, \
    "a suspended session was not sent to the unlock page (%s)" % url
code, body, _ = get("/unlock")
assert code == 200 and "unlock-btn" in body, "unlock page did not render"
assert "DemoSecret42" not in body, "the unlock page carried vault content"

def assertion(csrf, rp_id=RP_ID, flags=0x05, origin=BASE, tamper=False,
              challenge=None):
    code, c = post_json("/unlock/challenge", {"csrf": csrf})
    if code != 200:
        return code, c
    used = challenge or c["challenge"]
    cd = client_data("webauthn.get", used, origin)
    ad = auth_data(rp_id, flags)
    sig = sign(ad + hashlib.sha256(cd).digest())
    if tamper:
        ad = auth_data(rp_id, flags, 1)
    return post_json("/unlock/verify", {
        "csrf": csrf, "credential_id": b64u(b"regression-cred"),
        "client_data": b64u(cd), "auth_data": b64u(ad), "signature": b64u(sig)})

# The positive path runs first: each refusal below spends the shared
# login-failure budget, and a valid attempt made after five failures is
# correctly answered 429 rather than 200.
code, res = assertion(csrf)
assert code == 200, ("a valid assertion did not resume the session", code, res)
code, body, _ = get("/passwords")
assert "Example" in body, "the resumed session could not reach the vault"

boot, _ = bootstrap()
csrf = boot["csrf"]
assert post_json("/unlock/suspend", {"csrf": csrf})[0] == 200
code, c = post_json("/unlock/challenge", {"csrf": csrf})
cd = client_data("webauthn.get", c["challenge"])
ad = auth_data()
replay = {"csrf": csrf, "credential_id": b64u(b"regression-cred"),
          "client_data": b64u(cd), "auth_data": b64u(ad),
          "signature": b64u(sign(ad + hashlib.sha256(cd).digest()))}
assert post_json("/unlock/verify", dict(replay))[0] == 200, "assertion refused once"
boot, _ = bootstrap()
csrf = boot["csrf"]
post_json("/unlock/suspend", {"csrf": csrf})
replay["csrf"] = csrf
code, res = post_json("/unlock/verify", replay)
assert code in (400, 403), ("a challenge was spendable twice", code, res)

# A refused assertion leaves the session suspended and its CSRF token intact,
# so these run back to back without re-suspending. Refusing to rotate the token
# on failure is deliberate: the page has to stay usable for a second try.
for name, kwargs in (
        ("a foreign relying party", {"rp_id": "evil.invalid"}),
        ("a bare user-presence tap", {"flags": 0x01}),
        ("a foreign origin", {"origin": "https://evil.invalid"}),
        ("tampered authenticatorData", {"tamper": True}),
        ("a forged challenge", {"challenge": b64u(b"z" * 32)})):
    code, res = assertion(csrf, **kwargs)
    assert code in (400, 403), ("%s was accepted" % name, code, res)

# The failure budget is spent. The next attempt must be throttled, not merely
# refused: an assertion that reaches the server having failed is attack-shaped,
# because a real Face ID mismatch never leaves the phone.
code, res = assertion(csrf, challenge=b64u(b"y" * 32))
assert code == 429, ("repeated unlock failures are not throttled", code, res)

print("webauthn unlock ceremonies verified")
PYWEBAUTHN

# --- 3.0.0 vault format version and pinned key derivation --------------------
printf 'Web regression: vault format version and KDF policy\n'

# Sourcing the script must never execute main. Before the entry-point guard,
# `source spm.sh` fell straight into the interactive menu, and a menu blocked
# on `read` keeps whatever it already acquired -- including an exclusive flock
# on ${VAULT_FILE}.lock, which for a caller that had not set PASSWORD_VAULT is
# the operator's real vault. It was found holding one for fourteen hours.
#
# stdin is a pipe that stays open without ever delivering a line, which is the
# condition that hung: with the guard the source returns at once, without it
# the read blocks until `timeout` kills the shell.
printf 'CLI regression: sourcing does not run main\n'
guard_out="$TEST_ROOT/source-guard.out"
# The path travels in the environment, not as a positional: an argument would
# reach `main "$@"` as a command name, and main would exit on the unknown
# command instead of reaching the menu -- so the probe would pass even with the
# guard removed. Verified by removing the guard and watching this block.
guard_rc=0
sleep 5 | SPM_GUARD_PROBE="$ROOT_DIR/spm.sh" timeout 9 bash -c \
	'source "$SPM_GUARD_PROBE" >/dev/null 2>&1; printf ready' > "$guard_out" 2>/dev/null \
	|| guard_rc=$?
# Only a timeout means the guard is gone. The probe discards stderr, so a
# source-time failure -- an unbalanced `if`, say -- also lands here with its
# own status, and blaming that on the entry-point guard would send the next
# reader looking in the wrong place entirely.
if [ "$guard_rc" -eq 124 ]; then
	printf 'sourcing spm.sh executed main and blocked; the entry-point guard is gone\n' >&2
	exit 1
elif [ "$guard_rc" -ne 0 ]; then
	# Ambiguous on purpose rather than confidently wrong. A missing guard does
	# not always hang: with a fresh HOME, main reaches the consent or language
	# prompt and exits non-zero instead of blocking. A source-time error in the
	# script produces the same shape. Both are failures; neither is worth
	# guessing between in the message.
	printf 'sourcing spm.sh exited %s instead of returning cleanly.\n' "$guard_rc" >&2
	printf 'Either the entry-point guard is gone (main ran) or the script fails at source time.\n' >&2
	exit 1
fi
[ "$(cat "$guard_out")" = "ready" ] \
	|| { printf 'sourcing spm.sh did not complete cleanly\n' >&2; exit 1; }

# It must still run main when executed, or the guard has broken the CLI.
# Deliberately not `... | grep -q`: under `set -o pipefail` grep exits on the
# first match, the writer takes SIGPIPE, and the pipeline reports 141 -- which
# fails the check for a reason that has nothing to do with the guard. This
# suite has been bitten by that shape before; capture, then match.
guard_help="$TEST_ROOT/source-guard.help"
help_rc=0
timeout 20 bash "$ROOT_DIR/spm.sh" help > "$guard_help" 2>/dev/null || help_rc=$?
# The status is asserted too: printing the banner and then failing, or being
# killed at the timeout after printing, would otherwise pass on the text alone.
[ "$help_rc" -eq 0 ] \
	|| { printf 'executing spm.sh help exited %s\n' "$help_rc" >&2; exit 1; }
grep -q "Sans Password Manager" "$guard_help" \
	|| { printf 'executing spm.sh no longer runs main\n' >&2; exit 1; }

# Piped to a shell there is no BASH_SOURCE at all, and under `set -o nounset`
# a bare `${BASH_SOURCE[0]}` aborts with "unbound variable" rather than running
# -- which would break `curl ... | bash` for a guard that is only trying to
# tell sourcing apart from execution. The `:-$0` default covers it.
#
# A real pipe, not `< file`: a redirect from a file is seekable, and bash reads
# a block then lseeks back, which is a different code path from the incremental
# read it does on a non-seekable pipe. `curl | bash` is the latter, so the test
# has to be too.
guard_pipe="$TEST_ROOT/source-guard.pipe"
pipe_rc=0
cat "$ROOT_DIR/spm.sh" | timeout 20 bash -s help > "$guard_pipe" 2>&1 || pipe_rc=$?
if grep -q 'unbound variable' "$guard_pipe"; then
	printf 'piping spm.sh into bash aborts on an unbound BASH_SOURCE\n' >&2
	exit 1
fi
[ "$pipe_rc" -eq 0 ] \
	|| { printf 'piping spm.sh into bash exited %s\n' "$pipe_rc" >&2; exit 1; }
grep -q "Sans Password Manager" "$guard_pipe" \
	|| { printf 'piping spm.sh into bash no longer runs main\n' >&2; exit 1; }
printf '  source is inert; execution and a real pipe still dispatch\n'

# The trusted core is tested on its own first: the vault format, key handling
# and vault mutation are exercised against the module directly, without a
# shell or a web server in the way. That this file can exist at all is the
# point of extracting it.
printf 'Portability regression: platform-specific command behaviour\n'
# This suite runs on Linux, macOS and Termux, and the failures that only show
# up on one of them are the ones nobody sees until a user reports them. Each
# helper below wraps a command whose flags differ between GNU and BSD, so each
# is asserted on its behaviour rather than on which branch it took.

# Version ordering was `sort -V` until 3.4.0. That is a GNU extension: BSD
# sort has no -V, so on macOS the command fails and the comparison reads an
# empty string, and a lexical substitute orders 2.10.10 before 2.10.9 --
# backwards, in the function the auto-updater uses to decide whether a newer
# release exists. The truth table is asserted directly.
version_case() {
	local newer="$1" older="$2" expect="$3" got="ok"
	if version_is_newer "$newer" "$older"; then got="newer"; else got="not-newer"; fi
	[ "$got" = "$expect" ] || {
		printf 'version_is_newer %s %s said %s, wanted %s\n' \
			"$newer" "$older" "$got" "$expect" >&2
		exit 1
	}
}
version_case 2.10.10 2.10.9  newer
version_case 2.10.9  2.10.10 not-newer
version_case 3.10.0  3.9.0   newer
version_case 3.9.0   3.10.0  not-newer
version_case 10.0.0  9.9.9   newer
version_case 3.0.1   3.0.0   newer
version_case 3.0.0   3.0.0   not-newer
version_case 3.1.0   3.0.9   newer
# Unequal component counts must compare as if the shorter were zero-padded.
version_case 3.1     3.0.9   newer
version_case 3.0.0   3.0     not-newer
# A shorter version on the LEFT, where the missing component decides the
# answer, is the only shape that catches a wrong zero-pad. Every other
# unequal-length pair is settled before the padding is reached.
[ "$(version_compare 3.0 3.0.1)" = "-1" ] || {
	printf 'version_compare 3.0 3.0.1 did not zero-pad the shorter side\n' >&2; exit 1; }
[ "$(version_compare 3.0.1 3.0)" = "1" ] || {
	printf 'version_compare 3.0.1 3.0 got the padded case backwards\n' >&2; exit 1; }
[ "$(version_compare 1.2.3 1.2.3)" = "0" ] || {
	printf 'version_compare says two equal versions differ\n' >&2; exit 1; }
[ "$(version_compare 1.2.4 1.2.3)" = "1" ] || {
	printf 'version_compare got the greater case wrong\n' >&2; exit 1; }
[ "$(version_compare 1.2.3 1.2.4)" = "-1" ] || {
	printf 'version_compare got the lesser case wrong\n' >&2; exit 1; }

# file_mode: GNU stat wants -c, BSD stat wants -f. Whichever is present, the
# answer has to be octal permission bits that mode_is_exposed can read.
portable_probe="$TEST_ROOT/portable-probe"
: > "$portable_probe"
chmod 600 "$portable_probe"
probe_mode="$(file_mode "$portable_probe")"
case "$probe_mode" in
	600|0600) ;;
	*) printf 'file_mode returned %s for a 0600 file\n' "$probe_mode" >&2; exit 1 ;;
esac
mode_is_exposed "$probe_mode" && {
	printf 'mode_is_exposed called 0600 exposed\n' >&2; exit 1; }
chmod 644 "$portable_probe"
mode_is_exposed "$(file_mode "$portable_probe")" || {
	printf 'mode_is_exposed did not flag a world-readable file\n' >&2; exit 1; }
chmod 600 "$portable_probe"

# canon_path: realpath, readlink -f, then a cd fallback. Older macOS has
# neither of the first two, so the contract is only that the result is
# absolute and names the same file.
canon_out="$(canon_path "$portable_probe")"
case "$canon_out" in
	/*) ;;
	*) printf 'canon_path returned a relative path: %s\n' "$canon_out" >&2; exit 1 ;;
esac
[ -f "$canon_out" ] || {
	printf 'canon_path returned a path that does not exist: %s\n' "$canon_out" >&2
	exit 1
}

# Nothing may reintroduce a GNU-only flag without a fallback beside it. These
# are the ones this codebase has actually tripped over.
# Comment lines are stripped first: the commentary explaining why sort -V was
# removed names it, and a guard that cannot survive its own rationale is not a
# guard anyone will keep.
grep -v '^[[:space:]]*#' "$ROOT_DIR/spm.sh" > "$TEST_ROOT/spm-code-only.sh"
for gnuism in 'sort -V' 'date -d ' 'base64 -w' 'grep -P' 'sed -i ' 'mktemp -p '; do
	if grep -qF -- "$gnuism" "$TEST_ROOT/spm-code-only.sh"; then
		printf 'spm.sh uses the GNU-only construct "%s" with no BSD fallback\n' \
			"$gnuism" >&2
		exit 1
	fi
done
printf '  version ordering, stat, and path resolution verified without GNU-only flags\n'

printf 'Durability regression: competing writers\n'
# Two writers racing on one vault is the failure the advisory lock exists to
# prevent, and it is the one nobody notices until a record disappears. This
# runs concurrent writers against a real vault and asserts what has to hold
# afterwards: the vault still opens, and every writer that reported success
# left its record behind. A lost update passes a "does it still open" check
# on its own, which is why the record count is asserted too.
race_dir="$TEST_ROOT/race"
mkdir -p "$race_dir"
race_vault="$race_dir/vault.gpg"
printf 'META_RECOVERY_PUBKEY	%s	-	-	-	-
' "$TEST_RECOVERY_B64" > "$race_dir/seed"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$race_vault" "$race_dir/seed"
chmod 600 "$race_vault"

# Serialise on the same lock file the CLI uses, then read-modify-write. Without
# the lock these interleave and the last writer wins with a vault missing the
# others' rows.
race_writer() {
	local index="$1" plain
	plain="$race_dir/plain.$index"
	(
		exec 9>"$race_vault.lock"
		# The same lock the CLI takes, rather than flock(1) directly: this
		# test ran on macOS, where there is no flock, and every writer sailed
		# through unlocked while the assertion below still expected the lock
		# to have held.
		vault_lock_hold_fd9 || exit 1
		# shellcheck disable=SC2317
		printf '%s' "$AUDIT_PASSWORD" | \
			python3 "$SPM_CORE_PATH" read "$race_vault" "$plain" >/dev/null
		printf '%s\tRacer%s\tu%s\ts%s\thttps://r%s.invalid\t2025-01-01T00:00:00Z\n' \
			"$index" "$index" "$index" "$index" "$index" >> "$plain"
		printf '%s' "$AUDIT_PASSWORD" | \
			python3 "$SPM_CORE_PATH" write "$race_vault" "$plain" >/dev/null
	)
}

SPM_CORE_DIR="$XDG_DATA_HOME/spm" ensure_core_script "$XDG_DATA_HOME/spm" >/dev/null

race_pids=""
for racer in 1 2 3 4 5; do
	race_writer "$racer" &
	race_pids="$race_pids $!"
done
race_failed=0
for pid in $race_pids; do wait "$pid" || race_failed=1; done
[ "$race_failed" -eq 0 ] || { printf 'a locked concurrent writer failed\n' >&2; exit 1; }

printf '%s' "$AUDIT_PASSWORD" | \
	python3 "$SPM_CORE_PATH" read "$race_vault" "$TEST_ROOT/race-final" >/dev/null \
	|| { printf 'the vault does not open after concurrent writes\n' >&2; exit 1; }
race_rows="$(awk -F '\t' '$2 ~ /^Racer/ {n++} END{print n+0}' "$TEST_ROOT/race-final")"
[ "$race_rows" -eq 5 ] || {
	printf 'concurrent writers lost updates: %s of 5 rows survived\n' "$race_rows" >&2
	exit 1
}
# A staging file left behind by a racing writer would be collected by the next
# backup sweep and is a real leak, so the directory has to come back clean.
race_stage_files="$(find "$race_dir" -name '*.stage.*' -print -quit)"
[ -z "$race_stage_files" ] || {
	printf 'concurrent writers left staging files behind: %s\n' "$race_stage_files" >&2
	exit 1
}
printf '  5 concurrent writers, all 5 records survived, no staging files left\n'

# The same race again, this time through the lock SPM itself takes, and with
# flock(1) forced out of reach so the Python path is the one under test.
#
# That forcing is the point. macOS has no flock(1), so before 3.4.1 the CLI
# took no lock there at all while the dashboard did -- one side believing it
# was protected. Testing the fallback only on macOS would mean testing it
# nowhere most of the time, so it is exercised here on every platform.
lock_fallback_dir="$TEST_ROOT/lock-fallback"
mkdir -p "$lock_fallback_dir/bin"
# A PATH containing only the tools these writers need, and deliberately not
# flock(1), so `command -v flock` genuinely fails inside them. Stripping
# flock's directory out of the real PATH does not work -- it lives in the same
# directory as everything else.
for lock_tool in bash python3 cat sleep; do
	lock_tool_path="$(command -v "$lock_tool")" || {
		printf 'the lock fallback test needs %s\n' "$lock_tool" >&2; exit 1; }
	ln -sf "$lock_tool_path" "$lock_fallback_dir/bin/$lock_tool"
done
lock_counter="$lock_fallback_dir/counter"
printf '0\n' > "$lock_counter"
cat > "$lock_fallback_dir/writer.sh" <<'LOCKW'
set -u
VAULT_FILE="$1"
COUNTER="$2"
CLI_VAULT_LOCKED=0
vault_lock_hold_fd9() {
	if command -v flock >/dev/null 2>&1; then
		flock -x 9
		return $?
	fi
	python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX)' 2>/dev/null
}
exec 9>"${VAULT_FILE}.lock" || exit 1
vault_lock_hold_fd9 || exit 1
# A read-modify-write wide enough that unlocked writers reliably overlap.
n="$(cat "$COUNTER")"
sleep 0.2
printf '%s\n' "$((n + 1))" > "$COUNTER"
exec 9>&-
LOCKW

lock_path_without_flock="$lock_fallback_dir/bin"
if PATH="$lock_path_without_flock" command -v flock >/dev/null 2>&1; then
	printf 'could not hide flock(1); the fallback path was not exercised\n' >&2
	exit 1
fi
lock_pids=""
for _lock_racer in 1 2 3 4 5 6 7 8; do
	PATH="$lock_path_without_flock" bash "$lock_fallback_dir/writer.sh" \
		"$race_vault" "$lock_counter" &
	lock_pids="$lock_pids $!"
done
for pid in $lock_pids; do wait "$pid" || {
	printf 'a writer using the python lock fallback failed\n' >&2; exit 1; }
done
lock_total="$(cat "$lock_counter")"
[ "$lock_total" -eq 8 ] || {
	printf 'the python lock fallback lost updates: %s of 8\n' "$lock_total" >&2
	exit 1
}
printf '  python lock fallback (flock hidden): 8 racing writers, 8 survived\n'

printf 'Web regression: session vault-key cache\n'
# The dashboard holds a session's unwrapped vault key so every read after the
# first skips the key envelope. Three things have to hold, and only the first
# is about speed:
#   - a cached read returns exactly what a master-password read returns
#   - a key that no longer opens the vault falls back instead of failing, since
#     a restore or a sync can replace the file under a live session
#   - the key never outlives the session that holds it
python3 - "$web_script" "$PASSWORD_VAULT" "$AUDIT_PASSWORD" <<'CACHEPY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("spmweb", sys.argv[1])
web = importlib.util.module_from_spec(spec)
os.environ["SPM_VAULT_PATH"] = sys.argv[2]
try:
    spec.loader.exec_module(web)
except SystemExit:
    pass

vault, master = sys.argv[2], sys.argv[3]
web.VAULT_PATH = vault

session = {"master": master}
first = web.load_vault(master, session)
if not session.get("vault_key"):
    # A legacy vault has no separate key; the cache is a no-op and that is
    # correct, so the rest of this only applies to a container.
    print("  vault-key cache: legacy vault, nothing to cache (correct)")
    sys.exit(0)

second = web.load_vault(master, session)
if first != second:
    sys.exit("a cached read returned different plaintext from the first read")

# A key that does not open this vault must not break the session.
session["vault_key"] = "not-this-vaults-key"
recovered = web.load_vault(master, session)
if recovered != first:
    sys.exit("a stale cached key was not recovered from")
if session["vault_key"] == "not-this-vaults-key":
    sys.exit("the stale key was left in the session")
print("  vault-key cache: cached read matches, stale key falls back and re-caches")
CACHEPY

# The cached key must live in the session record and nowhere else, so that
# popping the session is enough to forget it. A module-level cache would
# survive logout, which is the one thing this must not do.
if grep -nE '^[A-Z_]*(KEY_CACHE|VAULT_KEY_CACHE)' "$web_script"; then
	printf 'the vault key is cached outside the session record\n' >&2
	exit 1
fi
grep -q '"vault_key": opened_key or ""' "$web_script" || {
	printf 'login does not seed the session vault key\n' >&2; exit 1
}

printf 'CLI regression: doctor --json\n'
# doctor --json is the machine-readable half of the same checks. Two things
# make it useful and both are asserted: stdout carries the document and
# nothing else, so it pipes into jq without a filter; and the exit status
# mirrors the verdict, so a script can gate on it without parsing.
doctor_plain="$TEST_ROOT/doctor-plain"
doctor_vault="$TEST_ROOT/doctor-vault.gpg"
printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n1\tGood\tu@example.invalid\tSecret1\thttps://a.invalid\t2025-01-01T00:00:00Z\nNOTE\t1\tMemo\taGk=\t2025-01-01T00:00:00Z\t-\n' \
	"$TEST_RECOVERY_B64" > "$doctor_plain"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$doctor_vault" "$doctor_plain"
chmod 600 "$doctor_vault"

doctor_json="$TEST_ROOT/doctor.json"
doctor_rc=0
( export VAULT_FILE="$doctor_vault" MASTER_PW="$AUDIT_PASSWORD" VAULT_KEY=""
  cmd_doctor_json ) > "$doctor_json" 2>/dev/null || doctor_rc=$?

python3 - "$doctor_json" "$doctor_rc" "$doctor_vault" <<'DOCPY'
import json
import sys

path, exit_code, vault = sys.argv[1], int(sys.argv[2]), sys.argv[3]
raw = open(path, encoding="utf-8").read()
try:
    report = json.loads(raw)
except ValueError as exc:
    sys.exit("doctor --json did not emit a lone JSON document: %s" % exc)

if report["vault"]["path"] != vault:
    sys.exit("report names the wrong vault: %s" % report["vault"]["path"])

by_id = {c["id"]: c for c in report["checks"]}
for required in ("duplicate_ids", "empty_passwords", "split_records",
                 "vault_format", "recovery_pubkey", "recovery_pairing",
                 "file_permissions"):
    if required not in by_id:
        sys.exit("report is missing the %s check" % required)
    if by_id[required]["status"] not in ("ok", "warn", "fail"):
        sys.exit("%s has a status outside ok/warn/fail" % required)

if by_id["duplicate_ids"]["status"] != "ok":
    sys.exit("a clean vault reported duplicate ids")
if by_id["split_records"]["status"] != "ok":
    sys.exit("a clean vault reported split records")
if report["counts"]["passwords"] != 1 or report["counts"]["notes"] != 1:
    sys.exit("counts are wrong: %r" % report["counts"])

# The exit status has to follow the verdict, or gating on it is a lie.
failed = report["summary"]["failed"]
if failed and exit_code == 0:
    sys.exit("checks failed but doctor --json exited 0")
if not failed and exit_code != 0:
    sys.exit("no check failed but doctor --json exited %d" % exit_code)

# A report is only safe to hand to a log collector if it carries no secret.
blob = json.dumps(report)
for secret in ("Secret1", "aGk="):
    if secret in blob:
        sys.exit("doctor --json leaked a secret field: %s" % secret)
print("  doctor --json: %d checks, exit %d, no secret in the document"
      % (len(report["checks"]), exit_code))
DOCPY

# The tests above call cmd_doctor_json after sourcing the library, which skips
# main() entirely -- and main() is where the banner, the language prompt and
# the consent gate live. 3.4.1 shipped `doctor --json` emitting a banner and a
# password prompt on stdout for exactly that reason: the function was tested,
# the command was not. This runs the real command, as a user would.
doctor_cli_json="$TEST_ROOT/doctor-cli.json"
doctor_cli_err="$TEST_ROOT/doctor-cli.err"
doctor_cli_rc=0
printf '%s\n' "$AUDIT_PASSWORD" | \
	env HOME="$TEST_ROOT/doctor-home" XDG_DATA_HOME="$TEST_ROOT/doctor-home/data" \
		PASSWORD_VAULT="$doctor_vault" \
		bash "$ROOT_DIR/spm.sh" doctor --json \
	> "$doctor_cli_json" 2> "$doctor_cli_err" || doctor_cli_rc=$?

# The very first byte has to be the document. Parsing alone is not enough --
# a JSON parser that skips leading whitespace would accept a banner that ends
# in a newline, and a caller piping to jq would not.
[ "$(head -c 1 "$doctor_cli_json")" = "{" ] || {
	printf 'doctor --json did not start with the document:\n' >&2
	head -c 200 "$doctor_cli_json" | cat -v >&2
	exit 1
}
grep -q 'Sans Password Manager' "$doctor_cli_json" && {
	printf 'the banner is on stdout, where the JSON document belongs\n' >&2
	exit 1
}
grep -qi 'master password' "$doctor_cli_json" && {
	printf 'the password prompt is on stdout, where the JSON document belongs\n' >&2
	exit 1
}
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$doctor_cli_json" || {
	printf 'doctor --json emitted something that is not one JSON document\n' >&2
	exit 1
}
# The prompt still has to reach a human, just not through stdout.
grep -qi 'master password' "$doctor_cli_err" || {
	printf 'the password prompt vanished entirely; it belongs on stderr\n' >&2
	exit 1
}
# The exit status has to follow the verdict here too, not just when the
# function is called directly.
doctor_cli_failed="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"]["failed"])' "$doctor_cli_json")"
if [ "$doctor_cli_failed" -gt 0 ] && [ "$doctor_cli_rc" -eq 0 ]; then
	printf 'doctor --json reported %s failed check(s) but exited 0\n' "$doctor_cli_failed" >&2
	exit 1
fi
if [ "$doctor_cli_failed" -eq 0 ] && [ "$doctor_cli_rc" -ne 0 ]; then
	printf 'doctor --json reported no failures but exited %s\n' "$doctor_cli_rc" >&2
	exit 1
fi
printf '  doctor --json as a real command: stdout is the document, prompt on stderr\n'

# A vault with a duplicate id and a split record has to be reported as failed,
# and the exit status has to follow. Proving the clean case alone would pass
# for a report that never says "fail".
doctor_bad_plain="$TEST_ROOT/doctor-bad-plain"
doctor_bad_vault="$TEST_ROOT/doctor-bad.gpg"
printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n7\tOne\tu\tS1\thttps://a.invalid\t2025-01-01T00:00:00Z\n7\tTwo\tu\tS2\thttps://b.invalid\t2025-01-01T00:00:00Z\nBACKUP_CODE\t9\tBro\vken\tY29kZQ==\t2025-01-01T00:00:00Z\t-\n' \
	"$TEST_RECOVERY_B64" > "$doctor_bad_plain"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$doctor_bad_vault" "$doctor_bad_plain"
chmod 600 "$doctor_bad_vault"
doctor_bad_rc=0
( export VAULT_FILE="$doctor_bad_vault" MASTER_PW="$AUDIT_PASSWORD" VAULT_KEY=""
  cmd_doctor_json ) > "$TEST_ROOT/doctor-bad.json" 2>/dev/null || doctor_bad_rc=$?
[ "$doctor_bad_rc" -ne 0 ] || {
	printf 'doctor --json exited 0 for a vault with a duplicate id and a split record\n' >&2
	exit 1
}
python3 - "$TEST_ROOT/doctor-bad.json" <<'DOCBADPY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
by_id = {c["id"]: c for c in report["checks"]}
if by_id["duplicate_ids"]["status"] != "fail":
    sys.exit("a duplicated password id was not reported as a failure")
if by_id["split_records"]["status"] != "fail":
    sys.exit("a record split by a line break was not reported as a failure")
if report["summary"]["status"] != "fail":
    sys.exit("summary status is %r with two failing checks"
             % report["summary"]["status"])
print("  doctor --json: a damaged vault is reported failed, and exits non-zero")
DOCBADPY

# The human doctor and the JSON report must not drift: they now read the same
# scan out of the core, and this is what proves it stayed that way.
scan_out="$TEST_ROOT/scan-records.tsv"
core scan-records "$doctor_bad_plain" > "$scan_out"
grep -q '^SUMMARY	1	0$' "$scan_out" || {
	printf 'core scan-records did not report the one broken record\n' >&2
	cat "$scan_out" >&2; exit 1
}
grep -q '^BROKEN	4	BACKUP_CODE	9	' "$scan_out" || {
	printf 'core scan-records did not describe the broken record\n' >&2
	cat "$scan_out" >&2; exit 1
}
grep -q 'Bro' "$scan_out" && ! grep -q 'Y29kZQ==' "$scan_out" || {
	printf 'core scan-records printed the secret field\n' >&2; exit 1
}

printf 'Core regression: trusted core\n'
SPM_CORE_DIR="$XDG_DATA_HOME/spm" ensure_core_script "$XDG_DATA_HOME/spm"
SPM_CORE_PATH="$SPM_CORE_PATH" python3 "$ROOT_DIR/tests/core-test.py" \
	|| { printf 'the trusted core failed its own tests\n' >&2; exit 1; }

# The format version is the core's to state; nothing else may hold a copy.
VAULT_FORMAT_VERSION="$(core current-version)"
[ -n "$VAULT_FORMAT_VERSION" ] || { printf 'the core did not report a format version\n' >&2; exit 1; }

# Every write stamps exactly one current version row, wherever it came from.
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/fmt-plain"
stamped="$(awk -F '\t' '$1=="META_VAULT_VERSION"' "$TEST_ROOT/fmt-plain" | wc -l)"
[ "$stamped" -eq 1 ] || { printf 'expected exactly 1 version row, found %s\n' "$stamped" >&2; exit 1; }
[ "$(awk -F '\t' '$1=="META_VAULT_VERSION"{print $2}' "$TEST_ROOT/fmt-plain")" = "$VAULT_FORMAT_VERSION" ]
# It must be first, so a reader can identify the format without scanning.
[ "$(head -n1 "$TEST_ROOT/fmt-plain" | cut -f1)" = "META_VAULT_VERSION" ]

# A vault with no version row is format 1, and upgrades on the next write
# rather than through a separate migration step.
printf '1\tLegacy\tuser\tsecret\t-\t2025-01-01T00:00:00Z\t-\n' > "$TEST_ROOT/legacy-plain"
[ "$(vault_format_version "$TEST_ROOT/legacy-plain")" = "1" ]
stamp_vault_version "$TEST_ROOT/legacy-plain" "$TEST_ROOT/legacy-stamped"
[ "$(vault_format_version "$TEST_ROOT/legacy-stamped")" = "$VAULT_FORMAT_VERSION" ]
# Stamping is idempotent: a second pass must not add a second row.
stamp_vault_version "$TEST_ROOT/legacy-stamped" "$TEST_ROOT/legacy-twice"
[ "$(awk -F '\t' '$1=="META_VAULT_VERSION"' "$TEST_ROOT/legacy-twice" | wc -l)" -eq 1 ]
cmp -s "$TEST_ROOT/legacy-stamped" "$TEST_ROOT/legacy-twice" \
	|| { printf 'stamping is not idempotent\n' >&2; exit 1; }
# A stale version row is replaced, never duplicated.
printf 'META_VAULT_VERSION\t1\t-\t-\t-\t-\n1\tA\tb\tc\td\te\n' > "$TEST_ROOT/stale-plain"
stamp_vault_version "$TEST_ROOT/stale-plain" "$TEST_ROOT/stale-out"
[ "$(awk -F '\t' '$1=="META_VAULT_VERSION"' "$TEST_ROOT/stale-out" | wc -l)" -eq 1 ]
[ "$(vault_format_version "$TEST_ROOT/stale-out")" = "$VAULT_FORMAT_VERSION" ]

# There is one implementation, not two that agree. Before the trusted core the
# CLI and the dashboard each carried their own stamping, key wrapping and
# vault mutation, and this test compared them byte for byte; a shared core
# makes that comparison vacuous, so what is asserted now is the sharing itself.
python3 - "$web_script" "$VAULT_FORMAT_VERSION" "$SPM_LIBRARY" <<'PYFMT'
import ast, os, shlex, subprocess, sys, tempfile

web_src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(web_src)

# The dashboard must not define vault crypto of its own. Adapters that forward
# to the core are fine; a function body that reimplements one is not.
OWNED = {"stamp_vault_version", "vault_format_version", "encrypt_vault",
         "rewrap_vault_key", "unwrap_vault_key", "decrypt_vault_file",
         "recovery_pubkey_pem", "_archive_vault_generation"}
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in OWNED:
        body = [n for n in node.body if not isinstance(n, ast.Expr)
                or not isinstance(n.value, ast.Constant)]
        assert len(body) == 1 and isinstance(body[0], (ast.Return, ast.Expr)), (
            "the dashboard reimplements %s instead of delegating to the core"
            % node.name)
        assert "core." in ast.unparse(body[0]), (
            "%s does not delegate to the core" % node.name)
assert "_load_core()" in web_src, "the dashboard does not load the trusted core"

# Locate the one core the CLI installs, and confirm the dashboard resolves to
# a byte-identical file.
lib = sys.argv[3]
core_path = subprocess.check_output(
    ["bash", "-c", "source %s >/dev/null 2>&1; ensure_core_script; printf %%s \"$SPM_CORE_PATH\""
     % shlex.quote(lib)],
    text=True)
assert os.path.isfile(core_path), "the CLI did not install a core at %r" % core_path
web_core = os.path.join(os.path.dirname(os.path.abspath(sys.argv[1])), "spm_core.py")
assert os.path.isfile(web_core), "no core beside the dashboard at %r" % web_core
assert open(core_path, "rb").read() == open(web_core, "rb").read(), (
    "the CLI and the dashboard resolved to different cores")

sys.path.insert(0, os.path.dirname(core_path))
import spm_core

assert str(spm_core.VAULT_FORMAT_VERSION) == sys.argv[2], (
    "core version %r != what the CLI reports %r"
    % (spm_core.VAULT_FORMAT_VERSION, sys.argv[2]))

# The shell wrapper must pass through to the core without altering anything.
cases = [
    "META_RECOVERY_PUBKEY\tabc\t-\t-\t-\t-\n1\tA\tb\tc\td\te\n",
    "META_VAULT_VERSION\t2\t-\t-\t-\t-\n1\tA\tb\tc\td\te\n",
    "META_VAULT_VERSION\t1\t-\t-\t-\t-\nMETA_VAULT_VERSION\t9\t-\t-\t-\t-\n1\tA\tb\tc\td\te\n",
    "",
    "META_RECOVERY_PUBKEY\tabc\t-\t-\t-\t-\n1\tA\tb\tc\td\te",
    "META_RECOVERY_PUBKEY\tabc\t-\t-\t-\t-\n\n1\tA\tb\tc\td\te\n",
]
d = tempfile.mkdtemp()
for i, text in enumerate(cases):
    open(d + "/in", "w", encoding="utf-8").write(text)
    subprocess.run(["bash", "-c",
        "source %s >/dev/null 2>&1; stamp_vault_version %s/in %s/out"
        % (shlex.quote(lib), shlex.quote(d), shlex.quote(d))],
        check=True)
    sh = open(d + "/out", encoding="utf-8").read()
    py = spm_core.stamp_version(text)
    assert sh == py, "case %d diverged\n  shell %r\n  core  %r" % (i, sh, py)
print("  one shared core; shell wrapper verified over %d cases" % len(cases))
PYFMT

# Key derivation is pinned, not inherited. The measurable part is the digest:
# GnuPG 2.2 already defaults to s2k mode 3 at the maximum count, but defaults to
# SHA1 (hash 2) for the digest. hash 10 is SHA512.
# list-packets exits non-zero on a symmetric file it cannot decrypt, but it
# still prints the header packet, which is the only part being asserted.
awk 'NR==2{sub(/^KEY /,"");print;exit}' "$PASSWORD_VAULT" | base64 -d >"$TEST_ROOT/key-envelope.gpg"
sed -n '/^DATA$/,$p' "$PASSWORD_VAULT" | sed '1d' | base64 -d >"$TEST_ROOT/vault-data.gpg"
gpg --list-packets "$TEST_ROOT/key-envelope.gpg" >"$TEST_ROOT/vault-packets" 2>/dev/null || true
gpg --list-packets "$TEST_ROOT/vault-data.gpg" >>"$TEST_ROOT/vault-packets" 2>/dev/null || true
grep -q 'symkey enc packet' "$TEST_ROOT/vault-packets"
if ! grep -qE 's2k 3, hash 10' "$TEST_ROOT/vault-packets"; then
	printf 'vault was not written under the pinned s2k policy:\n' >&2
	grep 'symkey enc packet' "$TEST_ROOT/vault-packets" >&2
	exit 1
fi
grep -qE 'count 65011712' "$TEST_ROOT/vault-packets"

# The new row must be invisible to every parser and to the integrity scanner.
[ "$(awk -F '\t' '$1 ~ /^[0-9]+$/' "$TEST_ROOT/fmt-plain" | wc -l)" -ge 1 ]
cmd_doctor >"$TEST_ROOT/doctor-fmt.txt" 2>&1 || true
if ! grep -q 'Vault format version' "$TEST_ROOT/doctor-fmt.txt"; then
	printf 'doctor does not report the vault format version. Output was:\n' >&2
	sed 's/^/    /' "$TEST_ROOT/doctor-fmt.txt" >&2
	exit 1
fi
grep -q 'Vault format version 3 (current)' "$TEST_ROOT/doctor-fmt.txt" \
	|| { printf 'doctor did not see the upgraded format:\n' >&2
	     grep -i 'format' "$TEST_ROOT/doctor-fmt.txt" >&2; exit 1; }

# --- 2.13.0 master password change from the SPM Dashboard --------------------
printf 'Web regression: master password change\n'

# The fixture vault ships a placeholder recovery pubkey ("test"), which is not
# a key at all. Swap in the real one generated earlier so the SUCCESS path can
# be proved end to end -- the refusal path is exercised separately below by
# breaking it again on purpose.
web_pub_b64="$(base64 < "$TEST_ROOT/public.pem" | tr -d '\n')"
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/rekey-plain"
awk -F '\t' -v pub="$web_pub_b64" 'BEGIN{OFS="\t"}
	$1=="META_RECOVERY_PUBKEY"{$2=pub} {print}' \
	"$TEST_ROOT/rekey-plain" > "$TEST_ROOT/rekey-plain.new"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$PASSWORD_VAULT" "$TEST_ROOT/rekey-plain.new"

NEW_MASTER="SPM-Rotated-Only-4242"

curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/settings.html" \
	"http://127.0.0.1:$WEB_PORT/settings"
grep -q '<use href="#i-gear"' "$TEST_ROOT/settings.html"
grep -q 'action="/settings/master-password"' "$TEST_ROOT/settings.html"
grep -q 'data-i18n="nav.group.settings"' "$TEST_ROOT/settings.html"
grep -q 'data-i18n="nav.master_password"' "$TEST_ROOT/settings.html"
# Biometric Unlock moved into Settings; it must not have been dropped on the way.
grep -q 'href="/unlock/settings"' "$TEST_ROOT/settings.html"
# The form is a plain in-flow POST, and _send_html must have stamped its token.
mp_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$TEST_ROOT/settings.html" | head -n1)"
[ "${#mp_csrf}" -eq 64 ]

vault_before="$(sha256sum < "$PASSWORD_VAULT")"

# Each refusal must leave the vault byte-identical. A change-master path that
# half-applies is worse than one that does not run at all.
mp_reject() {
	curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/mp-reject.html" \
		-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
		--data-urlencode "csrf=$mp_csrf" \
		--data-urlencode "current=$2" --data-urlencode "new=$3" \
		--data-urlencode "confirm=$4" \
		"http://127.0.0.1:$WEB_PORT/settings/master-password"
	if ! grep -q "$1" "$TEST_ROOT/mp-reject.html"; then
		printf 'expected refusal %s was not shown\n' "$1" >&2
		sed -n 's/.*class=.flash error.>\([^<]*\).*/got: \1/p' "$TEST_ROOT/mp-reject.html" >&2
		exit 1
	fi
	if [ "$(sha256sum < "$PASSWORD_VAULT")" != "$vault_before" ]; then
		printf 'vault was modified by a refused change (%s)\n' "$1" >&2
		exit 1
	fi
}

mp_reject 'Current master password is incorrect' \
	'not-the-password' "$NEW_MASTER" "$NEW_MASTER"
mp_reject 'do not match' \
	"$AUDIT_PASSWORD" "$NEW_MASTER" "${NEW_MASTER}-typo"
mp_reject 'at least 12 characters' \
	"$AUDIT_PASSWORD" 'short11chr' 'short11chr'
mp_reject 'same as the current one' \
	"$AUDIT_PASSWORD" "$AUDIT_PASSWORD" "$AUDIT_PASSWORD"

# A vault whose recovery pubkey is unusable must fail BEFORE the vault is
# touched: a rotated vault whose .recovery file still holds the old password
# is the one state `spm forgot` cannot get out of.
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/nopub-plain"
awk -F '\t' 'BEGIN{OFS="\t"} $1=="META_RECOVERY_PUBKEY"{$2="dGVzdA=="} {print}' \
	"$TEST_ROOT/nopub-plain" > "$TEST_ROOT/nopub-plain.new"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$PASSWORD_VAULT" "$TEST_ROOT/nopub-plain.new"
vault_before="$(sha256sum < "$PASSWORD_VAULT")"
mp_reject 'could not be migrated' \
	"$AUDIT_PASSWORD" "$NEW_MASTER" "$NEW_MASTER"
# Put the real key back for the success path.
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 \
	-o "$PASSWORD_VAULT" "$TEST_ROOT/rekey-plain.new"

# A second session, to prove the change signs it out rather than leaving it
# holding a password that no longer opens anything.
# A throttle key of its own: the biometric section above deliberately burns
# this host's login-failure budget, and the lockout is per client.
curl -fsS -c "$TEST_ROOT/cookies2" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	-H 'X-Real-IP: 203.0.113.7' \
	--data-urlencode "password=$AUDIT_PASSWORD" "http://127.0.0.1:$WEB_PORT/login"
code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$TEST_ROOT/cookies2" \
	"http://127.0.0.1:$WEB_PORT/passwords")"
[ "$code" = "200" ] || { printf 'second session did not open\n' >&2; exit 1; }

curl -fsS -D "$TEST_ROOT/mp-ok.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$mp_csrf" \
	--data-urlencode "current=$AUDIT_PASSWORD" \
	--data-urlencode "new=$NEW_MASTER" --data-urlencode "confirm=$NEW_MASTER" \
	"http://127.0.0.1:$WEB_PORT/settings/master-password"
grep -qi '^Location: /settings?msg=changed' "$TEST_ROOT/mp-ok.headers"

# The vault now opens with the new password and no longer with the old one.
test_decrypt_vault "$PASSWORD_VAULT" "$NEW_MASTER" "$TEST_ROOT/rotated-plain"
grep -q 'DemoSecret42' "$TEST_ROOT/rotated-plain"
if test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/old-master-should-fail" >/dev/null 2>&1; then
	printf 'the old master password still opens the vault after a change\n' >&2
	exit 1
fi

# Recovery wraps the stable vault key, not either master password. Assert the
# property that matters: the recovered secret opens the vault DATA section on
# its own, and is neither password. A file that merely differs from the
# password would pass a comparison and still recover nothing.
openssl rsautl -decrypt -inkey "$TEST_ROOT/private.pem" \
	-in "$PASSWORD_VAULT.recovery" > "$TEST_ROOT/recovered-vault-key" 2>/dev/null
[ -s "$TEST_ROOT/recovered-vault-key" ] || { printf 'recovery file is empty\n' >&2; exit 1; }
for known in "$NEW_MASTER" "$AUDIT_PASSWORD"; do
	if [ "$(cat "$TEST_ROOT/recovered-vault-key")" = "$known" ]; then
		printf 'recovery file still holds a master password, not an independent vault key\n' >&2
		exit 1
	fi
done
sed -n '/^DATA$/,$p' "$PASSWORD_VAULT" | sed '1d' | base64 -d >"$TEST_ROOT/recover-data.gpg"
gpg --batch --quiet --pinentry-mode loopback \
	--passphrase-file "$TEST_ROOT/recovered-vault-key" \
	--decrypt "$TEST_ROOT/recover-data.gpg" >"$TEST_ROOT/recovered-plain" 2>/dev/null \
	|| { printf 'the recovered vault key does not decrypt the vault data\n' >&2; exit 1; }
grep -q 'DemoSecret42' "$TEST_ROOT/recovered-plain" \
	|| { printf 'vault key decrypted the container but the contents are wrong\n' >&2; exit 1; }

# The previous vault is kept, still under the old password. It is the same
# container the live vault is, so it must open through the same reader -- a
# .bak that only raw gpg could read would mean the two had diverged.
test_decrypt_vault "$PASSWORD_VAULT.bak" "$AUDIT_PASSWORD" "$TEST_ROOT/bak-plain"
grep -q 'DemoSecret42' "$TEST_ROOT/bak-plain" \
	|| { printf 'the preserved .bak does not hold the previous vault\n' >&2; exit 1; }

# The acting session survives without a re-login; every other one is gone.
code="$(curl -sS -o /dev/null -w '%{http_code}' -b "$TEST_ROOT/cookies" \
	"http://127.0.0.1:$WEB_PORT/settings")"
[ "$code" = "200" ] || { printf 'the acting session was signed out by its own change\n' >&2; exit 1; }
curl -sS -b "$TEST_ROOT/cookies2" -o "$TEST_ROOT/stale.html" \
	"http://127.0.0.1:$WEB_PORT/passwords"
if ! grep -q 'name="password"' "$TEST_ROOT/stale.html"; then
	printf 'a session holding the old password was not signed out\n' >&2
	exit 1
fi

# Rotate back so the rest of the suite keeps its fixture password, which also
# exercises the flow a second time from a session that has already used it.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/settings2.html" \
	"http://127.0.0.1:$WEB_PORT/settings"
grep -q 'Master password changed' "$TEST_ROOT/settings2.html" || true
mp_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' "$TEST_ROOT/settings2.html" | head -n1)"
curl -fsS -D "$TEST_ROOT/mp-back.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$mp_csrf" \
	--data-urlencode "current=$NEW_MASTER" \
	--data-urlencode "new=$AUDIT_PASSWORD" --data-urlencode "confirm=$AUDIT_PASSWORD" \
	"http://127.0.0.1:$WEB_PORT/settings/master-password"
grep -qi '^Location: /settings?msg=changed' "$TEST_ROOT/mp-back.headers"
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/rotated-back-plain"

# A WEBAUTHN row must be invisible to password parsing and to the security
# score: it is neither a credential the user stores nor one that can be weak.
python3 - "$web_script" <<'PYWEBROW'
import os, sys
# Exec'ing the module head rather than importing it means there is no __file__
# for the core loader to work from, so point it at the core explicitly.
os.environ["SPM_CORE_DIR"] = os.path.dirname(os.path.abspath(sys.argv[1]))
src = open(sys.argv[1], encoding="utf-8").read()
head = src.split("class Handler")[0]
head = head.replace('VAULT_PATH = os.environ.get("SPM_VAULT_PATH")', 'VAULT_PATH = "/dev/null"')
head = head.replace('raise SystemExit(f"Vault file not found: {VAULT_PATH!r}")', "pass")
ns = {}
exec(compile(head, "generated", "exec"), ns)
plain = "\n".join([
    "1\tExample\tuser@example.invalid\tDemoSecret42\thttps://example.invalid\t2025-01-01T00:00:00Z",
    "WEBAUTHN\t1\tY3JlZA\tTUlJQg==\tlocalhost\tiPhone\t2026-08-25T00:00:00Z",
])
_, entries = ns["parse_entries"](plain)
assert len(entries) == 1, "a WEBAUTHN row was parsed as a password: %r" % entries
_, creds = ns["parse_webauthn"](plain)
assert len(creds) == 1 and creds[0][1][5] == "iPhone", creds
# Suspension must be bounded, and an unusable value must fall back rather than
# be taken literally as "resumable forever".
assert ns["_suspend_max_age"]() > 0

# The expected origin follows the RELYING PARTY, never the bind address. SPM's
# documented deployment binds loopback behind a TLS reverse proxy, so a bind of
# 127.0.0.1 says nothing about what the browser connected to. Deriving the
# scheme from the bind yielded http://<public name>:<port> in exactly that
# shape and every assertion failed on an origin mismatch -- while this suite,
# which only ever ran localhost-on-loopback, saw both paths agree and passed.
cfg = ns["_webauthn_config"]
import os as _os
def origin_for(rp, bind, port, override=None):
    ns["BIND_ADDR"], ns["PORT"] = bind, port
    keep = _os.environ.get("SPM_WEB_RP_ID"), _os.environ.get("SPM_WEB_ORIGIN")
    _os.environ["SPM_WEB_RP_ID"] = rp
    if override is None:
        _os.environ.pop("SPM_WEB_ORIGIN", None)
    else:
        _os.environ["SPM_WEB_ORIGIN"] = override
    try:
        return cfg()
    finally:
        for k, v in zip(("SPM_WEB_RP_ID", "SPM_WEB_ORIGIN"), keep):
            if v is None:
                _os.environ.pop(k, None)
            else:
                _os.environ[k] = v

# The production shape: loopback bind, public name, TLS terminated upstream.
assert origin_for("spm.example.test", "127.0.0.1", 8777) == \
    ("spm.example.test", "https://spm.example.test"), origin_for("spm.example.test", "127.0.0.1", 8777)
# Local development still works over plain HTTP, because localhost is the one
# host a browser treats as a secure context without TLS.
assert origin_for("localhost", "127.0.0.1", 18000) == \
    ("localhost", "http://localhost:18000")
# A non-loopback bind with a public name is https too.
assert origin_for("spm.example.test", "0.0.0.0", 8777)[1] == "https://spm.example.test"
# Explicit override, for a proxy on a non-default port.
assert origin_for("spm.example.test", "127.0.0.1", 8777,
                  "https://spm.example.test:8443")[1] == "https://spm.example.test:8443"
# A malformed override disables the feature rather than being trusted.
assert origin_for("spm.example.test", "127.0.0.1", 8777, "javascript:alert(1)") == ("", "")
# No relying party at all means the feature does not exist.
assert origin_for("", "127.0.0.1", 8777) == ("", "")
assert origin_for("not a domain", "127.0.0.1", 8777) == ("", "")
PYWEBROW

# Unlock credentials are a distinct row type from PASSKEY on purpose, so
# `spm passkey-list` must not report them.
cmd_webauthn_list | grep -q 'Regression'
cmd_passkey_list | grep -qv 'Regression'

# With no relying party configured the endpoints must not exist at all: a nav
# entry pointing at a 404 is worse than no entry.
grep -q 'if WEBAUTHN_ENABLED:' "$web_script"
grep -q 'SPM_WEB_RP_ID' "$ROOT_DIR/spm.sh"

# The history picker must resolve a snapshot by number: the point of the menu
# is that a generated filename never has to be typed.
grep -q '23) interactive_menu_history ;;' "$ROOT_DIR/spm.sh"
# Two distinct writes, so the two newest snapshots differ in content. With only
# one write the snapshot below it can hold identical bytes, and an off-by-one
# in the picker would restore the right content by accident.
menu_v0="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
menu_tmp="$(make_tmp)"
decrypt_vault_to_file "$menu_tmp"
printf '77\tMenuProbeA\tprobe\tMp9!wwwwwwwwww\tnotes\t2026-01-01T00:00:00Z\n' >> "$menu_tmp"
encrypt_file_to_vault "$menu_tmp"
secure_wipe "$menu_tmp"
menu_v1="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
sleep 1
menu_tmp="$(make_tmp)"
decrypt_vault_to_file "$menu_tmp"
printf '78\tMenuProbeB\tprobe\tMp8!wwwwwwwwww\tnotes\t2026-01-01T00:00:00Z\n' >> "$menu_tmp"
encrypt_file_to_vault "$menu_tmp"
secure_wipe "$menu_tmp"
[ "$menu_v0" != "$menu_v1" ]
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" != "$menu_v1" ]
# Snapshot 1 is the newest: the vault as it stood after probe A. Choosing it
# must bring back exactly that state -- an off-by-one would land on menu_v0.
printf '1\nyes\n\n0\n' | interactive_menu_history >/dev/null 2>&1 || true
menu_now="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
[ "$menu_now" = "$menu_v1" ] || {
	printf 'history picker restored the wrong snapshot (got %s, wanted %s)\n' \
		"$menu_now" "$menu_v1" >&2
	exit 1
}
# `if`, not `&& { exit 1; }`: the expected case is grep finding nothing, and
# under errexit that form would abort the suite exactly when it should pass.
if cmd_list | grep -q 'MenuProbeB'; then
	printf 'restored vault still contains the newer probe entry\n' >&2
	exit 1
fi
cmd_list | grep -q 'MenuProbeA'

# doctor's duplicate-ID line is a verdict, not a progress step, so it must not
# keep the empty "[ ]" marker that the in-progress lines use.
cmd_doctor 2>/dev/null > "$TEST_ROOT/doctor.out"
# `if !`, never `grep -q ... && { exit 1; }`: under errexit the latter aborts
# the whole suite the moment grep simply finds nothing.
if grep -q '^\[ \] Duplicate IDs' "$TEST_ROOT/doctor.out"; then
	printf 'doctor duplicate-ID line still uses the progress marker\n' >&2
	exit 1
fi
if ! grep -qE '^\[(✔|!)\] Duplicate IDs' "$TEST_ROOT/doctor.out"; then
	printf 'doctor duplicate-ID line lost its verdict marker\n' >&2
	exit 1
fi

# --- 3.0.0 wrapped vault key -------------------------------------------------
# The point of a separate vault key is that it is STABLE: a master-password
# change rewraps a small envelope and leaves the vault ciphertext, every .bak,
# every history snapshot and the recovery file untouched. These assert that
# property directly rather than only that the new password works.
printf 'CLI regression: wrapped vault key\n'

VK_ROOT="$TEST_ROOT/vaultkey"
mkdir -p "$VK_ROOT"
VK_OLD="VaultKey-Old-Password-1"
VK_NEW="VaultKey-New-Password-2"

# Drive the interactive flows without a terminal. Only the two stty-guarded
# prompts are stubbed; every other line of change-master and forgot runs.
prompt_master_password() { MASTER_PW="$STUB_NEW_MASTER"; }

vk_data_section() { sed -n '/^DATA$/,$p' "$1" | sed '1d'; }
vk_unwrap() {
	# The vault key as `spm forgot` would recover it: straight out of the
	# recovery file with the private key, no master password involved.
	openssl rsautl -decrypt -inkey "$TEST_RECOVERY_PRIVATE" -in "$1.recovery" 2>/dev/null
}
vk_new_legacy_vault() {
	# A format-1 vault: encrypted under the master password directly, exactly
	# what every vault written before 3.0.0 looks like on disk.
	local target="$1" password="$2"
	printf '%s' "$password" | gpg --batch --yes --pinentry-mode loopback \
		--passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$target" "$PLAIN"
	printf '%s' "$password" | openssl rsautl -encrypt -pubin \
		-inkey "$TEST_RECOVERY_PUBLIC" -out "$target.recovery" 2>/dev/null
}

# --- migration, then a password change that does not re-encrypt anything -----
(
	export VAULT_FILE="$VK_ROOT/a.gpg" RECOVERY_FILE="$VK_ROOT/a.gpg.recovery"
	vk_new_legacy_vault "$VAULT_FILE" "$VK_OLD"
	# `if !`, never `... && { exit 1; }`: the latter makes the whole compound
	# return 1 in the passing case, which errexit turns into a suite abort.
	if is_vault_container "$VAULT_FILE"; then
		printf 'fixture was not a legacy vault\n' >&2; exit 1
	fi

	MASTER_PW="$VK_OLD" VAULT_KEY="" STUB_NEW_MASTER="$VK_NEW" cmd_change_master </dev/null >/dev/null

	is_vault_container "$VAULT_FILE" || { printf 'change-master did not migrate the vault\n' >&2; exit 1; }

	# Two distinct steps, and this is what proves it: the .bak left behind is
	# the MIGRATED container still sealed under the OLD password. Migrating and
	# rekeying in one write would seal the envelope under the new password
	# while .recovery still named the old one -- and the .bak would be the
	# pre-migration legacy file instead of a container.
	is_vault_container "$VAULT_FILE.bak" \
		|| { printf 'the vault was migrated and rekeyed in a single write\n' >&2; exit 1; }
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE.bak" "$VK_ROOT/bak-a" "$VK_OLD" \
		|| { printf 'the migration step did not run under the old password\n' >&2; exit 1; }
	vk_data_section "$VAULT_FILE" > "$VK_ROOT/data-after-change"

	# The recovery file holds the vault key, and that key opens the data.
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-a"
	[ -s "$VK_ROOT/key-a" ] || { printf 'recovery file is empty after migration\n' >&2; exit 1; }
	for known in "$VK_OLD" "$VK_NEW"; do
		[ "$(cat "$VK_ROOT/key-a")" != "$known" ] \
			|| { printf 'recovery file still holds a master password\n' >&2; exit 1; }
	done
	vk_data_section "$VAULT_FILE" | base64 -d > "$VK_ROOT/data-a.gpg"
	gpg --batch --quiet --pinentry-mode loopback --passphrase-file "$VK_ROOT/key-a" \
		--decrypt "$VK_ROOT/data-a.gpg" 2>/dev/null | grep -q 'DemoSecret42' \
		|| { printf 'the recovered vault key does not open the vault\n' >&2; exit 1; }

	# The new password opens it; the old one does not.
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/plain-new" "$VK_NEW" \
		|| { printf 'the new master password does not open the vault\n' >&2; exit 1; }
	grep -q 'DemoSecret42' "$VK_ROOT/plain-new"
	if VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" /dev/null "$VK_OLD" 2>/dev/null; then
		printf 'the old master password still opens the vault\n' >&2; exit 1
	fi

	# Change it once more. This is the assertion the whole design exists for:
	# only the envelope is rewritten, so the ciphertext and the recovery file
	# are byte-identical afterwards.
	# decrypt_vault_to_file, not the container reader: only the former loads
	# VAULT_KEY, and the rewrap below must use a key this call produced.
	MASTER_PW="$VK_NEW"; VAULT_KEY=""
	decrypt_vault_to_file "$VK_ROOT/reload"
	[ -n "$VAULT_KEY" ] || { printf 'reading the vault did not load its key\n' >&2; exit 1; }
	rewrap_vault_key "$VK_OLD"
	vk_data_section "$VAULT_FILE" > "$VK_ROOT/data-after-rewrap"
	cmp -s "$VK_ROOT/data-after-change" "$VK_ROOT/data-after-rewrap" \
		|| { printf 'a master-password change re-encrypted the vault data\n' >&2; exit 1; }
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-a2"
	cmp -s "$VK_ROOT/key-a" "$VK_ROOT/key-a2" \
		|| { printf 'the vault key did not survive a master-password change\n' >&2; exit 1; }
)

# --- an ordinary write must never mint a new vault key -----------------------
# Rotating the key on a save would strand every .bak, snapshot and synced copy
# that the current recovery file can still open.
(
	export VAULT_FILE="$VK_ROOT/b.gpg" RECOVERY_FILE="$VK_ROOT/b.gpg.recovery"
	vk_new_legacy_vault "$VAULT_FILE" "$VK_OLD"
	MASTER_PW="$VK_OLD" VAULT_KEY="" encrypt_file_to_vault "$PLAIN"
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-b1"

	# VAULT_KEY deliberately empty, as it is for any caller that did not just
	# decrypt: the write has to recover the key from the vault, not invent one.
	MASTER_PW="$VK_OLD" VAULT_KEY="" encrypt_file_to_vault "$PLAIN"
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-b2"
	cmp -s "$VK_ROOT/key-b1" "$VK_ROOT/key-b2" \
		|| { printf 'an ordinary vault write rotated the vault key\n' >&2; exit 1; }

	# The .bak it left behind is the same container and opens the same way.
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE.bak" "$VK_ROOT/bak-plain" "$VK_OLD" \
		|| { printf 'the .bak from a format-3 write does not open\n' >&2; exit 1; }
	grep -q 'DemoSecret42' "$VK_ROOT/bak-plain"
)

# --- the migration crash window is recoverable -------------------------------
# Migration installs the container BEFORE it swaps the recovery file. A vault
# caught between the two has a key envelope sealed under the master password
# that .recovery still names, which is the route cmd_forgot tries second.
(
	export VAULT_FILE="$VK_ROOT/c.gpg" RECOVERY_FILE="$VK_ROOT/c.gpg.recovery"
	vk_new_legacy_vault "$VAULT_FILE" "$VK_OLD"
	cp "$RECOVERY_FILE" "$VK_ROOT/c-recovery-before"
	MASTER_PW="$VK_OLD" VAULT_KEY="" encrypt_file_to_vault "$PLAIN"
	# Put the pre-migration recovery file back: the container is installed but
	# the swap never happened.
	cp "$VK_ROOT/c-recovery-before" "$RECOVERY_FILE"

	export RECOVERY_PRIV_DEFAULT="$TEST_RECOVERY_PRIVATE"
	recovered="$(openssl rsautl -decrypt -inkey "$TEST_RECOVERY_PRIVATE" -in "$RECOVERY_FILE" 2>/dev/null)"
	[ "$recovered" = "$VK_OLD" ] || { printf 'the stale recovery file did not hold the master password\n' >&2; exit 1; }
	# Read as a vault key it opens nothing, so only the master-password
	# fallback can rescue this vault.
	vk_data_section "$VAULT_FILE" | base64 -d > "$VK_ROOT/data-c.gpg"
	if printf '%s' "$recovered" | gpg --batch --quiet --pinentry-mode loopback \
		--passphrase-fd 0 --decrypt "$VK_ROOT/data-c.gpg" >/dev/null 2>&1; then
		printf 'the recovered secret should not have been a vault key\n' >&2; exit 1
	fi

	# Drive the real command, not just the helper it leans on.
	MASTER_PW="" VAULT_KEY="" STUB_NEW_MASTER="$VK_NEW" cmd_forgot </dev/null >/dev/null
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/plain-c" "$VK_NEW" \
		|| { printf 'a vault caught mid-migration is unrecoverable\n' >&2; exit 1; }
	grep -q 'DemoSecret42' "$VK_ROOT/plain-c"

	# Recovering once by luck is not enough: the interrupted migration must be
	# finished, or the next recovery would find a password that opens nothing.
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-c"
	[ "$(cat "$VK_ROOT/key-c")" != "$VK_OLD" ] \
		|| { printf 'forgot left the stale recovery file in place\n' >&2; exit 1; }
	vk_data_section "$VAULT_FILE" | base64 -d > "$VK_ROOT/data-c2.gpg"
	gpg --batch --quiet --pinentry-mode loopback --passphrase-file "$VK_ROOT/key-c" \
		--decrypt "$VK_ROOT/data-c2.gpg" 2>/dev/null | grep -q 'DemoSecret42' \
		|| { printf 'the repaired recovery file does not hold the vault key\n' >&2; exit 1; }
)

# --- an unusable recovery pubkey must fail before the vault is touched -------
(
	export VAULT_FILE="$VK_ROOT/d.gpg" RECOVERY_FILE="$VK_ROOT/d.gpg.recovery"
	printf '%s' "$VK_OLD" | gpg --batch --yes --pinentry-mode loopback \
		--passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$VAULT_FILE" "$PLAIN"
	awk -F '\t' 'BEGIN{OFS="\t"} $1=="META_RECOVERY_PUBKEY"{$2="dGVzdA=="} {print}' \
		"$PLAIN" > "$VK_ROOT/d-plain"
	before="$(sha256sum < "$VAULT_FILE")"
	# A nested subshell: the refusal is a `die`, which exits rather than
	# returning, so it has to be contained before `if` can judge it.
	if ( MASTER_PW="$VK_OLD" VAULT_KEY="" encrypt_file_to_vault "$VK_ROOT/d-plain" ) 2>/dev/null; then
		printf 'migration proceeded with an unusable recovery public key\n' >&2; exit 1
	fi
	[ "$(sha256sum < "$VAULT_FILE")" = "$before" ] \
		|| { printf 'a refused migration still rewrote the vault\n' >&2; exit 1; }
	# And it must not litter the vault directory with staging files.
	leftovers="$(find "$VK_ROOT" -maxdepth 1 -name '.d.gpg.*' | wc -l)"
	[ "$leftovers" -eq 0 ] \
		|| { printf 'a refused migration left %s staging file(s) behind\n' "$leftovers" >&2; exit 1; }
)

# --- forgot recovers a fully migrated vault ----------------------------------
(
	export VAULT_FILE="$VK_ROOT/e.gpg" RECOVERY_FILE="$VK_ROOT/e.gpg.recovery"
	export RECOVERY_PRIV_DEFAULT="$TEST_RECOVERY_PRIVATE"
	vk_new_legacy_vault "$VAULT_FILE" "$VK_OLD"
	MASTER_PW="$VK_OLD" VAULT_KEY="" encrypt_file_to_vault "$PLAIN"
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-e"

	MASTER_PW="" VAULT_KEY="" STUB_NEW_MASTER="$VK_NEW" cmd_forgot </dev/null >/dev/null
	# Recovery reset the password without re-encrypting the data, so the vault
	# key -- and therefore the recovery file -- is unchanged.
	vk_unwrap "$VAULT_FILE" > "$VK_ROOT/key-e2"
	cmp -s "$VK_ROOT/key-e" "$VK_ROOT/key-e2" \
		|| { printf 'forgot rotated the vault key\n' >&2; exit 1; }
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/plain-e" "$VK_NEW" \
		|| { printf 'the vault does not open with the password forgot set\n' >&2; exit 1; }
	grep -q 'DemoSecret42' "$VK_ROOT/plain-e"

	# doctor is the only place a user can learn their recovery file is stale,
	# so it has to distinguish "decryptable" from "actually holds the key".
	MASTER_PW="$VK_NEW" VAULT_KEY="" cmd_doctor 2>/dev/null > "$VK_ROOT/doctor-e" || true
	grep -q 'Recovery file holds the current vault key' "$VK_ROOT/doctor-e" \
		|| { printf 'doctor did not confirm the recovery file holds the vault key\n' >&2
		     grep -i 'recovery' "$VK_ROOT/doctor-e" >&2; exit 1; }

	# Break it on purpose: a recovery file holding a master password is exactly
	# what an interrupted migration leaves behind, and doctor must say so.
	printf '%s' "$VK_NEW" | openssl rsautl -encrypt -pubin \
		-inkey "$TEST_RECOVERY_PUBLIC" -out "$RECOVERY_FILE" 2>/dev/null
	MASTER_PW="$VK_NEW" VAULT_KEY="" cmd_doctor 2>/dev/null > "$VK_ROOT/doctor-e2" || true
	grep -q "does not hold this vault's key" "$VK_ROOT/doctor-e2" \
		|| { printf 'doctor did not flag a stale recovery file\n' >&2
		     grep -i 'recovery' "$VK_ROOT/doctor-e2" >&2; exit 1; }
)

# --- every file that IS a vault must be read as one ---------------------------
# .bak, history snapshots and synced copies are the same container as the live
# vault. Each of these paths proves a file opens before it overwrites the live
# one, and each of them read it with raw gpg until the container existed.
(
	export VAULT_FILE="$VK_ROOT/f.gpg" RECOVERY_FILE="$VK_ROOT/f.gpg.recovery"
	vk_new_legacy_vault "$VAULT_FILE" "$VK_OLD"
	export MASTER_PW="$VK_OLD"
	VAULT_KEY="" encrypt_file_to_vault "$PLAIN"

	# A second write archives the first generation as a snapshot.
	VAULT_KEY=""; decrypt_vault_to_file "$VK_ROOT/f-plain"
	printf '2\tSecond\tuser@example.invalid\tAddedLater99\t-\t2025-01-02T00:00:00Z\n' \
		>> "$VK_ROOT/f-plain"
	encrypt_file_to_vault "$VK_ROOT/f-plain"
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/f-check" "$VK_OLD"
	grep -q 'AddedLater99' "$VK_ROOT/f-check"

	snapshot="$(cmd_history_list | head -n1)"
	[ -n "$snapshot" ] || { printf 'no history snapshot was archived\n' >&2; exit 1; }
	printf 'yes\n' | VAULT_KEY="" cmd_history_restore "$snapshot" >/dev/null
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/f-restored" "$VK_OLD" \
		|| { printf 'the restored snapshot does not open\n' >&2; exit 1; }
	grep -q 'DemoSecret42' "$VK_ROOT/f-restored"
	if grep -q 'AddedLater99' "$VK_ROOT/f-restored"; then
		printf 'history-restore did not roll the vault back\n' >&2; exit 1
	fi

	# Sync stages an encrypted copy and proves it opens before pulling it.
	VAULT_KEY="" cmd_sync push "$VK_ROOT/syncdir" >/dev/null
	VAULT_KEY=""; decrypt_vault_to_file "$VK_ROOT/f-plain2"
	printf '3\tThird\tuser@example.invalid\tLocalOnly77\t-\t2025-01-03T00:00:00Z\n' \
		>> "$VK_ROOT/f-plain2"
	encrypt_file_to_vault "$VK_ROOT/f-plain2"
	VAULT_KEY="" SPM_SYNC_FORCE_INITIAL=1 cmd_sync pull "$VK_ROOT/syncdir" >/dev/null
	VAULT_KEY="" decrypt_vault_container "$VAULT_FILE" "$VK_ROOT/f-pulled" "$VK_OLD" \
		|| { printf 'the pulled vault does not open\n' >&2; exit 1; }
	if grep -q 'LocalOnly77' "$VK_ROOT/f-pulled"; then
		printf 'sync pull did not replace the local vault\n' >&2; exit 1
	fi
	grep -q 'DemoSecret42' "$VK_ROOT/f-pulled"
)

printf '  vault key stability, migration ordering and recovery verified\n'

printf 'SPM regression suite passed (%s formats plus web and advanced features).\n' \
	"$(printf '%s\n' "$formats" | awk '{ print NF }')"

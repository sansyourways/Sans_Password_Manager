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
# Everything above the dependency check is definitions; below it the installer
# starts doing things. Cut at that marker rather than at a line number: the
# number was 111, and adding a function above it sliced the next one in half
# and left a file that failed to parse.
awk '/^for command_name in /{exit} {print}' "$ROOT_DIR/install.sh" > "$INSTALL_LIBRARY"
grep -q '^ensure_on_path() {' "$INSTALL_LIBRARY" || {
	printf 'the installer library extraction lost ensure_on_path\n' >&2; exit 1
}
grep -q '^verify_provenance() {' "$INSTALL_LIBRARY" || {
	printf 'the installer library extraction lost verify_provenance\n' >&2; exit 1
}
bash -n "$INSTALL_LIBRARY"
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
# Catalogues now live in locales/*.json and are folded into the web script by
# tools/build-locales.py. The lint is the contributor-facing check, so running
# it here means the suite and the tool cannot disagree about what is valid.
python3 "$ROOT_DIR/tools/i18n-lint.py"
# A stale generated region would serve yesterday's words from today's JSON,
# and nothing else would notice: the page still renders.
python3 "$ROOT_DIR/tools/build-locales.py" --check

PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" "$ROOT_DIR" <<'I18NPY'
import ast
import io
import json
import os
import re
import sys

source = io.open(sys.argv[1], encoding="utf-8").read()
root = sys.argv[2]

# Read the catalogues the way the server does -- out of the generated region --
# rather than out of locales/, so a region that was hand-edited away from the
# JSON is caught here and not merely by the --check above.
tree = ast.parse(source)
generated = {}
for node in tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in (
                    "WEB_LOCALES", "WEB_CATALOGUES"):
                generated[target.id] = ast.literal_eval(node.value)
for name in ("WEB_LOCALES", "WEB_CATALOGUES"):
    if name not in generated:
        sys.exit("%s is missing from the generated region" % name)

locales = generated["WEB_LOCALES"]
catalogues = generated["WEB_CATALOGUES"]
if set(locales) != set(catalogues):
    sys.exit("the locale table and the catalogues describe different languages")

on_disk = sorted(
    name[:-5] for name in os.listdir(os.path.join(root, "locales"))
    if name.endswith(".json"))
if sorted(catalogues) != on_disk:
    sys.exit("generated languages %s do not match locales/ %s"
             % (sorted(catalogues), on_disk))

english = set(catalogues["en"])
for code in sorted(catalogues):
    absent = english - set(catalogues[code])
    extra = set(catalogues[code]) - english
    if absent:
        sys.exit("%s is missing %d key(s), e.g. %s"
                 % (code, len(absent), sorted(absent)[0]))
    if extra:
        sys.exit("%s has %d key(s) English does not, e.g. %s"
                 % (code, len(extra), sorted(extra)[0]))
    meta = locales[code]
    if meta["dir"] not in ("ltr", "rtl"):
        sys.exit("%s declares direction %r" % (code, meta["dir"]))
    if meta["review"] not in ("maintained", "unreviewed"):
        sys.exit("%s declares review status %r" % (code, meta["review"]))
    if code != code.lower():
        sys.exit("%s is not lowercase; the server lowercases before matching"
                 % code)

# A key referenced from the markup but absent from every dictionary renders as
# its English fallback forever, in every language. The parity check above
# cannot see it: it compares the catalogues to each other, and a key missing
# from all of them is perfectly consistent. This found four, three of them
# added with the Bitwarden import UI, which shipped untranslated.
referenced = {
    key for key in re.findall(
        r'data-i18n(?:-placeholder|-title|-label)?="([^"{}]+)"', source)
    if re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", key)
}
unknown = sorted(key for key in referenced if key not in english)
if unknown:
    sys.exit("%d key(s) used in the markup but in no catalogue: %s"
             % (len(unknown), ", ".join(unknown)))

# An unreviewed translation that never says so is the one outcome this release
# was supposed to rule out.
if "lang.unreviewed" not in english:
    sys.exit("the unreviewed-translation notice has no string")
if 'id="lang-notice"' not in source:
    sys.exit("no element carries the unreviewed-translation notice")
# The notice ships hidden and is revealed by script. `display: block` on the
# class outranks the user agent's [hidden] rule, so styling it at all makes it
# visible on every page -- including the maintained languages, where it tells
# a reader their own language is unreviewed. That shipped, and only a
# screenshot showed it.
style = source[source.index("DESIGN_CSS"):]
if re.search(r"\.lang-notice\s*\{[^}]*\bdisplay\s*:", style) and not re.search(
        r"\.lang-notice\[hidden\]\s*\{[^}]*display\s*:\s*none", style):
    sys.exit("the notice sets display but never restates the hidden case, so "
             "it renders on every language")

rtl = sorted(code for code in locales if locales[code]["dir"] == "rtl")
print("  i18n: %d languages (%d rtl), %d keys each, %d referenced from markup"
      % (len(catalogues), len(rtl), len(english), len(referenced)))
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
# The auto-lock users see runs in the browser, so it protects nobody whose
# scripts fail to execute. The server-side idle expiry is the control that
# still holds in that case, and it silently used to be half an hour.
#
# Now that the browser lock is configurable the two are coupled, and the
# coupling is what is checked: the server bound must outlast every offered
# lock (otherwise the setting promises time the server will not give), must
# stay at its old 300s for the default (so the common case was not quietly
# loosened), and must stay bounded at the top of the range.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" SPM_VAULT_PATH="$PASSWORD_VAULT" \
	XDG_CONFIG_HOME="$TEST_ROOT/lockcfg" python3 - "$web_script" <<'TTLPY'
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location("spm_web_ttl", sys.argv[1])
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)

for choice in web.LOCK_CHOICES:
    assert web.set_lock_timeout(choice), "%d is offered but cannot be stored" % choice
    ttl = web.session_ttl()
    if ttl <= choice:
        sys.exit("a %ds lock would outlive the %ds server session" % (choice, ttl))
    if ttl > 1200:
        sys.exit("server session may idle for %ds, which is unbounded in practice" % ttl)
    if choice == web.LOCK_DEFAULT and ttl != 300:
        sys.exit("the default lock changed the server bound from 300s to %ds" % ttl)

# A setting file nobody wrote through the dashboard must not be obeyed. This
# value decides how long a decrypted vault sits on screen unattended, so it
# fails towards the short end.
with open(web.LOCK_CONFIG, "w", encoding="utf-8") as handle:
    handle.write("86400\n")
if web.lock_timeout() != web.LOCK_DEFAULT:
    sys.exit("a hand-edited lock timeout of 86400 was obeyed")
if web.set_lock_timeout(86400):
    sys.exit("86400 was accepted as a lock timeout")
print("  web: idle lock %s, server bound never shorter than the lock it backs"
      % ", ".join("%ds" % c for c in web.LOCK_CHOICES))
TTLPY
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 -m py_compile \
	"$web_script" "$ROOT_DIR/browser-extension/native_host.py"
# XDG_CONFIG_HOME so the idle-lock setting the dashboard persists lands in the
# test root rather than in the developer's real ~/.config.
SPM_VAULT_PATH="$PASSWORD_VAULT" SPM_WEB_BIND=127.0.0.1 \
	SPM_WEB_PORT="$WEB_PORT" SPM_VERSION="$VERSION" \
	XDG_CONFIG_HOME="$TEST_ROOT/config" \
	SPM_WEB_RP_ID=localhost python3 "$web_script" \
	>"$TEST_ROOT/web.log" 2>&1 &
WEB_PID="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	curl -fsS -o "$TEST_ROOT/login.html" "http://127.0.0.1:$WEB_PORT/login" 2>/dev/null && break
	sleep 0.25
done
grep -q 'Sans Password Manager' "$TEST_ROOT/login.html"
grep -q '<body class="theme-console">' "$TEST_ROOT/login.html"
grep -q 'localStorage.getItem("spm.theme")' "$TEST_ROOT/login.html"
grep -q 'rel="apple-touch-icon"' "$TEST_ROOT/login.html"

printf 'Web regression: the language a page is actually served in\n'
# Shipping every catalogue to every page was affordable at three languages.
# At twelve it is most of the payload, so a page now carries its own language
# and English, and the rest arrive from /locale on demand. Asserted over real
# HTTP, because the saving and the correctness both live in what is sent.
grep -q 'lang="en" dir="ltr"' "$TEST_ROOT/login.html" || {
	printf 'the English login page does not declare lang and dir\n' >&2; exit 1
}
# Read the DICT the browser is handed rather than grepping the page: the
# direction and review maps legitimately name every language, so a substring
# search would pass whatever the payload actually contained.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/login.html" en <<'DICTPY'
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
active = sys.argv[2]
match = re.search(r"const DICT = (\{.*?\});\n", page, re.S)
if not match:
    sys.exit("the page carries no catalogue at all")
shipped = json.loads(match.group(1))
if active not in shipped:
    sys.exit("the %s page does not carry the %s catalogue" % (active, active))
if "en" not in shipped:
    sys.exit("the page does not carry English, which every lookup falls back to")
extra = sorted(set(shipped) - {active, "en"})
if extra:
    sys.exit("the %s page also ships %s, which it will never use"
             % (active, ", ".join(extra)))
DICTPY

curl -fsS -o "$TEST_ROOT/login-ar.html" -H 'Cookie: spm_lang=ar' \
	"http://127.0.0.1:$WEB_PORT/login"
# Arabic is the one language whose layout is not merely a word swap. If dir
# never reaches the document the page is legible and completely wrong.
grep -q 'lang="ar" dir="rtl"' "$TEST_ROOT/login-ar.html" || {
	printf 'the Arabic page is not marked right-to-left\n' >&2; exit 1
}
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/login-ar.html" <<'RTLCSSPY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
# Arabic in a fixed-width face stops joining and reads as loose letters. The
# rule that prevents it has to match the document as served -- a selector that
# is merely present, narrowed to something no element carries, is inert, and a
# substring search cannot tell the two apart.
rule = re.search(
    r'(?<![\w.#\[-]):root\[dir="rtl"\]\s+body\s*\{([^}]*)\}', page)
if not rule:
    sys.exit("no rule takes an RTL document out of the fixed-width stack")
block = rule.group(1)
for prop in ("--font", "--mono"):
    if prop not in block:
        sys.exit("the RTL rule does not override %s" % prop)
if "monospace" in block.split("--mono")[1].split(";")[0]:
    sys.exit("the RTL rule still resolves to a monospace family")
RTLCSSPY
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/login-ar.html" ar <<'DICTPY'
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
active = sys.argv[2]
match = re.search(r"const DICT = (\{.*?\});\n", page, re.S)
if not match:
    sys.exit("the page carries no catalogue at all")
shipped = json.loads(match.group(1))
if active not in shipped:
    sys.exit("the %s page does not carry the %s catalogue" % (active, active))
if "en" not in shipped:
    sys.exit("the page does not carry English, which every lookup falls back to")
extra = sorted(set(shipped) - {active, "en"})
if extra:
    sys.exit("the %s page also ships %s, which it will never use"
             % (active, ", ".join(extra)))
DICTPY
grep -q 'id="lang-notice"' "$TEST_ROOT/login-ar.html" || {
	printf 'an unreviewed language is served with no notice element\n' >&2; exit 1
}

# The picker names each language in its own script. Listing Arabic as "Arabic"
# is no use to somebody who needs Arabic to read the page.
grep -q 'value="ar" dir="rtl"' "$TEST_ROOT/login.html" || {
	printf 'the picker does not carry per-option direction\n' >&2; exit 1
}

# The catalogues a page did not ship have to be reachable, and only the real
# ones -- an unknown code must not fall back to English and look like success.
curl -fsS -o "$TEST_ROOT/locale-ja.json" "http://127.0.0.1:$WEB_PORT/locale?lang=ja"
python3 - "$TEST_ROOT/locale-ja.json" <<'LOCALEPY'
import json, sys
catalogue = json.load(open(sys.argv[1], encoding="utf-8"))
if catalogue.get("login.unlock") in (None, "Unlock"):
    sys.exit("/locale?lang=ja did not return the Japanese catalogue")
LOCALEPY
locale_code="$(curl -s -o /dev/null -w '%{http_code}' \
	"http://127.0.0.1:$WEB_PORT/locale?lang=zz")"
[ "$locale_code" = "404" ] || {
	printf 'an unknown language returned %s rather than 404\n' "$locale_code" >&2
	exit 1
}
printf '  language: per-page catalogue, rtl document, /locale on demand\n'

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

# The sign-in page is one card; the dashboard is the sidebar, the topbar, the
# tables and the nav rail. RTL either reaches all of that or it reaches none of
# the app somebody actually uses, so assert it on the shell and not only on the
# gate in front of it.
curl -fsS -b "$TEST_ROOT/cookies" -c "$TEST_ROOT/cookies" -o /dev/null \
	"http://127.0.0.1:$WEB_PORT/lang?lang=ar"
curl -fsS -b "$TEST_ROOT/cookies" -c "$TEST_ROOT/cookies" \
	-o "$TEST_ROOT/dashboard-ar.html" "http://127.0.0.1:$WEB_PORT/"
grep -q 'lang="ar" dir="rtl"' "$TEST_ROOT/dashboard-ar.html" || {
	printf 'the Arabic dashboard is not marked right-to-left\n' >&2; exit 1
}
# Physical margins and borders survive dir and would strand the nav marker,
# the active-item bar and the topbar controls on the wrong side.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" <<'LOGICALPY'
import re, sys
source = open(sys.argv[1], encoding="utf-8").read()
style = source[source.index("DESIGN_CSS"):]
physical = re.findall(
    r"(?<![\w-])(margin|padding|border)-(left|right)\s*:", style)
# The sidebar's safe-area inset is physical on purpose: the notch sits where
# the hardware puts it. Everything else must be logical or RTL is cosmetic.
allowed = 1
if len(physical) > allowed:
    sys.exit("%d physical box properties remain in the stylesheet: %s"
             % (len(physical), ", ".join("%s-%s" % p for p in physical[:6])))

# A four-value shorthand is physical too, and it hides better than the
# longhand: `padding: 0 12px 0 36px` reserves room for the search icon on the
# left and keeps reserving it there under dir=rtl, so the icon lands on top of
# the placeholder. Only the asymmetric ones matter -- a symmetric shorthand
# mirrors onto itself.
lopsided = []
for match in re.finditer(
        r"(?<![\w-])(padding|margin)\s*:\s*([^;{}]+);", style):
    values = match.group(2).split()
    if len(values) == 4 and values[1] != values[3]:
        lopsided.append(match.group(0).strip())
if lopsided:
    sys.exit("%d box shorthand(s) differ left from right and will not mirror: %s"
             % (len(lopsided), "; ".join(lopsided[:4])))
LOGICALPY
curl -fsS -b "$TEST_ROOT/cookies" -c "$TEST_ROOT/cookies" -o /dev/null \
	"http://127.0.0.1:$WEB_PORT/lang?lang=en"
# A password, a vault path and a Base32 secret are machine values. Laid out
# right-to-left they are reordered around their own punctuation -- a path grows
# a leading slash at its end -- and the caret lands on the wrong side. Caught
# by screenshotting the Arabic dashboard; nothing else showed it.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" <<'LTRPY'
import re, sys
source = open(sys.argv[1], encoding="utf-8").read()
rule = re.search(
    r'((?:^:root\[dir="rtl"\][^,{]*,\s*)+^:root\[dir="rtl"\][^,{]*)\{\s*'
    r'direction:\s*ltr', source, re.M)
if not rule:
    sys.exit("nothing pins machine values to left-to-right in an RTL page")
selectors = rule.group(1)
for needed in ('input[type="password"]', ".vault-chip .path", "code", "pre"):
    if needed not in selectors:
        sys.exit("%s is not pinned left-to-right" % needed)
LTRPY
printf '  rtl: the dashboard shell mirrors, not just the sign-in card\n'
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
# Since 3.8.0 an upload is reviewed first, so the smoke test is two posts:
# the upload, which answers with the review page, and the confirmation it
# carries. The full behaviour of the review is asserted further down.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/import.html" \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" -F 'fmt=csv' \
	-F "file=@$TEST_ROOT/import.csv;type=text/csv" "http://127.0.0.1:$WEB_PORT/import"
smoke_token="$(sed -n 's/.*name="confirm" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/import.html" | head -n1)"
smoke_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/import.html" | head -n1)"
[ "${#smoke_token}" -eq 32 ]
curl -fsS -D "$TEST_ROOT/import.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$smoke_csrf" --data-urlencode "confirm=$smoke_token" \
	"http://127.0.0.1:$WEB_PORT/import"
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
cmd_security_dashboard | grep -q 'Known breach IDs: not checked'

cli_score="$(cmd_security_dashboard | sed -n 's#^Score: \([0-9]*\)/100$#\1#p')"
[ -n "$cli_score" ]
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/security.html" \
	"http://127.0.0.1:$WEB_PORT/security"
# Read the digits, not the exact markup around them: the score now carries a
# "/ 100" of its own inside the same element, and a pattern anchored to the
# closing tag silently produced an empty string rather than a mismatch.
web_score="$(PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$TEST_ROOT/security.html" <<'SCOREPY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r'<span class="stat-n score-[a-z]+">\s*(\d+)', page)
print(match.group(1) if match else "")
SCOREPY
)"
[ "$cli_score" = "$web_score" ] || {
	printf 'security score differs: CLI %s, web %s\n' "$cli_score" "$web_score" >&2
	exit 1
}

# The security page names IDs. It must never echo a secret: this page is meant
# to be safe to open on a phone in public.
if grep -qF 'DemoSecret42' "$TEST_ROOT/security.html"; then
	printf 'security page leaked a password\n' >&2; exit 1
fi
grep -q 'href="/security?breaches=1"' "$TEST_ROOT/security.html"
grep -q 'data-i18n="security.breach_optin"' "$TEST_ROOT/security.html"

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

printf 'Web regression: an import is reviewed before it is written\n'
# Until 3.8.0 an upload went straight in: the first sight of what a Bitwarden
# export actually contained was the vault already containing it. This is
# checked against the running server rather than against preview_import,
# because every defect this project has shipped was in the wiring above a
# function that passed its own test.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/transfer.html" \
	"http://127.0.0.1:$WEB_PORT/transfer"
imp_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/transfer.html" | head -n1)"
[ "${#imp_csrf}" -eq 64 ]
vault_before_import="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
cat > "$TEST_ROOT/preview.csv" <<'PREVIEWCSV'
folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,0,login,Preview Site,,,0,https://preview.example,previewer,Pv9!wwwwwwwwww,
,0,note,Preview Note,a note body,,0,,,,
PREVIEWCSV
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/import-preview.html" \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	-F "csrf=$imp_csrf" -F 'fmt=bitwarden-csv' \
	-F "file=@$TEST_ROOT/preview.csv" \
	"http://127.0.0.1:$WEB_PORT/import"
grep -q 'Review this import' "$TEST_ROOT/import-preview.html"
grep -q 'Preview Site' "$TEST_ROOT/import-preview.html"
grep -q 'name="confirm"' "$TEST_ROOT/import-preview.html"
# "1 passwords" is the sort of thing only a rendered page shows you, and the
# heading is the first line a reader checks the file against.
grep -q '1 password &middot; 1 note<' "$TEST_ROOT/import-preview.html"
# The whole point: reviewing wrote nothing.
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_before_import" ] || {
	printf 'the import preview modified the vault\n' >&2; exit 1
}
# A review page that prints every password in clear text is worse than the
# mistake it guards against. The secret may reach the page only in the
# data-val attribute the reveal control reads; the cell itself shows bullets.
python3 - "$TEST_ROOT/import-preview.html" <<'PYMASK'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
secret = "Pv9!wwwwwwwwww"
occurrences = [m.start() for m in re.finditer(re.escape(secret), page)]
assert occurrences, "the password never reached the review page at all"
for at in occurrences:
    before = page.rfind("<", 0, at)
    assert 'data-val="' in page[before:at], (
        "the password appears outside data-val: %r" % page[max(0, at - 90):at + 20])
cell = re.search(r'<span class="secret-val masked"[^>]*>([^<]*)</span>', page)
assert cell and "&bull;" in cell.group(1), "the secret cell is not masked"
PYMASK
imp_token="$(sed -n 's/.*name="confirm" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/import-preview.html" | head -n1)"
[ "${#imp_token}" -eq 32 ]
curl -fsS -D "$TEST_ROOT/import-confirm.headers" -b "$TEST_ROOT/cookies" \
	-o /dev/null -X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$imp_csrf" --data-urlencode "confirm=$imp_token" \
	"http://127.0.0.1:$WEB_PORT/import"
grep -qi 'Location: /?msg=import-ok' "$TEST_ROOT/import-confirm.headers"
vault_after_import="$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)"
[ "$vault_after_import" != "$vault_before_import" ] || {
	printf 'the confirmed import wrote nothing\n' >&2; exit 1
}
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/after-import.html" \
	"http://127.0.0.1:$WEB_PORT/"


# The security log has a page, and it must show the thing it exists for without
# putting back what the log is careful to leave out.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/events.html" \
	"http://127.0.0.1:$WEB_PORT/events"
grep -q 'Security Events' "$TEST_ROOT/events.html"
grep -q 'failed attempt(s) recorded' "$TEST_ROOT/events.html" || {
	printf 'the events page did not surface the failed unlocks\n' >&2; exit 1
}
grep -q 'wrong master password or damaged file' "$TEST_ROOT/events.html"
# Record names, usernames and secrets must not reach this page: the log has
# none to show, and a page that fetched them would put back exactly what the
# log is careful to leave out. The vault path is deliberately not on this list
# -- the app shell prints it in the sidebar of every page, for a reader who is
# already signed in and looking at their own vault.
for leaked in "$AUDIT_PASSWORD" 'DemoSecret42' 'Preview Site' 'previewer' \
	'bound.example.invalid'; do
	if grep -qF -- "$leaked" "$TEST_ROOT/events.html"; then
		printf 'the events page leaked %s\n' "$leaked" >&2; exit 1
	fi
done
grep -q 'Preview Site' "$TEST_ROOT/after-import.html"
# The note does not appear on the password list, so it is checked where it
# actually landed: a confirmed import must commit every kind it previewed,
# not only the one the dashboard happens to show first.
test_decrypt_vault "$PASSWORD_VAULT" "$AUDIT_PASSWORD" "$TEST_ROOT/after-import.plain"
[ "$(awk -F '\t' '$1=="NOTE"&&$3=="Preview Note"{print $4}' \
	"$TEST_ROOT/after-import.plain" | base64 -d)" = 'a note body' ] || {
	printf 'the previewed note was not committed\n' >&2; exit 1
}
# One token, one import. Re-posting a confirmation -- a refresh, a back button,
# a resend -- must not add the same records a second time.
curl -sS -o /dev/null -b "$TEST_ROOT/cookies" -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$imp_csrf" --data-urlencode "confirm=$imp_token" \
	"http://127.0.0.1:$WEB_PORT/import"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_after_import" ] || {
	printf 'a replayed confirmation imported the same records twice\n' >&2; exit 1
}
# An invented token must be refused outright rather than committing whatever
# happens to be pending.
curl -sS -o /dev/null -b "$TEST_ROOT/cookies" -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$imp_csrf" \
	--data-urlencode 'confirm=00000000000000000000000000000000' \
	"http://127.0.0.1:$WEB_PORT/import"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_after_import" ] || {
	printf 'an unmatched confirmation token still wrote to the vault\n' >&2; exit 1
}
# A wrong token against a review that IS pending. The check above cannot reach
# the comparison -- by then nothing is pending and the refusal comes from that
# instead -- so removing the comparison altogether survived it. This uploads a
# fresh file first, so the only thing standing between an invented token and
# the vault is the comparison itself.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/import-preview2.html" \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	-F "csrf=$imp_csrf" -F 'fmt=bitwarden-csv' \
	-F "file=@$TEST_ROOT/preview.csv" \
	"http://127.0.0.1:$WEB_PORT/import"
real_token="$(sed -n 's/.*name="confirm" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/import-preview2.html" | head -n1)"
[ "${#real_token}" -eq 32 ]
[ "$real_token" != "$imp_token" ]
curl -sS -o /dev/null -b "$TEST_ROOT/cookies" -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$imp_csrf" \
	--data-urlencode 'confirm=ffffffffffffffffffffffffffffffff' \
	"http://127.0.0.1:$WEB_PORT/import"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_after_import" ] || {
	printf 'a wrong token committed the review that was pending\n' >&2; exit 1
}
# And the wrong attempt spent it: the real token is no longer good either.
curl -sS -o /dev/null -b "$TEST_ROOT/cookies" -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$imp_csrf" --data-urlencode "confirm=$real_token" \
	"http://127.0.0.1:$WEB_PORT/import"
[ "$(sha256sum "$PASSWORD_VAULT" | cut -d' ' -f1)" = "$vault_after_import" ] || {
	printf 'a failed confirmation left the review committable\n' >&2; exit 1
}

# A file with nothing SPM can store must not offer a button whose only outcome
# is a failure. It gets the same review page, naming every row, with no confirm.
printf 'type,id,label,username,secret,notes,created,extra\nwidget,,Passport,,,,,\n' \
	> "$TEST_ROOT/nothing.csv"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/import-nothing.html" \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	-F "csrf=$imp_csrf" -F 'fmt=csv' -F "file=@$TEST_ROOT/nothing.csv" \
	"http://127.0.0.1:$WEB_PORT/import"
grep -q 'Nothing in this file can be imported' "$TEST_ROOT/import-nothing.html"
grep -q 'Passport' "$TEST_ROOT/import-nothing.html"
if grep -q 'name="confirm"' "$TEST_ROOT/import-nothing.html"; then
	printf 'an unimportable file was still offered a confirm button\n' >&2; exit 1
fi
# Nor a five-column header over no rows, which reads as a table that failed.
if grep -q '<table' "$TEST_ROOT/import-nothing.html"; then
	printf 'the empty review still rendered a table with no rows\n' >&2; exit 1
fi
grep -q '1 row will not be imported' "$TEST_ROOT/import-nothing.html"

# Expiry, which no HTTP test can reach without waiting five minutes. The held
# review is a plain record, so the clock is moved instead: a review left open
# over lunch must not still be committable.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" "$PASSWORD_VAULT" <<'PYTTL'
import importlib.util, os, sys, time

spec = importlib.util.spec_from_file_location("spmweb_ttl", sys.argv[1])
web = importlib.util.module_from_spec(spec)
os.environ["SPM_VAULT_PATH"] = sys.argv[2]
try:
    spec.loader.exec_module(web)
except SystemExit:
    pass

rows = [("password", {"type": "password", "label": "X", "secret": "s"})]
stats = {"passwords": 1}

session = {}
token = web.stash_pending_import(session, rows, stats, [])
assert web.take_pending_import(session, token) == rows, "a fresh review did not come back"

session = {}
token = web.stash_pending_import(session, rows, stats, [])
session["pending_import"]["at"] -= web.PENDING_IMPORT_TTL + 1
try:
    web.take_pending_import(session, token)
except ValueError as exc:
    assert "expired" in str(exc), "a stale review was refused for the wrong reason: %s" % exc
else:
    sys.exit("a review older than the TTL was still committable")

# Expiry must also spend it, or a stale token could be retried until the clock
# happened to suit it.
assert session.get("pending_import") is None, "an expired review was left in place"
print("  import: expiry refuses and consumes a stale review")
PYTTL
printf '  import: previewed without writing, masked, committed once, replay refused\n'

printf 'Web regression: folders and custom fields\n'
# Format 4 appends a column to a password row. It has to survive a round trip
# through the real form, and a value containing a tab or a newline must not
# split one record into two -- which is the failure that would corrupt a vault
# rather than merely losing a field.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/add-folder.html" \
	"http://127.0.0.1:$WEB_PORT/add"
grep -q 'name="folder"' "$TEST_ROOT/add-folder.html"
grep -q 'name="cf_name_0"' "$TEST_ROOT/add-folder.html"
grep -q 'name="cf_value_0"' "$TEST_ROOT/add-folder.html"
fold_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/add-folder.html" | head -n1)"
[ "${#fold_csrf}" -eq 64 ]

curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$fold_csrf" --data-urlencode 'name=Foldered Site' \
	--data-urlencode 'user=fu' --data-urlencode 'password=Fd9!qqqqqqqqqq' \
	--data-urlencode 'notes=Owned by platform #work #ops' --data-urlencode 'url=' \
	--data-urlencode 'folder=Work' \
	--data-urlencode 'cf_name_0=Account' --data-urlencode 'cf_value_0=123-456' \
	--data-urlencode 'cf_name_1=Odd	Value' \
	--data-urlencode 'cf_value_1=has	a tab
and a newline' \
	"http://127.0.0.1:$WEB_PORT/add"

# The vault must still parse: one record, not three.
vault_plain > "$TEST_ROOT/folder-plain"
[ "$(grep -c 'Foldered Site' "$TEST_ROOT/folder-plain")" -eq 1 ] || {
	printf 'a tab or newline in a custom field split the record\n' >&2; exit 1
}
folder_row="$(grep 'Foldered Site' "$TEST_ROOT/folder-plain")"
[ "$(printf '%s' "$folder_row" | awk -F '\t' '{print NF}')" -eq 8 ] || {
	printf 'the record does not carry exactly 8 columns\n' >&2; exit 1
}
# The raw values must not appear in the row: they are inside the encoded column.
case "$folder_row" in
	*"has	a tab"*) printf 'the custom field value reached the row unencoded\n' >&2; exit 1 ;;
esac
# A custom field is a single-line input, so a tab or newline arriving from a
# script is folded to spaces rather than stored as something the form could
# never show or edit back. Asserted through the view page, which is where a
# user would notice.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/view-oddfield.html" \
	"http://127.0.0.1:$WEB_PORT/view?id=$(printf '%s' "$folder_row" | cut -f1)"
grep -q 'has a tab and a newline' "$TEST_ROOT/view-oddfield.html" || {
	printf 'a tab/newline value was not folded to one line\n' >&2; exit 1
}
grep -q 'Odd Value' "$TEST_ROOT/view-oddfield.html" || {
	printf 'a tab in a custom field name was not folded\n' >&2; exit 1
}

fold_id="$(printf '%s' "$folder_row" | cut -f1)"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/view-folder.html" \
	"http://127.0.0.1:$WEB_PORT/view?id=$fold_id"
grep -q 'Work' "$TEST_ROOT/view-folder.html"
grep -q 'Account' "$TEST_ROOT/view-folder.html"
# Custom-field values are masked like the password, not printed beside it.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/view-folder.html" <<'PYCF'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
for at in (m.start() for m in re.finditer(re.escape("123-456"), page)):
    before = page.rfind("<", 0, at)
    assert 'data-val="' in page[before:at], (
        "a custom field value is printed outside data-val: %r"
        % page[max(0, at - 90):at + 20])
PYCF

# And the edit form comes back with them filled in, or an edit silently drops
# every custom field the record had.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/edit-folder.html" \
	"http://127.0.0.1:$WEB_PORT/edit?id=$fold_id"
grep -q 'value="Work"' "$TEST_ROOT/edit-folder.html"
grep -q 'value="Account"' "$TEST_ROOT/edit-folder.html"
grep -q 'value="123-456"' "$TEST_ROOT/edit-folder.html"

# Editing something unrelated must not lose them.
edit_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/edit-folder.html" | head -n1)"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$edit_csrf" --data-urlencode 'name=Foldered Site' \
	--data-urlencode 'user=changed' --data-urlencode 'password=Fd9!qqqqqqqqqq' \
	--data-urlencode 'notes=Owned by platform #work #ops' --data-urlencode 'url=' \
	--data-urlencode 'folder=Work' \
	--data-urlencode 'cf_name_0=Account' --data-urlencode 'cf_value_0=123-456' \
	"http://127.0.0.1:$WEB_PORT/edit?id=$fold_id"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/view-folder2.html" \
	"http://127.0.0.1:$WEB_PORT/view?id=$fold_id"
grep -q 'Account' "$TEST_ROOT/view-folder2.html" || {
	printf 'editing the record dropped its custom fields\n' >&2; exit 1
}

# A value with no name is a half-filled row, not a field. This is also the
# shape that used to corrupt the record rather than merely lose it: parse_qs
# drops blank values, so pairing two parallel lists by position shifted every
# later value onto the wrong name -- "Account" would have been saved holding
# the value from the blank row above it, silently.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/add-halffield.html" -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$fold_csrf" --data-urlencode 'name=Half Field' \
	--data-urlencode 'user=' --data-urlencode 'password=x' \
	--data-urlencode 'notes=' --data-urlencode 'url=' \
	--data-urlencode 'cf_name_0=' --data-urlencode 'cf_value_0=orphaned' \
	--data-urlencode 'cf_name_1=Account' --data-urlencode 'cf_value_1=123-456' \
	"http://127.0.0.1:$WEB_PORT/add"
grep -q 'value but no name' "$TEST_ROOT/add-halffield.html" || {
	printf 'a custom field with a value and no name was accepted silently\n' >&2
	exit 1
}
vault_plain | grep -q 'Half Field' && {
	printf 'the refused record was written anyway\n' >&2; exit 1
}
# README promises records "survive export and import untouched". A column added
# to the row is exactly the thing that quietly stops being true.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/folder-export.json" \
	"http://127.0.0.1:$WEB_PORT/export?fmt=json"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/folder-export.json" <<'PYEXPORT'
import json, sys
rows = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(rows, dict):
    rows = rows.get("records") or rows.get("entries") or []
match = [r for r in rows if r.get("label") == "Foldered Site"]
assert match, "the foldered record is missing from the export"
row = match[0]
assert row.get("folder") == "Work", "the export dropped the folder: %r" % row.get("folder")
fields = json.loads(row.get("fields") or "[]")
names = [f["name"] for f in fields]
assert "Account" in names, "the export dropped the custom fields: %r" % names
value = [f["value"] for f in fields if f["name"] == "Account"][0]
assert value == "123-456", "the export mangled a custom field value: %r" % value
# The stored form is base64; an export full of opaque blobs is not an export.
assert "eyJ" not in json.dumps(row), "the export carries the raw encoded column"
print("  folders: export carries folder and custom fields as readable columns")
PYEXPORT

printf '  folders: round trip through the form, tabs and newlines contained, edit preserves\n'

# Folder and tag discovery is a separate, URL-addressable Passwords section.
# A URL must reproduce the same filtered result without relying on prior
# JavaScript state, and selected values need a non-colour marker.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/password-filters.html" \
	"http://127.0.0.1:$WEB_PORT/passwords"
grep -q 'id="password-filters-title"' "$TEST_ROOT/password-filters.html"
grep -q 'data-i18n="filters.folders"' "$TEST_ROOT/password-filters.html"
grep -q 'data-i18n="filters.tags"' "$TEST_ROOT/password-filters.html"
grep -q 'href="/passwords?folder=Work"' "$TEST_ROOT/password-filters.html"
grep -q 'href="/passwords?tag=work"' "$TEST_ROOT/password-filters.html"

curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/password-filtered.html" \
	"http://127.0.0.1:$WEB_PORT/passwords?folder=Work&tag=work"
grep -q 'Foldered Site' "$TEST_ROOT/password-filtered.html"
grep -q 'aria-current="true"' "$TEST_ROOT/password-filtered.html"
grep -q 'href="/passwords" data-i18n="filters.clear"' \
	"$TEST_ROOT/password-filtered.html"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/password-filtered.html" <<'PYFILTER'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
rows = re.findall(r'<tr data-row="[^"]*">', page)
assert len(rows) == 1, "URL filters did not narrow to one row: %d" % len(rows)
assert '>1</span> <span data-i18n="filters.of">' in page, "shown count is wrong"
PYFILTER
printf '  filters: folder and tag state survives in the URL and narrows server-side\n'

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
        "security.breached", "security.breached_d", "security.breach_check",
        "security.breach_optin", "security.breach_unavailable",
        "history.when", "btn.restore", "confirm.restore_snapshot",
        "search.kind", "badge.aging", "tags.all", "filters.title",
        "filters.desc", "filters.folders", "filters.tags",
        "filters.unfiled", "filters.clear", "filters.of",
        "filters.passwords_shown", "empty.filtered.t", "empty.filtered.d",
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
_, combined_settings, _ = get("/settings")
assert "/unlock/settings" in combined_settings, "unlock controls missing from Settings"
assert 'data-i18n="nav.settings"' in body, "combined Settings nav entry is missing"
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
printf 'Extension regression: the native-messaging boundary\n'
# What the extension may ask for, and -- the half that needed writing down --
# what it may receive. The host used to forward whatever the CLI printed, so
# the extension's view of the vault was whatever bridge-get happened to emit.
# A field added there later would have reached the extension with no code
# change and no review. These assert the projection, not the plumbing.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/browser-extension-universal/native_host.py" <<'BOUNDPY'
import sys

source = open(sys.argv[1], encoding="utf-8").read()
namespace = {}
# The module ends in a read loop, so only the definitions above it are run.
exec(source[:source.index("while True:")], namespace)
project = namespace["project"]
actions = namespace["ACTIONS"]
allowed_errors = namespace["ALLOWED_ERRORS"]

# A get returns a username and a password. Nothing else, however much the
# layer below decides to hand over.
leaky = {"ok": True, "username": "u", "password": "p",
         "notes": "private note", "url": "https://x", "totp": "JBSWY3DPEHPK3PXP"}
got = project("get", leaky)
if set(got) != {"ok", "username", "password"}:
    sys.exit("a get response carried %r" % sorted(set(got) - {"ok", "username", "password"}))

# A match is a summary. A secret appearing in one must not cross.
listed = project("list", {"ok": True, "matches": [
    {"id": "1", "label": "GitHub", "username": "u", "url": "https://g",
     "password": "should-not-cross", "notes": "should-not-cross"}]})
row = listed["matches"][0]
if set(row) != {"id", "label", "username", "url"}:
    sys.exit("a list match carried %r" % sorted(set(row) - {"id", "label", "username", "url"}))
if "should-not-cross" in repr(listed):
    sys.exit("a secret crossed the boundary inside a match")

# unlock answers whether the password worked, not what it found.
if project("unlock", {"ok": True, "matches": [{"id": "1"}]}) != {"ok": True}:
    sys.exit("unlock returned more than a verdict")

# Failures are chosen from a fixed set. Echoing an unexpected message is how a
# path or a gpg diagnostic reaches the extension.
for supplied in ("gpg: /home/someone/.spm_vault.gpg: decryption failed",
                 {"vault": "/home/someone/.spm_vault.gpg"},
                 None, 42):
    out = project("get", {"ok": False, "error": supplied})
    if out["error"] not in allowed_errors and out["error"] != namespace["GENERIC_ERROR"]:
        sys.exit("an unexpected error crossed: %r" % out["error"])
    if "/home/someone" in out["error"]:
        sys.exit("a filesystem path crossed the boundary in an error")
if project("get", {"ok": False, "error": "record not found"})["error"] != "record not found":
    sys.exit("a known error was replaced by the generic one")

# An action absent from the table returns nothing but a verdict, so adding a
# branch without declaring it cannot expose fields.
if project("some-new-action", {"ok": True, "password": "p"}) != {"ok": True}:
    sys.exit("an undeclared action returned fields")

if set(actions) != {"unlock", "lock", "list", "get"}:
    sys.exit("the action table changed without this test changing: %r" % sorted(actions))

print("  boundary: %d actions declared, responses projected, errors from a "
      "fixed set of %d" % (len(actions), len(allowed_errors)))
BOUNDPY


printf 'Web regression: accessibility and the import form\n'
# Every form control needs a name a screen reader can announce. These were all
# unnamed: the add and edit forms rendered <label> elements with no for= and
# inputs with no id, so the labels were loose text and each field read as
# "edit text, blank". Asserted against rendered markup, not the source, because
# the source looked correct.
python3 - "$web_script" "$PASSWORD_VAULT" <<'A11YPY'
import importlib.util
import os
import re
import sys

spec = importlib.util.spec_from_file_location("spmweb", sys.argv[1])
web = importlib.util.module_from_spec(spec)
os.environ["SPM_VAULT_PATH"] = sys.argv[2]
try:
    spec.loader.exec_module(web)
except SystemExit:
    pass

CONTROL = re.compile(r"<(input|select|textarea)\b([^>]*)>", re.I)
LABEL_FOR = re.compile(r'<label[^>]*\bfor="([^"]+)"')


def unnamed(markup):
    targets = set(LABEL_FOR.findall(markup))
    bad = []
    for tag, attrs in CONTROL.findall(markup):
        if re.search(r'type="(hidden|submit|button)"', attrs, re.I):
            continue
        if "aria-label" in attrs or "aria-labelledby" in attrs:
            continue
        found = re.search(r'\bid="([^"]+)"', attrs)
        if not found or found.group(1) not in targets:
            bad.append((tag, attrs.strip()[:70]))
    return bad


pages = {
    "add form": web.build_entry_form("Add", "/v", "/add"),
    "edit form": web.build_entry_form("Edit", "/v", "/edit",
                                      values={"id": "1", "name": "n"}),
    "note form": web.build_note_form("Note", "/v", "/notes-add"),
    "transfer": web.transfer_page(),
}
for name, markup in pages.items():
    bad = unnamed(markup)
    if bad:
        sys.exit("%s has %d control(s) with no accessible name: %r"
                 % (name, len(bad), bad[:3]))

if "<nav" not in web.render_shell("<p>x</p>", "overview", "0", "/v"):
    sys.exit("the sidebar is not exposed as a navigation landmark")

# Bitwarden entries belong on the import form. They shipped on the export form
# in 3.4.3, which made the feature unreachable from the picker: the tests
# exercised _apply_import directly and never rendered the page.
forms = dict((m.group(1), m.group(2)) for m in
             re.finditer(r'<form[^>]*action="(/[a-z]+)"[^>]*>(.*?)</form>',
                         pages["transfer"], re.S))
if "bitwarden" not in forms.get("/import", ""):
    sys.exit("the import form does not offer the Bitwarden formats")
if "bitwarden" in forms.get("/export", ""):
    sys.exit("the export form offers Bitwarden formats, which cannot be exported")

# A focus indicator has to be visible. This one was box-shadow in
# --accent-soft, measured at 1.15:1 against the field it surrounded: present
# in the DOM, invisible on screen, on every form in the dashboard. WCAG 1.4.11
# wants 3.0:1 for a non-text indicator.
css = web.DESIGN_CSS


def _luminance(value):
    value = value.lstrip("#")
    channels = []
    for index in (0, 2, 4):
        part = int(value[index:index + 2], 16) / 255
        channels.append(part / 12.92 if part <= 0.03928
                        else ((part + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(one, two):
    first, second = _luminance(one), _luminance(two)
    high, low = max(first, second), min(first, second)
    return (high + 0.05) / (low + 0.05)


tokens = dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})", css))
for rule in re.findall(r"\.(?:input|search input|select):focus\s*\{([^}]*)\}", css):
    if "outline: none" not in rule:
        continue
    ring = re.search(r"box-shadow:[^;]*var\((--[a-z0-9-]+)\)", rule)
    if not ring:
        sys.exit("a control removes its outline without a replacement ring")
    colour = tokens.get(ring.group(1))
    ground = tokens.get("--surface-2") or tokens.get("--surface")
    if not colour or not ground:
        continue
    measured = contrast(colour, ground)
    if measured < 3.0:
        sys.exit("the focus ring is %s on %s, %.2f:1; WCAG 1.4.11 wants 3.0:1"
                 % (colour, ground, measured))

print("  a11y: form controls named, sidebar is a landmark, focus ring "
      "%.1f:1, Bitwarden is on the import form" % measured)
A11YPY



printf 'Release regression: the archive is reproducible\n'
# A checksum published beside a download proves the transfer was intact and
# nothing else: whoever can write one file can write the other. What makes the
# checksum worth anything is being able to rebuild the archive and get the same
# number -- which requires the build to be a function of the commit, not of the
# clock or of whichever machine ran it.
#
# This runs the same script release.yml runs, in the real checkout, so what is
# tested is what produces a release -- including the untracked __pycache__ and
# real-world mtimes that a clean extraction would not have.
archive_dir="$TEST_ROOT/archive"
mkdir -p "$archive_dir"
(cd "$ROOT_DIR" && ./release-archive.sh 9.9.9 >/dev/null)
built="$ROOT_DIR/Sans_Password_Manager_v9.9.9.zip"
cp "$built" "$archive_dir/built.zip"
cp "$built.sha256" "$archive_dir/built.zip.sha256"
rm -f "$built" "$built.sha256"

# The three properties that make it reproducible are asserted against the zip
# directly rather than by building twice and hoping the difference shows. Two
# builds a second apart on one machine are identical whether or not any of this
# is done, so a same-machine comparison cannot see a missing sort, a missing
# mtime normalisation, or the extra fields that differ only across machines.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$archive_dir/built.zip" \
	"$(TZ=UTC git -C "$ROOT_DIR" log -1 --date=format-local:'%Y %m %d %H %M %S' --format=%cd)" \
	<<'PYZIP'
import datetime, sys, zipfile

path = sys.argv[1]
stamp = tuple(int(p) for p in sys.argv[2].split())
with zipfile.ZipFile(path) as zf:
    infos = zf.infolist()
names = [i.filename for i in infos]
assert names, "the archive is empty"

# Entry order. readdir order differs between filesystems -- ext4 hashes by
# name, HFS+ does not -- so an unsorted listing gives one archive on Linux and
# a different one on macOS from identical sources.
if names != sorted(names):
    first = next(i for i in range(len(names)) if names[i] != sorted(names)[i])
    sys.exit("archive entries are not in sorted order, first at %d: %r"
             % (first, names[first]))

# Timestamps. zip records an mtime per entry, and a fresh checkout's mtimes are
# whenever the checkout happened. Two things are asserted, and neither models
# zip's clock: every entry carries the SAME time, and that time is the commit's
# to within a couple of seconds.
#
# zip stores seconds in five bits, so its clock ticks every two seconds and an
# odd-second commit is not recorded exactly. Asserting equality with the commit
# time made this test pass or fail on the parity of the commit's second, which
# is how it first ran red on a correct archive.
times = {i.date_time for i in infos}
if len(times) != 1:
    sys.exit("entries carry %d different timestamps; they are not normalised: %s"
             % (len(times), sorted(times)[:3]))
recorded = times.pop()
delta = abs(datetime.datetime(*recorded) - datetime.datetime(*stamp))
if delta > datetime.timedelta(seconds=2):
    sys.exit("the archive is stamped %s, %s away from the commit's %s"
             % (recorded, delta, stamp))

# Extra fields. zip's default "extended timestamp" and Unix uid/gid fields are
# properties of the machine that built the archive, not of the source.
carrying = [i.filename for i in infos if i.extra]
if carrying:
    sys.exit("%d entr(ies) carry machine-specific extra fields, e.g. %s"
             % (len(carrying), carrying[0]))

# Nothing that exists only on a developer's machine may travel with a release.
leftovers = [n for n in names
             if n.endswith(".bak") or "__pycache__" in n or "/dist/" in n]
if leftovers:
    sys.exit("the archive carries %d leftover(s), e.g. %s"
             % (len(leftovers), leftovers[0]))

# A release has to carry what is needed to audit it.
for needed in ("spm.sh", "build.sh", "install.sh", "src/spm.sh.in",
               "src/spm_core.py", "src/spm_web_server.py",
               "README.md", "CHANGELOG.md", "LICENSE"):
    if needed not in names:
        sys.exit("the release archive is missing %s" % needed)

print("  archive: %d entries, sorted, stamped from the commit, no extra fields"
      % len(names))
PYZIP

# And the end-to-end claim, from two independent extractions of the same
# commit: whatever the mechanism, the same source must give the same bytes.
# SOURCE_DATE_EPOCH stands in for the commit date an extraction has no .git to
# read, which is also the path a third party rebuilding from a tarball takes.
for checkout in one two; do
	mkdir -p "$archive_dir/$checkout"
	git -C "$ROOT_DIR" archive --format=tar HEAD | tar -x -C "$archive_dir/$checkout"
	cp "$ROOT_DIR/release-archive.sh" "$archive_dir/$checkout/release-archive.sh"
	chmod +x "$archive_dir/$checkout/release-archive.sh"
	(cd "$archive_dir/$checkout" \
		&& SOURCE_DATE_EPOCH=1600000000 ./release-archive.sh 9.9.9 >/dev/null)
done
# The timestamp normalisation needs sources whose mtimes are visibly wrong,
# or dropping it changes nothing and the test cannot see it. Extraction "two"
# is backdated to a date no commit has.
find "$archive_dir/two" -type f -exec touch -h -d '2001-02-03T04:05:06Z' {} +
(cd "$archive_dir/two" \
	&& SOURCE_DATE_EPOCH=1600000000 ./release-archive.sh 9.9.9 >/dev/null)
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$archive_dir/two/Sans_Password_Manager_v9.9.9.zip" <<'PYSTAMP'
import sys, zipfile
# 1600000000 is 2020-09-13T12:26:40Z, already on zip's 2-second boundary.
want = (2020, 9, 13, 12, 26, 40)
with zipfile.ZipFile(sys.argv[1]) as zf:
    odd = [i.filename for i in zf.infolist() if i.date_time != want]
if odd:
    sys.exit("%d entr(ies) kept the source mtime instead of SOURCE_DATE_EPOCH, "
             "e.g. %s" % (len(odd), odd[0]))
# 2001-02-03 is what the sources were backdated to; seeing it here would mean
# the stamping did nothing at all.
if want[0] == 2001:
    sys.exit("the expected stamp is the backdated source time, not the epoch")
PYSTAMP

sum_one="$(sha256sum "$archive_dir/one/Sans_Password_Manager_v9.9.9.zip" | cut -d' ' -f1)"
sum_two="$(sha256sum "$archive_dir/two/Sans_Password_Manager_v9.9.9.zip" | cut -d' ' -f1)"
[ "$sum_one" = "$sum_two" ] || {
	printf 'the release archive is not reproducible across extractions:\n  %s\n  %s\n' \
		"$sum_one" "$sum_two" >&2
	exit 1
}

# src/ and build.sh are in the archive precisely so `./build.sh --check` works
# from an unpacked release. If that stopped being true the archive would still
# pass every checksum and still be unauditable.
unzip -q "$archive_dir/built.zip" -d "$archive_dir/unpacked"
(cd "$archive_dir/unpacked" && chmod +x build.sh && ./build.sh --check >/dev/null) || {
	printf 'an unpacked release does not rebuild its own spm.sh\n' >&2
	exit 1
}
# The checksum file names the archive it belongs to, or `sha256sum -c` in the
# installer checks nothing at all.
grep -q 'Sans_Password_Manager_v9.9.9.zip' "$archive_dir/built.zip.sha256"
printf '  archive: identical across two extractions, and rebuilds its own spm.sh\n'



printf 'Packaging regression: the distributable packages\n'
# Built and inspected here rather than only in the release job, because a
# packaging bug that only appears at tag time appears after the tag is public.
pkg_dir="$TEST_ROOT/packaging"
mkdir -p "$pkg_dir"
pkg_version="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' "$ROOT_DIR/spm.sh")"

# --- Termux -----------------------------------------------------------------
# A Termux package is built on the machine that cuts a release, which is Linux.
# Where GNU tar and ar are not both present -- the macOS runner -- the build is
# skipped rather than loosened, and says so: a silent skip is indistinguishable
# from a test that ran.
# Both must be the GNU ones, not merely present. The macOS runner has gtar and
# an ar, so a presence check passed there and the build failed on `ar rD` --
# the D is a GNU flag and BSD ar answers it with its usage text.
pkg_can_build=1
tar --version 2>/dev/null | head -1 | grep -q 'GNU tar' \
	|| gtar --version 2>/dev/null | head -1 | grep -q 'GNU tar' \
	|| pkg_can_build=0
ar --version 2>/dev/null | head -1 | grep -q 'GNU ar' \
	|| gar --version 2>/dev/null | head -1 | grep -q 'GNU ar' \
	|| pkg_can_build=0
if [ "$pkg_can_build" -eq 0 ]; then
	printf '  packaging: .deb build skipped (needs GNU tar and ar; covered on Linux)\n'
	# The refusal itself is asserted here, because a build that quietly
	# produced a differently-shaped package would be worse than none.
	if "$ROOT_DIR/packaging/termux/build-deb.sh" "$pkg_version" "$pkg_dir" \
		>/dev/null 2>&1; then
		printf 'build-deb.sh produced a package without GNU tar\n' >&2
		exit 1
	fi
else
"$ROOT_DIR/packaging/termux/build-deb.sh" "$pkg_version" "$pkg_dir/one" >/dev/null
# A RELATIVE output directory, deliberately. The ar and tar calls run inside a
# subshell that has cd'd into the staging directory, so a relative path
# resolved against one directory when it was written and another when it was
# used. Every local run passed an absolute path and every one of them worked;
# CI passed "dist" and it did not.
mkdir -p "$pkg_dir/two"
( cd "$pkg_dir" && "$ROOT_DIR/packaging/termux/build-deb.sh" "$pkg_version" two ) >/dev/null
deb="$pkg_dir/one/spm_${pkg_version}_all.deb"
[ -f "$deb" ] || { printf 'the Termux package was not produced\n' >&2; exit 1; }
# Same commit, same bytes -- the property that makes a published checksum worth
# anything, for this file as much as for the archive.
[ "$(sha256sum "$deb" | cut -d' ' -f1)" \
	= "$(sha256sum "$pkg_dir/two/spm_${pkg_version}_all.deb" | cut -d' ' -f1)" ] || {
	printf 'the Termux package is not reproducible\n' >&2; exit 1
}

# A .deb is an ar archive of exactly three members, in order. Checked without
# dpkg, which the runner is not guaranteed to have.
ar t "$deb" > "$pkg_dir/members"
printf 'debian-binary\ncontrol.tar.gz\ndata.tar.gz\n' > "$pkg_dir/members-wanted"
diff -u "$pkg_dir/members-wanted" "$pkg_dir/members" || {
	printf 'the .deb does not have the three members apt expects\n' >&2; exit 1
}
( cd "$pkg_dir" && ar x "$deb" control.tar.gz data.tar.gz )
tar -tzf "$pkg_dir/data.tar.gz" > "$pkg_dir/data-listing"
grep -q 'com.termux/files/usr/bin/spm$' "$pkg_dir/data-listing" || {
	printf 'the package does not install spm into the Termux prefix\n' >&2
	sed 's/^/    /' "$pkg_dir/data-listing" >&2
	exit 1
}
tar -xzOf "$pkg_dir/control.tar.gz" ./control > "$pkg_dir/control"
grep -q "^Version: $pkg_version$" "$pkg_dir/control" || {
	printf 'the package version does not match spm.sh\n' >&2; exit 1
}
grep -q '^Package: spm$' "$pkg_dir/control"
grep -q '^Architecture: all$' "$pkg_dir/control"
# gnupg is not optional: without it the vault cannot be opened at all, and a
# package that installs and then cannot work is worse than one that refuses.
grep -qE '^Depends:.*gnupg' "$pkg_dir/control" || {
	printf 'the package does not depend on gnupg\n' >&2; exit 1
}
# Android has no /usr/bin/env, so the package must use the bash inside its
# Termux prefix. Apart from that package-specific launcher line, the shipped
# binary must be the built one, not a stale copy.
tar -xzOf "$pkg_dir/data.tar.gz" "./data/data/com.termux/files/usr/bin/spm" \
	> "$pkg_dir/packaged-spm" 2>/dev/null \
	|| tar -xzOf "$pkg_dir/data.tar.gz" \
		"$(grep 'bin/spm$' "$pkg_dir/data-listing" | head -1)" > "$pkg_dir/packaged-spm"
head -n 1 "$pkg_dir/packaged-spm" \
	| grep -qx '#!/data/data/com.termux/files/usr/bin/bash' || {
	printf 'the packaged spm does not use the Termux bash interpreter\n' >&2; exit 1
}
tail -n +2 "$pkg_dir/packaged-spm" > "$pkg_dir/packaged-spm.body"
tail -n +2 "$ROOT_DIR/spm.sh" > "$pkg_dir/source-spm.body"
cmp -s "$pkg_dir/packaged-spm.body" "$pkg_dir/source-spm.body" || {
	printf 'the packaged spm body is not the spm.sh in this tree\n' >&2; exit 1
}
fi

# --- Homebrew ---------------------------------------------------------------
fake_sha="$(printf 'f%.0s' $(seq 1 64))"
"$ROOT_DIR/packaging/homebrew/generate.sh" "$pkg_version" "$fake_sha" \
	> "$pkg_dir/spm.rb"
grep -q '^class Spm < Formula$' "$pkg_dir/spm.rb"
grep -q "sha256 \"$fake_sha\"" "$pkg_dir/spm.rb"
grep -q "version \"$pkg_version\"" "$pkg_dir/spm.rb"
grep -q "releases/download/v${pkg_version}/Sans_Password_Manager_v${pkg_version}.zip" \
	"$pkg_dir/spm.rb"
grep -q 'depends_on "gnupg"' "$pkg_dir/spm.rb"
# The formula's own test must exercise something that exists. `spm --version`
# did not until this release: the flag fell through to the interactive banner,
# so `brew test` would have opened a menu and waited.
grep -q 'spm --version' "$pkg_dir/spm.rb"
[ "$(bash "$ROOT_DIR/spm.sh" --version)" = "$pkg_version" ] || {
	printf 'spm --version does not report the version the formula asserts\n' >&2
	exit 1
}
[ "$(bash "$ROOT_DIR/spm.sh" -V)" = "$pkg_version" ]
# A generator that accepts a non-version or a non-sha would produce a formula
# that fails for every user at once.
for bad in "3.11" "v3.11.0" "" "3.11.0; rm -rf /"; do
	if "$ROOT_DIR/packaging/homebrew/generate.sh" "$bad" "$fake_sha" >/dev/null 2>&1; then
		printf 'the formula generator accepted the version %s\n' "$bad" >&2
		exit 1
	fi
done
if "$ROOT_DIR/packaging/homebrew/generate.sh" "$pkg_version" "not-a-sha" >/dev/null 2>&1; then
	printf 'the formula generator accepted a bad sha256\n' >&2
	exit 1
fi
# The closing line reports what actually ran. Printing the .deb claim after
# skipping the .deb build is the same overclaim this suite exists to prevent.
if [ "$pkg_can_build" -eq 1 ]; then
	printf '  packaging: reproducible .deb into the Termux prefix, formula pinned to one archive\n'
else
	printf '  packaging: formula pinned to one archive (.deb build not verified here)\n'
fi

printf 'Docs regression: every capture reaches the documentation\n'
# A screenshot that is captured but never referenced is invisible: the release
# carries the file, the documentation site never renders it, and nothing fails.
# 3.12.4 shipped two such captures. The site is generated from the images this
# document links, so being linked here is what publishes them.
docs_src="$ROOT_DIR/docs/FULL_DOCUMENTATION.md"
docs_orphans=0
for docs_shot in "$ROOT_DIR"/docs/screenshots/*/*.png "$ROOT_DIR"/docs/screenshots/*/*.jpg; do
	[ -e "$docs_shot" ] || continue
	docs_name="${docs_shot#"$ROOT_DIR"/}"
	grep -qF "($docs_name)" "$docs_src" || {
		printf '  captured but never referenced: %s\n' "$docs_name" >&2
		docs_orphans=$((docs_orphans + 1))
	}
done
[ "$docs_orphans" -eq 0 ] || {
	printf '%d capture(s) would ship without ever being published\n' "$docs_orphans" >&2
	exit 1
}
grep -qF '(docs/product-demo.gif)' "$docs_src" || {
	printf 'the product demo GIF is not referenced by the documentation\n' >&2; exit 1
}
# And the mirror of the check above: a reference to an image the repository
# does not have. The site never notices, because build.mjs redirects every
# docs/screenshots path at the current capture set -- so a broken link here is
# visible only to someone reading the manual on GitHub, which is most people
# who read it at all.
docs_missing=0
for docs_ref in $(sed -n 's/.*(\(docs\/screenshots\/[^)]*\)).*/\1/p' "$docs_src" | sort -u); do
	[ -f "$ROOT_DIR/$docs_ref" ] || {
		printf '  referenced but not in the repository: %s\n' "$docs_ref" >&2
		docs_missing=$((docs_missing + 1))
	}
done
[ "$docs_missing" -eq 0 ] || {
	printf '%d referenced image(s) do not exist\n' "$docs_missing" >&2
	exit 1
}
docs_shot_count=$(ls "$ROOT_DIR"/docs/screenshots/*/*.png "$ROOT_DIR"/docs/screenshots/*/*.jpg 2>/dev/null | wc -l)
printf '  docs: %s captures and the demo GIF all referenced\n' "$docs_shot_count"

printf 'Release regression: the version is declared everywhere it is checked\n'
# The release workflow verifies the changelog entry and the extension manifests
# -- but only after the tag has been pushed, so a missing entry leaves a public
# tag with no release behind it. 3.13.0 did exactly that. Checking here means
# the same omission fails before anything is published.
release_version="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' "$ROOT_DIR/spm.sh")"
[ -n "$release_version" ] || {
	printf 'no VERSION in spm.sh\n' >&2; exit 1
}
grep -q "^## \[$release_version\]" "$ROOT_DIR/CHANGELOG.md" || {
	printf 'CHANGELOG.md has no "## [%s]" entry, which the release job only checks after the tag is public\n' \
		"$release_version" >&2
	exit 1
}
for release_manifest in browser-extension/manifest.json \
	browser-extension-universal/manifest.chromium.json \
	browser-extension-universal/manifest.firefox.json; do
	grep -q '"version": "'"$release_version"'"' "$ROOT_DIR/$release_manifest" || {
		printf '%s does not declare version %s\n' \
			"$release_manifest" "$release_version" >&2
		exit 1
	}
done
[ -f "$ROOT_DIR/docs/releases/$release_version.md" ] || {
	printf 'docs/releases/%s.md is missing\n' "$release_version" >&2; exit 1
}
printf '  release: %s declared in the changelog, 3 manifests and its notes\n' \
	"$release_version"

printf 'Install regression: build attestation verification\n'
# The installer compares a checksum it fetched from the same host as the
# archive. That proves the transfer was intact and nothing about where the file
# came from. The attestation check is what closes that, so its decision table
# is asserted rather than assumed -- including the cases where it deliberately
# does nothing, because "not checked" must never print as "verified".
# The same extraction the PATH tests above use, rather than a second one with
# its own way of going stale.
prov="$INSTALL_LIBRARY"
grep -q '^version_at_least() {' "$prov" || {
	printf 'version_at_least is missing from the installer library\n' >&2; exit 1
}

prov_bin="$TEST_ROOT/prov-bin"
prov_min="$TEST_ROOT/prov-min"
mkdir -p "$prov_bin" "$prov_min"
# Only what the function genuinely reaches outside the shell for: bash to run
# it, and awk for the version comparison. Everything else it uses is a builtin.
# Linking just these means an absent gh is genuinely absent rather than merely
# shadowed by the real one in /usr/bin.
ln -sf "$(command -v bash)" "$prov_min/bash"
ln -sf "$(command -v awk)" "$prov_min/awk"

run_prov() {
	# $1 gh behaviour: absent | unauthed | pass | fail
	# $2 version
	# One stub, three switches: whether `gh attestation` exists at all, whether
	# `gh auth status` succeeds, and whether a real verify passes. Written from
	# a heredoc rather than printf -- an earlier printf version escaped its && as
	# \&\&, which made every stub a syntax error, so every case looked like an
	# unsupported gh and the one that should have failed quietly passed.
	rm -f "$prov_bin/gh"
	# `pins` is whether this gh advertises --signer-workflow; `pinned` is what a
	# pinned verify answers. Two switches because the interesting case is a gh
	# that verifies the repository happily and refuses the workflow -- a real
	# attestation minted by the wrong workflow, which must not read as success.
	case "$1" in
		absent)    supports=x authed=x verifies=x pins=0 pinned=0 ;;
		ancient)   supports=1 authed=0 verifies=1 pins=1 pinned=1 ;;
		unauthed)  supports=0 authed=1 verifies=0 pins=0 pinned=0 ;;
		pass)      supports=0 authed=0 verifies=0 pins=0 pinned=0 ;;
		fail)      supports=0 authed=0 verifies=1 pins=0 pinned=1 ;;
		nopin)     supports=0 authed=0 verifies=0 pins=1 pinned=1 ;;
		wrongflow) supports=0 authed=0 verifies=0 pins=0 pinned=1 ;;
		*) printf 'unknown gh behaviour %s\n' "$1" >&2; exit 1 ;;
	esac
	if [ "$supports" != x ]; then
		cat > "$prov_bin/gh" <<GHSTUB
#!/bin/sh
case "\$1" in
	auth) exit $authed ;;
	attestation)
		case "\$*" in
			*--help*)
				[ $pins -eq 0 ] && printf '  --signer-workflow string\\n'
				exit $supports ;;
			*--signer-workflow*) exit $pinned ;;
		esac
		exit $verifies ;;
esac
exit 1
GHSTUB
	fi
	[ -f "$prov_bin/gh" ] && chmod +x "$prov_bin/gh"
	# A PATH holding the stub and nothing else that could answer to "gh". The
	# system bin directories are deliberately absent: this machine has a real gh
	# in /usr/bin, and with it on PATH the "no gh at all" case silently tested
	# the signed-out branch instead -- which is how a mutant that printed
	# "verified" when gh was missing survived.
	# The positional arguments are cleared before sourcing: the library carries
	# the installer's own option parser, which would read the file path it was
	# handed as an unknown flag and exit 2.
	PATH="$prov_bin:$prov_min" bash -c '
		lib="$1"; want="$2"; shift $#
		REPO="sansyourways/Sans_Password_Manager"
		FIRST_ATTESTED_VERSION="3.9.0"
		archive="test.zip"
		. "$lib"
		verify_provenance /dev/null "$want"
	' _ "$prov" "$2" 2>&1
}

expect_prov() {
	local label="$1" behaviour="$2" version="$3" want_status="$4" want_text="$5"
	local out status
	out="$(run_prov "$behaviour" "$version")" && status=0 || status=$?
	[ "$status" = "$want_status" ] || {
		printf 'provenance/%s: exit %s, wanted %s\n  %s\n' \
			"$label" "$status" "$want_status" "$out" >&2
		exit 1
	}
	case "$out" in
		*"$want_text"*) ;;
		*) printf 'provenance/%s said %s\n  wanted text: %s\n' \
			"$label" "$out" "$want_text" >&2; exit 1 ;;
	esac
}

# An old release has nothing to verify, and refusing it would break installs
# that were fine when they were made.
expect_prov "old release"  pass     3.8.0 0 "predates build attestations"
# 3.10.0 must not be read as older than 3.9.0. A string compare gets this
# wrong and would silently skip verification for every release after this one.
expect_prov "double digit" pass     3.10.0 0 "attestation verified"
expect_prov "current"      pass     3.9.0 0 "attestation verified"
# Absent or unauthenticated gh is not a failure, but it must say so: a silent
# skip reads as a successful check.
expect_prov "no gh"        absent   3.9.0 0 "GitHub CLI is not installed"
expect_prov "gh signed out" unauthed 3.9.0 0 "not signed in"
# Debian stable's gh has no attestation command. Reading that as a forged
# archive would refuse an install for a reason that is not about the archive.
expect_prov "gh too old"   ancient  3.9.0 0 "too old"
# A release that should carry an attestation and does not is the whole point.
expect_prov "bad attestation" fail   3.9.0 1 "Installation aborted"
# --repo alone only says "some workflow in this repository". An attestation
# minted by any other workflow must not read as a verified release.
expect_prov "wrong workflow" wrongflow 3.9.0 1 "Installation aborted"
# A gh that cannot pin still verifies, and says which check it actually did:
# a weaker check that reads like the stronger one is worse than none, because
# it gets trusted.
expect_prov "gh cannot pin" nopin  3.9.0 0 "cannot pin"

# The truth table for the comparison itself, including the two cases a string
# compare and a bare `sort -V` respectively get wrong.
prov_versions="3.9.0 3.9.0 1|3.10.0 3.9.0 1|3.9.1 3.9.0 1|4.0.0 3.9.0 1|3.8.0 3.9.0 0|3.8.9 3.9.0 0|2.13.0 3.9.0 0|3.9 3.9.0 1|3.8 3.9.0 0|10.0.0 9.0.0 1"
printf '%s' "$prov_versions" | tr '|' '\n' | while read -r a b want; do
	got="$(bash -c 'lib="$1"; l="$2"; r="$3"; shift $#; . "$lib"; version_at_least "$l" "$r"' \
		_ "$prov" "$a" "$b")"
	[ "$got" = "$want" ] || {
		printf 'version_at_least %s %s = %s, wanted %s\n' "$a" "$b" "$got" "$want" >&2
		exit 1
	}
done
printf '  provenance: 9 installer decisions and 10 version comparisons verified\n'

printf 'Import regression: Bitwarden JSON, CSV and password-protected exports\n'
# People arrive from Bitwarden, and its export shares no field names with SPM's.
# Before this, a Bitwarden CSV imported as one empty note and every login was
# silently dropped -- the dashboard still reported success. The JSON export
# raised AttributeError. Both are asserted here, along with the encrypted
# export, which is built independently rather than by the code under test.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$web_script" "$PASSWORD_VAULT" <<'BWPY'
import base64
import hashlib
import hmac
import importlib.util
import io
import json
import os
import sys

spec = importlib.util.spec_from_file_location("spmweb", sys.argv[1])
web = importlib.util.module_from_spec(spec)
# The module refuses to finish loading without a vault it can see, so it is
# pointed at the suite's own disposable one. Nothing here reads or writes it.
os.environ["SPM_VAULT_PATH"] = sys.argv[2]
try:
    spec.loader.exec_module(web)
except SystemExit:
    pass

BASE = "META_RECOVERY_PUBKEY\tX\t-\t-\t-\t-\n"
PLAIN = {
    "encrypted": False,
    "folders": [{"id": "f1", "name": "Work"}],
    "items": [
        {"id": "a", "type": 1, "name": "GitHub", "notes": "work account",
         "folderId": "f1", "creationDate": "2025-03-04T08:00:00.000Z",
         "login": {"uris": [{"uri": "https://github.com"}],
                   "username": "dev@example.invalid", "password": "s3cr3t-pw",
                   "totp": "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&period=60"}},
        {"id": "b", "type": 2, "name": "Recovery notes",
         "notes": "line one\nline two"},
    ],
}
CSV = (
    "folder,favorite,type,name,notes,fields,reprompt,"
    "login_uri,login_username,login_password,login_totp\n"
    "Work,1,login,GitHub,work account,,0,https://github.com,"
    "dev@example.invalid,s3cr3t-pw,JBSWY3DPEHPK3PXP\n"
    ',0,note,Recovery notes,"line one\nline two",,0,,,,\n'
)


def rows_of(text):
    return [line for line in text.splitlines() if not line.startswith("META_")]


def check(name, fmt, content, password="", expect_auth_period=None):
    plain, stats = web._apply_import(fmt, content, BASE, password)
    body = rows_of(plain)
    if stats["passwords"] != 1:
        sys.exit("%s: expected 1 password, got %s" % (name, stats))
    if stats["notes"] != 1:
        sys.exit("%s: expected 1 note, got %s" % (name, stats))
    if stats["authenticators"] != 1:
        sys.exit("%s: expected 1 authenticator, got %s" % (name, stats))
    joined = "\n".join(body)
    if "s3cr3t-pw" not in joined:
        sys.exit("%s: the login password was not imported" % name)
    if "dev@example.invalid" not in joined:
        sys.exit("%s: the username was not imported" % name)
    if "https://github.com" not in joined:
        sys.exit("%s: the URI was not imported" % name)
    # The TOTP must arrive as a base32 secret, not as the otpauth URI: SPM's
    # authenticator row holds the secret alone and would try to decode a URI.
    auth = [line for line in body if line.startswith("AUTH\t")][0].split("\t")
    if auth[3] != "JBSWY3DPEHPK3PXP":
        sys.exit("%s: authenticator secret is %r, not the base32 secret"
                 % (name, auth[3]))
    if expect_auth_period and auth[4] != expect_auth_period:
        sys.exit("%s: authenticator period is %r, wanted %r"
                 % (name, auth[4], expect_auth_period))
    # The note body is stored base64; it must round-trip with its newline.
    note = [line for line in body if line.startswith("NOTE\t")][0].split("\t")
    if base64.b64decode(note[3]).decode("utf-8") != "line one\nline two":
        sys.exit("%s: the note body did not survive" % name)


check("bitwarden-json", "bitwarden-json", json.dumps(PLAIN), expect_auth_period="60")
check("bitwarden-csv", "bitwarden-csv", CSV)
# Choosing plain json or csv must still work: a wrong pick used to mean a
# silent partial import rather than an error.
check("json autodetect", "json", json.dumps(PLAIN), expect_auth_period="60")
check("csv autodetect", "csv", CSV)

# A password-protected export, constructed here the way Bitwarden constructs
# one, so the decryptor is tested against a file it did not produce.
password, salt, iters = "export-pw-123", "bw-salt", 50000
master = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iters, dklen=32)


def hkdf(prk, info, n=32):
    okm, block, counter = b"", b"", 1
    while len(okm) < n:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:n]


try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("  bitwarden: json and csv verified; protected export skipped "
          "(no python3 cryptography here, which SPM reports rather than guesses)")
    raise SystemExit(0)

enc_key, mac_key = hkdf(master, b"enc"), hkdf(master, b"mac")
payload = json.dumps(PLAIN).encode("utf-8")
pad = 16 - (len(payload) % 16)
iv = os.urandom(16)
encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
ciphertext = encryptor.update(payload + bytes([pad]) * pad) + encryptor.finalize()
mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
blob = "2.%s|%s|%s" % (base64.b64encode(iv).decode(),
                       base64.b64encode(ciphertext).decode(),
                       base64.b64encode(mac).decode())
protected = json.dumps({"encrypted": True, "passwordProtected": True,
                        "salt": salt, "kdfType": 0, "kdfIterations": iters,
                        "data": blob})

check("bitwarden-protected", "bitwarden-protected", protected, password,
      expect_auth_period="60")

for name, fmt, content, pw, expected in (
        ("no password", "bitwarden-protected", protected, "", "password-protected"),
        ("wrong password", "bitwarden-protected", protected, "wrong", "wrong export password"),
):
    try:
        web._apply_import(fmt, content, BASE, pw)
    except Exception as exc:
        if expected not in str(exc):
            sys.exit("%s: unhelpful error %r" % (name, exc))
    else:
        sys.exit("%s: a protected export was imported without the right password" % name)

# Argon2id is not derivable here, and must be refused by name rather than
# producing an empty or partial import.
argon = json.loads(protected)
argon["kdfType"] = 1
try:
    web._apply_import("bitwarden-protected", json.dumps(argon), BASE, password)
except Exception as exc:
    if "Argon2id" not in str(exc):
        sys.exit("an Argon2id export was refused without saying why: %r" % exc)
else:
    sys.exit("an Argon2id export was accepted")

print("  bitwarden: json, csv, protected, autodetect, and four refusals verified")
BWPY

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

printf 'CLI regression: per-record password history\n'
# History is captured at the write boundary rather than at each of the twenty-one
# CLI edit paths, so what has to be proven is that the boundary fires -- not that
# one particular command remembered to call it.
hist_plain="$TEST_ROOT/hist-plain"
hist_vault="$TEST_ROOT/hist-vault.gpg"
printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n1\tGitHub\tuser\tfirst-pw\tnotes\t2025-01-01T00:00:00Z\n2\tUntouched\tu2\tkeep-me\tn\t2025-01-01T00:00:00Z\n' \
	"$TEST_RECOVERY_B64" > "$hist_plain"
printf '%s' "$AUDIT_PASSWORD" | gpg --batch --yes --pinentry-mode loopback \
	--passphrase-fd 0 --symmetric --cipher-algo AES256 -o "$hist_vault" "$hist_plain"
chmod 600 "$hist_vault"

(
	export VAULT_FILE="$hist_vault" MASTER_PW="$AUDIT_PASSWORD" VAULT_KEY=""
	for secret in second-pw third-pw; do
		hist_tmp="$(make_tmp)"
		decrypt_vault_to_file "$hist_tmp"
		sed -i.bak "s/\t[a-z-]*pw\t/\t$secret\t/" "$hist_tmp" && rm -f "$hist_tmp.bak"
		encrypt_file_to_vault "$hist_tmp"
	done
	# An edit that changes something other than the password must record nothing.
	hist_tmp="$(make_tmp)"
	decrypt_vault_to_file "$hist_tmp"
	sed -i.bak "s/\tnotes\t/\tdifferent notes\t/" "$hist_tmp" && rm -f "$hist_tmp.bak"
	encrypt_file_to_vault "$hist_tmp"

	final="$(make_tmp)"
	decrypt_vault_to_file "$final"
	rows="$(core password-history "$final" 1)"
	[ "$(printf '%s\n' "$rows" | wc -l | tr -d ' ')" = "2" ] || {
		printf 'expected two previous passwords, got:\n%s\n' "$rows" >&2; exit 1; }
	printf '%s\n' "$rows" | grep -q 'first-pw' || {
		printf 'the original password was not recorded\n' >&2; exit 1; }
	printf '%s\n' "$rows" | grep -q 'second-pw' || {
		printf 'the second password was not recorded\n' >&2; exit 1; }
	printf '%s\n' "$rows" | grep -q 'third-pw' && {
		printf 'the CURRENT password was recorded as history\n' >&2; exit 1; }
	[ -z "$(core password-history "$final" 2)" ] || {
		printf 'an untouched record gained history\n' >&2; exit 1; }
	# History must not reach an export: a plaintext CSV of the vault should not
	# spill passwords the user has already replaced.
	export_out="$TEST_ROOT/hist-export.csv"
	cmd_export csv "$export_out" >/dev/null 2>&1 || true
	if [ -f "$export_out" ] && grep -q 'first-pw' "$export_out"; then
		printf 'an old password leaked into a CSV export\n' >&2; exit 1
	fi
) || exit 1
printf '  two rotations recorded, current excluded, untouched record clean, export clean\n'

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


printf 'Security regression: the event log\n'
# The log lives outside the vault, in the clear, because the events worth
# reading most -- failed unlocks -- cannot be written into a vault nobody could
# open. That choice is only safe if the file carries nothing worth reading, so
# that is what is asserted here, against the real CLI and the real dashboard
# rather than against the function underneath them.
events_log="$(core events-path "$PASSWORD_VAULT")"
[ -n "$events_log" ] || { printf 'the core did not report an events path\n' >&2; exit 1; }
[ -f "$events_log" ] || {
	printf 'no event log after a suite that has opened this vault many times\n' >&2
	exit 1
}
# 600 or 0600 depending on whose stat answered; the suite's own probe above
# accepts both for exactly this reason.
case "$(file_mode "$events_log")" in
	600|0600) ;;
	*) printf 'the event log is mode %s, not 600\n' "$(file_mode "$events_log")" >&2
	   exit 1 ;;
esac

# Nothing from the vault may appear in it. The suite has by now written real
# records through the CLI and the dashboard, so these are live values.
for forbidden in "$AUDIT_PASSWORD" 'DemoSecret42' 'WebSecret42' 'Pv9!wwwwwwwwww' \
	'bound.example.invalid' 'Preview Site' "$PASSWORD_VAULT"; do
	if grep -qF -- "$forbidden" "$events_log"; then
		printf 'the event log leaked %s\n' "$forbidden" >&2
		exit 1
	fi
done

# Every line must parse as the closed format. A line that does not is either a
# leak or a bug, and both matter.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$events_log" <<'PYEVENTS'
import re, sys
KINDS = {"unlock", "write", "rewrap", "recover", "restore", "archive"}
OUTCOMES = {"ok", "fail"}
KEYS = {"records", "format", "scope", "reason"}
seen = set()
for number, line in enumerate(open(sys.argv[1], encoding="utf-8"), start=1):
    fields = line.rstrip("\n").split("\t")
    if len(fields) != 4:
        sys.exit("line %d has %d fields, not 4: %r" % (number, len(fields), line))
    when, kind, outcome, detail = fields
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", when):
        sys.exit("line %d has a malformed timestamp: %r" % (number, when))
    if kind not in KINDS:
        sys.exit("line %d has an unknown kind %r" % (number, kind))
    if outcome not in OUTCOMES:
        sys.exit("line %d has an unknown outcome %r" % (number, outcome))
    for item in detail.split(","):
        if not item:
            continue
        if "=" not in item:
            sys.exit("line %d detail %r is not key=value" % (number, item))
        key, value = item.split("=", 1)
        if key not in KEYS:
            sys.exit("line %d carries the detail key %r" % (number, key))
        # The only values permitted are numbers and a fixed vocabulary. Free
        # text here is how a record label would arrive.
        if not re.fullmatch(r"[a-z0-9-]+", value):
            sys.exit("line %d detail %s=%r is not a plain token" % (number, key, value))
    seen.add((kind, outcome))
if ("unlock", "ok") not in seen:
    sys.exit("no successful unlock was recorded across the whole suite")
if ("write", "ok") not in seen:
    sys.exit("no write was recorded across the whole suite")
print("  events: every line parses, %d kind/outcome pairs seen" % len(seen))
PYEVENTS

# A failed unlock must be recorded -- it is the reason the log is outside the
# vault at all.
before_fail="$(grep -c 'unlock	fail' "$events_log" || true)"
printf 'definitely-not-the-master\n' \
	| core read "$PASSWORD_VAULT" "$TEST_ROOT/events-probe" >/dev/null 2>&1 || true
rm -f "$TEST_ROOT/events-probe"
after_fail="$(grep -c 'unlock	fail' "$events_log" || true)"
[ "$after_fail" -gt "$before_fail" ] || {
	printf 'a failed unlock was not recorded (%s -> %s)\n' "$before_fail" "$after_fail" >&2
	exit 1
}

# The CLI reports it without opening the vault: no master password is read, so
# it still answers when the vault will not open, which is the moment it matters.
cmd_events --json > "$TEST_ROOT/events.json"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/events.json" <<'PYCLI'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
events = doc["events"]
assert events, "spm events --json reported nothing"
assert any(e["kind"] == "unlock" and e["outcome"] == "fail" for e in events), \
    "the failed unlock is missing from the CLI document"
for event in events:
    assert set(event) == {"when", "kind", "outcome", "detail"}, event
PYCLI
printf '  events: a failed unlock is recorded and reported without opening the vault\n'

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

# Key derivation is pinned, not inherited, and from 4.0.0 the vault says so in
# its own header instead of it having to be recovered from gpg packet dumps.
# Asserted against the file on disk and against the core's constants -- not
# against numbers written here, because a hardcoded copy would fail a raise of
# the cost parameter for no reason and pass a silent drop of it.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$PASSWORD_VAULT" \
	"$ROOT_DIR/src/spm_core.py" <<'KDFPY'
import base64, importlib.util, re, sys

vault = open(sys.argv[1], "rb").read()
spec = importlib.util.spec_from_file_location("spm_core_kdf", sys.argv[2])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

if core.container_backend(vault) != "openssl":
    sys.exit("the vault was not written by the current backend")
kdf, envelope, cipher = core.parse_container_aead(vault)
if (kdf["name"], kdf["n"], kdf["r"], kdf["p"]) != (
        core.KDF_NAME, core.KDF_N, core.KDF_R, core.KDF_P):
    sys.exit("the vault header does not carry the core's KDF policy: %r" % kdf)
if len(kdf["salt"]) != core.KDF_SALT_BYTES:
    sys.exit("KDF salt is %d bytes, not %d" % (len(kdf["salt"]), core.KDF_SALT_BYTES))

# Both layers are sealed, and sealed separately: a salt or an IV shared between
# the envelope and the data would mean one keystream covering both.
head = len(core.SEAL_MAGIC) + core.SEAL_SALT_BYTES + core.SEAL_IV_BYTES
for name, blob in (("key envelope", envelope), ("vault data", cipher)):
    if not blob.startswith(core.SEAL_MAGIC):
        sys.exit("the %s is not a sealed block" % name)
    if len(blob) < head + core.SEAL_TAG_BYTES:
        sys.exit("the %s carries no authentication tag" % name)
if envelope[len(core.SEAL_MAGIC):head] == cipher[len(core.SEAL_MAGIC):head]:
    sys.exit("the key envelope and the vault data share a salt and IV")

# And it is no longer an OpenPGP message at all, which is the half a header
# check cannot show on its own.
if vault[:1] == b"\x85" or b"BEGIN PGP" in vault[:200]:
    sys.exit("the vault still looks like an OpenPGP message")
print("  vault: %s n=%d r=%d p=%d, both layers sealed and separately salted"
      % (kdf["name"], kdf["n"], kdf["r"], kdf["p"]))
KDFPY

# The new row must be invisible to every parser and to the integrity scanner.
[ "$(awk -F '\t' '$1 ~ /^[0-9]+$/' "$TEST_ROOT/fmt-plain" | wc -l)" -ge 1 ]
cmd_doctor >"$TEST_ROOT/doctor-fmt.txt" 2>&1 || true
if ! grep -q 'Vault format version' "$TEST_ROOT/doctor-fmt.txt"; then
	printf 'doctor does not report the vault format version. Output was:\n' >&2
	sed 's/^/    /' "$TEST_ROOT/doctor-fmt.txt" >&2
	exit 1
fi
# The number comes from the core, not from this line: hard-coding it means a
# format bump fails a test that was never about the number.
grep -q "Vault format version $VAULT_FORMAT_VERSION (current)" "$TEST_ROOT/doctor-fmt.txt" \
	|| { printf 'doctor did not see the upgraded format:\n' >&2
	     grep -i 'format' "$TEST_ROOT/doctor-fmt.txt" >&2; exit 1; }

printf 'Web regression: the idle lock is a setting, not a constant\n'
# The lock was 30 seconds in a literal inside the page script. What has to hold
# now is that the number a page carries comes from the setting -- on every page,
# not only the one the form is on -- because the failure mode of a stamped
# value is one forgotten template still locking at the old time.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/settings.html" \
	"http://127.0.0.1:$WEB_PORT/settings"
grep -q 'id="lock-timeout"' "$TEST_ROOT/settings.html" || {
	printf 'the settings page offers no idle lock control\n' >&2; exit 1
}
grep -q 'var IDLE_MS = 30000;' "$TEST_ROOT/settings.html" || {
	printf 'the default idle lock is not 30s in the page as served\n' >&2; exit 1
}
lock_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/settings.html" | head -n1)"
[ "${#lock_csrf}" -eq 64 ]
curl -fsS -D "$TEST_ROOT/lock.headers" -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$lock_csrf" --data-urlencode 'seconds=600' \
	"http://127.0.0.1:$WEB_PORT/settings/lock-timeout"
grep -q '303 See Other' "$TEST_ROOT/lock.headers"
for lock_page in / /settings /passwords; do
	curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/lock-page.html" \
		"http://127.0.0.1:$WEB_PORT$lock_page"
	grep -q 'var IDLE_MS = 600000;' "$TEST_ROOT/lock-page.html" || {
		printf '%s still carries the old idle lock after the setting changed\n' \
			"$lock_page" >&2
		exit 1
	}
done
# A value outside the offered list must be refused rather than stored, and the
# stored one must survive the attempt.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/lock-refused.html" \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$lock_csrf" --data-urlencode 'seconds=86400' \
	"http://127.0.0.1:$WEB_PORT/settings/lock-timeout"
grep -q 'not one of the available lock timeouts' "$TEST_ROOT/lock-refused.html" || {
	printf 'an unlisted lock timeout was not refused\n' >&2; exit 1
}
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/lock-after.html" \
	"http://127.0.0.1:$WEB_PORT/settings"
grep -q 'var IDLE_MS = 600000;' "$TEST_ROOT/lock-after.html" || {
	printf 'a refused lock timeout still changed the setting\n' >&2; exit 1
}
# Put it back, so the pages the rest of this suite fetches carry the default.
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null \
	-X POST -H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$lock_csrf" --data-urlencode 'seconds=30' \
	"http://127.0.0.1:$WEB_PORT/settings/lock-timeout"
printf '  web: the lock timer on every page follows the setting; 86400 refused\n'

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
grep -q 'data-i18n="nav.settings"' "$TEST_ROOT/settings.html"
# Theme selection previews independently and persists only through Apply.
grep -q 'name="dashboard-theme" value="sundial"' "$TEST_ROOT/settings.html"
grep -q 'name="dashboard-theme" value="console"' "$TEST_ROOT/settings.html"
grep -q 'name="dashboard-theme" value="cyberpunk"' "$TEST_ROOT/settings.html"
grep -q 'name="dashboard-theme" value="edgerunner"' "$TEST_ROOT/settings.html"
[ "$(grep -o 'class="theme-preview"' "$TEST_ROOT/settings.html" | wc -l)" -eq 4 ]
grep -q 'data-preview="sundial"' "$TEST_ROOT/settings.html"
grep -q 'data-preview="console"' "$TEST_ROOT/settings.html"
grep -q 'data-preview="cyberpunk"' "$TEST_ROOT/settings.html"
grep -q 'data-preview="edgerunner"' "$TEST_ROOT/settings.html"
grep -q 'prefers-reduced-motion:no-preference' "$TEST_ROOT/settings.html"
grep -q '@media (min-width:1601px)' "$TEST_ROOT/settings.html"
grep -q 'body.theme-edgerunner .nav-label' "$TEST_ROOT/settings.html"
grep -q 'id="apply-theme"' "$TEST_ROOT/settings.html"
grep -q 'localStorage.setItem("spm.theme", next)' "$TEST_ROOT/settings.html"
# Biometric Unlock is part of the one Settings page; it must not have been
# dropped when its separate sidebar destination was removed.
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
# Opened through the live backend rather than through gpg. Reaching for gpg
# here would keep passing on a vault gpg cannot read at all -- it fails on
# every input, so proving it fails on this one proves nothing.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$PASSWORD_VAULT" \
	"$TEST_ROOT/recovered-vault-key" "$TEST_ROOT/recovered-plain" \
	"$ROOT_DIR/src/spm_core.py" <<'RECOVERPY'
import importlib.util, sys

spec = importlib.util.spec_from_file_location("spm_core_recover", sys.argv[4])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

vault = open(sys.argv[1], "rb").read()
key = open(sys.argv[2], encoding="utf-8").read()
parsed = core.parse_container_aead(vault)
if parsed is None:
    sys.exit("the vault is not in the current format")
try:
    plaintext = core.unseal(key, parsed[2])
except core.VaultError as exc:
    sys.exit("the recovered vault key does not decrypt the vault data: %s" % exc)
open(sys.argv[3], "wb").write(plaintext)
RECOVERPY
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
printf 'Web regression: tidying imported entries\n'
# A vault filled by importing from a phone carries its folders as text in the
# notes and its service names as Android package identifiers. Tidying that is a
# bulk edit of hundreds of records, so the whole feature is a review: the guess
# is offered, the person corrects it, and only then is anything written.
tidy_root="$TEST_ROOT/tidy"
mkdir -p "$tidy_root"
tidy_vault="$tidy_root/vault.gpg"
tidy_plain="$tidy_root/plain"
tidy_master="Tidy-Regression-Master-1"
{
	printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n' "$TEST_RECOVERY_B64"
	printf '1\tcom.duolingo\tu@example.invalid\tpw1\tfolder: Main Database\t2025-01-01T00:00:00Z\t\t\n'
	printf '2\tcom.lsdroid.cerberuss\tu@example.invalid\tpw2\tanti theft folder: Security\t2025-01-02T00:00:00Z\t\t\n'
	printf '3\tid.go.kemensos.pelaporan\tu@example.invalid\tpw3\tfolder: Government url: https://k.invalid\t2025-01-03T00:00:00Z\t\t\n'
	printf '4\tMy Bank\tu@example.invalid\tpw4\tnothing special\t2025-01-04T00:00:00Z\t\t\n'
} > "$tidy_plain"
printf '%s' "$tidy_master" | core write "$tidy_vault" "$tidy_plain" >/dev/null

TIDY_PORT="$((WEB_PORT + 4))"
SPM_VAULT_PATH="$tidy_vault" SPM_WEB_BIND=127.0.0.1 \
	SPM_WEB_PORT="$TIDY_PORT" SPM_VERSION="$VERSION" \
	SPM_WEB_RP_ID=localhost python3 "$web_script" \
	>"$TEST_ROOT/tidy-web.log" 2>&1 &
TIDY_PID="$!"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	curl -fsS -o /dev/null "http://127.0.0.1:$TIDY_PORT/login" 2>/dev/null && break
	sleep 0.25
done
curl -fsS -c "$tidy_root/cookies" -o /dev/null -X POST \
	--data-urlencode "password=$tidy_master" "http://127.0.0.1:$TIDY_PORT/login"

# The offer only appears when there is something to accept.
curl -fsS -b "$tidy_root/cookies" -o "$tidy_root/passwords.html" \
	"http://127.0.0.1:$TIDY_PORT/passwords"
grep -q 'data-i18n="tidy.review"' "$tidy_root/passwords.html" || {
	printf 'the passwords page does not offer to tidy a vault that needs it\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}

curl -fsS -b "$tidy_root/cookies" -o "$tidy_root/review.html" \
	"http://127.0.0.1:$TIDY_PORT/tidy"
tidy_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$tidy_root/review.html" | head -n1)"
[ -n "$tidy_csrf" ] || {
	printf 'the review form carries no CSRF token\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}
# Reviewing must change nothing. It is the whole promise of the page.
[ "$(sha256sum "$tidy_vault" | awk '{print $1}')" = \
  "$(printf '%s' "$tidy_master" | core read "$tidy_vault" /dev/null >/dev/null; \
     sha256sum "$tidy_vault" | awk '{print $1}')" ] || true
tidy_before="$(sha256sum "$tidy_vault" | awk '{print $1}')"
grep -q 'name="label_1" value="Duolingo"' "$tidy_root/review.html" || {
	printf 'the review does not propose a name for a package identifier\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}
grep -q 'value="Cerberuss"' "$tidy_root/review.html" || {
	printf 'the review does not propose a name for a three-part identifier\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}
grep -q '>Main Database<' "$tidy_root/review.html" || {
	printf 'the review does not show the folder read from the notes\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}
grep -q 'com.duolingo' "$tidy_root/review.html" || {
	printf 'the review does not show the identifier being replaced\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}
[ "$(sha256sum "$tidy_vault" | awk '{print $1}')" = "$tidy_before" ] || {
	printf 'merely reviewing changed the vault\n' >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}

# Apply: one name corrected by hand, one accepted, one row left out entirely.
curl -fsS -b "$tidy_root/cookies" -o /dev/null \
	-w '%{http_code} %{redirect_url}\n' -X POST \
	--data-urlencode "csrf=$tidy_csrf" \
	--data-urlencode "pick=1" --data-urlencode "label_1=Duolingo" \
	--data-urlencode "pick=2" --data-urlencode "label_2=Cerberus" \
	"http://127.0.0.1:$TIDY_PORT/tidy" > "$tidy_root/apply.txt"
grep -q '^303 .*tidied=2' "$tidy_root/apply.txt" || {
	printf 'applying did not report two tidied entries: %s\n' \
		"$(cat "$tidy_root/apply.txt")" >&2
	kill "$TIDY_PID" 2>/dev/null; exit 1
}

printf '%s' "$tidy_master" | core read "$tidy_vault" "$tidy_root/after" >/dev/null
kill "$TIDY_PID" 2>/dev/null || true
wait "$TIDY_PID" 2>/dev/null || true

PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$tidy_root/after" "$ROOT_DIR" <<'TIDYPY'
import importlib.util, sys
after, root = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location(
    "spm_core", root + "/src/spm_core.py")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)

rows = {}
for line in open(after, encoding="utf-8"):
    parts = line.rstrip("\n").split("\t")
    if parts and parts[0].isdigit():
        rows[parts[0]] = parts

if rows["1"][1] != "Duolingo":
    sys.exit("record 1 was not renamed: %r" % rows["1"][1])
# The corrected name, not the guess. This is the point of reviewing.
if rows["2"][1] != "Cerberus":
    sys.exit("the reviewed name was ignored; got %r" % rows["2"][1])
if rows["3"][1] != "id.go.kemensos.pelaporan":
    sys.exit("an unselected record was changed: %r" % rows["3"][1])
if rows["4"][1] != "My Bank":
    sys.exit("a record with nothing to tidy was changed: %r" % rows["4"][1])

for record_id, folder in (("1", "Main Database"), ("2", "Security")):
    got, _, _ = core.decode_attrs(rows[record_id][7] if len(rows[record_id]) > 7 else "")
    if got != folder:
        sys.exit("record %s went to folder %r, expected %r"
                 % (record_id, got, folder))
if core.decode_attrs(rows["3"][7] if len(rows["3"]) > 7 else "")[0]:
    sys.exit("an unselected record was filed anyway")

# The identifier the phone knew is kept, exactly once.
for record_id, original in (("1", "com.duolingo"), ("2", "com.lsdroid.cerberuss")):
    if original not in rows[record_id][4]:
        sys.exit("record %s lost its original identifier" % record_id)
    if rows[record_id][4].count(original) != 1:
        sys.exit("record %s records its identifier twice" % record_id)

# Every row still has its columns: a name arrives from a form, and a tab in one
# would split the record and orphan everything after it.
for record_id, parts in rows.items():
    if len(parts) != 8:
        sys.exit("record %s has %d columns" % (record_id, len(parts)))
print("  tidy: reviewed, corrected, applied to 2 of 4; folders filed, "
      "identifiers kept, unselected rows untouched")
TIDYPY

printf 'Sync regression: pluggable transports\n'
# The conflict model, the digest verification, the archive-before-replace and
# the refusal to install a remote that will not decrypt all live above the
# transport, so they are identical for every one of them. That is the claim
# this block exists to check -- per transport, not just for a directory.
sync_root="$TEST_ROOT/transports"
mkdir -p "$sync_root"
sync_vault_sha="$(sha256sum "$PASSWORD_VAULT" | awk '{print $1}')"

# A remote shell that drops the host and runs the command here. As far as
# rsync's wire protocol is concerned this is a remote host, which is what makes
# the transport testable without a server or an ssh key.
sync_shim="$sync_root/remote-shell.sh"
printf '#!/bin/sh\nshift\nexec "$@"\n' > "$sync_shim"
chmod +x "$sync_shim"

sync_available=""
for sync_t in $(sync_transport_names); do
	case "$sync_t" in
		dir) sync_available="$sync_available dir" ;;
		rsync)
			if command -v rsync >/dev/null 2>&1; then
				sync_available="$sync_available rsync"
			fi
			;;
		rclone)
			if command -v rclone >/dev/null 2>&1; then
				sync_available="$sync_available rclone"
			fi
			;;
	esac
done

sync_target_for() {
	case "$1" in
		dir) printf '%s' "$sync_root/dir" ;;
		rsync) printf 'fakehost:%s' "$sync_root/rsync" ;;
		rclone) printf ':local:%s' "$sync_root/rclone" ;;
	esac
}

for sync_t in $sync_available; do
	mkdir -p "$sync_root/$sync_t"
	sync_target="$(sync_target_for "$sync_t")"
	(
		export SPM_SYNC_RSYNC_SHELL="$sync_shim"
		export SPM_CONFIG_DIR="$sync_root/cfg-$sync_t"
		mkdir -p "$SPM_CONFIG_DIR"

		cmd_sync push "$sync_target" chan --transport "$sync_t" >/dev/null

		# Only ciphertext leaves, and it leaves unaltered. A transport that
		# transcoded or truncated would be caught here rather than at the
		# moment somebody needed the remote copy.
		pushed="$sync_root/pushed-$sync_t"
		sync_transport_fetch "$sync_t" "$sync_target/spm-chan.gpg" "$pushed" \
			|| { printf '%s: the pushed vault could not be read back\n' "$sync_t" >&2; exit 1; }
		[ "$(sha256sum "$pushed" | awk '{print $1}')" = "$sync_vault_sha" ] || {
			printf '%s: the pushed vault is not the local vault\n' "$sync_t" >&2; exit 1
		}
		if grep -q 'META_RECOVERY_PUBKEY' "$pushed"; then
			printf '%s: the vault crossed the transport as plaintext\n' "$sync_t" >&2
			exit 1
		fi

		cmd_sync status "$sync_target" chan --transport "$sync_t" \
			> "$sync_root/status-$sync_t"
		grep -q "^transport=$sync_t$" "$sync_root/status-$sync_t" || {
			printf '%s: status does not name its transport\n' "$sync_t" >&2; exit 1
		}
		grep -q "^remote=$sync_vault_sha$" "$sync_root/status-$sync_t" || {
			printf '%s: status reports the wrong remote digest\n' "$sync_t" >&2; exit 1
		}

		# Both sides move after the base was recorded. Every transport must
		# refuse rather than pick a winner.
		sync_conflict="$sync_root/conflict-$sync_t"
		sync_transport_fetch "$sync_t" "$sync_target/spm-chan.gpg" "$sync_conflict" >/dev/null
		printf 'drift' >> "$sync_conflict"
		sync_transport_publish "$sync_t" "$sync_target/spm-chan.gpg" "$sync_conflict"
		sync_local_backup="$sync_root/local-$sync_t"
		cp "$PASSWORD_VAULT" "$sync_local_backup"
		printf 'drift' >> "$PASSWORD_VAULT"
		if ( cmd_sync push "$sync_target" chan --transport "$sync_t" ) >/dev/null 2>&1; then
			printf '%s: a divergent push was allowed\n' "$sync_t" >&2; exit 1
		fi
		if ( cmd_sync pull "$sync_target" chan --transport "$sync_t" ) >/dev/null 2>&1; then
			printf '%s: a divergent pull was allowed\n' "$sync_t" >&2; exit 1
		fi
		cp "$sync_local_backup" "$PASSWORD_VAULT"

		# A remote that does not decrypt must never reach the vault file, and
		# the local copy must survive the refusal untouched.
		mkdir -p "$sync_root/$sync_t-bad"
		sync_bad_target="$(sync_target_for "$sync_t" | sed "s|$sync_root/$sync_t|$sync_root/$sync_t-bad|")"
		sync_junk="$sync_root/junk-$sync_t"
		# Deterministic, not random. This was 512 bytes from /dev/urandom, and
		# gpg exits 0 on about 1.1% of those: byte 0 is read as an OpenPGP
		# packet header and a few tags -- an unencrypted literal-data packet
		# among them -- are parsed and emitted without any decryption at all.
		# Three transports per run made that a ~3% chance of this block failing
		# with "an undecryptable remote was installed", on a file that had been
		# parsed rather than opened. Twice observed in CI, on two transports.
		printf 'this file is not a vault and must never be installed as one\n' \
			> "$sync_junk"
		# Proved rather than assumed. If the fixture ever stops being
		# undecryptable, that is what fails -- not the assertion it exists to
		# support, and not one run in thirty.
		if decrypt_vault_container "$sync_junk" "$sync_root/junk-check-$sync_t" \
			"$AUDIT_PASSWORD"; then
			printf '%s: the junk fixture decrypted, so it cannot test a refusal\n' \
				"$sync_t" >&2
			exit 1
		fi
		sync_transport_publish "$sync_t" "$sync_bad_target/spm-bad.gpg" "$sync_junk"
		sync_before="$(sha256sum "$PASSWORD_VAULT" | awk '{print $1}')"
		if ( SPM_SYNC_FORCE_INITIAL=1 cmd_sync pull "$sync_bad_target" bad \
			--transport "$sync_t" ) >/dev/null 2>&1; then
			printf '%s: an undecryptable remote was installed\n' "$sync_t" >&2; exit 1
		fi
		[ "$(sha256sum "$PASSWORD_VAULT" | awk '{print $1}')" = "$sync_before" ] || {
			printf '%s: the vault was replaced by a remote that does not decrypt\n' \
				"$sync_t" >&2
			exit 1
		}
	) || exit 1
done

# Apple still ships rsync 2.6.9, which has no --chmod. A push must still work
# there, and must still use the flag where it exists. CI on macOS found this
# after the flag had been added unconditionally; a stub finds it here.
if command -v rsync >/dev/null 2>&1; then
	sync_old_bin="$sync_root/old-rsync"
	mkdir -p "$sync_old_bin"
	cat > "$sync_old_bin/rsync" <<'OLDRSYNC'
#!/bin/sh
# rsync 2.6.9 as Apple ships it: no --chmod, and it says so.
if [ "$1" = "--help" ]; then
	printf 'rsync version 2.6.9\n  --perms, -p    preserve permissions\n'
	exit 0
fi
for arg in "$@"; do
	case "$arg" in
		--chmod*) printf 'rsync: %s: invalid argument\n' "$arg" >&2; exit 1 ;;
	esac
done
exec /usr/bin/env -i PATH="$SPM_REAL_PATH" rsync "$@"
OLDRSYNC
	chmod +x "$sync_old_bin/rsync"
	mkdir -p "$sync_root/oldrsync"
	cp "$PASSWORD_VAULT" "$sync_root/oldrsync/spm-chan.gpg"
	touch -r "$PASSWORD_VAULT" "$sync_root/oldrsync/spm-chan.gpg"
	chmod 644 "$sync_root/oldrsync/spm-chan.gpg"
	(
		export SPM_REAL_PATH="$PATH"
		export PATH="$sync_old_bin:$PATH"
		export SPM_SYNC_RSYNC_SHELL="$sync_shim"
		export SPM_CONFIG_DIR="$sync_root/cfg-oldrsync"
		mkdir -p "$SPM_CONFIG_DIR"
		rsync --help 2>&1 | grep -q -- '--chmod' && {
			printf 'the stub still advertises --chmod\n' >&2; exit 1
		}
		cmd_sync push "fakehost:$sync_root/oldrsync" chan --transport rsync >/dev/null
	) || { printf 'a push failed against an rsync without --chmod\n' >&2; exit 1; }
	[ -f "$sync_root/oldrsync/spm-chan.gpg" ] || {
		printf 'the push against an old rsync wrote nothing\n' >&2; exit 1
	}
	# The mode still has to travel, or the remote copy lands with whatever the
	# far side's umask gives it.
	[ "$(file_mode "$sync_root/oldrsync/spm-chan.gpg")" = "600" ] || {
		printf 'the pushed vault landed as %s, not 0600\n' \
			"$(file_mode "$sync_root/oldrsync/spm-chan.gpg")" >&2
		exit 1
	}
fi

# Unreachable must never read as empty: that is the state in which pushing over
# a remote nobody could contact feels safe.
for sync_t in $sync_available; do
	case "$sync_t" in
		rsync) sync_dead="nosuchhost.invalid:/nowhere" ;;
		rclone) sync_dead="nosuchremote:path" ;;
		*) continue ;;
	esac
	if ( export SPM_SYNC_RSYNC_SHELL=""
		cmd_sync status "$sync_dead" chan --transport "$sync_t" ) >/dev/null 2>&1; then
		printf '%s: an unreachable target was reported rather than refused\n' \
			"$sync_t" >&2
		exit 1
	fi
done

if ( cmd_sync status "$sync_root/dir" chan --transport carrierpigeon ) >/dev/null 2>&1; then
	printf 'an unknown transport was accepted\n' >&2; exit 1
fi

printf '  sync: %s verified for round-trip, conflict, undecryptable remote and unreachable target\n' \
	"$(printf '%s' "$sync_available" | sed 's/^ //' | tr ' ' ',')"

printf 'Recovery regression: Shamir split recovery\n'
# The recovery file and its private key have to survive together and stay
# secret together. Shares replace that pair with a threshold. What has to hold:
# any `t` reconstruct, fewer never do, a mistyped share is refused rather than
# combined into a wrong key, and the set keeps working after the master
# password changes -- which is the only reason writing them down is sensible.
sh_root="$TEST_ROOT/shares"
mkdir -p "$sh_root"
sh_vault="$sh_root/vault.gpg"
sh_plain="$sh_root/plain"
sh_master="Shares-Regression-Master-1"
sh_rotated="Shares-Regression-Master-2"
printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n1\tExample\tu@example.invalid\tSecret1\thttps://a.invalid\t2025-01-01T00:00:00Z\n' \
	"$TEST_RECOVERY_B64" > "$sh_plain"
printf '%s' "$sh_master" | core write "$sh_vault" "$sh_plain" > "$sh_root/key"
[ -s "$sh_root/key" ] || { printf 'no vault key was minted\n' >&2; exit 1; }

printf '%s' "$sh_master" | core shares-split "$sh_vault" 3 5 > "$sh_root/out"
sh_set="$(sed -n '1p' "$sh_root/out")"
sed -n '2,$p' "$sh_root/out" > "$sh_root/shares"
[ "$(wc -l < "$sh_root/shares")" -eq 5 ] || {
	printf 'expected 5 shares, got %s\n' "$(wc -l < "$sh_root/shares")" >&2; exit 1
}
grep -qE "^SPMS1-3-[1-5]-$sh_set-[A-Z2-7]+-[0-9A-F]{4}$" "$sh_root/shares" || {
	printf 'a share is not in the documented format\n' >&2; exit 1
}

# The shares are shown once and stored nowhere. A copy on disk beside the
# vault would quietly undo the whole point of distributing them.
if grep -rqF "$(sed -n '1p' "$sh_root/shares")" "$sh_vault" "$sh_vault.recovery" 2>/dev/null; then
	printf 'a share was written next to the vault it protects\n' >&2
	exit 1
fi

# Any three of the five, and the vault proves it is the right key.
for sh_pick in '1p;2p;3p' '1p;3p;5p' '3p;4p;5p'; do
	sed -n "$sh_pick" "$sh_root/shares" \
		| core shares-combine "$sh_vault" > "$sh_root/got"
	cmp -s "$sh_root/got" "$sh_root/key" || {
		printf 'shares %s did not reconstruct the vault key\n' "$sh_pick" >&2
		exit 1
	}
done

# Two of five is one short, and must be refused rather than answered.
sh_err="$(sed -n '1p;2p' "$sh_root/shares" \
	| core shares-combine "$sh_vault" 2>&1 >/dev/null)" && {
	printf 'two shares of a three-of-five set reconstructed the key\n' >&2
	exit 1
}
case "$sh_err" in
	*"needs 3"*) ;;
	*) printf 'below-threshold refusal did not say how many are needed: %s\n' \
		"$sh_err" >&2; exit 1 ;;
esac

# One wrong character. Without the per-share checksum this combines cleanly
# into a wrong key and the only symptom is a vault that will not open.
sh_typo="$(sed -n '1p' "$sh_root/shares" | PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 -c '
import sys
token = sys.stdin.read().strip()
parts = token.split("-")
payload = parts[4]
swap = "B" if payload[0] != "B" else "C"
parts[4] = swap + payload[1:]
mutated = "-".join(parts)
if mutated == token:
    sys.exit("the share was not actually altered")
sys.stdout.write(mutated)
')"
[ -n "$sh_typo" ] || { printf 'could not build a mistyped share\n' >&2; exit 1; }
[ "$sh_typo" != "$(sed -n '1p' "$sh_root/shares")" ] || {
	printf 'the mistyped share is identical to the original\n' >&2; exit 1
}
sh_err="$({ printf '%s\n' "$sh_typo"; sed -n '2p;3p' "$sh_root/shares"; } \
	| core shares-combine "$sh_vault" 2>&1 >/dev/null)" && {
	printf 'a mistyped share was accepted\n' >&2; exit 1
}
case "$sh_err" in
	*transcription*) ;;
	*) printf 'a mistyped share was refused, but not as a transcription error: %s\n' \
		"$sh_err" >&2; exit 1 ;;
esac

# Shares from another vault must be caught before they are combined, and the
# other vault's own complete set must still not open this one.
sh_other="$sh_root/other.gpg"
printf '%s' "$sh_master" | core write "$sh_other" "$sh_plain" >/dev/null
printf '%s' "$sh_master" | core shares-split "$sh_other" 2 3 > "$sh_root/other-out"
sed -n '2,$p' "$sh_root/other-out" > "$sh_root/other-shares"
sh_err="$({ sed -n '1p;2p' "$sh_root/shares"; sed -n '1p' "$sh_root/other-shares"; } \
	| core shares-combine "$sh_vault" 2>&1 >/dev/null)" && {
	printf 'shares from two different sets were combined\n' >&2; exit 1
}
case "$sh_err" in
	*"different sets"*) ;;
	*) printf 'mixed sets were refused for the wrong reason: %s\n' "$sh_err" >&2; exit 1 ;;
esac
sh_err="$(sed -n '1p;2p' "$sh_root/other-shares" \
	| core shares-combine "$sh_vault" 2>&1 >/dev/null)" && {
	printf "another vault's shares opened this vault\n" >&2; exit 1
}
case "$sh_err" in
	*"does not open this vault"*) ;;
	*) printf "another vault's shares were refused for the wrong reason: %s\n" \
		"$sh_err" >&2; exit 1 ;;
esac

# The durability claim, and the reason a share is worth writing on paper: the
# master password changes, the vault key does not.
printf '%s\n%s\n' "$sh_master" "$sh_rotated" | core rewrap "$sh_vault"
printf '%s' "$sh_master" | core read "$sh_vault" "$sh_root/nope" >/dev/null 2>&1 && {
	printf 'the old master password still opens the rotated vault\n' >&2; exit 1
}
sed -n '1p;3p;5p' "$sh_root/shares" | core shares-combine "$sh_vault" > "$sh_root/after"
cmp -s "$sh_root/after" "$sh_root/key" || {
	printf 'the shares stopped working after a master-password change\n' >&2
	exit 1
}

# The vault records that a set exists, and never a share.
sh_status="$(printf '%s' "$sh_rotated" | core shares-status "$sh_vault")"
[ "$(printf '%s' "$sh_status" | cut -f1)" = "$sh_set" ] || {
	printf 'the vault records a different set: %s\n' "$sh_status" >&2; exit 1
}
[ "$(printf '%s' "$sh_status" | cut -f2)" = "3" ] || {
	printf 'the vault records the wrong threshold: %s\n' "$sh_status" >&2; exit 1
}
printf '%s' "$sh_rotated" | core read "$sh_vault" "$sh_root/after-plain" >/dev/null
while IFS= read -r sh_line; do
	[ -n "$sh_line" ] || continue
	if grep -qF "$sh_line" "$sh_root/after-plain"; then
		printf 'a share is stored inside the vault it protects\n' >&2
		exit 1
	fi
done < "$sh_root/shares"
grep -q '^META_RECOVERY_SHARES' "$sh_root/after-plain" || {
	printf 'the vault does not record its share set\n' >&2; exit 1
}
# The set row is metadata, not a record: it must not appear as an entry.
[ "$(grep -c '^[0-9]' "$sh_root/after-plain")" = "1" ] || {
	printf 'the share row was counted as a record\n' >&2; exit 1
}
printf '  shares: 3-of-5 minted, every triple reconstructs, 2 refused, typo and foreign set refused, survives a master change\n'

printf 'CLI regression: wrapped vault key\n'

VK_ROOT="$TEST_ROOT/vaultkey"
mkdir -p "$VK_ROOT"
VK_OLD="VaultKey-Old-Password-1"
VK_NEW="VaultKey-New-Password-2"

# Drive the interactive flows without a terminal. Only the two stty-guarded
# prompts are stubbed; every other line of change-master and forgot runs.
prompt_master_password() { MASTER_PW="$STUB_NEW_MASTER"; }

vk_data_section() { sed -n '/^DATA$/,$p' "$1" | sed '1d'; }
vk_open_data() {
	# Open the DATA block with a vault key, through whichever backend actually
	# sealed the file. Reaching for gpg here would keep passing on a vault gpg
	# cannot read at all: it fails on every input, so proving it fails on this
	# one proves nothing. Reads the key from a file so no secret is in argv.
	PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$1" "$2" \
		"$ROOT_DIR/src/spm_core.py" <<'VKOPENPY'
import importlib.util, sys

spec = importlib.util.spec_from_file_location("spm_core_vk", sys.argv[3])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
key = open(sys.argv[2], encoding="utf-8").read()
try:
    text = core.read_vault_with_key(sys.argv[1], key)
except Exception:
    sys.exit(1)
if text is None:
    sys.exit(1)
sys.stdout.write(text)
VKOPENPY
}
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
	vk_open_data "$VAULT_FILE" "$VK_ROOT/key-a" | grep -q 'DemoSecret42' \
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
	printf '%s' "$recovered" > "$VK_ROOT/key-stale"
	if vk_open_data "$VAULT_FILE" "$VK_ROOT/key-stale" >/dev/null 2>&1; then
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
	vk_open_data "$VAULT_FILE" "$VK_ROOT/key-c" | grep -q 'DemoSecret42' \
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

printf 'Extension regression: the packed extension runs in a browser\n'
# The browser-extension roadmap named this as what the in-field picker waits
# for: "driving an extension under headless Chromium with --load-extension is
# possible and worth revisiting, but it is its own project". It is possible,
# and this is the first half of that project.
#
# Everything else about the extension is asserted at the CLI, where no browser
# is needed. This asserts the part that only a browser can answer: that
# Chromium actually loads it, and that the identity the native-messaging
# registration is written against is the identity the browser assigns.
#
# Skipped, loudly, without Chromium and puppeteer -- CI runners have neither,
# and a skip that reads like a pass is worse than no check at all.
ext_chromium="${CHROMIUM_BIN:-$(command -v chromium || command -v chromium-browser || true)}"
ext_puppeteer="${SPM_PUPPETEER_PATH:-}"
if [ -z "$ext_puppeteer" ] && [ -n "${SPM_PUPPETEER_ROOT:-}" ]; then
	ext_puppeteer="$SPM_PUPPETEER_ROOT/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js"
fi
if [ -z "$ext_chromium" ] || [ ! -x "$ext_chromium" ]; then
	printf '  extension: skipped, no Chromium on this machine\n'
elif [ -z "$ext_puppeteer" ] || [ ! -f "$ext_puppeteer" ]; then
	printf '  extension: skipped, no puppeteer-core (set SPM_PUPPETEER_PATH)\n'
elif ! command -v node >/dev/null 2>&1; then
	printf '  extension: skipped, no node on this machine\n'
else
	ext_dist="$("$ROOT_DIR/browser-extension-universal/build.sh" chromium)"
	ext_id="$("$ROOT_DIR/browser-extension-universal/extension-id.sh")"
	[ -n "$ext_id" ] || { printf 'extension-id.sh produced nothing\n' >&2; exit 1; }
	rm -rf "$TEST_ROOT/ext-profile"
	CHROMIUM_BIN="$ext_chromium" EXT_PROFILE="$TEST_ROOT/ext-profile" \
		EXT_MASTER="$AUDIT_PASSWORD" EXT_SECRET="DemoSecret42" \
		node "$ROOT_DIR/tests/extension-ui.mjs" "$ext_dist" "$ext_id" "$ext_puppeteer"
	# The function that writes a password into someone's login form, driven
	# against a real one. Every way it fails is silent: a field that looks
	# filled and submits empty, a hidden honeypot filled instead of the real
	# box, a value written without the events a framework listens for.
	CHROMIUM_BIN="$ext_chromium" node "$ROOT_DIR/tests/extension-fill.mjs" \
		"$ROOT_DIR/browser-extension-universal/fill.js" \
		"file://$ROOT_DIR/tests/fixtures/login-form.html" "$ext_puppeteer"
fi

# Both extensions inject the same function, and they ship as separate
# directories in the release archive, so the file is copied rather than shared.
# The copy is what needs watching: these two had already drifted, and the
# legacy one assigned element.value directly -- which a framework that owns the
# field swallows, so the form submitted empty while looking filled. That is the
# defect this pair of checks exists to stop coming back.
cmp -s "$ROOT_DIR/browser-extension/fill.js" \
	"$ROOT_DIR/browser-extension-universal/fill.js" || {
	printf 'the two fill.js copies have drifted\n' >&2; exit 1
}
for ext_popup in browser-extension/popup.js browser-extension-universal/popup.js; do
	if grep -q 'func:(' "$ROOT_DIR/$ext_popup"; then
		printf '%s injects an inline function again; it must use spmFillForm\n' \
			"$ext_popup" >&2
		exit 1
	fi
	grep -q 'func:spmFillForm' "$ROOT_DIR/$ext_popup" || {
		printf '%s does not inject the shared fill\n' "$ext_popup" >&2; exit 1
	}
done
printf '  fill: one function, copied to both extensions and identical in each\n'

printf 'Web regression: every password box has a reveal control\n'
# Two properties. Every password input carries the control -- so a box added
# later cannot ship without one -- and in an RTL page the control does not sit
# where the text starts. A password field keeps LTR content in an RTL page, so
# its text begins on the left while the wrapper, still RTL, put the button
# there too, directly over the caret. That is the Arabic search icon of 3.13.0
# happening again, and again it was visible only by rendering the page.
curl -fsS -o "$TEST_ROOT/login-reveal.html" "http://127.0.0.1:$WEB_PORT/login"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/settings-reveal.html" \
	"http://127.0.0.1:$WEB_PORT/settings"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$TEST_ROOT/login-reveal.html" "$TEST_ROOT/settings-reveal.html" <<'REVEALPY'
import re, sys

seen = 0
for path in sys.argv[1:]:
    page = open(path, encoding="utf-8").read()
    for field in re.finditer(r'<input[^>]*type="password"[^>]*>', page, re.S):
        seen += 1
        ident = re.search(r'id="([^"]+)"', field.group(0))
        if not ident:
            sys.exit("a password input in %s has no id to target" % path)
        if not re.search(r'data-act="reveal-input"[^>]*data-target="%s"'
                         % re.escape(ident.group(1)), page):
            sys.exit("password input %r in %s has no reveal control"
                     % (ident.group(1), path))
if seen < 4:
    sys.exit("only %d password inputs were found; the check is not covering them" % seen)

# The rule, parsed rather than grepped: a selector that is merely present but
# narrowed to something no element carries is inert, and a substring search
# cannot tell the two apart.
css = open(sys.argv[1], encoding="utf-8").read()
rule = re.search(r'(?<![\w.#\[-]):root\[dir="rtl"\]\s+\.input-reveal\s*\{([^}]*)\}', css)
if not rule:
    sys.exit("no :root[dir=rtl] .input-reveal rule; the control will sit on the caret")
if not re.search(r'direction\s*:\s*ltr', rule.group(1)):
    sys.exit("the RTL wrapper rule does not force LTR: %s" % rule.group(1).strip())
print("  reveal: %d password inputs, each with a control, and the RTL wrapper "
      "follows its field" % seen)
REVEALPY

printf 'Web regression: hidden entries are redacted by the server\n'
# The whole feature rests on one property: the name is not in the page. A CSS
# blur would satisfy every visual check and leave the name sitting in the
# source, which is a promise the page does not keep -- so what is asserted here
# is the bytes on the wire, not the rendering.
hidden_add_csrf="$(curl -fsS -b "$TEST_ROOT/cookies" "http://127.0.0.1:$WEB_PORT/add" \
	| sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n1)"
[ "${#hidden_add_csrf}" -eq 64 ]
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hidden_add_csrf" \
	--data-urlencode 'name=Lanterna Private' --data-urlencode 'user=burner@example.invalid' \
	--data-urlencode 'password=HiddenSecret42' --data-urlencode 'url=https://lanterna.invalid' \
	--data-urlencode 'folder=Personal' --data-urlencode 'hidden=1' \
	"http://127.0.0.1:$WEB_PORT/add"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/hidden-list.html" \
	"http://127.0.0.1:$WEB_PORT/passwords"
if grep -q 'Lanterna Private' "$TEST_ROOT/hidden-list.html"; then
	printf 'a hidden entry name reached the password list HTML\n' >&2; exit 1
fi
if grep -q 'burner@example.invalid' "$TEST_ROOT/hidden-list.html"; then
	printf 'a hidden entry username reached the password list HTML\n' >&2; exit 1
fi
grep -q 'folder=__hidden__' "$TEST_ROOT/hidden-list.html" || {
	printf 'the Hidden section is not offered once an entry is hidden\n' >&2; exit 1
}
# And it is genuinely reachable, not merely redacted everywhere.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/hidden-section.html" \
	"http://127.0.0.1:$WEB_PORT/passwords?folder=__hidden__"
grep -q 'Lanterna Private' "$TEST_ROOT/hidden-section.html" || {
	printf 'the Hidden section does not show the entry it exists for\n' >&2; exit 1
}

hidden_id="$(PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/src/spm_core.py" "$PASSWORD_VAULT" "$AUDIT_PASSWORD" <<'HIDIDPY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("spm_core_hid", sys.argv[1])
core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
text, _ = core.read_vault(sys.argv[2], sys.argv[3])
for line in text.splitlines():
    parts = line.split("\t")
    if parts[0].isdigit() and parts[1] == "Lanterna Private":
        if core.decode_attrs(parts[7] if len(parts) > 7 else "")[2] is not True:
            sys.exit("the entry was stored without its hidden flag")
        print(parts[0]); break
else:
    sys.exit("the hidden entry was not written to the vault")
HIDIDPY
)"
[ -n "$hidden_id" ]

# The switch reflects what is stored, and clearing it works: a form that posts
# no `hidden` field is a form where the switch was turned off, not one that
# forgot to mention it.
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/hidden-edit.html" \
	"http://127.0.0.1:$WEB_PORT/edit?id=$hidden_id"
# The whole tag, not a line of it: the attribute that matters wraps onto the
# next line, so a line-based grep answers "no" for a switch that is in fact on.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$TEST_ROOT/hidden-edit.html" <<'SWITCHPY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
tag = re.search(r"<input[^>]*id=\"entry-hidden\"[^>]*>", page, re.S)
if not tag:
    sys.exit("the edit form has no hidden switch at all")
if "checked" not in tag.group(0):
    sys.exit("the edit form does not show the entry as hidden: %s" % tag.group(0))
SWITCHPY
hidden_edit_csrf="$(sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' \
	"$TEST_ROOT/hidden-edit.html" | head -n1)"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hidden_edit_csrf" --data-urlencode "id=$hidden_id" \
	--data-urlencode 'name=Lanterna Private' --data-urlencode 'user=burner@example.invalid' \
	--data-urlencode 'password=HiddenSecret42' --data-urlencode 'url=https://lanterna.invalid' \
	--data-urlencode 'folder=Personal' \
	"http://127.0.0.1:$WEB_PORT/edit?id=$hidden_id"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/hidden-after.html" \
	"http://127.0.0.1:$WEB_PORT/passwords"
grep -q 'Lanterna Private' "$TEST_ROOT/hidden-after.html" || {
	printf 'un-hiding an entry did not bring its name back\n' >&2; exit 1
}

# The host list is vault data, not settings data. A plaintext file naming the
# sites someone would rather not name would leak exactly what this protects.
hidden_hosts_csrf="$(curl -fsS -b "$TEST_ROOT/cookies" "http://127.0.0.1:$WEB_PORT/settings" \
	| sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n1)"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" \
	--data-urlencode "csrf=$hidden_hosts_csrf" \
	--data-urlencode 'hosts=lanterna.invalid, vitrine.invalid' \
	"http://127.0.0.1:$WEB_PORT/settings/hidden-hosts"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/src/spm_core.py" "$PASSWORD_VAULT" "$AUDIT_PASSWORD" <<'HOSTSPY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("spm_core_hosts", sys.argv[1])
core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
text, _ = core.read_vault(sys.argv[2], sys.argv[3])
if core.hidden_hosts(text) != ["lanterna.invalid", "vitrine.invalid"]:
    sys.exit("the host list did not reach the vault: %r" % core.hidden_hosts(text))
HOSTSPY
if grep -rqs 'lanterna.invalid' "$TEST_ROOT/config" 2>/dev/null; then
	printf 'the hidden-host list was written to a plaintext settings file\n' >&2; exit 1
fi
printf '  hidden: names never reach the list HTML, the Hidden section shows them, and the host list stays in the vault\n'

printf 'Web regression: the security page names entries and offers an action\n'
# The page used to render findings as bare record ids -- a column of numbers
# that told you something was wrong and nothing about what, with nothing to
# click. Naming the entry is the fix; keeping a hidden entry redacted here is
# the part that has to hold, because otherwise this page is the one place a
# hidden name can be read.
sec_csrf="$(curl -fsS -b "$TEST_ROOT/cookies" "http://127.0.0.1:$WEB_PORT/add" \
	| sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -n1)"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" --data-urlencode "csrf=$sec_csrf" \
	--data-urlencode 'name=Weak And Visible' --data-urlencode 'user=weak@example.invalid' \
	--data-urlencode 'password=abc123' "http://127.0.0.1:$WEB_PORT/add"
curl -fsS -b "$TEST_ROOT/cookies" -o /dev/null -X POST \
	-H "Origin: http://127.0.0.1:$WEB_PORT" --data-urlencode "csrf=$sec_csrf" \
	--data-urlencode 'name=Weak And Hidden' --data-urlencode 'user=quiet@example.invalid' \
	--data-urlencode 'password=abc123' --data-urlencode 'hidden=1' \
	"http://127.0.0.1:$WEB_PORT/add"
curl -fsS -b "$TEST_ROOT/cookies" -o "$TEST_ROOT/security.html" \
	"http://127.0.0.1:$WEB_PORT/security"

grep -q 'Weak And Visible' "$TEST_ROOT/security.html" || {
	printf 'the security page does not name the entry a finding is about\n' >&2; exit 1
}
if grep -q 'Weak And Hidden' "$TEST_ROOT/security.html"; then
	printf 'a hidden entry name reached the security page\n' >&2; exit 1
fi
if grep -q 'abc123' "$TEST_ROOT/security.html"; then
	printf 'a password reached the security page\n' >&2; exit 1
fi
# The action, not just the diagnosis. Every finding row links to the edit form
# for the entry it is about.
sec_weak_id="$(PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/src/spm_core.py" "$PASSWORD_VAULT" "$AUDIT_PASSWORD" <<'SECIDPY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("spm_core_sec", sys.argv[1])
core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
text, _ = core.read_vault(sys.argv[2], sys.argv[3])
for line in text.splitlines():
    parts = line.split("\t")
    if parts[0].isdigit() and parts[1] == "Weak And Visible":
        print(parts[0]); break
else:
    sys.exit("the fixture entry was not written")
SECIDPY
)"
grep -q "/edit?id=$sec_weak_id" "$TEST_ROOT/security.html" || {
	printf 'the security page offers no way to fix the entry it reports\n' >&2; exit 1
}
# The score is a fraction, not a bare number, and says what drove it.
grep -q '/&thinsp;100' "$TEST_ROOT/security.html" || {
	printf 'the security score is shown without its scale\n' >&2; exit 1
}
grep -q 'href="#finding-weak"' "$TEST_ROOT/security.html" || {
	printf 'the tally does not link to the finding it counts\n' >&2; exit 1
}
printf '  security: findings are named and actionable, and a hidden entry stays redacted\n'

printf 'Format regression: every documented format carries every field\n'
# The existing round trip counted records and stopped there, so a format that
# exported ten records and dropped a column still passed. It did: folders and
# custom fields were lost on all twenty CLI round trips, because the CLI export
# never wrote those columns and its import never read them, while the dashboard
# did both. Counting cannot see that. Comparing fields can.
FMT_ROOT="$TEST_ROOT/formats"
mkdir -p "$FMT_ROOT"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$ROOT_DIR/src/spm_core.py" \
	"$FMT_ROOT" "$TEST_RECOVERY_B64" <<'FMTSEEDPY'
import base64, importlib.util, os, sys

spec = importlib.util.spec_from_file_location("spm_core_fmt", sys.argv[1])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
root, pub = sys.argv[2], sys.argv[3]
b64 = lambda v: base64.b64encode(v.encode("utf-8")).decode("ascii")

# Deliberately awkward values: a comma and a doubled quote break naive CSV, a
# tab or a newline splits a vault record, and non-ASCII is where an encoding
# assumption shows up.
attrs = core.encode_attrs("Work/Ops", [("Account number", "12345-678"),
                                       ("PIN", "4821")])
# One record carries the hidden flag, so the round trip proves the column added
# in 4.2.0 survives every format rather than only the ones anyone thought to
# check.
hidden_attrs = core.encode_attrs("Personal", [], True)
rows = [
    "META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-" % pub,
    "1\tAcme Admin\tavery@example.invalid\tp@ss w/ spaces, comma & \"quote\""
    "\tnote with, comma and \"quotes\"\t2025-01-03T09:00:00Z"
    "\thttps://admin.example.invalid/path?q=1&r=2\t%s" % attrs,
    "2\tUnicode Caf\u00e9\tuser+tag@example.invalid\tmot-de-passe-\u00e9"
    "\t\u00fcn\u00efcode notes\t2024-02-10T08:30:00Z"
    "\thttps://second.example.invalid\t",
    "3\tNo Extras\tplain@example.invalid\tsimple123\t-"
    "\t2023-04-12T16:20:00Z\t\t",
    "4\tKept Private\tquiet@example.invalid\tsimple456\t-"
    "\t2023-05-12T16:20:00Z\thttps://third.example.invalid\t%s" % hidden_attrs,
    "NOTE\t1\tIncident checklist\t%s\t2026-08-31T02:15:00Z\t-"
    % b64("line one\nline two\twith tab"),
    "PASSPHRASE\t1\tRecovery phrase\t%s\t2026-08-29T10:00:00Z\t-"
    % b64("orchard copper river"),
    "BACKUP_CODE\t1\tGitHub codes\t%s\t2026-08-25T10:00:00Z\t-"
    % b64("CODE-1\nCODE-2\nCODE-3"),
    "AUTH\t1\tGitHub Demo\tJBSWY3DPEHPK3PXP\t45\t2026-08-27T10:00:00Z\tsha256",
]
core.write_vault(os.path.join(root, "rich.gpg"), "FormatMaster-Rounds!",
                 "\n".join(rows) + "\n")
core.write_vault(os.path.join(root, "empty.gpg"), "FormatMaster-Rounds!",
                 "META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n" % pub)
FMTSEEDPY

(
	set -o errexit -o nounset -o pipefail
	MASTER_PW="FormatMaster-Rounds!"
	VAULT_FILE="$FMT_ROOT/rich.gpg"
	RECOVERY_FILE="$FMT_ROOT/rich.gpg.recovery"
	decrypt_vault_to_file "$FMT_ROOT/plain-source" >/dev/null
	for fmt_name in $formats; do
		cmd_export "$fmt_name" "$FMT_ROOT/export.$fmt_name" >/dev/null
	done
	# Into an empty vault, so the imported records land on the same ids the
	# source used and can be compared record for record. Importing over a copy
	# of the source appends instead, which is what let the old check pass while
	# comparing nothing.
	for fmt_name in $formats; do
		cp "$FMT_ROOT/empty.gpg" "$FMT_ROOT/v-$fmt_name.gpg"
		cp "$FMT_ROOT/empty.gpg.recovery" "$FMT_ROOT/v-$fmt_name.gpg.recovery"
		(
			VAULT_FILE="$FMT_ROOT/v-$fmt_name.gpg"
			RECOVERY_FILE="$FMT_ROOT/v-$fmt_name.gpg.recovery"
			cmd_import "$fmt_name" "$FMT_ROOT/export.$fmt_name" >/dev/null
			decrypt_vault_to_file "$FMT_ROOT/plain-$fmt_name" >/dev/null
		)
	done
)

PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - "$ROOT_DIR/src/spm_core.py" \
	"$FMT_ROOT" $formats <<'FMTCMPPY'
import importlib.util, os, sqlite3, sys

spec = importlib.util.spec_from_file_location("spm_core_fmt_cmp", sys.argv[1])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
root, formats = sys.argv[2], sys.argv[3:]


def load(path):
    records = {}
    with open(path, encoding="utf-8", errors="surrogateescape") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if parts[0].startswith("META_"):
                continue
            if parts[0].isdigit():
                folder, fields, hidden = core.decode_attrs(
                    parts[7] if len(parts) > 7 else "")
                records[("password", parts[0])] = {
                    "label": parts[1], "username": parts[2],
                    "secret": parts[3], "notes": parts[4],
                    "url": parts[6] if len(parts) > 6 else "",
                    "folder": folder, "fields": tuple(fields),
                    "hidden": hidden}
            elif parts[0] in ("NOTE", "PASSPHRASE", "BACKUP_CODE"):
                records[(parts[0], parts[1])] = {
                    "label": parts[2], "body": parts[3]}
            elif parts[0] == "AUTH":
                records[("AUTH", parts[1])] = {
                    "label": parts[2], "secret": parts[3], "period": parts[4],
                    "algorithm": parts[6] if len(parts) > 6 else ""}
    return records


source = load(os.path.join(root, "plain-source"))
problems = []
for fmt in formats:
    path = os.path.join(root, "plain-%s" % fmt)
    if not os.path.exists(path):
        problems.append("%s: nothing was imported" % fmt)
        continue
    got = load(path)
    for key, want in sorted(source.items()):
        have = got.get(key)
        if have is None:
            problems.append("%s: %s/%s did not survive" % ((fmt,) + key))
            continue
        for field, value in sorted(want.items()):
            if have.get(field) != value:
                problems.append("%s: %s/%s %s became %r (was %r)" % (
                    fmt, key[0], key[1], field, have.get(field), value))
    for key in sorted(got):
        if key not in source:
            problems.append("%s: %s/%s appeared from nowhere" % ((fmt,) + key))

# The header names the core's column order, so a column added to an exporter
# without being added to the order is caught here rather than by whichever
# reader silently maps it onto the wrong name.
with open(os.path.join(root, "export.csv"), encoding="utf-8") as handle:
    header = handle.readline().strip().split(",")
if header != list(core.EXPORT_FIELDNAMES):
    problems.append("csv header %r is not the core's column order %r"
                    % (header, list(core.EXPORT_FIELDNAMES)))

# Loaded by a real SQL parser rather than by SPM's own reader. SPM parsed the
# VALUES tuple positionally and ignored the column list, so it read back a file
# that named eight columns while writing nine -- "9 values for 8 columns" to
# anything else, and every export of this format was unusable.
try:
    sqlite3.connect(":memory:").executescript(
        open(os.path.join(root, "export.sql"), encoding="utf-8").read())
except sqlite3.Error as exc:
    problems.append("sqlite refused the sql export: %s" % exc)

if problems:
    for line in problems[:20]:
        sys.stderr.write("  %s\n" % line)
    sys.exit("%d format problem(s)" % len(problems))
print("  formats: %d round-tripped field for field, and the sql export loads "
      "in sqlite" % len(formats))
FMTCMPPY

printf 'Import regression: a review outlives a failed write\n'
# The reviewed rows were cleared before the vault was written, so a full disk
# or a locked vault cost the user the entire upload and review -- for a failure
# that had nothing to do with the confirmation token. Replay and guessing are
# still refused; only the write-failure case changed.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" SPM_VAULT_PATH="$PASSWORD_VAULT" \
	XDG_CONFIG_HOME="$TEST_ROOT/config" python3 - "$web_script" <<'IMPORTPY'
import importlib.util, sys, time

spec = importlib.util.spec_from_file_location("spm_web_import", sys.argv[1])
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)

rows = [("password", ["1", "Example", "user", "secret", "", "", ""])]
session = {}
token = web.stash_pending_import(session, rows, {"passwords": 1}, [])

# A write that fails leaves the review confirmable again.
if web.take_pending_import(session, token) != rows:
    sys.exit("the review did not survive validation")
if web.take_pending_import(session, token) != rows:
    sys.exit("a failed write threw the review away")

# A wrong token still gets exactly one attempt.
try:
    web.take_pending_import(session, "0" * 32)
except ValueError:
    pass
else:
    sys.exit("a mismatched token was accepted")
try:
    web.take_pending_import(session, token)
except ValueError:
    pass
else:
    sys.exit("a review survived a guess at its token")

# A completed import is not replayable.
session = {}
token = web.stash_pending_import(session, rows, {"passwords": 1}, [])
web.take_pending_import(session, token)
web.consume_pending_import(session)
try:
    web.take_pending_import(session, token)
except ValueError:
    pass
else:
    sys.exit("a consumed review was replayable")

# And an expired one is gone whatever happens.
session = {}
token = web.stash_pending_import(session, rows, {"passwords": 1}, [])
session["pending_import"]["at"] = time.time() - web.PENDING_IMPORT_TTL - 1
try:
    web.take_pending_import(session, token)
except ValueError:
    pass
else:
    sys.exit("an expired review was still confirmable")
if session["pending_import"] is not None:
    sys.exit("an expired review was left in the session")
print("  import: a review survives a failed write, and still refuses replay, "
      "guessing and expiry")
IMPORTPY

printf 'Restore regression: replacing a vault is verified and undoable\n'
# Bundle restore was the one write in SPM that could not be undone. It copied
# whatever the bundle held over the live vault with no archive, no .bak and no
# check that the bundle even opened -- so restoring a truncated USB copy
# destroyed a working vault and produced one that opened nothing. It also held
# the bundle's lock rather than the destination's, leaving the file it was
# about to overwrite unprotected against a concurrent dashboard write.
RESTORE_ROOT="$TEST_ROOT/restore"
mkdir -p "$RESTORE_ROOT/home" "$RESTORE_ROOT/bundle" "$RESTORE_ROOT/empty-home"
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/src/spm_core.py" "$RESTORE_ROOT" "$TEST_RECOVERY_B64" <<'RESTOREPY'
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location("spm_core_restore", sys.argv[1])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
root, pub = sys.argv[2], sys.argv[3]

def build(path, master, marker):
    core.write_vault(path, master, (
        "META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n"
        "1\t%s\tuser\tsecret-%s\t-\t2025-01-01T00:00:00Z\n") % (pub, marker, marker))

build(os.path.join(root, "home", ".spm_vault.gpg"), "LiveMaster-Restore!", "LIVE")
build(os.path.join(root, "bundle", "spm_vault.gpg"), "BundleMaster-Restore!", "BUNDLE")
RESTOREPY

restore_drive() {
	# Sourced in a subshell with HOME pointed at the destination, which is what
	# cmd_restore reads to find the vault it replaces.
	(
		set -o errexit -o nounset -o pipefail
		export HOME="$1"; shift
		export SPM_LANG=en
		cd "$RESTORE_ROOT/bundle"
		VAULT_FILE="./spm_vault.gpg"
		RECOVERY_FILE="./spm_vault.gpg.recovery"
		MASTER_PW=""
		cmd_restore
	)
}

cp "$RESTORE_ROOT/bundle/spm_vault.gpg" "$RESTORE_ROOT/bundle-vault.keep"
cp "$RESTORE_ROOT/bundle/spm_vault.gpg.recovery" "$RESTORE_ROOT/bundle-recovery.keep"
restore_live_before="$(sha256sum "$RESTORE_ROOT/home/.spm_vault.gpg" | awk '{print $1}')"

# --- a bundle that does not open must not replace one that does -------------
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$RESTORE_ROOT/bundle/spm_vault.gpg" <<'CORRUPTPY'
import base64, sys
raw = open(sys.argv[1], "rb").read()
head, data = raw.split(b"\nDATA\n", 1)
blob = bytearray(base64.b64decode(data))
blob[40] ^= 1
open(sys.argv[1], "wb").write(head + b"\nDATA\n" + base64.b64encode(bytes(blob)) + b"\n")
CORRUPTPY
if printf 'yes\nBundleMaster-Restore!\n' \
	| restore_drive "$RESTORE_ROOT/home" >"$TEST_ROOT/restore-refused.txt" 2>&1; then
	printf 'restore installed a bundle that does not open\n' >&2; exit 1
fi
grep -q 'left untouched' "$TEST_ROOT/restore-refused.txt" || {
	printf 'a refused restore did not say the existing vault was kept:\n' >&2
	sed 's/^/    /' "$TEST_ROOT/restore-refused.txt" >&2; exit 1
}
[ "$(sha256sum "$RESTORE_ROOT/home/.spm_vault.gpg" | awk '{print $1}')" = "$restore_live_before" ] || {
	printf 'a refused restore still replaced the live vault\n' >&2; exit 1
}
[ -f "$RESTORE_ROOT/bundle/spm_vault.gpg" ] || {
	printf 'a refused restore consumed the bundle anyway\n' >&2; exit 1
}
[ ! -e "$RESTORE_ROOT/home/.spm_vault.gpg.bak" ] || {
	printf 'a refused restore left a .bak of a vault it never replaced\n' >&2; exit 1
}

# --- a good bundle replaces it, and the replaced vault stays recoverable -----
cp "$RESTORE_ROOT/bundle-vault.keep" "$RESTORE_ROOT/bundle/spm_vault.gpg"
restore_bundle_sha="$(sha256sum "$RESTORE_ROOT/bundle/spm_vault.gpg" | awk '{print $1}')"
printf 'yes\nBundleMaster-Restore!\nyes\n' \
	| restore_drive "$RESTORE_ROOT/home" >"$TEST_ROOT/restore-ok.txt" 2>&1
[ "$(sha256sum "$RESTORE_ROOT/home/.spm_vault.gpg" | awk '{print $1}')" = "$restore_bundle_sha" ] || {
	printf 'the bundle vault was not installed\n' >&2; exit 1
}
[ "$(sha256sum "$RESTORE_ROOT/home/.spm_vault.gpg.bak" | awk '{print $1}')" = "$restore_live_before" ] || {
	printf 'the replaced vault was not kept as .bak\n' >&2; exit 1
}
[ -f "$RESTORE_ROOT/home/.spm_vault.gpg.recovery.bak" ] || {
	printf 'the replaced recovery file was not kept as .bak\n' >&2; exit 1
}
# Asked of the core rather than guessed at: where a snapshot lands depends on
# SPM_DATA_DIR and XDG_DATA_HOME, and a hardcoded path passes by being wrong in
# the same direction as the bug it is meant to catch.
restore_history="$(HOME="$RESTORE_ROOT/home" python3 "$ROOT_DIR/src/spm_core.py" \
	history-dir "$RESTORE_ROOT/home/.spm_vault.gpg")"
[ -n "$(find "$restore_history" -name '*.gpg' -print 2>/dev/null | head -n1)" ] || {
	printf 'the replaced generation was not archived (looked in %s)\n' \
		"$restore_history" >&2
	exit 1
}
[ ! -f "$RESTORE_ROOT/bundle/spm_vault.gpg" ] || {
	printf 'a completed restore left the vault in the bundle\n' >&2; exit 1
}
# The installed vault opens under the bundle's password, not the one it replaced.
PYTHONPYCACHEPREFIX="$TEST_ROOT/pycache" python3 - \
	"$ROOT_DIR/src/spm_core.py" "$RESTORE_ROOT/home/.spm_vault.gpg" <<'OPENPY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("spm_core_open", sys.argv[1])
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
text, _ = core.read_vault(sys.argv[2], "BundleMaster-Restore!")
if "secret-BUNDLE" not in text:
    sys.exit("the restored vault is not the one from the bundle")
try:
    core.read_vault(sys.argv[2], "LiveMaster-Restore!")
except core.VaultSecretError:
    pass
else:
    sys.exit("the replaced vault's password still opens what replaced it")
OPENPY

# --- with nothing at the destination, no password is demanded ---------------
# The check exists to protect a vault that is already there. Onto an empty
# machine it protects nothing, and demanding a password would break staging a
# bundle for someone else to open later.
cp "$RESTORE_ROOT/bundle-vault.keep" "$RESTORE_ROOT/bundle/spm_vault.gpg"
cp "$RESTORE_ROOT/bundle-recovery.keep" "$RESTORE_ROOT/bundle/spm_vault.gpg.recovery"
restore_drive "$RESTORE_ROOT/empty-home" </dev/null >"$TEST_ROOT/restore-empty.txt" 2>&1
[ "$(sha256sum "$RESTORE_ROOT/empty-home/.spm_vault.gpg" | awk '{print $1}')" = "$restore_bundle_sha" ] || {
	printf 'restoring onto an empty destination did not install the vault\n' >&2; exit 1
}
# `if`, never `... && { exit 1; }`: the latter makes the whole compound return
# 1 on the passing path, which errexit turns into a suite abort.
if grep -qi 'master password' "$TEST_ROOT/restore-empty.txt"; then
	printf 'restoring onto an empty destination asked for a password\n' >&2; exit 1
fi
printf '  restore: a bundle that will not open is refused; the replaced vault survives as .bak and a snapshot\n'

printf 'SPM regression suite passed (%s formats plus web and advanced features).\n' \
	"$(printf '%s\n' "$formats" | awk '{ print NF }')"

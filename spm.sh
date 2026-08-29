#!/usr/bin/env bash
# Sans Password Manager (SPM)
# Portable Bash + GPG password manager with encrypted vault.
# Dependencies: bash, gpg, openssl, base64, curl (for update)
# Copyright 2025-2026 Sansyourways and contributors
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

VERSION="3.4.3"

# ----- Repo info for update check --------------------------------------------

# Adjust these to match your GitHub repo
REPO_OWNER="sansyourways"
REPO_NAME="Sans_Password_Manager"
REPO_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

# Global master password (in-memory only, per process)
MASTER_PW=""
VAULT_KEY=""
# Registry of temp files holding decrypted vault material.
# A file (not an array) because make_tmp is called via $(...) subshells,
# whose variable writes would be discarded. Wiped by cleanup() on any exit.
# Deliberately not "${TMPDIR:-/tmp}/.spm_tmpreg.$$": that path is guessable, and
# cleanup() feeds every line of this file to shred. A local user who pre-created
# it chose which files SPM destroyed. mktemp gives an unpredictable name and
# fails if it somehow exists. Created here rather than on first use because
# make_tmp runs inside command substitution, where an assignment would be lost.
SPM_TMP_REGISTRY="$(mktemp "${TMPDIR:-/tmp}/.spm_tmpreg.XXXXXX" 2>/dev/null)" || SPM_TMP_REGISTRY=""
if [ -n "$SPM_TMP_REGISTRY" ]; then
	chmod 600 "$SPM_TMP_REGISTRY" 2>/dev/null || true
fi
# Language: en / id (can be pre-set via env SPM_LANG)
SPM_LANG="${SPM_LANG:-}"

# Environment detection / package manager
ENV_FLAVOR=""   # termux / linux / macos / other
PKG_TYPE=""     # pkg / apt / pacman / dnf / apk / brew / none

# ----- Script + vault path detection -----------------------------------------

# Try to resolve the script path for copying into portable/save bundles.
SCRIPT_SRC="$0"
if [ ! -f "$SCRIPT_SRC" ]; then
	if command -v "$0" >/dev/null 2>&1; then
		SCRIPT_SRC="$(command -v "$0")"
	fi
fi

DEFAULT_VAULT_PATH="$HOME/.spm_vault.gpg"
SPM_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/spm"
SPM_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/spm"
SPM_PROFILE_FILE="$SPM_CONFIG_DIR/vaults.tsv"
SPM_DEFAULT_PROFILE_FILE="$SPM_CONFIG_DIR/default-profile"
SPM_AUTOUPDATE_FILE="$SPM_CONFIG_DIR/auto-update.conf"

if [ -z "${SPM_VAULT_PROFILE:-}" ] && [ -f "$SPM_DEFAULT_PROFILE_FILE" ]; then
	IFS= read -r SPM_VAULT_PROFILE < "$SPM_DEFAULT_PROFILE_FILE" || SPM_VAULT_PROFILE=""
fi

profile_vault_path() {
	local profile="$1"
	[ -f "$SPM_PROFILE_FILE" ] || return 1
	awk -F '\t' -v name="$profile" '$1 == name { print $2; found=1; exit } END { if (!found) exit 1 }' "$SPM_PROFILE_FILE"
}

# Vault resolution logic:
# 1) If PASSWORD_VAULT is set → use it
# 2) Else if ./spm_vault.gpg exists → use it (portable bundle case)
# 3) Else → use ~/.spm_vault.gpg
if [ -n "${PASSWORD_VAULT:-}" ]; then
	VAULT_FILE="$PASSWORD_VAULT"
elif [ -n "${SPM_VAULT_PROFILE:-}" ]; then
	VAULT_FILE="$(profile_vault_path "$SPM_VAULT_PROFILE")" || {
		printf "Unknown vault profile: %s\n" "$SPM_VAULT_PROFILE" >&2
		exit 1
	}
elif [ -f "./spm_vault.gpg" ]; then
	VAULT_FILE="./spm_vault.gpg"
else
	VAULT_FILE="$DEFAULT_VAULT_PATH"
fi

# Recovery-related paths (per vault)
RECOVERY_FILE="${VAULT_FILE}.recovery"
# Private key now always generated in the current working directory
RECOVERY_PRIV_DEFAULT="./spm_recovery_private.pem"

# Use $EDITOR or fallback
EDITOR_CMD="${EDITOR:-nano}"

# ----- Utility helpers --------------------------------------------------------

die() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found. Install it first."
}

now_iso() {
	if date -u +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
		date -u +"%Y-%m-%dT%H:%M:%SZ"
	else
		date
	fi
}

# Vault records are TAB-delimited, one line each. A field carrying a raw TAB or
# newline silently splits the record: a password pasted with a TAB used to be
# stored whole but read back truncated at the TAB, with the remainder bleeding
# into the next column. Collapse both to a space before any field is written.
sanitize_field() {
	# Collapse every character Python's splitlines() honours, not just the three
	# ASCII ones: the web server reads this vault back with splitlines(), so a
	# field holding U+2028 was written here and silently split there.
	printf '%s' "$1" \
		| tr '\t\r\n\v\f\034\035\036' '        ' \
		| sed 's/\xc2\x85/ /g; s/\xe2\x80\xa8/ /g; s/\xe2\x80\xa9/ /g'
}

sanitize_url() {
	# The URL field is the one vault field that becomes a clickable link in Web
	# Mode and, later, an auto-fill target for the browser extension. Both make
	# a non-http(s) scheme dangerous -- "javascript:" in a rendered href, or a
	# "data:" document the extension would treat as a login origin -- so the
	# scheme is an allowlist rather than a denylist. An empty value is valid:
	# the field is optional and always has been.
	local raw
	raw="$(sanitize_field "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
	[ -n "$raw" ] || { printf ''; return 0; }
	if ! printf '%s' "$raw" | grep -Eqi '^https?://[^[:space:]/]+'; then
		return 1
	fi
	printf '%s' "$raw"
}

validate_bundle_name() {
	local name="$1"
	case "$name" in
		""|.|..|-*|*/*|*\\*) die "Invalid bundle name. Use a simple file name without slashes or leading dashes." ;;
	esac
	# Reject control characters; they make archive names and cleanup targets
	# ambiguous even when shell quoting is otherwise correct.
	if printf '%s' "$name" | LC_ALL=C grep -q '[[:cntrl:]]'; then
		die "Invalid bundle name. Control characters are not allowed."
	fi
}

# Octal permission bits for a file, or empty if they cannot be read.
# GNU coreutils and BSD/macOS stat disagree on the flag, so try both.
file_mode() {
	local f="$1"
	stat -c '%a' "$f" 2>/dev/null && return 0
	stat -f '%Lp' "$f" 2>/dev/null && return 0
	printf ''
}

# True when a mode grants any group or other bit, i.e. anything but 0x00.
# Handles both 3-digit (600) and 4-digit (0600) stat output.
mode_is_exposed() {
	local mode="$1"
	[ -n "$mode" ] || return 1
	[ "${mode: -2}" != "00" ]
}

# Resolve a path to its canonical absolute form so the same file reached by two
# different paths is not audited (or reported) twice.
canon_path() {
	local p="$1"
	realpath "$p" 2>/dev/null && return 0
	readlink -f "$p" 2>/dev/null && return 0
	# Older macOS has neither; fall back to a subshell cd so the caller still
	# gets an absolute path and this function never changes our own cwd.
	local d b
	d="$(dirname "$p")"
	b="$(basename "$p")"
	( cd "$d" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$b" ) 2>/dev/null && return 0
	printf '%s\n' "$p"
}

# Every sensitive file 'doctor' should audit, one per line, de-duplicated.
#
# RECOVERY_PRIV_DEFAULT is cwd-relative by design (the key is generated in
# whatever directory you ran 'init' from), so checking only that path lets an
# exposed key in another directory pass unnoticed: run from $HOME and doctor
# reports OK while a world-readable copy sits in the project folder. Look in
# the cwd, alongside the vault, next to the script, and anywhere shallow
# under $HOME, matching the same glob .gitignore uses so renamed or spare
# keys are caught too.
sensitive_files() {
	local vault_dir script_dir d g p
	vault_dir="$(dirname "$VAULT_FILE")"
	script_dir="$(dirname "$0")"
	{
		printf '%s\n' "$VAULT_FILE" "${VAULT_FILE}.bak" "$RECOVERY_FILE"
		# The cwd and the vault's directory may sit outside $HOME entirely
		# (portable bundle on removable media), so check them explicitly.
		for d in "." "$vault_dir" "$script_dir"; do
			for g in "$d"/spm_recovery_private*.pem; do
				if [ -f "$g" ]; then
					printf '%s\n' "$g"
				fi
			done
		done
		# Copies of the key get left behind in project folders and backup
		# directories, where a directory-list check would never look. Bounded
		# depth keeps this well under a second on a normal home directory.
		find "$HOME" -maxdepth 4 -type f -name 'spm_recovery_private*.pem' 2>/dev/null || true
	} | while IFS= read -r p; do
		[ -f "$p" ] || continue
		printf '%s\t%s\n' "$(canon_path "$p")" "$p"
	done | awk -F '\t' '!seen[$1]++ { print $2 }'
}

make_tmp() {
	require_cmd mktemp
	local tmp
	[ -n "${SPM_TMP_REGISTRY:-}" ] || die "Temporary-file registry is unavailable; refusing to write decrypted data."
	tmp="$(mktemp "${TMPDIR:-/tmp}/spm.XXXXXX")"
	chmod 600 "$tmp" 2>/dev/null || true
	printf '%s\n' "$tmp" >>"$SPM_TMP_REGISTRY" 2>/dev/null || true
	printf '%s\n' "$tmp"
}

secure_wipe() {
	local f="$1"
	[ -f "$f" ] || return 0

	if command -v shred >/dev/null 2>&1; then
		shred -u "$f" || rm -f "$f" || true
	else
		rm -f "$f" || true
	fi
}

print_banner() {
	cat <<'EOF'

      *******            ***** **         *****   **    **
    *       ***       ******  ****     ******  ***** *****
   *         **      **   *  *  ***   **   *  *  ***** *****
   **        *      *    *  *    *** *    *  *   * **  * **
    ***                 *  *      **     *  *    *     *
   ** ***              ** **      **    ** **    *     *
    *** ***            ** **      **    ** **    *     *
      *** ***        **** **      *     ** **    *     *
        *** ***     * *** **     *      ** **    *     *
          ** ***       ** *******       ** **    *     **
           ** **       ** ******        *  **    *     **
            * *        ** **               *     *      **
  ***        *         ** **           ****      *      **
 *  *********          ** **          *  *****           **
*     *****       **   ** **         *     **
*                ***   *  *          *
 **               ***    *            **
                   ******
                     ***

EOF
	local year
	year="$(date +%Y 2>/dev/null || echo "2025")"
	printf "Sans Password Manager (SPM)  v%s  \u00a9 %s Sansyourways and contributors · Apache-2.0\n\n" "$VERSION" "$year"
}

pause_menu() {
	if [ "${SPM_LANG}" = "id" ]; then
		printf '\nTekan Enter untuk kembali ke menu...'
	else
		printf '\nPress Enter to return to menu...'
	fi
	read -r _ || true
}

cleanup() {
	if [ -n "${MASTER_PW:-}" ]; then
		MASTER_PW="$(printf '%*s' "${#MASTER_PW}" '' | tr ' ' 'X')"
	fi
	unset MASTER_PW 2>/dev/null || true
	if [ -n "${VAULT_KEY:-}" ]; then
		VAULT_KEY="$(printf '%*s' "${#VAULT_KEY}" '' | tr ' ' 'X')"
	fi
	unset VAULT_KEY 2>/dev/null || true

	# Never leave decrypted vault material behind, even on error or interrupt.
	if [ -n "${SPM_TMP_REGISTRY:-}" ] && [ -f "$SPM_TMP_REGISTRY" ]; then
		local f
		while IFS= read -r f; do
			[ -n "$f" ] && secure_wipe "$f"
		done <"$SPM_TMP_REGISTRY"
		rm -f "$SPM_TMP_REGISTRY" 2>/dev/null || true
	fi

	# Restore terminal echo in case we died inside a hidden prompt.
	if [ -t 0 ]; then
		stty echo 2>/dev/null || true
	fi
}

# Ctrl-C must abort the operation, not fall through with a wiped master password.
on_interrupt() {
	trap - INT
	cleanup
	printf '\n' >&2
	exit 130
}

# SIGTERM/SIGHUP do not run the EXIT trap on their own, so handle them
# explicitly or a killed process would strand a decrypted vault on disk.
on_terminate() {
	trap - TERM HUP
	cleanup
	exit 143
}

trap cleanup EXIT
trap on_interrupt INT
trap on_terminate TERM HUP

# ----- Environment & auto-install -------------------------------------------

detect_env() {
	if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux/files/usr" ]; then
		ENV_FLAVOR="termux"
		PKG_TYPE="pkg"
		return
	fi

	local uname_s
	uname_s="$(uname -s 2>/dev/null || echo "Unknown")"

	case "$uname_s" in
		Darwin)
			ENV_FLAVOR="macos"
			if command -v brew >/dev/null 2>&1; then
				PKG_TYPE="brew"
			else
				PKG_TYPE="none"
			fi
			;;
		Linux)
			ENV_FLAVOR="linux"
			if command -v apt-get >/dev/null 2>&1; then
				PKG_TYPE="apt"
			elif command -v pacman >/dev/null 2>&1; then
				PKG_TYPE="pacman"
			elif command -v dnf >/dev/null 2>&1; then
				PKG_TYPE="dnf"
			elif command -v apk >/dev/null 2>&1; then
				PKG_TYPE="apk"
			else
				PKG_TYPE="none"
			fi
			;;
		*)
			ENV_FLAVOR="other"
			PKG_TYPE="none"
			;;
	esac
}

install_tool() {
	local tool="$1"
	local candidates="$tool"
	local rc=1

	case "$tool" in
		gpg) candidates="gpg gnupg gnupg2" ;;
		openssl) candidates="openssl" ;;
		curl) candidates="curl" ;;
		zip) candidates="zip" ;;
		xclip) candidates="xclip" ;;
		wl-copy) candidates="wl-clipboard" ;;
		termux-clipboard-set) candidates="termux-api" ;;
		python3) candidates="python3 python" ;;
	esac

	set +e
	for pkg in $candidates; do
		case "$PKG_TYPE" in
			pkg)
				pkg install -y "$pkg" >/dev/null 2>&1
				rc=$?
				;;
			apt)
				if command -v sudo >/dev/null 2>&1; then
					sudo apt-get install -y "$pkg" >/dev/null 2>&1
				else
					apt-get install -y "$pkg" >/dev/null 2>&1
				fi
				rc=$?
				;;
			pacman)
				if command -v sudo >/dev/null 2>&1; then
					sudo pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1
				else
					pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1
				fi
				rc=$?
				;;
			dnf)
				if command -v sudo >/dev/null 2>&1; then
					sudo dnf install -y "$pkg" >/dev/null 2>&1
				else
					dnf install -y "$pkg" >/dev/null 2>&1
				fi
				rc=$?
				;;
			apk)
				if command -v sudo >/dev/null 2>&1; then
					sudo apk add "$pkg" >/dev/null 2>&1
				else
					apk add "$pkg" >/dev/null 2>&1
				fi
				rc=$?
				;;
			brew)
				brew install "$pkg" >/dev/null 2>&1
				rc=$?
				;;
			*)
				rc=1
				;;
		esac
		if [ "$rc" -eq 0 ]; then
			break
		fi
	done
	set -e
	return "$rc"
}

loading_line() {
	local msg="$1"
	printf "%s" "$msg"
	for _ in 1 2 3; do
		printf "."
		sleep 0.15
	done
	printf "\n"
}

install_clipboard_helpers() {
	printf "\n"
	if [ "$SPM_LANG" = "id" ]; then
		printf "Pemeriksaan helper clipboard (opsional, untuk auto-copy & auto-clean):\n"
	else
		printf "Checking clipboard helpers (optional, for auto-copy & auto-clean):\n"
	fi

	if command -v pbcopy >/dev/null 2>&1; then
		printf "  [\033[0;32m✔\033[0m] pbcopy (macOS clipboard)\n"
	fi

	if [ "$ENV_FLAVOR" = "termux" ]; then
		printf "  [ ] termux-clipboard-set - checking/installing...\n"
		if command -v termux-clipboard-set >/dev/null 2>&1; then
			printf "\r  [\033[0;32m✔\033[0m] termux-clipboard-set available\n"
		else
			if install_tool "termux-clipboard-set"; then
				if command -v termux-clipboard-set >/dev/null 2>&1; then
					printf "\r  [\033[0;32m✔\033[0m] termux-clipboard-set installed\n"
				else
					printf "\r  [\033[0;31m✖\033[0m] termux-clipboard-set install ok but command not found\n"
				fi
			else
				printf "\r  [\033[0;31m✖\033[0m] termux-clipboard-set install failed\n"
			fi
		fi
	fi

	local opt_tools=("xclip" "wl-copy")
	local t
	for t in "${opt_tools[@]}"; do
		printf "  [ ] %-16s - checking/installing..." "$t"
		if command -v "$t" >/dev/null 2>&1; then
			printf "\r  [\033[0;32m✔\033[0m] %-16s - available          \n" "$t"
		else
			if [ "$PKG_TYPE" != "none" ]; then
				if install_tool "$t"; then
					if command -v "$t" >/dev/null 2>&1; then
						printf "\r  [\033[0;32m✔\033[0m] %-16s - installed           \n" "$t"
					else
						printf "\r  [\033[0;31m✖\033[0m] %-16s - install ok but not found\n" "$t"
					fi
				else
					printf "\r  [\033[0;31m✖\033[0m] %-16s - install failed       \n" "$t"
				fi
			else
				printf "\r  [\033[0;31m✖\033[0m] %-16s - no package manager   \n" "$t"
			fi
		fi
	done
	printf "\n"
}

ensure_requirements() {
	detect_env

	clear
	print_banner

	printf "Environment check\n"
	printf "  Detected environment : %s\n" "${ENV_FLAVOR:-unknown}"
	printf "  Package manager type : %s\n\n" "${PKG_TYPE:-none}"

	loading_line "Checking and installing required tools"

	local tools=("gpg" "openssl" "curl" "zip")
	local t

	for t in "${tools[@]}"; do
		printf "  [ ] %-8s - checking..." "$t"
		sleep 0.1

		if command -v "$t" >/dev/null 2>&1; then
			printf "\r  [\033[0;32m✔\033[0m] %-8s - available     \n" "$t"
			continue
		fi

		if [ "$PKG_TYPE" = "none" ]; then
			printf "\r  [\033[0;31m✖\033[0m] %-8s - missing (no package manager detected)\n" "$t"
		else
			printf "\r  [ ] %-8s - installing..." "$t"
			if install_tool "$t"; then
				if command -v "$t" >/dev/null 2>&1; then
					printf "\r  [\033[0;32m✔\033[0m] %-8s - installed      \n" "$t"
				else
					printf "\r  [\033[0;31m✖\033[0m] %-8s - install ok but command not found\n" "$t"
				fi
			else
				printf "\r  [\033[0;31m✖\033[0m] %-8s - install failed, please install manually\n" "$t"
			fi
		fi
		sleep 0.1
	done

	for t in "${tools[@]}"; do
		if ! command -v "$t" >/dev/null 2>&1; then
			printf "\nRequired tool '%s' is still missing. Please install it manually and rerun SPM.\n" "$t"
			exit 1
		fi
	done

	install_clipboard_helpers

	printf "\n"
	loading_line "Preparing language selection"
	sleep 0.2
	clear
}

choose_language() {
	if [ -n "${SPM_LANG}" ]; then
		case "$SPM_LANG" in
			id|ID) SPM_LANG="id" ;;
			*) SPM_LANG="en" ;;
		esac
		return
	fi

	print_banner
	printf "Language? (en/id) [default: en]: "
	read -r lang_in || true

	case "$lang_in" in
		id|ID|2)
			SPM_LANG="id"
			;;
		*)
			SPM_LANG="en"
			;;
	esac
}

# ----- Terms & Privacy Consent ----------------------------------------------

ensure_policy_consent() {
	# You can change this to be per-project if you want, but HOME-based is simple & portable
	SPM_CONSENT_FILE="${HOME}/.spm_spm_consent"

	# If already accepted, just return
	if [ -f "$SPM_CONSENT_FILE" ]; then
		if grep -q '^ACCEPTED=1' "$SPM_CONSENT_FILE" 2>/dev/null; then
			return
		fi
	fi

	clear
	print_banner

	if [ "$SPM_LANG" = "id" ]; then
		cat <<'EOF'
[PERJANJIAN PENGGUNA]

Sebelum menggunakan Sans Password Manager (SPM), kamu harus
menyetujui:

  • Syarat & Ketentuan Layanan (Terms & Conditions)
  • Kebijakan Privasi (Privacy Policy)

Dokumen resmi:
  • TERMS & CONDITIONS:
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/TERMS_AND_CONDITIONS.md

  • PRIVACY POLICY:
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/PRIVACY_POLICY.md

Silakan baca dokumen tersebut di browser kamu.

Tanpa persetujuan, kamu tidak dapat menggunakan aplikasi ini.

Apakah kamu sudah membaca dan SETUJU dengan
Syarat & Ketentuan + Kebijakan Privasi di atas?
Ketik: yes / y / ya untuk menyetujui.
EOF
		printf "\nJawaban (yes/ya/y atau lainnya untuk TIDAK): "
	else
		cat <<'EOF'
[USER AGREEMENT]

Before using Sans Password Manager (SPM), you must agree to:

  • Terms & Conditions of Service
  • Privacy Policy

Official documents:
  • TERMS & CONDITIONS:
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/TERMS_AND_CONDITIONS.md

  • PRIVACY POLICY:
    https://github.com/sansyourways/Sans_Password_Manager/blob/main/docs/PRIVACY_POLICY.md

Please open and read these documents in your browser.

Without your consent, you cannot use this application.

Have you read and do you AGREE to the Terms & Conditions
and Privacy Policy above?
Type: yes / y to accept.
EOF
		printf "\nAnswer (yes/y to accept, anything else to decline): "
	fi

	read -r ans || ans=""

	# Normalize to lowercase
	ans_lc=$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')

	if [ "$ans_lc" = "yes" ] || [ "$ans_lc" = "y" ] || [ "$ans_lc" = "ya" ]; then
		# Record consent
		{
			printf 'ACCEPTED=1\n'
			printf 'DATE_UTC=%s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date)"
			printf 'VERSION=%s\n' "$VERSION"
			printf 'LANG=%s\n' "$SPM_LANG"
		} > "$SPM_CONSENT_FILE" 2>/dev/null || true

		if [ "$SPM_LANG" = "id" ]; then
			printf "\nTerima kasih. Persetujuan tersimpan. Melanjutkan...\n"
		else
			printf "\nThank you. Consent recorded. Continuing...\n"
		fi
		sleep 1
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nKamu tidak menyetujui Terms & Privacy.\n"
			printf "Aplikasi tidak dapat digunakan tanpa persetujuan.\n"
		else
			printf "\nYou did not accept the Terms & Privacy.\n"
			printf "The application cannot be used without consent.\n"
		fi
		exit 1
	fi
}

# ----- Master password handling ----------------------------------------------

prompt_master_password() {
	local pw1 pw2
	if [ "$SPM_LANG" = "id" ]; then
		printf 'Kata sandi utama: '
	else
		printf 'Master password: '
	fi
	stty -echo
	IFS= read -r pw1
	stty echo
	printf '\n'

	if [ "$SPM_LANG" = "id" ]; then
		printf 'Konfirmasi kata sandi utama: '
	else
		printf 'Confirm master password: '
	fi
	stty -echo
	IFS= read -r pw2
	stty echo
	printf '\n'

	[ "$pw1" = "$pw2" ] || die "Master passwords do not match / Kata sandi utama tidak sama."

	MASTER_PW="$pw1"
}

read_master_password_once() {
	# The prompt goes to stderr, not stdout. A command whose stdout is a
	# document -- `doctor --json`, and anything machine-readable added after it
	# -- would otherwise hand its caller a prompt in the middle of the payload,
	# which is the bug 3.4.1 shipped. An interactive user sees no difference:
	# stderr is the same terminal.
	if [ "$SPM_LANG" = "id" ]; then
		printf 'Kata sandi utama: ' >&2
	else
		printf 'Master password: ' >&2
	fi
	# stty fails when stdin is not a terminal, which is the normal case for a
	# piped password. The read still works, so that failure is not fatal and
	# its complaint does not belong on the user's screen.
	stty -echo 2>/dev/null || true
	IFS= read -r MASTER_PW
	stty echo 2>/dev/null || true
	printf '\n' >&2
}

ensure_master_password_loaded() {
	if [ -z "${MASTER_PW:-}" ]; then
		read_master_password_once
	fi
}

re_verify_master_password() {
	# If master password is not yet loaded, capture it once (counts as verification)
	if [ -z "${MASTER_PW:-}" ]; then
		read_master_password_once
		return
	fi

	local entered_pw
	if [ "$SPM_LANG" = "id" ]; then
		printf 'Masukkan kata sandi utama untuk verifikasi: '
	else
		printf 'Enter master password for verification: '
	fi
	stty -echo
	IFS= read -r entered_pw
	stty echo
	printf '\n'

	if [ "$entered_pw" != "$MASTER_PW" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			die "Verifikasi kata sandi utama gagal."
		else
			die "Master password verification failed."
		fi
	fi
	# Securely wipe the entered password from local variable
	entered_pw="$(printf '%*s' "${#entered_pw}" '' | tr ' ' 'X')"
	unset entered_pw 2>/dev/null || true
}

# ----- GPG encrypt / decrypt wrapper -----------------------------------------

# ----- The trusted core ------------------------------------------------------
# Everything that decides how a vault is protected -- the container format, key
# wrapping, version stamping, vault mutation, history archiving and the recovery
# file -- lives in one reviewable Python module and nowhere else. This half of
# SPM and the SPM Dashboard both reach it rather than each carrying a copy: the
# two used to, and a regression test existed purely to prove the copies still
# agreed, which is a test a shared implementation does not need.
#
# Secrets reach it on stdin, never in argv, because argv is world-readable
# through `ps` and /proc/<pid>/cmdline.

SPM_CORE_PATH=""

ensure_core_script() {
	require_cmd python3
	local base_dir
	base_dir="${1:-${SPM_CORE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/spm}}"
	mkdir -p "$base_dir" || die "Cannot create the SPM data directory."
	# A stable name, because the SPM Dashboard imports this module by path.
	SPM_CORE_PATH="${base_dir}/spm_core.py"
	# Written unconditionally and installed atomically. The write is a
	# millisecond against a vault operation's second, and always writing means
	# an upgraded spm can never be left running last release's core.
	local staged
	staged="$(mktemp "${base_dir}/.spm_core.XXXXXX")" || die "Cannot stage the SPM core."
	cat >"$staged" <<'SPMCORE'
"""SPM trusted core: vault format, key handling and vault mutation.

Everything that decides how a vault is protected lives here and nowhere else.
The CLI reaches it through the command interface at the bottom of this file;
the SPM Dashboard imports it directly. Before this module both surfaces
carried their own copy of the container format, the key wrapping, the version
stamping and the history archiving, and a regression test existed purely to
prove the two copies still agreed -- which is a test that a shared
implementation does not need.

Secrets never appear in argv. The command interface reads them from stdin,
and gpg receives them on a dedicated file descriptor, because argv is
world-readable through `ps` and /proc/<pid>/cmdline.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse

# ----- format and policy -----------------------------------------------------

# The vault records the format it was written in, so a later change can migrate
# instead of guessing. A vault with no META_VAULT_VERSION row predates this and
# is format 1; every write stamps the current version.
VAULT_FORMAT_VERSION = 3

CONTAINER_MAGIC = b"SPM-VAULT-3"

# Key derivation is pinned rather than inherited: a user's gpg.conf can change
# all of it underneath the application, and a security parameter that is
# implicit can be neither reviewed nor migrated. GnuPG 2.2 already defaults to
# s2k mode 3 at the maximum count, so the measurable change is the digest,
# whose default is SHA1.
S2K_ARGS = ["--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
            "--s2k-count", "65011712"]

HISTORY_RETENTION_DEFAULT = 20


class VaultError(Exception):
    """Anything that should reach a user as a refusal rather than a traceback."""


# ----- gpg backend -----------------------------------------------------------

def _passphrase_fd(secret):
    """A read fd holding `secret`, for gpg's --passphrase-fd.

    A pipe rather than argv: argv is world-readable through `ps` and
    /proc/<pid>/cmdline, so every local user could read the master password.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, secret.encode("utf-8"))
    finally:
        os.close(write_fd)
    return read_fd


def gpg_encrypt(secret, payload, timeout=60):
    fd = _passphrase_fd(secret)
    try:
        return subprocess.check_output(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(fd)] + S2K_ARGS +
            ["--cipher-algo", "AES256", "-c"],
            input=payload, stderr=subprocess.DEVNULL,
            timeout=timeout, pass_fds=(fd,))
    finally:
        os.close(fd)


def gpg_decrypt(secret, payload, timeout=60):
    fd = _passphrase_fd(secret)
    try:
        return subprocess.check_output(
            ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(fd), "-d"],
            input=payload, stderr=subprocess.DEVNULL,
            timeout=timeout, pass_fds=(fd,))
    finally:
        os.close(fd)


# ----- container -------------------------------------------------------------
# A format-3 vault is one file: a header line, the vault key sealed under the
# master password, then the vault ciphertext sealed under that key. Keeping it
# to a single self-contained file is why every path that copies, backs up,
# syncs or bundles "the vault" needed no change when the format did.

def is_container(raw):
    return raw.startswith(CONTAINER_MAGIC + b"\n")


def build_container(envelope, cipher):
    return (CONTAINER_MAGIC + b"\nKEY " + base64.b64encode(envelope) +
            b"\nDATA\n" + base64.b64encode(cipher) + b"\n")


def parse_container(raw):
    """(envelope, cipher), or None when `raw` predates the container format."""
    if not is_container(raw):
        return None
    try:
        key_line, data = raw.split(b"\nDATA\n", 1)
        envelope = base64.b64decode(key_line.split(b"\nKEY ", 1)[1])
        cipher = base64.b64decode(data)
    except Exception as exc:
        raise VaultError("vault key container is corrupt") from exc
    if not envelope or not cipher:
        raise VaultError("vault key container is incomplete")
    return envelope, cipher


def new_vault_key():
    return base64.b64encode(os.urandom(32)).decode("ascii")


# ----- version stamping ------------------------------------------------------

def stamp_version(plaintext):
    """Exactly one current META_VAULT_VERSION row, first, on every write."""
    lines = plaintext.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    rows = [l for l in lines if l.split("\t", 1)[0] != "META_VAULT_VERSION"]
    head = "META_VAULT_VERSION\t%d\t-\t-\t-\t-" % VAULT_FORMAT_VERSION
    return "\n".join([head] + rows) + "\n"


def format_version(plaintext):
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if parts[0] == "META_VAULT_VERSION" and len(parts) > 1:
            try:
                return int(parts[1])
            except ValueError:
                return 1
    return 1


# ----- durability ------------------------------------------------------------

# The `read` command returns the vault key on stdout, so an output path that
# resolves to stdout would interleave plaintext with it and silently lose both.
# Refusing is better than a corrupted read that looks like it worked.
_STDOUT_ALIASES = ("-", "/dev/stdout", "/dev/fd/1", "/proc/self/fd/1")


def write_plaintext(path, text):
    """Write decrypted vault material to a file, restricted to its owner."""
    if path in _STDOUT_ALIASES:
        raise VaultError("refusing to write vault plaintext to stdout; "
                         "give a file path")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    try:
        if stat.S_ISREG(os.stat(path).st_mode):
            os.chmod(path, 0o600)
    except OSError:
        pass


def _fsync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path):
    # A directory fsync is what makes a rename survive a crash. Not every
    # filesystem permits it, so a refusal must not fail the write.
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# ----- history ---------------------------------------------------------------
# The CLI and the dashboard must agree on this hash exactly, or the two would
# write snapshots into different directories and each would see only its own.

def vault_scope_id(vault_path):
    return hashlib.sha256(
        os.path.abspath(vault_path).encode("utf-8")).hexdigest()[:16]


def data_dir():
    explicit = os.environ.get("SPM_DATA_DIR")
    if explicit:
        return explicit
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "spm")


def history_dir(vault_path):
    return os.path.join(data_dir(), "history", vault_scope_id(vault_path))


def _retention():
    try:
        keep = int(os.environ.get("SPM_HISTORY_RETENTION", ""))
    except ValueError:
        return HISTORY_RETENTION_DEFAULT
    return keep if keep > 0 else HISTORY_RETENTION_DEFAULT


def archive_generation(vault_path):
    """Snapshot the current ciphertext before it is replaced.

    Failure here must never fail the write it protects: losing an undo point
    is bad, losing the edit is worse.
    """
    if not os.path.exists(vault_path):
        return
    try:
        target = history_dir(vault_path)
        os.makedirs(target, exist_ok=True)
        os.chmod(target, 0o700)
        with open(vault_path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()[:12]
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        snapshot = os.path.join(
            target, "%s.%d.%s.gpg" % (stamp, os.getpid(), digest))
        shutil.copy2(vault_path, snapshot)
        os.chmod(snapshot, 0o600)
        _prune(target, ".gpg", _retention())
    except Exception:
        return


def _prune(directory, suffix, keep):
    try:
        entries = [os.path.join(directory, n) for n in os.listdir(directory)
                   if n.endswith(suffix)]
        entries = [p for p in entries if os.path.isfile(p)]
        entries.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
        for stale in entries[keep:]:
            os.remove(stale)
    except Exception:
        return


# ----- recovery --------------------------------------------------------------

def recovery_path(vault_path):
    return vault_path + ".recovery"


def recovery_pubkey_pem(plaintext):
    """The vault's own recovery public key, or an exception saying why not."""
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if parts[0] == "META_RECOVERY_PUBKEY" and len(parts) > 1 and parts[1].strip():
            try:
                return base64.b64decode(parts[1].strip())
            except Exception:
                raise VaultError("recovery public key is not valid base64")
    raise VaultError("no META_RECOVERY_PUBKEY row in vault")


def stage_recovery(vault_path, plaintext, vault_key):
    """Seal `vault_key` under the vault's recovery pubkey; return a staged path.

    Staging is the safety property. Decoding the stored key only proves it is
    base64; the vault must not be touched until openssl has actually accepted
    it and produced the ciphertext. The caller installs the result once the
    vault it describes is in place.

    Deliberately the same `openssl rsautl -encrypt -pubin` the rest of the
    project uses. It is deprecated in OpenSSL 3, but `spm doctor` and
    `spm forgot` read this file back with `rsautl -decrypt`; switching only the
    writer would be a padding decision made in one place out of three.
    """
    pub_pem = recovery_pubkey_pem(plaintext)
    target = recovery_path(vault_path)
    rec_dir = os.path.dirname(os.path.abspath(target)) or "."
    pub_fd, pub_file = tempfile.mkstemp(prefix="spm.recpub.")
    staged = ""
    try:
        os.write(pub_fd, pub_pem)
        os.close(pub_fd)
        pub_fd = -1
        out_fd, staged = tempfile.mkstemp(
            prefix="." + os.path.basename(target) + ".stage.", dir=rec_dir)
        os.close(out_fd)
        os.chmod(staged, 0o600)
        proc = subprocess.Popen(
            ["openssl", "rsautl", "-encrypt", "-pubin",
             "-inkey", pub_file, "-out", staged],
            stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            proc.communicate(input=vault_key.encode("utf-8"), timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise VaultError("recovery encryption timed out")
        if proc.returncode != 0 or not os.path.getsize(staged):
            raise VaultError("the recovery public key was not usable")
        _fsync_path(staged)
        result, staged = staged, ""
        return result
    finally:
        if pub_fd != -1:
            os.close(pub_fd)
        if os.path.exists(pub_file):
            os.remove(pub_file)
        if staged and os.path.exists(staged):
            os.remove(staged)


def install_recovery(vault_path, staged):
    target = recovery_path(vault_path)
    os.replace(staged, target)
    os.chmod(target, 0o600)
    _fsync_dir(os.path.dirname(os.path.abspath(target)) or ".")


# ----- reading ---------------------------------------------------------------

def unwrap_key(vault_path, master):
    """The vault key alone, or None when the vault predates the container."""
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        return None
    key = gpg_decrypt(master, parts[0]).decode("utf-8")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return key


def read_vault(vault_path, master):
    """(plaintext, vault_key) for any vault file, whatever format it is in.

    Not only the live vault: .bak files, history snapshots and synced copies
    are the same container, and everything that proves one opens before
    overwriting the live vault has to come through here.

    vault_key is None for formats 1 and 2, which were sealed under the master
    password directly.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    parts = parse_container(raw)
    if parts is None:
        return gpg_decrypt(master, raw).decode("utf-8", errors="ignore"), None
    key = gpg_decrypt(master, parts[0]).decode("utf-8")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return gpg_decrypt(key, parts[1]).decode("utf-8", errors="ignore"), key


def read_vault_with_key(vault_path, vault_key):
    """Plaintext from a format-3 vault using a key that is already unwrapped.

    Returns None when the file is not a container -- formats 1 and 2 are sealed
    under the master password directly and have no separate key -- so a caller
    holding a stale key falls back to the master rather than failing.

    A format-3 read is two gpg invocations: one to unwrap the key envelope
    under the master password, one to decrypt the data under that key. The
    envelope is the expensive half and its answer does not change between
    reads, so a caller that can hold the key skips it. Nothing here weakens the
    format: the key is exactly what the master password would have produced.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    parts = parse_container(raw)
    if parts is None:
        return None
    return gpg_decrypt(vault_key, parts[1]).decode("utf-8", errors="ignore")


# ----- writing ---------------------------------------------------------------

def write_vault(vault_path, master, plaintext, vault_key=None):
    """Install `plaintext` as a format-3 vault. Returns the vault key used.

    A write reuses the key the vault already has. Minting a fresh one whenever
    the caller did not supply it would strand every .bak, history snapshot and
    synced copy that the current recovery file can still open, and the whole
    point of a separate vault key is that it survives password changes.

    Migration from formats 1 and 2 is ordered so that no instant is
    unrecoverable. The new recovery file is staged first, before anything is
    encrypted, so a vault whose recovery pubkey is unusable refuses with
    nothing changed. The container is then installed BEFORE the recovery file
    is swapped, with the key envelope sealed under the master password that
    .recovery still names -- which makes the window between the two harmless,
    because the recovered secret still opens the vault as a password. The
    reverse order has no such route.
    """
    vault_dir = os.path.dirname(os.path.abspath(vault_path)) or "."
    vault_name = os.path.basename(vault_path)
    plaintext = stamp_version(plaintext)

    migrating = False
    if vault_key is None and os.path.exists(vault_path):
        vault_key = unwrap_key(vault_path, master)
    if vault_key is None:
        vault_key = new_vault_key()
        migrating = True

    staged_recovery = stage_recovery(vault_path, plaintext, vault_key) if migrating else ""

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="." + vault_name + ".stage.", dir=vault_dir)
    os.close(tmp_fd)
    try:
        os.chmod(tmp_path, 0o600)
        envelope = gpg_encrypt(master, vault_key.encode("utf-8"))
        cipher = gpg_encrypt(vault_key, plaintext.encode("utf-8"))
        with open(tmp_path, "wb") as handle:
            handle.write(build_container(envelope, cipher))

        if os.path.exists(vault_path):
            archive_generation(vault_path)
            shutil.copy2(vault_path, vault_path + ".bak")
            os.chmod(vault_path + ".bak", 0o600)

        # The rename is atomic but not durable on its own: flush the ciphertext
        # first so a crash cannot leave the new name over unwritten blocks.
        _fsync_path(tmp_path)
        os.replace(tmp_path, vault_path)
        tmp_path = ""
        os.chmod(vault_path, 0o600)
        _fsync_dir(vault_dir)

        if staged_recovery:
            # Second, deliberately. A failure here leaves .recovery naming the
            # master password, which still unwraps this container, so it is
            # reported rather than undoing the user's save.
            try:
                install_recovery(vault_path, staged_recovery)
                staged_recovery = ""
            except Exception as exc:
                sys.stderr.write(
                    "warning: the vault was migrated but its recovery file "
                    "still holds the master password (%s)\n" % exc)
        return vault_key
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        if staged_recovery and os.path.exists(staged_recovery):
            os.remove(staged_recovery)


def rewrap(vault_path, old_master, new_master):
    """Change only the master-password envelope, given the old password."""
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        raise VaultError("vault must be migrated before its key can be rewrapped")
    key = gpg_decrypt(old_master, parts[0]).decode("utf-8")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return rewrap_with_key(vault_path, key, new_master)


def rewrap_with_key(vault_path, vault_key, new_master):
    """Change only the master-password envelope, given the vault key.

    The vault ciphertext stays byte-identical and the recovery file is not
    touched at all, because both key off the vault key, which does not change.
    This is the reason for separating the vault key: a password change stops
    being a re-encryption of everything the user owns.

    Taking the key rather than the old password lets a caller that has just
    read the vault skip an entire gpg invocation, which is the dominant cost
    of any vault operation.
    """
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        raise VaultError("vault must be migrated before its key can be rewrapped")
    key = vault_key
    updated = build_container(gpg_encrypt(new_master, key.encode("utf-8")), parts[1])

    vault_dir = os.path.dirname(os.path.abspath(vault_path)) or "."
    fd, staged = tempfile.mkstemp(
        prefix="." + os.path.basename(vault_path) + ".rewrap.", dir=vault_dir)
    try:
        os.write(fd, updated)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.chmod(staged, 0o600)
        archive_generation(vault_path)
        shutil.copy2(vault_path, vault_path + ".bak")
        os.chmod(vault_path + ".bak", 0o600)
        os.replace(staged, vault_path)
        staged = ""
        os.chmod(vault_path, 0o600)
        _fsync_dir(vault_dir)
    finally:
        if fd != -1:
            os.close(fd)
        if staged and os.path.exists(staged):
            os.remove(staged)
    return key


def recover(vault_path, secret, out_path):
    """Open a vault with a secret recovered from the .recovery file.

    What that file holds depends on when it was last written: format 3 stores
    the vault key, the formats before it stored the master password, and a
    vault caught mid-migration is described by neither. Try every reading
    rather than assume -- the master-password route is also what makes the
    migration window recoverable, because the key envelope of a just-migrated
    vault is sealed under exactly the password the stale file still names.

    Returns (vault_key, recovery_is_stale). A stale recovery file recovered
    this vault by luck and will not recover it again once the envelope is
    rewrapped, so the caller must refresh it.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    parts = parse_container(raw)

    if parts is None:
        # Formats 1 and 2: the recovery file can only hold the password.
        write_plaintext(out_path, gpg_decrypt(secret, raw).decode("utf-8", errors="ignore"))
        return None, False

    try:
        plaintext = gpg_decrypt(secret, parts[1]).decode("utf-8", errors="ignore")
        key, stale = secret, False
    except subprocess.CalledProcessError:
        try:
            key = gpg_decrypt(secret, parts[0]).decode("utf-8")
        except subprocess.CalledProcessError:
            raise VaultError("the recovery file does not open this vault")
        if not key:
            raise VaultError("vault key envelope decrypted to nothing")
        plaintext = gpg_decrypt(key, parts[1]).decode("utf-8", errors="ignore")
        stale = True
    write_plaintext(out_path, plaintext)
    return key, stale


# ----- command interface -----------------------------------------------------
# How the shell half reaches the core. Secrets arrive on stdin, one per line,
# never in argv. A master password cannot contain a newline: every prompt that
# collects one reads a single line.

# ----- foreign export formats ------------------------------------------------
# Bitwarden's export is the one people arrive with, and its shape has nothing
# in common with SPM's. Normalising it here rather than in either surface means
# the CLI and the dashboard cannot disagree about what a Bitwarden file means.

# Bitwarden item types. 3 and 4 carry structured data with no SPM equivalent,
# so they become notes rather than being dropped -- an import that silently
# loses a card is worse than one that stores it as text the user can read.
BITWARDEN_LOGIN = 1
BITWARDEN_SECURE_NOTE = 2
BITWARDEN_CARD = 3
BITWARDEN_IDENTITY = 4


def looks_like_bitwarden_json(payload):
    return isinstance(payload, dict) and isinstance(payload.get("items"), list)


def looks_like_bitwarden_csv_header(fieldnames):
    names = {(name or "").strip().lower() for name in (fieldnames or ())}
    return "login_password" in names or "login_username" in names


def _bitwarden_uri(item):
    login = item.get("login") or {}
    for entry in login.get("uris") or []:
        if isinstance(entry, dict) and entry.get("uri"):
            return entry["uri"]
        if isinstance(entry, str) and entry:
            return entry
    return ""


def _bitwarden_structured(item):
    """Card and identity fields rendered as readable lines."""
    for key in ("card", "identity"):
        section = item.get(key)
        if isinstance(section, dict):
            pairs = [(k, v) for k, v in section.items() if v not in (None, "")]
            if pairs:
                return "\n".join("%s: %s" % (k, v) for k, v in sorted(pairs))
    return ""


def _hkdf_expand_sha256(prk, info, length=32):
    """HKDF-Expand, the half Bitwarden uses to split one key into enc and mac."""
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _split_cipher_string(value):
    """(type, iv, ciphertext, mac) from Bitwarden's "2.iv|ct|mac" encoding."""
    text = (value or "").strip()
    if "." not in text:
        raise VaultError("malformed encrypted field in the export")
    kind, _, rest = text.partition(".")
    parts = rest.split("|")
    if kind != "2" or len(parts) != 3:
        raise VaultError(
            "unsupported encryption type %r in the export; SPM reads "
            "AesCbc256_HmacSha256_B64 exports" % kind)
    try:
        return (kind, base64.b64decode(parts[0]),
                base64.b64decode(parts[1]), base64.b64decode(parts[2]))
    except Exception:
        raise VaultError("the encrypted field is not valid base64")


def decrypt_bitwarden_export(payload, password):
    """The plaintext JSON inside a Bitwarden password-protected export.

    Two deliberate refusals rather than approximations:

    Argon2id (kdfType 1) is not derivable here for the same reason SPM does not
    use it for its own vaults -- no stdlib implementation, and no dependency
    this project is willing to take. Such an export is refused by name.

    AES-256-CBC needs a real implementation. `cryptography` is used when it is
    importable and the import is refused when it is not. The alternatives were
    to shell out to `openssl enc -K`, which puts the key in argv where any
    local user can read it and which this module forbids by design, or to
    hand-write AES, which is not something that belongs in a password
    manager's trusted core for the sake of a one-off conversion.
    """
    if not isinstance(payload, dict) or not payload.get("encrypted"):
        raise VaultError("this file is not an encrypted Bitwarden export")

    kdf_type = payload.get("kdfType", 0)
    if kdf_type not in (0, None):
        raise VaultError(
            "this export was protected with Argon2id, which SPM cannot derive. "
            "Re-export from Bitwarden without a password, or export as CSV.")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise VaultError(
            "reading a password-protected export needs the python3 "
            "'cryptography' package, which is not installed. Re-export from "
            "Bitwarden without a password, or install it and try again.")

    salt = (payload.get("salt") or "").encode("utf-8")
    iterations = int(payload.get("kdfIterations") or 600000)
    if not salt:
        raise VaultError("the export carries no salt")

    master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iterations, dklen=32)
    enc_key = _hkdf_expand_sha256(master, b"enc", 32)
    mac_key = _hkdf_expand_sha256(master, b"mac", 32)

    _, iv, ciphertext, mac = _split_cipher_string(payload.get("data"))

    # Authenticate before decrypting, and compare in constant time. A wrong
    # password fails here, which is why it is reported as a wrong password
    # rather than as corrupt data.
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise VaultError("wrong export password, or the file has been altered")

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    if not padded:
        raise VaultError("the export decrypted to nothing")
    pad = padded[-1]
    if pad < 1 or pad > 16 or padded[-pad:] != bytes([pad]) * pad:
        raise VaultError("the export did not decrypt cleanly")
    return padded[:-pad].decode("utf-8")


def parse_otpauth(value):
    """(secret, period, algorithm) from a TOTP value Bitwarden might store.

    Bitwarden's `totp` field is either a bare base32 secret or a whole
    otpauth:// URI. SPM's authenticator row holds the secret, the period and
    the algorithm in separate fields, so a URI stored verbatim produces an
    authenticator that cannot generate a code -- it would try to base32-decode
    the URI itself.
    """
    text = (value or "").strip()
    if not text:
        return "", "30", "sha1"
    if not text.lower().startswith("otpauth://"):
        return text, "30", "sha1"
    query = urllib.parse.urlparse(text).query
    params = urllib.parse.parse_qs(query)
    secret = (params.get("secret") or [""])[0].strip()
    period = (params.get("period") or ["30"])[0].strip() or "30"
    algorithm = (params.get("algorithm") or ["sha1"])[0].strip().lower() or "sha1"
    if not period.isdigit():
        period = "30"
    if algorithm not in ("sha1", "sha256", "sha512"):
        algorithm = "sha1"
    return secret, period, algorithm


def bitwarden_rows(payload):
    """Bitwarden's JSON export as rows in SPM's import schema.

    Custom fields, folder names and TOTP secrets are carried across rather than
    dropped. A TOTP becomes an authenticator row; everything else Bitwarden
    kept as structure is appended to the notes, because silently losing it
    during a migration is the kind of failure people notice months later.
    """
    rows = []
    folders = {}
    for folder in payload.get("folders") or []:
        if isinstance(folder, dict) and folder.get("id"):
            folders[folder["id"]] = folder.get("name") or ""

    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        created = item.get("creationDate") or ""
        extras = []
        for field in item.get("fields") or []:
            if isinstance(field, dict) and field.get("name"):
                extras.append("%s: %s" % (field["name"], field.get("value") or ""))
        structured = _bitwarden_structured(item)
        if structured:
            extras.append(structured)
        folder = folders.get(item.get("folderId") or "", "")
        if folder:
            extras.append("folder: %s" % folder)
        notes = "\n".join([n for n in [item.get("notes") or ""] + extras if n])

        login = item.get("login") or {}
        if item.get("type") == BITWARDEN_LOGIN or login:
            rows.append({"type": "password", "label": name,
                         "username": login.get("username") or "",
                         "secret": login.get("password") or "",
                         "notes": notes, "created": created,
                         "url": _bitwarden_uri(item)})
            secret, period, algorithm = parse_otpauth(login.get("totp"))
            if secret:
                rows.append({"type": "authenticator", "label": name,
                             "secret": secret, "period": period,
                             "algorithm": algorithm, "notes": "",
                             "created": created})
        else:
            rows.append({"type": "note", "label": name, "secret": notes,
                         "notes": "", "created": created})
    return rows


def bitwarden_csv_rows(records):
    """Bitwarden's CSV export as rows in SPM's import schema."""
    rows = []
    for record in records:
        def field(key):
            return (record.get(key) or "").strip()
        name = field("name")
        extras = [v for v in (field("fields"),) if v]
        if field("folder"):
            extras.append("folder: %s" % field("folder"))
        notes = "\n".join([n for n in [record.get("notes") or ""] + extras if n])

        if field("type").lower() == "login" or field("login_password") or field("login_username"):
            rows.append({"type": "password", "label": name,
                         "username": field("login_username"),
                         "secret": record.get("login_password") or "",
                         "notes": notes, "created": "",
                         "url": field("login_uri")})
            secret, period, algorithm = parse_otpauth(field("login_totp"))
            if secret:
                rows.append({"type": "authenticator", "label": name,
                             "secret": secret, "period": period,
                             "algorithm": algorithm, "notes": "",
                             "created": ""})
        else:
            rows.append({"type": "note", "label": name, "secret": notes,
                         "notes": "", "created": ""})
    return rows


# ----- diagnostics -----------------------------------------------------------

# Characters that splitlines() honours but a TAB-delimited, line-based record
# format does not survive. A value carrying one of these was written as a
# single record and reads back as two, so the tail becomes an orphan fragment
# that no surface displays. See the 2.10.12 sanitiser, which stops new ones.
RECORD_BREAKS = {
    "\v": "U+000B VERTICAL TAB",
    "\f": "U+000C FORM FEED",
    "\x1c": "U+001C FILE SEPARATOR",
    "\x1d": "U+001D GROUP SEPARATOR",
    "\x1e": "U+001E RECORD SEPARATOR",
    "\x85": "U+0085 NEXT LINE",
    "\u2028": "U+2028 LINE SEPARATOR",
    "\u2029": "U+2029 PARAGRAPH SEPARATOR",
}

# Field 3 holds the secret in every record shape SPM writes, so nothing here
# ever reads it. Only type, id and label are reported.
_RECORD_TAGS = {"NOTE": "NOTE", "PASSPHRASE": "PASSPHRASE",
                "BACKUP_CODE": "BACKUP_CODE", "AUTH": "AUTHENTICATOR"}


def _describe_record(line):
    parts = line.split("\t")
    tag = parts[0] if parts else ""
    if tag in _RECORD_TAGS:
        return (_RECORD_TAGS[tag],
                parts[1] if len(parts) > 1 else "?",
                parts[2] if len(parts) > 2 else "")
    if tag.isdigit():
        return "PASSWORD", tag, (parts[1] if len(parts) > 1 else "")
    return tag or "(unknown)", "?", ""


def _safe_text(text, limit=32):
    """A label rendered for a terminal: no raw control characters, ever."""
    out = []
    for ch in text:
        if ch in RECORD_BREAKS or ch == "\t":
            out.append("\u2423")
        elif unicodedata.category(ch).startswith("C"):
            out.append("?")
        else:
            out.append(ch)
    shown = "".join(out)
    return shown[:limit] + ("..." if len(shown) > limit else "")


def scan_broken_records(plaintext):
    """(broken, orphans) for records split by an embedded line break.

    Split on "\n" only, because that is how the record was physically written.
    """
    broken, orphans = [], []
    for number, line in enumerate(plaintext.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        hits = [name for ch, name in RECORD_BREAKS.items() if ch in line]
        if hits:
            kind, rid, label = _describe_record(line)
            broken.append((number, kind, rid, _safe_text(label), hits))
            continue
        if line.startswith("META_"):
            continue
        if len(line.split("\t")) < 5:
            orphans.append((number, _safe_text(line, 48)))
    return broken, orphans


def vault_counts(plaintext):
    """Record counts, duplicate password ids and empty password fields."""
    counts = {"passwords": 0, "notes": 0, "passphrases": 0,
              "backup_codes": 0, "authenticators": 0}
    by_tag = {"NOTE": "notes", "PASSPHRASE": "passphrases",
              "BACKUP_CODE": "backup_codes", "AUTH": "authenticators"}
    seen, duplicates, empty = {}, [], 0
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag in by_tag:
            counts[by_tag[tag]] += 1
        elif tag.isdigit():
            counts["passwords"] += 1
            seen[tag] = seen.get(tag, 0) + 1
            if len(parts) > 3 and not parts[3]:
                empty += 1
    duplicates = sorted((rid for rid, n in seen.items() if n > 1), key=int)
    return counts, duplicates, empty


def _check(identifier, status, summary, **extra):
    entry = {"id": identifier, "status": status, "summary": summary}
    entry.update(extra)
    return entry


def doctor_report(plaintext, vault_path, recovery_status="unchecked",
                  sensitive_files=()):
    """A machine-readable health report. Never contains a secret.

    Structured as a list of checks with stable ids rather than a bag of
    booleans, so a caller can act on one without parsing prose, and so a check
    added later does not change the shape of the ones already there.
    """
    checks = []
    counts, duplicates, empty = vault_counts(plaintext)

    if duplicates:
        checks.append(_check("duplicate_ids", "fail",
                             "%d password id(s) appear more than once" % len(duplicates),
                             ids=duplicates))
    else:
        checks.append(_check("duplicate_ids", "ok", "no duplicate password ids"))

    if empty:
        checks.append(_check("empty_passwords", "warn",
                             "%d entr(y/ies) have an empty password field" % empty,
                             count=empty))
    else:
        checks.append(_check("empty_passwords", "ok", "no empty password fields"))

    broken, orphans = scan_broken_records(plaintext)
    if broken or orphans:
        checks.append(_check(
            "split_records", "fail",
            "%d record(s) contain a line-break character; %d orphan fragment(s)"
            % (len(broken), len(orphans)),
            broken=[{"line": n, "kind": k, "id": i, "label": l, "characters": h}
                    for n, k, i, l, h in broken],
            orphans=[{"line": n, "text": t} for n, t in orphans]))
    else:
        checks.append(_check("split_records", "ok",
                             "no records split by a line-break character"))

    found = format_version(plaintext)
    if found >= VAULT_FORMAT_VERSION:
        checks.append(_check("vault_format", "ok",
                             "format version %d is current" % found,
                             found=found, current=VAULT_FORMAT_VERSION))
    else:
        checks.append(_check(
            "vault_format", "warn",
            "format version %d; %d is available and the next write upgrades in place"
            % (found, VAULT_FORMAT_VERSION),
            found=found, current=VAULT_FORMAT_VERSION))

    try:
        recovery_pubkey_pem(plaintext)
        checks.append(_check("recovery_pubkey", "ok",
                             "recovery public key present and decodable"))
    except VaultError as exc:
        checks.append(_check("recovery_pubkey", "fail", str(exc)))

    pairing = {
        "match-current": ("ok", "recovery file holds this vault's current key"),
        "match-legacy": ("ok", "recovery file decrypts; this format predates vault keys"),
        "match-stale": ("fail", "recovery file does not hold this vault's key; "
                                "run change-master to refresh it"),
        "mismatch": ("fail", "private key does not match the recovery file"),
        "no-private-key": ("fail", "no default private key found"),
        "no-recovery-file": ("fail", "no recovery file found"),
        "unchecked": ("warn", "recovery pairing was not checked"),
    }
    status, summary = pairing.get(recovery_status,
                                  ("warn", "unrecognised recovery state"))
    checks.append(_check("recovery_pairing", status, summary, state=recovery_status))

    exposed = []
    for path in sensitive_files:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            continue
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            exposed.append({"path": path, "mode": "%03o" % mode})
    if exposed:
        checks.append(_check("file_permissions", "fail",
                             "%d sensitive file(s) readable by other users" % len(exposed),
                             files=exposed))
    else:
        checks.append(_check("file_permissions", "ok",
                             "sensitive files are not group- or world-accessible"))

    failed = sum(1 for c in checks if c["status"] == "fail")
    warned = sum(1 for c in checks if c["status"] == "warn")
    return {
        "schema": 1,
        "vault": {"path": vault_path,
                  "format_version": found,
                  "current_format_version": VAULT_FORMAT_VERSION},
        "counts": counts,
        "checks": checks,
        "summary": {"failed": failed, "warned": warned,
                    "status": "fail" if failed else ("warn" if warned else "ok")},
    }


def _secrets(count):
    data = sys.stdin.buffer.read().decode("utf-8")
    fields = data.split("\n")
    if len(fields) < count:
        raise VaultError("expected %d secret(s) on stdin" % count)
    return fields[:count]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: spm_core.py <command> [args]\n")
        return 2
    command = argv[1]
    try:
        if command == "read":
            # read <vault> <out> ; stdin: master ; stdout: vault key (may be empty)
            vault, out = argv[2], argv[3]
            (master,) = _secrets(1)
            plaintext, key = read_vault(vault, master)
            write_plaintext(out, plaintext)
            sys.stdout.write(key or "")
        elif command == "write":
            # write <vault> <plainfile> ; stdin: master[\nvault key]
            vault, source = argv[2], argv[3]
            fields = sys.stdin.buffer.read().decode("utf-8").split("\n")
            master = fields[0]
            key = fields[1] if len(fields) > 1 and fields[1] else None
            with open(source, "r", encoding="utf-8") as handle:
                plaintext = handle.read()
            sys.stdout.write(write_vault(vault, master, plaintext, key))
        elif command == "rewrap":
            # rewrap <vault> ; stdin: old master\nnew master
            old, new = _secrets(2)
            rewrap(argv[2], old, new)
        elif command == "rewrap-key":
            # rewrap-key <vault> ; stdin: vault key\nnew master
            key, new = _secrets(2)
            if not key:
                raise VaultError("a vault key is required")
            rewrap_with_key(argv[2], key, new)
        elif command == "recover":
            # recover <vault> <out> ; stdin: recovered secret
            # stdout: "<vault key>\n<1 if the recovery file is stale else 0>"
            (secret,) = _secrets(1)
            key, stale = recover(argv[2], secret, argv[3])
            sys.stdout.write("%s\n%d\n" % (key or "", 1 if stale else 0))
        elif command == "unwrap":
            # unwrap <vault> ; stdin: master ; stdout: vault key
            (master,) = _secrets(1)
            sys.stdout.write(unwrap_key(argv[2], master) or "")
        elif command == "is-container":
            with open(argv[2], "rb") as handle:
                return 0 if is_container(handle.read(len(CONTAINER_MAGIC) + 1)) else 1
        elif command == "format-version":
            with open(argv[2], "r", encoding="utf-8", errors="ignore") as handle:
                sys.stdout.write("%d\n" % format_version(handle.read()))
        elif command == "stamp-version":
            with open(argv[2], "r", encoding="utf-8") as handle:
                stamped = stamp_version(handle.read())
            with open(argv[3], "w", encoding="utf-8") as handle:
                handle.write(stamped)
        elif command == "write-recovery":
            # write-recovery <vault> <plainfile> ; stdin: vault key
            (key,) = _secrets(1)
            with open(argv[3], "r", encoding="utf-8") as handle:
                plaintext = handle.read()
            install_recovery(argv[2], stage_recovery(argv[2], plaintext, key))
        elif command == "scope-id":
            sys.stdout.write(vault_scope_id(argv[2]))
        elif command == "current-version":
            sys.stdout.write("%d\n" % VAULT_FORMAT_VERSION)
        elif command == "history-dir":
            sys.stdout.write(history_dir(argv[2]) + "\n")
        elif command == "archive":
            archive_generation(argv[2])
        elif command == "scan-records":
            # scan-records <plainfile> ; stdout: the TSV the CLI's doctor renders
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                broken, orphans = scan_broken_records(handle.read())
            for number, kind, rid, label, hits in broken:
                sys.stdout.write("BROKEN\t%d\t%s\t%s\t%s\t%s\n"
                                 % (number, kind, rid, label, "; ".join(hits)))
            for number, text in orphans:
                sys.stdout.write("ORPHAN\t%d\t%s\n" % (number, text))
            sys.stdout.write("SUMMARY\t%d\t%d\n" % (len(broken), len(orphans)))
        elif command == "doctor-report":
            # doctor-report <plainfile> <vault> <recovery state> [sensitive file ...]
            # stdout: JSON. Exit 1 when any check failed, so a script can gate
            # on the status without parsing the document.
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                plaintext = handle.read()
            report = doctor_report(plaintext, argv[3], argv[4], argv[5:])
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
            return 1 if report["summary"]["failed"] else 0
        elif command == "self-test":
            return 0
        else:
            sys.stderr.write("unknown command: %s\n" % command)
            return 2
    except VaultError as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    except subprocess.CalledProcessError:
        sys.stderr.write("gpg refused the supplied secret\n")
        return 1
    except (OSError, IndexError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
SPMCORE
	chmod 600 "$staged" 2>/dev/null || true
	mv -f "$staged" "$SPM_CORE_PATH" || { rm -f "$staged"; die "Cannot install the SPM core."; }
}

core() {
	[ -n "${SPM_CORE_PATH:-}" ] && [ -f "$SPM_CORE_PATH" ] || ensure_core_script
	python3 "$SPM_CORE_PATH" "$@"
}

is_vault_container() {
	core is-container "$1" 2>/dev/null
}

decrypt_vault_to_file() {
	local out_file="$1"
	[ -f "$VAULT_FILE" ] || die "Vault does not exist. Run '$0 init' first."

	ensure_master_password_loaded

	if ! VAULT_KEY="$(printf '%s' "$MASTER_PW" | core read "$VAULT_FILE" "$out_file" 2>/dev/null)"; then
		secure_wipe "$out_file"
		MASTER_PW=""
		VAULT_KEY=""
		if [ "$SPM_LANG" = "id" ]; then
			die "Gagal mendekripsi vault. Kata sandi utama salah?"
		else
			die "Failed to decrypt vault. Wrong master password?"
		fi
	fi
}

# Decrypt any SPM vault file -- a .bak, a history snapshot, a synced copy --
# under "$3". Returns non-zero instead of dying, because its callers are
# proving that a file opens and own their own error message.
#
# The vault key is deliberately NOT captured here: a key unwrapped from a
# snapshot must never become the key the live vault is written under.
decrypt_vault_container() {
	printf '%s' "$3" | core read "$1" "$2" >/dev/null 2>&1
}

encrypt_file_to_vault() {
	local in_file="$1"
	[ "${MASTER_PW:-}" ] || die "MASTER_PW is empty in encrypt_file_to_vault"

	# The key is passed back in so an ordinary write does not pay to unwrap
	# the envelope it already holds. Passing none makes the core recover it
	# from the vault; only a vault with no key at all gets a new one.
	if ! VAULT_KEY="$(printf '%s\n%s' "$MASTER_PW" "${VAULT_KEY:-}" \
		| core write "$VAULT_FILE" "$in_file")"; then
		die "Failed to write the vault. The existing vault was not changed; plaintext remains in '$in_file'."
	fi

	if ! ( maybe_auto_backup ); then
		printf 'Warning: vault write succeeded, but the automatic backup failed.\n' >&2
	fi
}

rewrap_vault_key() {
	local new_master="$1"
	[ -n "${VAULT_KEY:-}" ] || die "Vault key is not loaded."
	printf '%s\n%s' "$VAULT_KEY" "$new_master" | core rewrap-key "$VAULT_FILE" \
		|| die "Failed to rewrap the vault key. The vault was not changed."
}

stamp_vault_version() {
	core stamp-version "$1" "$2" || die "Failed to stamp the vault format version."
}

vault_format_version() {
	core format-version "$1" 2>/dev/null || printf '1\n'
}


# The advisory lock the CLI shares with the SPM Dashboard.
#
# This used to require flock(1), which is util-linux and which macOS does not
# ship. The dashboard never needed it -- Python's fcntl.flock exists on every
# platform SPM supports -- so on macOS the dashboard was locking and the CLI
# was not. That is the worst of the two arrangements, because one side
# believed it was protected while the other walked straight through.
#
# python3 is already a hard dependency, and locking through it uses the same
# primitive on the same file, so the two genuinely exclude each other. The
# lock is taken on fd 9, which this shell holds open for the duration: the
# helper exiting does not release it, because the lock belongs to the open
# file description and the shell still has a descriptor for it.
#
# There is no stale lock to detect and no PID file to get wrong. The kernel
# drops the lock when the last descriptor for it closes, which includes the
# process being killed. That is the property a mkdir-based lock would have had
# to reimplement badly.
vault_lock_hold_fd9() {
	if command -v flock >/dev/null 2>&1; then
		flock -x 9
		return $?
	fi
	python3 -c 'import fcntl; fcntl.flock(9, fcntl.LOCK_EX)' 2>/dev/null
}

acquire_cli_vault_lock() {
	if ! command -v flock >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
		printf "Warning: neither 'flock' nor python3 is available; do not run concurrent CLI or web vault operations.\n" >&2
		return 0
	fi
	exec 9>"${VAULT_FILE}.lock" || die "Cannot open vault lock file."
	chmod 600 "${VAULT_FILE}.lock" 2>/dev/null || true
	vault_lock_hold_fd9 || die "Cannot lock vault."
	CLI_VAULT_LOCKED=1
}

# Memoised: the scope id is a pure function of the vault path, and
# maybe_auto_backup asks for it several times per write.
SPM_VAULT_SCOPE_ID=""
vault_scope_id() {
	if [ -z "$SPM_VAULT_SCOPE_ID" ]; then
		SPM_VAULT_SCOPE_ID="$(core scope-id "$VAULT_FILE")" \
			|| die "Cannot determine the vault scope id."
	fi
	printf '%s' "$SPM_VAULT_SCOPE_ID"
}

history_dir() {
	core history-dir "$VAULT_FILE"
}

archive_current_vault() {
	core archive "$VAULT_FILE" || true
}

auto_backup_config() {
	printf '%s/auto-backup-%s.conf\n' "$SPM_CONFIG_DIR" "$(vault_scope_id)"
}

maybe_auto_backup() {
	[ -f "$VAULT_FILE" ] || return 0
	local cfg enabled target interval retention last now name digest
	cfg="$(auto_backup_config)"
	[ -f "$cfg" ] || return 0
	enabled="$(sed -n '1p' "$cfg")"; [ "$enabled" = "enabled" ] || return 0
	target="$(sed -n '2p' "$cfg")"; interval="$(sed -n '3p' "$cfg")"
	retention="$(sed -n '4p' "$cfg")"; last="$(sed -n '5p' "$cfg")"
	printf '%s' "$interval" | grep -Eq '^[1-9][0-9]*$' || interval=24
	printf '%s' "$retention" | grep -Eq '^[1-9][0-9]*$' || retention=14
	printf '%s' "$last" | grep -Eq '^[0-9]+$' || last=0
	now="$(date +%s)"
	[ $((now - last)) -ge $((interval * 3600)) ] || return 0
	mkdir -p "$target" || die "Failed to create automatic-backup directory."
	chmod 700 "$target" 2>/dev/null || true
	name="spm-$(vault_scope_id)-$(date -u +%Y%m%dT%H%M%SZ).gpg"
	cp "$VAULT_FILE" "$target/$name" || die "Automatic encrypted backup failed."
	chmod 600 "$target/$name" 2>/dev/null || true
	digest="$(sha256sum "$VAULT_FILE" | awk '{print $1}')"
	[ "$digest" = "$(sha256sum "$target/$name" | awk '{print $1}')" ] || die "Automatic backup verification failed."
	find "$target" -maxdepth 1 -type f -name "spm-$(vault_scope_id)-*.gpg" -print 2>/dev/null \
		| while IFS= read -r item; do printf '%s\t%s\n' "$(stat -c '%Y' "$item" 2>/dev/null || stat -f '%m' "$item")" "$item"; done \
		| sort -nr | awk -F '\t' -v keep="$retention" 'NR > keep { print $2 }' \
		| while IFS= read -r old; do secure_wipe "$old"; done
	{
		printf 'enabled\n%s\n%s\n%s\n%s\n' "$target" "$interval" "$retention" "$now"
	} > "$cfg"
	chmod 600 "$cfg" 2>/dev/null || true
}

release_cli_vault_lock() {
	[ "${CLI_VAULT_LOCKED:-0}" = "1" ] || return 0
	# Closing the descriptor releases the lock on every platform, which is the
	# only mechanism available where flock(1) is not. `flock -u` is kept for
	# the platforms that have it, but it is no longer what does the work.
	flock -u 9 2>/dev/null || true
	exec 9>&-
	CLI_VAULT_LOCKED=0
}

# ----- Vault format helpers ---------------------------------------------------
# Password entry line:
# id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at
#
# Secure note line:
# NOTE<TAB>note_id<TAB>title<TAB>base64_body<TAB>created_at<TAB>-
#
# Meta line (recovery public key):
# META_RECOVERY_PUBKEY<TAB><base64_pubkey><TAB>-<TAB>-<TAB>-<TAB>-

next_id_from_vault() {
	local file="$1"
	if [ ! -s "$file" ]; then
		printf '1\n'
		return
	fi

	awk -F '\t' '
		$1 ~ /^[0-9]+$/ {
			if ($1 > max) max = $1
		}
		END {
			if (max == 0) print 1;
			else print max + 1;
		}
	' "$file"
}

next_note_id_from_vault() {
	local file="$1"
	if [ ! -s "$file" ]; then
		printf '1\n'
		return
	fi
	awk -F '\t' '
		$1=="NOTE" && $2 ~ /^[0-9]+$/ {
			if ($2 > max) max = $2
		}
		END {
			if (max == 0) print 1;
			else print max + 1;
		}
	' "$file"
}

next_backup_code_id_from_vault() {
	local file="$1"
	if [ ! -s "$file" ]; then
		printf '1\n'
		return
	fi
	awk -F '\t' '
		$1=="BACKUP_CODE" && $2 ~ /^[0-9]+$/ {
			if ($2 > max) max = $2
		}
		END {
			if (max == 0) print 1;
			else print max + 1;
		}
	' "$file"
}

next_passphrase_id_from_vault() {
	local file="$1"
	if [ ! -s "$file" ]; then
		printf '1\n'
		return
	fi
	awk -F '\t' '
		$1=="PASSPHRASE" && $2 ~ /^[0-9]+$/ {
			if ($2 > max) max = $2
		}
		END {
			if (max == 0) print 1;
			else print max + 1;
		}
	' "$file"
}

next_authenticator_id_from_vault() {
	local file="$1"
	if [ ! -s "$file" ]; then
		printf '1\n'
		return
	fi
	awk -F '\t' '
		$1=="AUTH" && $2 ~ /^[0-9]+$/ {
			if ($2 > max) max = $2
		}
		END {
			if (max == 0) print 1;
			else print max + 1;
		}
	' "$file"
}

print_vault_table() {
	local file="$1"
	if [ ! -s "$file" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Vault kosong.\n"
		else
			printf "Vault is empty.\n"
		fi
		return
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf '%-5s  %-20s  %-24s  %-20s  %s\n' "ID" "Layanan" "Username / Email" "Dibuat" "URL"
	else
		printf '%-5s  %-20s  %-24s  %-20s  %s\n' "ID" "Service" "Username / Email" "Created" "URL"
	fi
	printf '%.0s-' $(seq 1 96); printf '\n'

	awk -F '\t' '
		NF >= 6 && $1 ~ /^[0-9]+$/ {
			printf "%-5s  %-20s  %-24s  %-20s  %s\n", $1, $2, $3, $6, (NF >= 7 ? $7 : "")
		}
	' "$file"
}

search_vault() {
	local file="$1"
	local pattern="$2"

	awk -F '\t' -v p="$pattern" '
		$1 ~ /^[0-9]+$/ && (tolower($2) ~ tolower(p) || tolower($3) ~ tolower(p) \
			|| (NF >= 7 && tolower($7) ~ tolower(p))) {
			printf "%-5s  %-20s  %-24s  %-20s  %s\n", $1, $2, $3, $6, (NF >= 7 ? $7 : "")
		}
	' "$file"
}

get_entry_by_id() {
	local file="$1"
	local id="$2"

	awk -F '\t' -v target="$id" '
		$1 ~ /^[0-9]+$/ && $1 == target {
			print $0;
		}
	' "$file"
}

get_recovery_pub_b64_from_vault() {
	local file="$1"
	awk -F '\t' '$1=="META_RECOVERY_PUBKEY"{print $2; exit}' "$file"
}

write_recovery_file() {
	local vault_plain="$1"
	[ -n "${VAULT_KEY:-}" ] || die "Vault key is not loaded. Cannot update recovery file."
	printf '%s' "$VAULT_KEY" | core write-recovery "$VAULT_FILE" "$vault_plain" \
		|| die "Failed to create/update recovery file '$RECOVERY_FILE'."
}

# ----- Password strength coaching --------------------------------------------

password_strength_report() {
	local pw="$1"
	local len="${#pw}"
	local has_lower=0 has_upper=0 has_digit=0 has_symbol=0
	local i ch

	for (( i=0; i<len; i++ )); do
		ch="${pw:i:1}"
		case "$ch" in
			[a-z]) has_lower=1 ;;
			[A-Z]) has_upper=1 ;;
			[0-9]) has_digit=1 ;;
			*) has_symbol=1 ;;
		esac
	done

	local charset=0
	(( has_lower )) && charset=$((charset+26))
	(( has_upper )) && charset=$((charset+26))
	(( has_digit )) && charset=$((charset+10))
	(( has_symbol )) && charset=$((charset+32))
	[ "$charset" -le 0 ] && charset=1

	local entropy bits_int
	local types_en="" types_id=""

	entropy="$(awk -v L="$len" -v N="$charset" 'BEGIN {
		if (L<=0 || N<=1) {print 0; exit}
		e = L * log(N)/log(2);
		printf "%.1f", e;
	}')"

	bits_int="${entropy%.*}"

	(( has_lower )) && { types_en+="lowercase, "; types_id+="huruf kecil, "; }
	(( has_upper )) && { types_en+="uppercase, "; types_id+="huruf besar, "; }
	(( has_digit )) && { types_en+="digits, "; types_id+="angka, "; }
	(( has_symbol )) && { types_en+="symbols, "; types_id+="simbol, "; }

	if [ -z "$types_en" ]; then
		types_en="(none detected)"
		types_id="(tidak terdeteksi)"
	else
		types_en="${types_en%, }"
		types_id="${types_id%, }"
	fi

	local strength_en strength_id time_en time_id

	if [ "$bits_int" -lt 40 ]; then
		strength_en="VERY WEAK"
		strength_id="SANGAT LEMAH"
		time_en="likely crackable in seconds/minutes (offline attacker)"
		time_id="kemungkinan bisa dibobol dalam hitungan detik/menit (offline)"
	elif [ "$bits_int" -lt 60 ]; then
		strength_en="WEAK"
		strength_id="LEMAH"
		time_en="minutes to hours for strong attacker"
		time_id="menit hingga jam untuk penyerang kuat"
	elif [ "$bits_int" -lt 80 ]; then
		strength_en="MODERATE"
		strength_id="SEDANG"
		time_en="days to months of brute-force"
		time_id="hari hingga bulan brute-force"
	elif [ "$bits_int" -lt 100 ]; then
		strength_en="STRONG"
		strength_id="KUAT"
		time_en="many years of brute-force"
		time_id="bisa butuh bertahun-tahun brute-force"
	else
		strength_en="VERY STRONG"
		strength_id="SANGAT KUAT"
		time_en="decades or more of brute-force"
		time_id="puluhan tahun atau lebih brute-force"
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "\n[Analisis Kekuatan Password / Password Strength Analysis]\n"
	else
		printf "\n[Password Strength Analysis / Analisis Kekuatan Password]\n"
	fi

	printf "  Length / Panjang          : %d\n" "$len"
	printf "  Entropy / Entropi         : %s bits\n" "$entropy"
	printf "  Types / Jenis karakter    : %s  |  %s\n" "$types_en" "$types_id"
	printf "  Strength / Kekuatan       : %s  |  %s\n" "$strength_en" "$strength_id"
	printf "  Guess time (rough)        : %s  |  %s\n" "$time_en" "$time_id"

	if [ "$SPM_LANG" = "id" ]; then
		printf "  Saran:\n"
	else
		printf "  Suggestions:\n"
	fi

	if [ "$len" -lt 12 ]; then
		printf "   - EN: Use at least 12–16 characters.\n"
		printf "   - ID: Gunakan minimal 12–16 karakter.\n"
	fi
	if [ "$has_lower" -eq 0 ] || [ "$has_upper" -eq 0 ] || [ "$has_digit" -eq 0 ] || [ "$has_symbol" -eq 0 ]; then
		printf "   - EN: Mix lowercase, UPPERCASE, digits, and symbols.\n"
		printf "   - ID: Campur huruf kecil, BESAR, angka, dan simbol.\n"
	fi
	printf "   - EN: Avoid real words, names, or patterns.\n"
	printf "   - ID: Hindari kata asli, nama, atau pola yang mudah ditebak.\n"
	printf "   - EN: Consider using a passphrase of random words.\n"
	printf "   - ID: Pertimbangkan pakai passphrase dari beberapa kata acak.\n"
}

# ----- Cryptographically secure randomness -----------------------------------
# Password material must never come from $RANDOM (a predictable 15-bit LCG).
# Values are drawn from a CSPRNG byte pool with rejection sampling so the
# result is uniform (a plain "% n" would bias the low indices of the charset).
SPM_RAND_POOL=""
SPM_RAND_BYTE=0
SPM_RAND_BELOW=0

# Refill the hex byte pool. Returns 1 if no CSPRNG source is available.
_spm_rand_refill() {
	SPM_RAND_POOL=""
	if command -v openssl >/dev/null 2>&1; then
		SPM_RAND_POOL="$(openssl rand -hex 128 2>/dev/null | tr -d '\n')" || SPM_RAND_POOL=""
	fi
	if [ -z "$SPM_RAND_POOL" ] && [ -r /dev/urandom ]; then
		SPM_RAND_POOL="$(od -An -tx1 -N128 /dev/urandom 2>/dev/null | tr -d ' \n')" || SPM_RAND_POOL=""
	fi
	[ -n "$SPM_RAND_POOL" ]
}

# Pull one random byte (0-255) into SPM_RAND_BYTE.
_spm_rand_byte() {
	if [ "${#SPM_RAND_POOL}" -lt 2 ]; then
		_spm_rand_refill || return 1
	fi
	local h="${SPM_RAND_POOL:0:2}"
	SPM_RAND_POOL="${SPM_RAND_POOL:2}"
	SPM_RAND_BYTE=$(( 16#$h ))
	return 0
}

# Uniform integer in [0, $1) into SPM_RAND_BELOW. Bound must be 1..256.
# Falls back to $RANDOM only if no CSPRNG source exists at all.
_spm_rand_below() {
	local bound="$1" limit
	[ "$bound" -gt 0 ] 2>/dev/null || bound=1
	if [ "$bound" -gt 256 ]; then
		bound=256
	fi
	limit=$(( 256 - (256 % bound) ))
	while :; do
		if ! _spm_rand_byte; then
			die "No cryptographically secure random source is available (need openssl or /dev/urandom)."
		fi
		if [ "$SPM_RAND_BYTE" -lt "$limit" ]; then
			SPM_RAND_BELOW=$(( SPM_RAND_BYTE % bound ))
			return 0
		fi
	done
}

generate_password() {
	local length="${1:-16}"
	local mode="${2:-secure}"   # secure / easy / numeric
	local include_symbols="${3:-1}"
	local include_upper="${4:-1}"
	local include_lower="${5:-1}"
	local include_digits="${6:-1}"

	# simple wordlist for memorable passwords
	local WORDS=(
		"sun" "moon" "star" "river" "ocean" "cloud" "stone" "tree" "leaf" "fern"
		"fire" "ember" "storm" "wind" "breeze" "shadow" "light" "silver" "gold"
		"amber" "flame" "nova" "comet" "aurora" "pulse" "echo" "vapor" "wave"
		"mist" "dawn" "dusk" "zen" "sage" "whale" "lynx" "orca" "hawk" "raven"
	)

	if ! printf '%s' "$length" | grep -Eq '^[0-9]+$'; then
		length=16
	fi
	if [ "$length" -lt 4 ]; then
		length=4
	elif [ "$length" -gt 128 ]; then
		length=128
	fi
	case "$mode" in
		secure|easy|numeric) ;;
		*) mode="secure" ;;
	esac

	if [ "$mode" = "easy" ]; then
		local words_needed
		words_needed="$length"
		[ "$words_needed" -lt 2 ] && words_needed=2
		[ "$words_needed" -gt 8 ] && words_needed=8
		local parts=() idx word
		for (( i=0; i<words_needed; i++ )); do
			_spm_rand_below "${#WORDS[@]}"; idx="$SPM_RAND_BELOW"
			word="${WORDS[idx]}"
			if [ "$include_upper" = "1" ] && [ "$include_lower" != "1" ]; then
				word="$(printf '%s' "$word" | tr '[:lower:]' '[:upper:]')"
			elif [ "$include_upper" = "1" ]; then
				word="$(printf '%s' "$word" | sed 's/^./\U&/')"
			elif [ "$include_lower" != "1" ]; then
				word="$(printf '%s' "$word" | tr '[:lower:]' '[:upper:]')"
			fi
			parts+=("$word")
		done
		local pw
		pw="$(IFS='-'; echo "${parts[*]}")"
		if [ "$include_digits" = "1" ]; then
			_spm_rand_below 100
			pw="${pw}-$(printf '%02d' "$SPM_RAND_BELOW")"
		fi
		if [ "$include_symbols" = "1" ]; then
			local syms="!@#$%^&*"
			_spm_rand_below "${#syms}"
			local s="${syms:$SPM_RAND_BELOW:1}"
			pw="${pw}${s}"
		fi
		printf '%s\n' "$pw"
		return
	fi

	local charset=""
	if [ "$mode" = "numeric" ]; then
		charset="0123456789"
	else
		[ "$include_upper" = "1" ] && charset="${charset}ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		[ "$include_lower" = "1" ] && charset="${charset}abcdefghijklmnopqrstuvwxyz"
		[ "$include_digits" = "1" ] && charset="${charset}0123456789"
		[ "$include_symbols" = "1" ] && charset="${charset}!@#$%^&*()_-+=[]{}:;,.?/|~"
	fi

	if [ -z "$charset" ]; then
		charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	fi

	local pw=""
	local i idx ch set_len
	set_len="${#charset}"

	for (( i=0; i<length; i++ )); do
		_spm_rand_below "$set_len"; idx="$SPM_RAND_BELOW"
		ch="${charset:idx:1}"
		pw+="$ch"
	done

	printf '%s\n' "$pw"
}

cmd_generate_password() {
	local length=16
	local mode="secure"
	local symbols=1
	local upper=1
	local lower=1
	local digits=1

	while [ $# -gt 0 ]; do
		case "$1" in
			-l|--length)
				[ $# -ge 2 ] || die "Missing value for $1."
				length="$2"
				shift 2
				;;
			-m|--mode)
				[ $# -ge 2 ] || die "Missing value for $1."
				mode="$2"
				case "$mode" in secure|easy|numeric) ;; *) die "Invalid generator mode '$mode'." ;; esac
				shift 2
				;;
			--no-symbols)
				symbols=0
				shift
				;;
			--no-upper)
				upper=0
				shift
				;;
			--no-lower)
				lower=0
				shift
				;;
			--no-digits)
				digits=0
				shift
				;;
			-h|--help)
				echo "Usage: $0 generate [--length N] [--mode secure|easy|numeric] [--no-symbols] [--no-upper] [--no-lower] [--no-digits]"
				return 0
				;;
			*)
				die "Unknown generator option '$1'."
				;;
		esac
	done

	local pw
	pw="$(generate_password "$length" "$mode" "$symbols" "$upper" "$lower" "$digits")"
	printf "%s\n\n" "$pw"
	password_strength_report "$pw"
}

# ----- Clipboard + auto-clean -------------------------------------------------

clear_clipboard() {
	local method="$1"
	case "$method" in
		termux)
			if command -v termux-clipboard-set >/dev/null 2>&1; then
				termux-clipboard-set "" >/dev/null 2>&1 || true
			fi
			;;
		macos)
			if command -v pbcopy >/dev/null 2>&1; then
				printf '' | pbcopy >/dev/null 2>&1 || true
			fi
			;;
		xclip)
			if command -v xclip >/dev/null 2>&1; then
				xclip -selection clipboard /dev/null >/dev/null 2>&1 || true
			fi
			;;
		wlcopy)
			if command -v wl-copy >/dev/null 2>&1; then
				printf '' | wl-copy >/dev/null 2>&1 || true
			fi
			;;
	esac
}

copy_password_with_autoclear() {
	local password="$1"
	local method=""
	local copied=0

	if [ "$ENV_FLAVOR" = "termux" ] && command -v termux-clipboard-set >/dev/null 2>&1; then
		termux-clipboard-set "$password" >/dev/null 2>&1 && method="termux" && copied=1
	elif command -v pbcopy >/dev/null 2>&1; then
		printf '%s' "$password" | pbcopy >/dev/null 2>&1 && method="macos" && copied=1
	elif command -v xclip >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
		printf '%s' "$password" | xclip -selection clipboard >/dev/null 2>&1 && method="xclip" && copied=1
	elif command -v wl-copy >/dev/null 2>&1; then
		printf '%s' "$password" | wl-copy >/dev/null 2>&1 && method="wlcopy" && copied=1
	fi

	if [ "$copied" -eq 1 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\n[+] Password disalin ke clipboard. Clipboard akan dikosongkan otomatis dalam ~15 detik.\n"
		else
			printf "\n[+] Password copied to clipboard. Clipboard will be auto-cleared in ~15 seconds.\n"
		fi
		(
			sleep 15
			clear_clipboard "$method"
		) &
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "\n[!] Tidak ada helper clipboard tersedia. Password ditampilkan saja.\n"
		else
			printf "\n[!] No clipboard helper available. Password shown only.\n"
		fi
	fi
}

# ----- Recovery key generation (for init) ------------------------------------

generate_recovery_keypair_and_meta() {
	local vault_plain="$1"

	require_cmd openssl

	if [ "$SPM_LANG" = "id" ]; then
		printf "Membuat pasangan kunci RSA untuk pemulihan (4096-bit)...\n"
	else
		printf "Generating RSA key pair for recovery (4096-bit)...\n"
	fi

	if [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
		printf "Warning: recovery private key '%s' already exists, leaving it as-is.\n" "$RECOVERY_PRIV_DEFAULT"
	else
		if ! openssl genrsa -out "$RECOVERY_PRIV_DEFAULT" 4096 >/dev/null 2>&1; then
			die "Failed to generate RSA private key."
		fi
		chmod 600 "$RECOVERY_PRIV_DEFAULT" 2>/dev/null || true
	fi

	local tmp_pub
	tmp_pub="$(make_tmp)"
	if ! openssl rsa -in "$RECOVERY_PRIV_DEFAULT" -pubout -out "$tmp_pub" >/dev/null 2>&1; then
		secure_wipe "$tmp_pub"
		die "Failed to derive RSA public key from private key."
	fi

	local pub_b64
	pub_b64="$(base64 <"$tmp_pub" | tr -d '\n')"

	printf 'META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n' "$pub_b64" >"$vault_plain"

	VAULT_KEY="$(openssl rand -base64 32 | tr -d '\n')" || die "Failed to generate a random vault key."
	if ! printf '%s' "$VAULT_KEY" | openssl rsautl -encrypt -pubin -inkey "$tmp_pub" -out "$RECOVERY_FILE" 2>/dev/null; then
		secure_wipe "$tmp_pub"
		die "Failed to create recovery file '$RECOVERY_FILE'."
	fi

	secure_wipe "$tmp_pub"
	chmod 600 "$RECOVERY_FILE" 2>/dev/null || true

	printf "\n[RECOVERY SETUP]\n"
	printf "  Private key saved at (in this folder): %s\n" "$RECOVERY_PRIV_DEFAULT"
	printf "  Recovery file saved at                : %s\n" "$RECOVERY_FILE"
	if [ "$SPM_LANG" = "id" ]; then
		printf "SIMPAN PRIVATE KEY INI DI TEMPAT AMAN (offline / USB). Jika hilang, fitur 'forgot' tidak bisa dipakai.\n\n"
	else
		printf "STORE THIS PRIVATE KEY SAFELY (offline / USB). If you lose it, 'forgot' recovery will NOT work.\n\n"
	fi
}

# ----- Password commands -----------------------------------------------------

cmd_init() {
	if [ -f "$VAULT_FILE" ]; then
		die "Vault already exists at '$VAULT_FILE'. If you want a new one, move or delete the old file."
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Inisialisasi vault baru di: %s\n" "$VAULT_FILE"
	else
		printf "Initializing new vault at: %s\n" "$VAULT_FILE"
	fi
	prompt_master_password

	local tmp
	tmp="$(make_tmp)"

	generate_recovery_keypair_and_meta "$tmp"
	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Vault berhasil dibuat.\n"
	else
		printf "Vault created successfully.\n"
	fi
}

cmd_add() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf 'Nama layanan: '
	else
		printf 'Service name: '
	fi
	IFS= read -r service
	[ "$service" ] || die "Service cannot be empty."

	if [ "$SPM_LANG" = "id" ]; then
		printf 'Username / Email: '
	else
		printf 'Username / Email: '
	fi
	IFS= read -r username

	if [ "$SPM_LANG" = "id" ]; then
		printf 'Password (kosongkan untuk auto-generate 32 karakter): '
	else
		printf 'Password (leave empty to auto-generate 32 chars): '
	fi
	stty -echo
	IFS= read -r pw
	stty echo
	printf '\n'

	if [ -z "$pw" ]; then
		if command -v openssl >/dev/null 2>&1; then
			pw="$(openssl rand -base64 48 | tr -d '\n' | head -c 32)"
		else
			pw="$(tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' </dev/urandom | head -c 32)"
		fi
		if [ "$SPM_LANG" = "id" ]; then
			printf 'Password dibuat otomatis: %s\n' "$pw"
		else
			printf 'Generated password: %s\n' "$pw"
		fi
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf 'Catatan (opsional, satu baris): '
	else
		printf 'Notes (optional, single line): '
	fi
	IFS= read -r notes

	local url clean_url
	if [ "$SPM_LANG" = "id" ]; then
		printf 'URL (opsional, https://contoh.com): '
	else
		printf 'URL (optional, https://example.com): '
	fi
	IFS= read -r url
	if ! clean_url="$(sanitize_url "$url")"; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "URL harus diawali http:// atau https://."
		else
			die "URL must start with http:// or https://."
		fi
	fi

	local id created
	id="$(next_id_from_vault "$tmp")"
	created="$(now_iso)"

	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" \
		"$(sanitize_field "$service")" \
		"$(sanitize_field "$username")" \
		"$(sanitize_field "$pw")" \
		"$(sanitize_field "$notes")" \
		"$created" \
		"$clean_url" >>"$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Entry ditambahkan dengan ID %s.\n" "$id"
	else
		printf "Entry added with ID %s.\n" "$id"
	fi

	password_strength_report "$pw"
}

cmd_list() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	print_vault_table "$tmp"

	secure_wipe "$tmp"
}

cmd_get() {
	[ $# -ge 1 ] || die "Usage: $0 get <id | search-pattern>"

	local query="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if printf '%s' "$query" | grep -Eq '^[0-9]+$'; then
		local line
		line="$(get_entry_by_id "$tmp" "$query")" || true
		if [ -z "$line" ]; then
			secure_wipe "$tmp"
			if [ "$SPM_LANG" = "id" ]; then
				die "Tidak ada entry dengan ID $query."
			else
				die "No entry found with ID $query."
			fi
		fi

		IFS=$'\t' read -r id service username password notes created url <<EOF
$line
EOF

		# Backward-compat: old rows might have created_at in notes field
		if [ -z "${created:-}" ] && printf '%s\n' "${notes:-}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
			created="$notes"
			notes=""
		fi

		if [ "$SPM_LANG" = "id" ]; then
			printf "ID:              %s\n" "$id"
			printf "Layanan:         %s\n" "$service"
			printf "Username / Email: %s\n" "$username"
			printf "Password:        %s\n" "$password"
			printf "URL:             %s\n" "${url:-}"
			printf "Catatan:         %s\n" "$notes"
			printf "Dibuat:          %s\n" "$created"
		else
			printf "ID:               %s\n" "$id"
			printf "Service:          %s\n" "$service"
			printf "Username / Email: %s\n" "$username"
			printf "Password:         %s\n" "$password"
			printf "URL:              %s\n" "${url:-}"
			printf "Notes:            %s\n" "$notes"
			printf "Created:          %s\n" "$created"
		fi

		copy_password_with_autoclear "$password"
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "Hasil untuk pola '%s':\n" "$query"
		else
			printf "Matches for pattern '%s':\n" "$query"
		fi
		search_vault "$tmp" "$query"
	fi

	secure_wipe "$tmp"
}

cmd_edit() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Membuka vault di editor: %s\n" "$EDITOR_CMD"
		printf "# Format password: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at<TAB>url\n" >&2
		printf "# Format note    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-\n" >&2
		printf "# Format passphrase: PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-\n" >&2
		printf "# Format backup code: BACKUP_CODE<TAB>id<TAB>label<TAB>base64_codes<TAB>created_at<TAB>-\n" >&2
		printf "# Format authenticator: AUTH<TAB>id<TAB>label<TAB>base32_secret<TAB>period<TAB>created_at<TAB>algorithm\n" >&2
		printf "# Baris meta     : META_RECOVERY_PUBKEY...\n" >&2
	else
		printf "Opening vault in editor: %s\n" "$EDITOR_CMD"
		printf "# Password rows: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at<TAB>url\n" >&2
		printf "# Note rows    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-\n" >&2
		printf "# Passphrase rows: PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-\n" >&2
		printf "# Backup code rows: BACKUP_CODE<TAB>id<TAB>label<TAB>base64_codes<TAB>created_at<TAB>-\n" >&2
		printf "# Authenticator rows: AUTH<TAB>id<TAB>label<TAB>base32_secret<TAB>period<TAB>created_at<TAB>algorithm\n" >&2
		printf "# Meta row     : META_RECOVERY_PUBKEY...\n" >&2
	fi

	# EDITOR commonly carries arguments ("code --wait"); running the whole value
	# as one executable name made every such configuration fail.
	local editor_argv=()
	read -r -a editor_argv <<<"$EDITOR_CMD"
	[ "${#editor_argv[@]}" -gt 0 ] || editor_argv=(nano)
	"${editor_argv[@]}" "$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Vault diperbarui.\n"
	else
		printf "Vault updated.\n"
	fi
}

cmd_change_master() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	require_cmd openssl

	local tmp
	tmp="$(make_tmp)"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Masukkan kata sandi utama LAMA untuk membuka vault.\n"
	else
		printf "Enter OLD master password to decrypt vault.\n"
	fi
	decrypt_vault_to_file "$tmp"

	# A legacy vault is migrated FIRST, while MASTER_PW is still the old
	# password -- so the key envelope and the recovery file agree at every
	# instant. Doing it after the prompt would seal the envelope under the new
	# password while .recovery still named the old one, and neither would open
	# the vault if the process died in between.
	local migrated=0
	if [ -z "${VAULT_KEY:-}" ]; then
		encrypt_file_to_vault "$tmp"
		migrated=1
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Masukkan kata sandi utama BARU.\n"
	else
		printf "Enter NEW master password.\n"
	fi
	prompt_master_password

	# Only the small envelope is rewritten. The vault ciphertext and the
	# recovery file both key off the vault key, which does not change.
	rewrap_vault_key "$MASTER_PW"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Kata sandi utama berhasil diubah.\n"
		if [ "$migrated" -eq 1 ]; then
			printf "Vault dimigrasikan ke format kunci terbungkus.\n"
			printf "File pemulihan diperbarui di: %s\n" "$RECOVERY_FILE"
		else
			printf "Kunci vault dibungkus ulang; data vault dan file pemulihan tidak berubah.\n"
		fi
	else
		printf "Master password changed successfully.\n"
		if [ "$migrated" -eq 1 ]; then
			printf "The vault was migrated to the wrapped-key format.\n"
			printf "Recovery file updated at: %s\n" "$RECOVERY_FILE"
		else
			printf "Vault key rewrapped; the vault data and recovery file are unchanged.\n"
		fi
	fi
}

cmd_delete() {
	[ $# -ge 1 ] || die "Usage: $0 delete <id>"

	local target_id="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! awk -F '\t' -v target="$target_id" '$1 ~ /^[0-9]+$/ && $1 == target {found=1} END {exit(found?0:1)}' "$tmp"; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada entry dengan ID $target_id."
		else
			die "No entry found with ID $target_id."
		fi
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target_id" '
		!($1 ~ /^[0-9]+$/ && $1 == target) {print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Entry dengan ID %s dihapus.\n" "$target_id"
	else
		printf "Entry with ID %s deleted.\n" "$target_id"
	fi
}

# ----- Secure notes commands -------------------------------------------------

cmd_notes_add() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Judul catatan: "
	else
		printf "Note title: "
	fi
	IFS= read -r title
	[ -n "$title" ] || die "Title cannot be empty."

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nTulis isi catatan. Akhiri dengan Ctrl+D di baris baru.\n\n"
	else
		printf "\nType your note content. Finish with Ctrl+D on a new line.\n\n"
	fi

	local tmp_note
	tmp_note="$(make_tmp)"
	cat >"$tmp_note"

	local body_b64
	body_b64="$(base64 <"$tmp_note" | tr -d '\n')"
	local note_id created
	note_id="$(next_note_id_from_vault "$tmp")"
	created="$(now_iso)"

	printf 'NOTE\t%s\t%s\t%s\t%s\t-\n' "$note_id" "$(sanitize_field "$title")" "$body_b64" "$created" >>"$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"
	secure_wipe "$tmp_note"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nCatatan aman ditambahkan dengan ID %s.\n" "$note_id"
	else
		printf "\nSecure note added with ID %s.\n" "$note_id"
	fi
}

cmd_notes_list() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "%-5s  %-30s  %-20s\n" "ID" "Judul" "Dibuat"
	else
		printf "%-5s  %-30s  %-20s\n" "ID" "Title" "Created"
	fi
	printf '%.0s-' $(seq 1 70)
	printf '\n'

	# Print notes
	awk -F '\t' '
		$1=="NOTE" {
			printf "%-5s  %-30s  %-20s\n", $2, $3, $5;
		}
	' "$tmp"

	# Count notes (separate, simpler, and portable)
	local count
	count="$(awk -F '\t' '$1=="NOTE"{n++} END{print n+0}' "$tmp")"

	if [ "$count" -eq 0 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nTidak ada catatan.\n"
		else
			printf "\nNo notes.\n"
		fi
	fi

	secure_wipe "$tmp"
}

cmd_notes_view() {
	[ $# -ge 1 ] || die "Usage: $0 notes-view <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	local line
	line="$(awk -F '\t' -v target="$target" '$1=="NOTE" && $2==target {print $0; exit}' "$tmp")" || true

	if [ -z "$line" ]; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada catatan dengan ID $target."
		else
			die "No note found with ID $target."
		fi
	fi

	local tag nid title body_b64 created dummy
	IFS=$'\t' read -r tag nid title body_b64 created dummy <<EOF
$line
EOF

	local tmp_note
	tmp_note="$(make_tmp)"
	if ! printf '%s' "$body_b64" | base64 -d >"$tmp_note" 2>/dev/null; then
		secure_wipe "$tmp_note"
		secure_wipe "$tmp"
		die "Failed to decode note body (base64)."
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "ID:      %s\n" "$nid"
		printf "Judul:   %s\n" "$title"
		printf "Dibuat:  %s\n" "$created"
		printf "\nIsi catatan:\n\n"
	else
		printf "ID:      %s\n" "$nid"
		printf "Title:   %s\n" "$title"
		printf "Created: %s\n" "$created"
		printf "\nNote content:\n\n"
	fi

	cat "$tmp_note"

	secure_wipe "$tmp_note"
	secure_wipe "$tmp"
}

cmd_notes_delete() {
	[ $# -ge 1 ] || die "Usage: $0 notes-delete <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! awk -F '\t' -v target="$target" '$1=="NOTE" && $2==target {found=1} END{exit(found?0:1)}' "$tmp"; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada catatan dengan ID $target."
		else
			die "No note found with ID $target."
		fi
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target" '
		!($1=="NOTE" && $2==target) {print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Catatan dengan ID %s dihapus.\n" "$target"
	else
		printf "Note with ID %s deleted.\n" "$target"
	fi
}

# ----- Passphrase commands ---------------------------------------------------

cmd_passphrase_add() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Label passphrase: "
	else
		printf "Passphrase label: "
	fi
	IFS= read -r label
	[ -n "$label" ] || die "Label cannot be empty."

	if [ "$SPM_LANG" = "id" ]; then
		printf "Passphrase (kosongkan untuk auto-generate 32 karakter): "
	else
		printf "Passphrase (blank to auto-generate 32 chars): "
	fi
	stty -echo
	IFS= read -r secret
	stty echo
	printf '\n'

	if [ -z "$secret" ]; then
		if command -v openssl >/dev/null 2>&1; then
			secret="$(openssl rand -base64 48 | tr -d '\n' | head -c 32)"
		else
			secret="$(tr -dc 'A-Za-z0-9!@#$%^&*()_+-=' </dev/urandom | head -c 32)"
		fi
		if [ "$SPM_LANG" = "id" ]; then
			printf "Passphrase dibuat otomatis.\n"
		else
			printf "Passphrase auto-generated.\n"
		fi
	fi

	local pass_id created
	pass_id="$(next_passphrase_id_from_vault "$tmp")"
	created="$(now_iso)"
	local secret_b64
	secret_b64="$(printf '%s' "$secret" | base64 | tr -d '\n')"

	printf 'PASSPHRASE\t%s\t%s\t%s\t%s\t-\n' "$pass_id" "$(sanitize_field "$label")" "$secret_b64" "$created" >>"$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Passphrase ditambahkan dengan ID %s.\n" "$pass_id"
	else
		printf "Passphrase added with ID %s.\n" "$pass_id"
	fi
}

cmd_passphrase_list() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "%-5s  %-30s  %-20s\n" "ID" "Label" "Dibuat"
	else
		printf "%-5s  %-30s  %-20s\n" "ID" "Label" "Created"
	fi
	printf '%.0s-' $(seq 1 70)
	printf '\n'

	awk -F '\t' '
		$1=="PASSPHRASE" {
			printf "%-5s  %-30s  %-20s\n", $2, $3, $5;
		}
	' "$tmp"

	local count
	count="$(awk -F '\t' '$1=="PASSPHRASE"{n++} END{print n+0}' "$tmp")"
	if [ "$count" -eq 0 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nTidak ada passphrase.\n"
		else
			printf "\nNo passphrases stored.\n"
		fi
	fi

	secure_wipe "$tmp"
}

cmd_passphrase_view() {
	[ $# -ge 1 ] || die "Usage: $0 passphrase-view <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	# Require re-verification for sensitive viewing
	re_verify_master_password

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	local line
	line="$(awk -F '\t' -v target="$target" '$1=="PASSPHRASE" && $2==target {print $0; exit}' "$tmp")" || true
	if [ -z "$line" ]; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada passphrase dengan ID $target."
		else
			die "No passphrase found with ID $target."
		fi
	fi

	local tag pid label secret_b64 created dummy
	IFS=$'\t' read -r tag pid label secret_b64 created dummy <<EOF
$line
EOF
	: "$tag" "$dummy"

	local tmp_secret
	tmp_secret="$(make_tmp)"
	if ! printf '%s' "$secret_b64" | base64 -d >"$tmp_secret" 2>/dev/null; then
		secure_wipe "$tmp_secret"
		secure_wipe "$tmp"
		die "Failed to decode passphrase (base64)."
	fi

	local secret_value
	secret_value="$(cat "$tmp_secret")"

	if [ "$SPM_LANG" = "id" ]; then
		printf "ID:        %s\n" "$pid"
		printf "Label:     %s\n" "$label"
		printf "Dibuat:    %s\n" "$created"
		printf "Passphrase:%s\n" " "
	else
		printf "ID:        %s\n" "$pid"
		printf "Label:     %s\n" "$label"
		printf "Created:   %s\n" "$created"
		printf "Passphrase:%s\n" " "
	fi

	printf "%s\n" "$secret_value"
	copy_password_with_autoclear "$secret_value"

	secure_wipe "$tmp_secret"
	secure_wipe "$tmp"
}

cmd_passphrase_delete() {
	[ $# -ge 1 ] || die "Usage: $0 passphrase-delete <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! awk -F '\t' -v target="$target" '$1=="PASSPHRASE" && $2==target {found=1} END{exit(found?0:1)}' "$tmp"; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada passphrase dengan ID $target."
		else
			die "No passphrase found with ID $target."
		fi
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target" '
		!($1=="PASSPHRASE" && $2==target) {print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Passphrase dengan ID %s dihapus.\n" "$target"
	else
		printf "Passphrase with ID %s deleted.\n" "$target"
	fi
}

# ----- Authenticator (TOTP) commands ----------------------------------------

_spm_totp_code() {
	local secret="$1"
	local period="$2"
	local algo="${3:-sha1}"
	python3 - "$secret" "$period" "$algo" <<'PY'
import base64, hashlib, hmac, struct, time, sys
secret = (sys.argv[1] if len(sys.argv) > 1 else "").replace(" ", "").upper()
if not secret:
    sys.exit(1)
period = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() and int(sys.argv[2]) > 0 else 30
algo = sys.argv[3].lower() if len(sys.argv) > 3 else "sha1"
if algo not in ("sha1", "sha256", "sha512"):
    algo = "sha1"
try:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
except Exception:
    sys.exit(1)
counter = int(time.time() // period)
msg = struct.pack(">Q", counter)
digest_mod = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}[algo]
h = hmac.new(key, msg, digest_mod).digest()
offset = h[-1] & 0x0F
code_int = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
code = str(code_int % 10**6).zfill(6)
print(code)
PY
}

cmd_authenticator_add() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Label authenticator: "
	else
		printf "Authenticator label: "
	fi
	IFS= read -r label
	[ -n "$label" ] || die "Label cannot be empty."

	if [ "$SPM_LANG" = "id" ]; then
		printf "Secret (Base32, contoh: JBSWY3DPEHPK3PXP): "
	else
		printf "Secret (Base32, e.g., JBSWY3DPEHPK3PXP): "
	fi
	stty -echo
	IFS= read -r secret
	stty echo
	printf '\n'
	secret="${secret//[[:space:]]/}"
	[ -n "$secret" ] || die "Secret cannot be empty."

	local period
	if [ "$SPM_LANG" = "id" ]; then
		printf "Interval refresh (detik, default 30): "
	else
		printf "Refresh interval (seconds, default 30): "
	fi
	read -r period || true
	if ! printf '%s' "$period" | grep -Eq '^[0-9]+$'; then
		period="30"
	fi
	[ "$period" -gt 0 ] 2>/dev/null || period="30"

	local algo
	if [ "$SPM_LANG" = "id" ]; then
		printf "Algoritma (sha1/sha256/sha512) [sha1]: "
	else
		printf "Algorithm (sha1/sha256/sha512) [sha1]: "
	fi
	read -r algo || true
	case "${algo,,}" in
		sha1|sha256|sha512) ;;
		*) algo="sha1" ;;
	esac

	# validate secret by generating code
	if ! _spm_totp_code "$secret" "$period" "$algo" >/dev/null 2>&1; then
		die "Invalid Base32 secret for TOTP."
	fi

	local auth_id created
	auth_id="$(next_authenticator_id_from_vault "$tmp")"
	created="$(now_iso)"
	local secret_b32
	secret_b32="$(printf '%s' "$secret" | tr -d '\n' | tr '[:lower:]' '[:upper:]')"

	printf 'AUTH\t%s\t%s\t%s\t%s\t%s\t%s\n' "$auth_id" "$(sanitize_field "$label")" "$secret_b32" "$period" "$created" "$algo" >>"$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Authenticator ditambahkan dengan ID %s.\n" "$auth_id"
	else
		printf "Authenticator added with ID %s.\n" "$auth_id"
	fi
}

cmd_authenticator_list() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "%-5s  %-24s  %-8s  %-8s  %-20s\n" "ID" "Label" "Interval" "Algo" "Dibuat"
	else
		printf "%-5s  %-24s  %-8s  %-8s  %-20s\n" "ID" "Label" "Interval" "Algo" "Created"
	fi
	printf '%.0s-' $(seq 1 85)
	printf '\n'

	awk -F '\t' '
		$1=="AUTH" {
			period=($5? $5 : $4);
			created=($6? $6 : $5);
			algo=($7? $7 : "sha1");
			printf "%-5s  %-24s  %-8s  %-8s  %-20s\n", $2, $3, period, algo, created;
		}
	' "$tmp"

	local count
	count="$(awk -F '\t' '$1=="AUTH"{n++} END{print n+0}' "$tmp")"
	if [ "$count" -eq 0 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nTidak ada authenticator.\n"
		else
			printf "\nNo authenticators stored.\n"
		fi
	fi

	secure_wipe "$tmp"
}

cmd_authenticator_view() {
	[ $# -ge 1 ] || die "Usage: $0 authenticator-view <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	re_verify_master_password

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	local line
	line="$(awk -F '\t' -v target="$target" '$1=="AUTH" && $2==target {print $0; exit}' "$tmp")" || true
	if [ -z "$line" ]; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada authenticator dengan ID $target."
		else
			die "No authenticator found with ID $target."
		fi
	fi

	local tag aid label secret_b32 period created algo
	IFS=$'\t' read -r tag aid label secret_b32 period created algo <<EOF
$line
EOF

	local period_sec
	if printf '%s' "$period" | grep -Eq '^[0-9]+$'; then
		period_sec="$period"
	else
		period_sec=30
	fi
	[ "$period_sec" -gt 0 ] 2>/dev/null || period_sec=30
	[ -n "$algo" ] || algo="sha1"

	if [ "$SPM_LANG" = "id" ]; then
		printf "ID:       %s\n" "$aid"
		printf "Label:    %s\n" "$label"
		printf "Interval: %s detik\n" "$period_sec"
		printf "Dibuat:   %s\n" "$created"
		printf "Algoritma: %s\n" "$algo"
		printf "Secret:   %s\n" "$secret_b32"
		printf "Kode OTP (live, Ctrl+C untuk keluar):\n"
	else
		printf "ID:       %s\n" "$aid"
		printf "Label:    %s\n" "$label"
		printf "Interval: %s seconds\n" "$period_sec"
		printf "Created:  %s\n" "$created"
		printf "Algo:     %s\n" "$algo"
		printf "Secret:   %s\n" "$secret_b32"
		printf "OTP Code (live, Ctrl+C to stop):\n"
	fi

	trap 'printf "\n"; secure_wipe "$tmp"; exit 0' INT TERM

	while true; do
		local code
		code="$(_spm_totp_code "$secret_b32" "$period_sec" "$algo" 2>/dev/null || true)"
		local now rem
		now="$(date +%s)"
		rem=$((period_sec - (now % period_sec)))
		if [ "$rem" -le 0 ]; then
			rem="$period_sec"
		fi

		if [ "$SPM_LANG" = "id" ]; then
			printf "\rKode: %s  (refresh dalam %2ds)   " "${code:-"------"}" "$rem"
		else
			printf "\rCode: %s  (refresh in %2ds)   " "${code:-"------"}" "$rem"
		fi
		sleep 1
	done
}

cmd_authenticator_edit() {
	[ $# -ge 1 ] || die "Usage: $0 authenticator-edit <id>"
	local target="$1"
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	local line
	line="$(awk -F '\t' -v target="$target" '$1=="AUTH" && $2==target {print $0; exit}' "$tmp")" || true
	if [ -z "$line" ]; then
		secure_wipe "$tmp"
		die "Authenticator not found."
	fi

	local tag aid label secret_b32 period created algo
	IFS=$'\t' read -r tag aid label secret_b32 period created algo <<EOF
$line
EOF
	: "$tag"
	[ -n "$algo" ] || algo="sha1"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Label baru (kosong = tetap \"%s\"): " "$label"
	else
		printf "New label (blank keeps \"%s\"): " "$label"
	fi
	IFS= read -r new_label
	[ -n "$new_label" ] && label="$new_label"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Secret baru Base32 (kosong = tetap): "
	else
		printf "New Base32 secret (blank keeps current): "
	fi
	stty -echo
	IFS= read -r new_secret
	stty echo
	printf '\n'
	new_secret="${new_secret//[[:space:]]/}"
	[ -n "$new_secret" ] && secret_b32="$new_secret"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Interval baru (detik, kosong = %s): " "$period"
	else
		printf "New interval (seconds, blank = %s): " "$period"
	fi
	read -r new_period || true
	if printf '%s' "$new_period" | grep -Eq '^[0-9]+$'; then
		period="$new_period"
	fi
	[ "$period" -gt 0 ] 2>/dev/null || period="30"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Algorithm (sha1/sha256/sha512, kosong = %s): " "$algo"
	else
		printf "Algorithm (sha1/sha256/sha512, blank = %s): " "$algo"
	fi
	read -r new_algo || true
	case "${new_algo,,}" in
		sha1|sha256|sha512) algo="$new_algo" ;;
		*) ;;
	esac

	if ! _spm_totp_code "$secret_b32" "$period" "$algo" >/dev/null 2>&1; then
		secure_wipe "$tmp"
		die "Invalid secret or interval."
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target" -v label="$label" -v secret="$secret_b32" -v period="$period" -v created="$created" -v algo="$algo" '
		$1=="AUTH" && $2==target {
			printf "AUTH\t%s\t%s\t%s\t%s\t%s\t%s\n", $2, label, secret, period, created, algo;
			next
		}
		{print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Authenticator ID %s diperbarui.\n" "$target"
	else
		printf "Authenticator ID %s updated.\n" "$target"
	fi
}

cmd_authenticator_delete() {
	[ $# -ge 1 ] || die "Usage: $0 authenticator-delete <id>"
	local target="$1"
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! awk -F '\t' -v target="$target" '$1=="AUTH" && $2==target {found=1} END{exit(found?0:1)}' "$tmp"; then
		secure_wipe "$tmp"
		die "Authenticator not found."
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target" '
		!($1=="AUTH" && $2==target) {print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Authenticator ID %s dihapus.\n" "$target"
	else
		printf "Authenticator ID %s deleted.\n" "$target"
	fi
}

# ----- Backup codes commands -------------------------------------------------

cmd_backup_codes_add() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Label untuk kode backup (contoh: Google 2FA, GitHub Recovery): "
	else
		printf "Label for backup codes (e.g., Google 2FA, GitHub Recovery): "
	fi
	IFS= read -r label
	[ -n "$label" ] || die "Label cannot be empty."

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nMasukkan kode backup, satu per baris. Akhiri dengan Ctrl+D di baris baru.\n\n"
	else
		printf "\nEnter backup codes, one per line. Finish with Ctrl+D on a new line.\n\n"
	fi

	local tmp_codes
	tmp_codes="$(make_tmp)"
	cat >"$tmp_codes"

	local codes_b64
	codes_b64="$(base64 <"$tmp_codes" | tr -d '\n')"
	local bc_id created
	bc_id="$(next_backup_code_id_from_vault "$tmp")"
	created="$(now_iso)"

	printf 'BACKUP_CODE\t%s\t%s\t%s\t%s\t-\n' "$bc_id" "$(sanitize_field "$label")" "$codes_b64" "$created" >>"$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"
	secure_wipe "$tmp_codes"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nKode backup ditambahkan dengan ID %s.\n" "$bc_id"
	else
		printf "\nBackup codes added with ID %s.\n" "$bc_id"
	fi
}

cmd_backup_codes_list() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "%-5s  %-30s  %-20s\n" "ID" "Label" "Dibuat"
	else
		printf "%-5s  %-30s  %-20s\n" "ID" "Label" "Created"
	fi
	printf '%.0s-' $(seq 1 70)
	printf '\n'

	awk -F '\t' '
		$1=="BACKUP_CODE" {
			printf "%-5s  %-30s  %-20s\n", $2, $3, $5;
		}
	' "$tmp"

	local count
	count="$(awk -F '\t' '$1=="BACKUP_CODE"{n++} END{print n+0}' "$tmp")"

	if [ "$count" -eq 0 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nTidak ada kode backup.\n"
		else
			printf "\nNo backup codes.\n"
		fi
	fi

	secure_wipe "$tmp"
}

cmd_backup_codes_view() {
	[ $# -ge 1 ] || die "Usage: $0 backup-codes-view <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	# Re-verify master password before viewing sensitive backup codes
	re_verify_master_password

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	local line
	line="$(awk -F '\t' -v target="$target" '$1=="BACKUP_CODE" && $2==target {print $0; exit}' "$tmp")" || true

	if [ -z "$line" ]; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada kode backup dengan ID $target."
		else
			die "No backup code found with ID $target."
		fi
	fi

	local bc_id label codes_b64 created
	IFS=$'\t' read -r _ bc_id label codes_b64 created _ <<EOF
$line
EOF

	local tmp_codes
	tmp_codes="$(make_tmp)"
	if ! printf '%s' "$codes_b64" | base64 -d >"$tmp_codes" 2>/dev/null; then
		secure_wipe "$tmp_codes"
		secure_wipe "$tmp"
		die "Failed to decode backup codes (base64)."
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "ID:      %s\n" "$bc_id"
		printf "Label:   %s\n" "$label"
		printf "Dibuat:  %s\n" "$created"
		printf "\nIsi kode backup:\n\n"
	else
		printf "ID:      %s\n" "$bc_id"
		printf "Label:   %s\n" "$label"
		printf "Created: %s\n" "$created"
		printf "\nBackup codes content:\n\n"
	fi

	cat "$tmp_codes"

	secure_wipe "$tmp_codes"
	secure_wipe "$tmp"
}

cmd_backup_codes_delete() {
	[ $# -ge 1 ] || die "Usage: $0 backup-codes-delete <id>"
	local target="$1"

	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! awk -F '\t' -v target="$target" '$1=="BACKUP_CODE" && $2==target {found=1} END{exit(found?0:1)}' "$tmp"; then
		secure_wipe "$tmp"
		if [ "$SPM_LANG" = "id" ]; then
			die "Tidak ada kode backup dengan ID $target."
		else
			die "No backup code found with ID $target."
		fi
	fi

	local tmp2
	tmp2="$(make_tmp)"
	awk -F '\t' -v target="$target" '
		!($1=="BACKUP_CODE" && $2==target) {print $0}
	' "$tmp" >"$tmp2"

	encrypt_file_to_vault "$tmp2"
	secure_wipe "$tmp"
	secure_wipe "$tmp2"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Kode backup dengan ID %s dihapus.\n" "$target"
	else
		printf "Backup code with ID %s deleted.\n" "$target"
	fi
}


# ----- Portable & save bundles -----------------------------------------------





cmd_portable() {
	[ -f "$VAULT_FILE" ] || die "Vault not found at '$VAULT_FILE'. Nothing to export."

	local bundle_name="${1:-"spm_portable_$(date +%Y%m%d_%H%M%S)"}"
	validate_bundle_name "$bundle_name"
	local workdir="./$bundle_name"
	local has_recovery="no"
	local has_priv="no"

	if [ -e "$workdir" ]; then
		die "Target directory '$workdir' already exists. Choose another name."
	fi
	if [ -e "${bundle_name}.zip" ] || [ -e "${bundle_name}.tar.gz" ]; then
		die "Target archive for '$bundle_name' already exists. Choose another name."
	fi

	mkdir -p "$workdir" || die "Failed to create directory '$workdir'."

	# Copy script
	if [ -f "$SCRIPT_SRC" ]; then
		cp "$SCRIPT_SRC" "$workdir/spm.sh" || die "Failed to copy script to bundle."
	else
		die "Cannot resolve script source '$SCRIPT_SRC'."
	fi
	chmod +x "$workdir/spm.sh" 2>/dev/null || true

	# Copy vault
	cp "$VAULT_FILE" "$workdir/spm_vault.gpg" || die "Failed to copy vault to bundle."

	# Copy recovery file if exists
	if [ -f "$RECOVERY_FILE" ]; then
		cp "$RECOVERY_FILE" "$workdir/spm_vault.gpg.recovery" || die "Failed to copy recovery file to bundle."
		has_recovery="yes"
	fi

	# Keep the recovery private key separate by default. Putting it beside the
	# encrypted recovery blob makes possession of one archive equivalent to
	# possession of the master password.
	if [ "${SPM_BUNDLE_INCLUDE_RECOVERY_KEY:-0}" = "1" ] && [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
		cp "$RECOVERY_PRIV_DEFAULT" "$workdir/spm_recovery_private.pem" || die "Failed to copy private key to bundle."
		has_priv="yes"
	fi

	local created_on
	created_on="$(now_iso)"

	# Bundle-local README (EN + ID)
	cat >"$workdir/README.txt" <<EOF
Sans Password Manager (SPM) - Portable Bundle
=============================================

Created: $created_on
Bundle:  $bundle_name

[EN]

This archive is a portable bundle of Sans Password Manager (SPM).

Included files:
  - spm.sh                : main SPM script (Bash)
  - spm_vault.gpg         : encrypted password vault
  - spm_vault.gpg.recovery (optional)
                          : recovery file used with your RSA private key
  - spm_recovery_private.pem (explicit opt-in only)
                          : included only with SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1
  - README.txt            : this instructions file

Usage:
  1. Ensure dependencies are available on this machine:
       - bash, gpg, openssl, curl, zip (or tar), and optional clipboard helpers
  2. Make the script executable if needed:
       chmod +x ./spm.sh
  3. Run:
       ./spm.sh
  4. SPM will:
       - check requirements,
       - ask for language (EN / ID),
       - ask for your master password to open the vault.

Security notes:
  - The recovery private key is excluded by default. Store it separately.
  - SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1 creates a self-contained recovery archive; possession of that archive bypasses the master password.
  - With the private key + this bundle’s recovery file, you can use
    the "forgot password" feature to reset your master password.
  - Anyone who gets both your private key AND this bundle may be able
    to recover your vault depending on your settings. Protect them.

To move to another device:
  - Copy the ZIP / tar.gz file to the target device.
  - Extract it into a folder.
  - Run ./spm.sh from within that folder.

------------------------------------------------------------

[ID]

Arsip ini adalah bundle portabel dari Sans Password Manager (SPM).

File yang disertakan:
  - spm.sh                : script utama SPM (Bash)
  - spm_vault.gpg         : vault kata sandi terenkripsi
  - spm_vault.gpg.recovery (opsional)
                          : file pemulihan yang digunakan bersama private key RSA
  - spm_recovery_private.pem (hanya jika diaktifkan eksplisit)
                          : disertakan hanya dengan SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1
  - README.txt            : file petunjuk ini

Cara pakai:
  1. Pastikan dependensi tersedia di perangkat ini:
       - bash, gpg, openssl, curl, zip (atau tar),
         dan helper clipboard (opsional)
  2. Jadikan script bisa dieksekusi (jika perlu):
       chmod +x ./spm.sh
  3. Jalankan:
       ./spm.sh
  4. SPM akan:
       - cek requirement,
       - menanyakan bahasa (EN / ID),
       - menanyakan kata sandi utama (master password) untuk membuka vault.

Catatan keamanan:
  - Private key pemulihan tidak disertakan secara default. Simpan secara terpisah.
  - SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1 membuat arsip pemulihan lengkap; siapa pun yang memiliki arsip itu dapat melewati kata sandi utama.
  - Dengan private key + file pemulihan di bundle ini, kamu bisa
    menggunakan fitur "lupa password" untuk reset master password.
  - Jika orang lain mendapatkan bundle ini DAN private key-mu,
    ada kemungkinan vault bisa dipulihkan. Lindungi keduanya.

Untuk dipindahkan ke perangkat lain:
  - Salin file ZIP / tar.gz ke perangkat tujuan.
  - Ekstrak ke sebuah folder.
  - Jalankan ./spm.sh dari dalam folder tersebut.

EOF

	# Create archive
	if command -v zip >/dev/null 2>&1; then
		zip -rq "${bundle_name}.zip" "$bundle_name" || die "Failed to create zip archive."
		if [ "$SPM_LANG" = "id" ]; then
			printf "Bundle portable dibuat: %s\n" "${bundle_name}.zip"
		else
			printf "Portable bundle created: %s\n" "${bundle_name}.zip"
		fi
	else
		tar -czf "${bundle_name}.tar.gz" "$bundle_name" || die "Failed to create tar.gz archive."
		if [ "$SPM_LANG" = "id" ]; then
			printf "Peringatan: 'zip' tidak ditemukan. Dibuat tar.gz: %s\n" "${bundle_name}.tar.gz"
		else
			printf "Warning: 'zip' not found. Created tar.gz instead: %s\n" "${bundle_name}.tar.gz"
		fi
	fi

	# Print contents summary
	printf "Contents:\n"
	printf "  - %s/spm.sh\n" "$bundle_name"
	printf "  - %s/spm_vault.gpg\n" "$bundle_name"
	if [ "$has_recovery" = "yes" ]; then
		printf "  - %s/spm_vault.gpg.recovery\n" "$bundle_name"
	fi
	if [ "$has_priv" = "yes" ]; then
		printf "  - %s/spm_recovery_private.pem\n" "$bundle_name"
	fi
	printf "  - %s/README.txt\n" "$bundle_name"
}

# ----- Save (backup + wipe local data) ---------------------------------------

cmd_save() {
	[ -f "$VAULT_FILE" ] || die "Vault not found at '$VAULT_FILE'. Nothing to save."

	# If user provides a name: use that. Else: auto timestamp.
	local input_name="${1:-""}"
	local bundle_name
	if [ -n "$input_name" ]; then
		bundle_name="$input_name"
	else
		bundle_name="spm_save_$(date +%Y%m%d_%H%M%S)"
	fi
	validate_bundle_name "$bundle_name"

	local workdir="./$bundle_name"
	local has_recovery="no"
	local has_priv="no"
	local archive_path=""

	if [ -e "$workdir" ]; then
		die "Target directory '$workdir' already exists. Choose another name."
	fi
	if [ -e "${bundle_name}.zip" ] || [ -e "${bundle_name}.tar.gz" ]; then
		die "Target archive for '$bundle_name' already exists. Choose another name."
	fi

	mkdir -p "$workdir" || die "Failed to create directory '$workdir'."

	# Copy script into bundle
	if [ -f "$SCRIPT_SRC" ]; then
		cp "$SCRIPT_SRC" "$workdir/spm.sh" || die "Failed to copy script to bundle."
	else
		die "Cannot resolve script source '$SCRIPT_SRC'."
	fi
	chmod +x "$workdir/spm.sh" 2>/dev/null || true

	# Copy vault
	cp "$VAULT_FILE" "$workdir/spm_vault.gpg" || die "Failed to copy vault."

	# Copy recovery file if exists
	if [ -f "$RECOVERY_FILE" ]; then
		cp "$RECOVERY_FILE" "$workdir/spm_vault.gpg.recovery" || die "Failed to copy recovery file."
		has_recovery="yes"
	fi

	# Exclude the recovery key unless the user explicitly asks for a single
	# self-contained (and therefore master-password-bypassing) archive.
	if [ "${SPM_BUNDLE_INCLUDE_RECOVERY_KEY:-0}" = "1" ] && [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
		cp "$RECOVERY_PRIV_DEFAULT" "$workdir/spm_recovery_private.pem" || die "Failed to copy private key."
		has_priv="yes"
	fi

	local created_on
	created_on="$(now_iso)"

	# Bilingual README for backup bundle
	cat >"$workdir/README.txt" <<EOF
Sans Password Manager (SPM) - Backup Save Bundle
================================================

Created: $created_on
Bundle:  $bundle_name

This bundle is a secure backup of your SPM vault. After saving, SPM wipes
the local vault from this device.

------------------------------------------------------------
[EN]

Included files:
  - spm.sh                 : executable SPM script
  - spm_vault.gpg          : encrypted vault
  - spm_vault.gpg.recovery : (optional) recovery file
  - spm_recovery_private.pem : explicit opt-in with SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1
  - README.txt             : instructions

How to restore:
  1. Move this archive to the target device.
  2. Extract it into a folder.
  3. Run:
       ./spm.sh
  4. Enter your master password to access your vault.

Security notes:
  - Keep this backup offline (USB, encrypted disk, cloud with 2FA).
  - The recovery private key is excluded by default and should be stored separately.
  - With SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1, the archive can bypass the master password; protect it accordingly.
  - Anyone with both this bundle and your private key could reset the vault password.

------------------------------------------------------------
[ID]

File yang disertakan:
  - spm.sh                   : script SPM
  - spm_vault.gpg            : vault terenkripsi
  - spm_vault.gpg.recovery   : (opsional) file pemulihan
  - spm_recovery_private.pem : hanya dengan SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1
  - README.txt               : petunjuk

Cara mengembalikan:
  1. Pindahkan arsip ini ke perangkat tujuan.
  2. Ekstrak ke sebuah folder.
  3. Jalankan:
       ./spm.sh
  4. Masukkan master password.

Catatan keamanan:
  - Simpan backup di tempat aman (USB, disk terenkripsi, cloud dengan 2FA).
  - Private key pemulihan tidak disertakan secara default dan harus disimpan terpisah.
  - Dengan SPM_BUNDLE_INCLUDE_RECOVERY_KEY=1, arsip dapat melewati kata sandi utama; lindungi dengan ketat.
  - Jika orang lain mendapatkan bundle ini + private key, mereka bisa mereset master password.

EOF

	# Create archive (zip preferred, tar.gz fallback)
	if command -v zip >/dev/null 2>&1; then
		archive_path="${bundle_name}.zip"
		zip -rq "$archive_path" "$bundle_name" || die "Failed to create zip."
		if [ "$SPM_LANG" = "id" ]; then
			printf "Bundle penyimpanan dibuat: %s\n" "$archive_path"
		else
			printf "Save bundle created: %s\n" "$archive_path"
		fi
	else
		archive_path="${bundle_name}.tar.gz"
		tar -czf "$archive_path" "$bundle_name" || die "Failed to create tar.gz."
		if [ "$SPM_LANG" = "id" ]; then
			printf "Zip tidak ditemukan. Dibuat tar.gz: %s\n" "$archive_path"
		else
			printf "Zip not found. Created tar.gz instead: %s\n" "$archive_path"
		fi
	fi

	# A successful archiver exit alone is not enough to justify deleting the
	# local vault. Read the archived member back and require its digest to match.
	local source_vault_sha archived_vault_sha
	source_vault_sha="$(sha256sum "$VAULT_FILE" | awk '{print $1}')"
	if [ "${archive_path##*.}" = "zip" ]; then
		archived_vault_sha="$(unzip -p "$archive_path" "$bundle_name/spm_vault.gpg" 2>/dev/null | sha256sum | awk '{print $1}')"
	else
		archived_vault_sha="$(tar -xOf "$archive_path" "$bundle_name/spm_vault.gpg" 2>/dev/null | sha256sum | awk '{print $1}')"
	fi
	if [ -z "$source_vault_sha" ] || [ "$source_vault_sha" != "$archived_vault_sha" ]; then
		die "Archive verification failed; the local vault was not removed."
	fi

	# Remove the folder, leave ONLY the archive on disk
	rm -rf "$workdir"

	# Secure wipe of local vault + recovery file
	secure_wipe "$VAULT_FILE"
	rm -f "$VAULT_FILE"

	if [ -f "$RECOVERY_FILE" ]; then
		secure_wipe "$RECOVERY_FILE"
		rm -f "$RECOVERY_FILE"
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Vault lokal telah dihapus dari perangkat ini.\n"
	else
		printf "Local vault has been securely wiped from this device.\n"
	fi

	# Summary log
	printf "Archive contents (logical):\n"
	printf "  - spm.sh\n"
	printf "  - spm_vault.gpg\n"
	if [ "$has_recovery" = "yes" ]; then
		printf "  - spm_vault.gpg.recovery\n"
	fi
	if [ "$has_priv" = "yes" ]; then
		printf "  - spm_recovery_private.pem\n"
	fi
	printf "  - README.txt\n"
	printf "Final archive: %s\n" "$archive_path"
}

# ----- Restore helper for portable/save bundles ------------------------------

cmd_restore() {
	local bundle_vault="./spm_vault.gpg"
	local bundle_recovery="./spm_vault.gpg.recovery"
	local dest_vault="$HOME/.spm_vault.gpg"
	local dest_recovery="${dest_vault}.recovery"
	local restore_tmp=""

	if [ "$VAULT_FILE" != "$bundle_vault" ] || [ ! -f "$bundle_vault" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Perintah restore harus dijalankan dari folder bundle (berisi spm_vault.gpg).\n"
		else
			printf "The restore command must be run inside a portable/save bundle (with spm_vault.gpg next to the script).\n"
		fi
		return 1
	fi

	if [ -f "$dest_vault" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Vault sudah ada di %s. Timpa? (yes/NO): " "$dest_vault"
		else
			printf "Vault already exists at %s. Overwrite? (yes/NO): " "$dest_vault"
		fi
		local ans
		read -r ans || ans="no"
		case "$ans" in
			yes|y|YES|Y) ;;
			*) printf "Restore dibatalkan.\n"; return 1 ;;
		esac
	fi

	mkdir -p "$(dirname "$dest_vault")" || die "Failed to create destination directory."

	restore_tmp="$(mktemp "$(dirname "$dest_vault")/.spm_restore.XXXXXX")" || die "Failed to create restore staging file."
	cp "$bundle_vault" "$restore_tmp" || { rm -f "$restore_tmp"; die "Failed to stage vault restore."; }
	chmod 600 "$restore_tmp" 2>/dev/null || true
	mv -f "$restore_tmp" "$dest_vault" || { rm -f "$restore_tmp"; die "Failed to install restored vault."; }
	rm -f "$bundle_vault"

	if [ -f "$bundle_recovery" ]; then
		if [ -f "$dest_recovery" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "File pemulihan sudah ada di %s. Timpa? (yes/NO): " "$dest_recovery"
			else
				printf "Recovery file already exists at %s. Overwrite? (yes/NO): " "$dest_recovery"
			fi
			local ans2
			read -r ans2 || ans2="no"
			case "$ans2" in
				yes|y|YES|Y) ;;
				*) bundle_recovery="" ;;
			esac
		fi
		if [ -n "$bundle_recovery" ] && [ -f "./spm_vault.gpg.recovery" ]; then
			restore_tmp="$(mktemp "$(dirname "$dest_recovery")/.spm_recovery_restore.XXXXXX")" || die "Failed to create recovery staging file."
			cp "./spm_vault.gpg.recovery" "$restore_tmp" || { rm -f "$restore_tmp"; die "Failed to stage recovery file."; }
			chmod 600 "$restore_tmp" 2>/dev/null || true
			mv -f "$restore_tmp" "$dest_recovery" || { rm -f "$restore_tmp"; die "Failed to install recovery file."; }
			rm -f "./spm_vault.gpg.recovery"
		fi
	fi

	VAULT_FILE="$dest_vault"
	RECOVERY_FILE="$dest_recovery"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Vault dipindahkan ke %s.\n" "$dest_vault"
		if [ -f "$dest_recovery" ]; then
			printf "File pemulihan dipindahkan ke %s.\n" "$dest_recovery"
		fi
		printf "Sesi ini sekarang menggunakan vault di lokasi default; kamu bisa menjalankan SPM seperti biasa dari sana.\n"
	else
		printf "Vault moved to %s.\n" "$dest_vault"
		if [ -f "$dest_recovery" ]; then
			printf "Recovery file moved to %s.\n" "$dest_recovery"
		fi
		printf "This session now points to the default vault; feel free to launch SPM normally from that location.\n"
	fi
}

# ----- Update / Forgot / Doctor ----------------------------------------------

# ----- Auto-update preference ------------------------------------------------
#
# Off by default and never enabled implicitly. The privacy policy promises that
# network activity happens "only for features or deployment choices initiated
# by the user", so the automatic release check has to be something the user
# switches on rather than something they discover running.

autoupdate_get() {
	local key="$1" default="${2:-}" val=""
	if [ -f "$SPM_AUTOUPDATE_FILE" ]; then
		val="$(sed -n "s/^${key}=//p" "$SPM_AUTOUPDATE_FILE" 2>/dev/null | tail -n1)"
	fi
	if [ -n "$val" ]; then printf '%s' "$val"; else printf '%s' "$default"; fi
}

autoupdate_put() {
	local key="$1" val="$2" tmp
	mkdir -p "$SPM_CONFIG_DIR" 2>/dev/null || return 1
	chmod 700 "$SPM_CONFIG_DIR" 2>/dev/null || true
	tmp="$(mktemp "$SPM_CONFIG_DIR/.auto-update.XXXXXX" 2>/dev/null)" || return 1
	if [ -f "$SPM_AUTOUPDATE_FILE" ]; then
		grep -v "^${key}=" "$SPM_AUTOUPDATE_FILE" > "$tmp" 2>/dev/null || true
	fi
	printf '%s=%s\n' "$key" "$val" >> "$tmp"
	mv -f "$tmp" "$SPM_AUTOUPDATE_FILE" || { rm -f "$tmp"; return 1; }
	chmod 600 "$SPM_AUTOUPDATE_FILE" 2>/dev/null || true
}

autoupdate_mode() {
	case "$(autoupdate_get MODE off)" in
		notify) printf 'notify' ;;
		auto) printf 'auto' ;;
		*) printf 'off' ;;
	esac
}

# -1, 0 or 1 for $1 against $2, comparing dotted numeric components.
#
# This used to be `sort -V`, which is a GNU extension: BSD sort, and so macOS,
# has no -V. Where it is missing the option is not ignored -- sort fails and
# the comparison reads an empty string -- and where a lexical sort is
# substituted instead it orders 2.10.10 before 2.10.9, which is precisely
# backwards and precisely what these callers exist to get right. awk is POSIX
# and this script already depends on it everywhere else.
version_compare() {
	awk -v a="$1" -v b="$2" '
	BEGIN {
		na = split(a, x, "."); nb = split(b, y, ".")
		n = (na > nb) ? na : nb
		for (i = 1; i <= n; i++) {
			p = (i <= na) ? x[i] + 0 : 0
			q = (i <= nb) ? y[i] + 0 : 0
			if (p > q) { print 1; exit }
			if (p < q) { print -1; exit }
		}
		print 0
	}'
}

# True when $1 is strictly newer than $2. Plain string equality was enough for
# "is this the same release", but not for "is there a newer one".
version_is_newer() {
	[ "$1" != "$2" ] || return 1
	[ "$(version_compare "$1" "$2")" = "1" ]
}

autoupdate_latest_tag() {
	command -v curl >/dev/null 2>&1 || return 1
	local json
	json="$(curl -fsSL --max-time "${SPM_UPDATE_TIMEOUT:-6}" "$REPO_API_URL" 2>/dev/null)" || return 1
	printf '%s\n' "$json" | grep -m1 '"tag_name"' |
		sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/'
}

# Called once at startup. Silent and non-fatal in every failure mode: being
# offline, rate-limited, or unable to parse the response must never stop
# someone reaching their vault.
autoupdate_startup_check() {
	local mode; mode="$(autoupdate_mode)"
	[ "$mode" = "off" ] && return 0
	# Only ever speak up on a real terminal; scripted use stays untouched.
	[ -t 0 ] && [ -t 1 ] || return 0

	local now last interval
	now="$(date +%s 2>/dev/null)" || return 0
	last="$(autoupdate_get LAST_CHECK 0)"
	interval="$(autoupdate_get INTERVAL 86400)"
	case "$last" in ''|*[!0-9]*) last=0 ;; esac
	case "$interval" in ''|*[!0-9]*) interval=86400 ;; esac
	[ "$((now - last))" -ge "$interval" ] || return 0

	local latest
	latest="$(autoupdate_latest_tag)" || return 0
	[ -n "$latest" ] || return 0
	autoupdate_put LAST_CHECK "$now" || true
	autoupdate_put LAST_SEEN "$latest" || true
	version_is_newer "$latest" "$VERSION" || return 0

	clear 2>/dev/null || true
	print_banner
	if [ "$SPM_LANG" = "id" ]; then
		printf "Versi baru tersedia: %s (terpasang: %s)\n\n" "$latest" "$VERSION"
	else
		printf "A newer release is available: %s (installed: %s)\n\n" "$latest" "$VERSION"
	fi

	if [ "$mode" = "auto" ]; then
		SPM_UPDATE_ASSUME_YES=1 cmd_update || true
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "Perbarui sekarang? (yes/NO): "
		else
			printf "Update now? (yes/NO): "
		fi
		local reply; read -r reply || reply="no"
		case "$reply" in
			yes|y|Y|YES) SPM_UPDATE_ASSUME_YES=1 cmd_update || true ;;
			*) return 0 ;;
		esac
	fi
	pause_menu
}

cmd_autoupdate() {
	local action="${1:-status}"
	case "$action" in
		off|notify|auto)
			autoupdate_put MODE "$action" || die "Could not write $SPM_AUTOUPDATE_FILE."
			printf 'Auto-update mode: %s\n' "$action"
			;;
		status)
			printf 'Auto-update mode : %s\n' "$(autoupdate_mode)"
			printf 'Check interval   : %s seconds\n' "$(autoupdate_get INTERVAL 86400)"
			printf 'Last check       : %s\n' "$(autoupdate_get LAST_CHECK never)"
			printf 'Last seen release: %s\n' "$(autoupdate_get LAST_SEEN unknown)"
			printf 'Config file      : %s\n' "$SPM_AUTOUPDATE_FILE"
			;;
		*)
			printf 'Usage: spm auto-update [status|off|notify|auto]\n' >&2
			return 2
			;;
	esac
}

cmd_update() {
	require_cmd curl
	require_cmd sha256sum
	local unzip_cmd=""
	if command -v unzip >/dev/null 2>&1; then
		unzip_cmd="unzip -q"
	elif command -v bsdtar >/dev/null 2>&1; then
		unzip_cmd="bsdtar -xf"
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Memeriksa update...\n"
		printf "Versi saat ini: %s\n" "$VERSION"
		printf "Repo          : %s/%s\n" "$REPO_OWNER" "$REPO_NAME"
	else
		printf "Checking for updates...\n"
		printf "Current version: %s\n" "$VERSION"
		printf "Repo           : %s/%s\n" "$REPO_OWNER" "$REPO_NAME"
	fi

	local json
	if ! json="$(curl -fsSL "$REPO_API_URL" 2>/dev/null)"; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Gagal mengakses GitHub releases API.\n"
		else
			printf "Failed to query GitHub releases API.\n"
		fi
		return 1
	fi

	local latest_tag html_url
	# The leading "v" has to come off here too: without it the comparison below
	# never matched and every run offered to reinstall the running version.
	latest_tag="$(printf '%s\n' "$json" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')" || true
	html_url="$(printf '%s\n' "$json" | grep -m1 '"html_url"' | sed -E 's/.*"html_url": *"([^"]+)".*/\1/')" || true

	if [ -z "$latest_tag" ]; then
		printf "Could not parse latest tag_name from GitHub response.\n"
		return 1
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Versi terbaru  : %s\n" "$latest_tag"
		[ -n "$html_url" ] && printf "Halaman rilis : %s\n" "$html_url"
	else
		printf "Latest version : %s\n" "$latest_tag"
		[ -n "$html_url" ] && printf "Release page   : %s\n" "$html_url"
	fi

	# Find first ZIP asset from the release payload
	local asset_url
	asset_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -E '\.zip"' | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true

	if [ -z "$asset_url" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Tidak menemukan asset ZIP di rilis. Update manual diperlukan.\n"
		else
			printf "Could not find ZIP asset in release. Manual update required.\n"
		fi
		return 1
	fi

	local asset_name sha_url
	asset_name="${asset_url##*/}"
	sha_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -F "${asset_name}.sha256\"" | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true
	if [ -z "$sha_url" ]; then
		# Compatibility with the first checksum-enabled development builds,
		# which used this misleading filename for the ZIP digest.
		sha_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -E 'spm\.sh\.sha256"' | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true
	fi

	if [ -z "$sha_url" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "File checksum tidak ditemukan di rilis. Update manual diperlukan.\n"
		else
			printf "Checksum file not found in release. Manual update required.\n"
		fi
		return 1
	fi

	if [ "$latest_tag" = "$VERSION" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nSudah memakai versi terbaru. Reinstall? (yes/NO): "
		else
			printf "\nAlready on latest version. Reinstall anyway? (yes/NO): "
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nAda versi baru tersedia. Instal otomatis sekarang? (yes/NO): "
		else
			printf "\nNew version available. Auto-install now? (yes/NO): "
		fi
	fi

	local conf
	if [ "${SPM_UPDATE_ASSUME_YES:-0}" = "1" ]; then
		conf="yes"
		printf 'yes (auto-update is enabled)\n'
	else
		read -r conf || conf="no"
	fi
	if [ "$conf" != "yes" ] && [ "$conf" != "y" ]; then
		return 0
	fi

	if [ -z "$unzip_cmd" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Perlu 'unzip' atau 'bsdtar' untuk mengekstrak ZIP. Instal dulu.\n"
		else
			printf "Need 'unzip' or 'bsdtar' to extract ZIP. Please install it first.\n"
		fi
		return 1
	fi

	local tmpdir
	# No predictable fallback here: "mkdir -p" succeeds on a directory somebody
	# else already owns, and the release would then be unpacked from it. Refusing
	# to self-update is the safe outcome.
	if ! tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/spm_update.XXXXXX" 2>/dev/null)"; then
		printf 'Could not create a private temporary directory; update aborted.\n' >&2
		return 1
	fi
	local zip_path="$tmpdir/spm_latest.zip"
	local sha_path="$tmpdir/archive.sha256"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Mengunduh: %s\n" "$asset_url"
	else
		printf "Downloading: %s\n" "$asset_url"
	fi
	if ! curl -fL "$asset_url" -o "$zip_path"; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Download gagal.\n"
		else
			printf "Download failed.\n"
		fi
		rm -rf "$tmpdir"
		return 1
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Mengunduh checksum: %s\n" "$sha_url"
	else
		printf "Downloading checksum: %s\n" "$sha_url"
	fi
	if ! curl -fL "$sha_url" -o "$sha_path"; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Download checksum gagal.\n"
		else
			printf "Download checksum failed.\n"
		fi
		rm -rf "$tmpdir"
		return 1
	fi

	local expected_sha
	expected_sha=$(cut -d' ' -f1 < "$sha_path")
	local actual_sha
	actual_sha=$(sha256sum "$zip_path" | cut -d' ' -f1)

	if [ "$expected_sha" != "$actual_sha" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Verifikasi checksum GAGAL. File update mungkin rusak atau telah diubah.\n"
		else
			printf "Checksum verification FAILED. The update file may be corrupted or tampered with.\n"
		fi
		rm -rf "$tmpdir"
		return 1
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "Verifikasi checksum berhasil.\n"
	else
		printf "Checksum verification successful.\n"
	fi

	local extract_dir="$tmpdir/extract"
	mkdir -p "$extract_dir"
	if [ "$unzip_cmd" = "unzip -q" ]; then
		if ! unzip -q "$zip_path" -d "$extract_dir"; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "Gagal mengekstrak ZIP.\n"
			else
				printf "Failed to extract ZIP.\n"
			fi
			rm -rf "$tmpdir"
			return 1
		fi
	else
		if ! bsdtar -xf "$zip_path" -C "$extract_dir"; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "Gagal mengekstrak ZIP.\n"
			else
				printf "Failed to extract ZIP.\n"
			fi
			rm -rf "$tmpdir"
			return 1
		fi
	fi

	local new_spm
	new_spm="$(find "$extract_dir" -name 'spm.sh' -type f | head -n1)"
	if [ -z "$new_spm" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "spm.sh tidak ditemukan di arsip.\n"
		else
			printf "spm.sh not found in archive.\n"
		fi
		rm -rf "$tmpdir"
		return 1
	fi
	if ! bash -n "$new_spm"; then
		printf "Downloaded spm.sh failed its syntax check; installation aborted.\n"
		rm -rf "$tmpdir"
		return 1
	fi

	local target="/usr/local/bin/spm"
	if [ "$SPM_LANG" = "id" ]; then
		printf "Menginstal ke %s (mungkin butuh sudo)...\n" "$target"
	else
		printf "Installing to %s (sudo may be required)...\n" "$target"
	fi

	# Never write over $target in place. Bash reads a script lazily as it runs,
	# so replacing the bytes underneath a live instance can make it execute
	# garbage -- and auto-update makes that the common case rather than a rare
	# one. Staging a sibling and renaming swaps the path atomically; anything
	# already running stays on the old inode until it exits.
	local staged="${target}.new.$$" sudo_cmd=""
	if [ ! -w "$(dirname "$target")" ] && command -v sudo >/dev/null 2>&1; then
		sudo_cmd="sudo"
	fi
	if ! $sudo_cmd cp "$new_spm" "$staged" ||
		! $sudo_cmd chmod 0755 "$staged" ||
		! $sudo_cmd mv -f "$staged" "$target"; then
		$sudo_cmd rm -f "$staged" 2>/dev/null || true
		if [ "$SPM_LANG" = "id" ]; then
			printf "Gagal memasang ke %s.\n" "$target"
		else
			printf "Failed to install to %s.\n" "$target"
		fi
		rm -rf "$tmpdir"
		return 1
	fi

	rm -rf "$tmpdir"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Update selesai. Jalankan 'spm' untuk versi terbaru.\n"
	else
		printf "Update complete. Run 'spm' for the latest version.\n"
	fi
}

cmd_forgot() {
	[ -f "$VAULT_FILE" ] || die "Vault not found at '$VAULT_FILE'. Nothing to recover."
	[ -f "$RECOVERY_FILE" ] || die "Recovery file '$RECOVERY_FILE' not found. Forgot-mode unavailable."
	require_cmd openssl

	if [ "$SPM_LANG" = "id" ]; then
		printf ">>> LUPA KATA SANDI UTAMA (MODE PEMULIHAN) <<<\n\n"
		printf "Kamu butuh PRIVATE KEY RSA yang dibuat saat 'init'.\n"
		printf "Lokasi default private key (jika belum dipindah): %s\n\n" "$RECOVERY_PRIV_DEFAULT"
		printf "Masukkan path private key (kosong = default): "
	else
		printf ">>> FORGOT MASTER PASSWORD (RECOVERY MODE) <<<\n\n"
		printf "You will need your RSA PRIVATE KEY that was generated on 'init'.\n"
		printf "Default private key path (if not moved): %s\n\n" "$RECOVERY_PRIV_DEFAULT"
		printf "Enter private key path (blank = default): "
	fi
	read -r pk_path || true
	if [ -z "$pk_path" ]; then
		pk_path="$RECOVERY_PRIV_DEFAULT"
	fi

	[ -f "$pk_path" ] || die "Private key file '$pk_path' not found."

	local recovered_secret
	if ! recovered_secret="$(openssl rsautl -decrypt -inkey "$pk_path" -in "$RECOVERY_FILE" 2>/dev/null)"; then
		die "Failed to decrypt recovery file with the provided private key."
	fi

	# What the recovery file holds depends on when it was last written:
	# format 3 stores the vault key, the formats before it stored the master
	# password, and a vault caught mid-migration is described by neither. Try
	# every reading rather than assume -- the master-password route is also
	# what makes the migration crash window recoverable.
	local tmp recovery_stale=0
	tmp="$(make_tmp)"
	VAULT_KEY=""
	# The core decides what the recovered secret actually is: format 3 stores
	# the vault key, the formats before it stored the master password, and a
	# vault caught mid-migration is described by neither. It reports back
	# whether the recovery file is stale and therefore needs repairing below.
	local recover_out
	recover_out="$(printf '%s' "$recovered_secret" | core recover "$VAULT_FILE" "$tmp")" \
		|| { secure_wipe "$tmp"; die "The recovery file does not open this vault. Recovery aborted."; }
	VAULT_KEY="$(printf '%s\n' "$recover_out" | sed -n '1p')"
	recovery_stale="$(printf '%s\n' "$recover_out" | sed -n '2p')"
	[ "$recovery_stale" = "1" ] || recovery_stale=0
	if [ -z "$VAULT_KEY" ]; then
		# A legacy vault: the recovered secret is its master password.
		MASTER_PW="$recovered_secret"
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nVault berhasil didekripsi menggunakan kata sandi utama lama.\n"
		printf "Sekarang set kata sandi utama BARU.\n\n"
	else
		printf "\nVault successfully decrypted using recovered master password.\n"
		printf "Now set a NEW master password for this vault.\n\n"
	fi

	# Same two-step as change-master: migrate a legacy vault under the password
	# the recovery file already names, then rewrap to the new one.
	if [ -z "${VAULT_KEY:-}" ]; then
		encrypt_file_to_vault "$tmp"
		recovery_stale=0
	fi
	prompt_master_password
	rewrap_vault_key "$MASTER_PW"
	# Finish the migration this vault was caught in the middle of. Without
	# this the vault would open under the new password while its recovery file
	# still named the old one -- recoverable once, by luck, and never again.
	if [ "$recovery_stale" -eq 1 ]; then
		write_recovery_file "$tmp"
	fi
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nKata sandi utama berhasil DI-RESET.\n"
		printf "File pemulihan tetap berlaku: %s\n" "$RECOVERY_FILE"
		printf "Simpan baik-baik private key dan file recovery.\n"
	else
		printf "\nMaster password has been RESET.\n"
		# The recovery file wraps the vault key, which a password reset does
		# not change. Saying it was "updated" would invite the user to re-copy
		# a file that is byte-identical to the one they already keep offline.
		printf "Recovery file remains valid at: %s\n" "$RECOVERY_FILE"
		printf "Keep your private key and this recovery file safe.\n"
	fi
}

# Report vault records that contain a character Python's splitlines() treats as
# a line break. Such a record was written as one line but is read back as two,
# so neither half has enough fields and the entry disappears from the SPM Dashboard.
# 2.10.12 stopped new ones being created; this finds any that already exist.
# Strictly read-only: it reports and never edits the vault.
doctor_scan_broken_records() {
	# One implementation, in the core. This used to carry its own copy of the
	# break table and the record describer, which is exactly the arrangement
	# the trusted-core split exists to prevent -- the JSON report needs the
	# same scan, and two copies of it would drift the way the old dashboard
	# and CLI copies did.
	core scan-records "$1"
}
# Which of the recovery states this vault is in, as a single token. The human
# doctor prints these as sentences further down; the JSON report needs the same
# determination without the prose, and neither should decide it twice.
doctor_recovery_state() {
	[ -f "$RECOVERY_FILE" ] || { printf 'no-recovery-file'; return 0; }
	[ -f "$RECOVERY_PRIV_DEFAULT" ] || { printf 'no-private-key'; return 0; }
	local secret
	if secret="$(openssl rsautl -decrypt -inkey "$RECOVERY_PRIV_DEFAULT" \
			-in "$RECOVERY_FILE" 2>/dev/null)"; then
		if is_vault_container "$VAULT_FILE"; then
			if [ -n "${VAULT_KEY:-}" ] && [ "$secret" = "$VAULT_KEY" ]; then
				printf 'match-current'
			else
				printf 'match-stale'
			fi
		else
			printf 'match-legacy'
		fi
	else
		printf 'mismatch'
	fi
	secret=""
}

# `doctor --json`. Everything a script needs, nothing a human needs: no
# progress lines, no banner, and stdout carries the document and nothing else
# so it can be piped straight into jq. Exit status mirrors the report, so a
# caller can gate on it without parsing.
cmd_doctor_json() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	local tmp state status
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"
	state="$(doctor_recovery_state)"
	status=0
	# shellcheck disable=SC2046
	core doctor-report "$tmp" "$VAULT_FILE" "$state" $(sensitive_files) || status=$?
	secure_wipe "$tmp"
	return "$status"
}

cmd_doctor() {
	if [ "${1:-}" = "--json" ]; then
		cmd_doctor_json
		return $?
	fi
	if [ "$SPM_LANG" = "id" ]; then
		printf ">>> HEALTH / DOCTOR CHECK <<<\n\n"
	else
		printf ">>> HEALTH / DOCTOR CHECK <<<\n\n"
	fi

	if [ ! -f "$VAULT_FILE" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✖] Vault tidak ditemukan di: %s\n" "$VAULT_FILE"
		else
			printf "[✖] Vault not found at: %s\n" "$VAULT_FILE"
		fi
		return 1
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "[ ] Dekripsi vault...\n"
	else
		printf "[ ] Decrypting vault...\n"
	fi

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\r[✔] Dekripsi vault berhasil.\n"
	else
		printf "\r[✔] Vault decrypted successfully.\n"
	fi

	# Check password rows & duplicates
	local pw_count
	pw_count="$(awk -F '\t' '
		$1 ~ /^[0-9]+$/ { c++; if (length($4)==0) ep++; ids[$1]++ }
		END {
			for (i in ids) if (ids[i]>1) {dup=1}
			if (dup) print c+0 "|" ep+0 "|dup";
			else print c+0 "|" ep+0 "|ok";
		}
	' "$tmp")"

	local pw_total empty_pw status_dup
	pw_total="${pw_count%%|*}"
	local rest="${pw_count#*|}"
	empty_pw="${rest%%|*}"
	status_dup="${rest##*|}"

	# The marker has to be chosen after the result is known: this is a verdict
	# line, not a progress line, so it must not keep the empty "[ ]" that the
	# in-progress steps use.
	local dup_mark
	if [ "$status_dup" = "dup" ]; then
		dup_mark="[!]"
	else
		dup_mark="[✔]"
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah entry password : %s\n" "$pw_total"
		printf "%s Duplikasi ID          : " "$dup_mark"
	else
		printf "[✔] Password entries count: %s\n" "$pw_total"
		printf "%s Duplicate IDs         : " "$dup_mark"
	fi

	if [ "$status_dup" = "dup" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "ADA\n"
		else
			printf "FOUND\n"
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "tidak ada\n"
		else
			printf "none\n"
		fi
	fi

	if [ "$empty_pw" != "0" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[!] Peringatan: %s entry dengan password kosong.\n" "$empty_pw"
		else
			printf "[!] Warning: %s entries with EMPTY password field.\n" "$empty_pw"
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✔] Tidak ada entry dengan password kosong.\n"
		else
			printf "[✔] No entries with empty password.\n"
		fi
	fi

	# Check notes rows
	local note_count
	note_count="$(awk -F '\t' '$1=="NOTE"{n++} END{print n+0}' "$tmp")"
	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah catatan aman    : %s\n" "$note_count"
	else
		printf "[✔] Secure notes count     : %s\n" "$note_count"
	fi

	local pass_count
	pass_count="$(awk -F '\t' '$1=="PASSPHRASE"{n++} END{print n+0}' "$tmp")"
	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah passphrase      : %s\n" "$pass_count"
	else
		printf "[✔] Passphrases count      : %s\n" "$pass_count"
	fi

	local bc_count
	bc_count="$(awk -F '\t' '$1=="BACKUP_CODE"{n++} END{print n+0}' "$tmp")"
	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah kode backup     : %s\n" "$bc_count"
	else
		printf "[✔] Backup codes count     : %s\n" "$bc_count"
	fi

	local auth_count
	auth_count="$(awk -F '\t' '$1=="AUTH"{n++} END{print n+0}' "$tmp")"
	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah authenticator   : %s\n" "$auth_count"
	else
		printf "[✔] Authenticators count   : %s\n" "$auth_count"
	fi

	# Records split by a stray line-break character (see 2.10.12).
	local scan_out scan_summary broken_count orphan_count
	if scan_out="$(doctor_scan_broken_records "$tmp" 2>/dev/null)"; then
		scan_summary="$(printf '%s\n' "$scan_out" | awk -F '\t' '$1=="SUMMARY"{print $2"|"$3}')"
		broken_count="${scan_summary%%|*}"
		orphan_count="${scan_summary##*|}"
		if [ "${broken_count:-0}" = "0" ] && [ "${orphan_count:-0}" = "0" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "[✔] Tidak ada record yang terpotong.\n"
			else
				printf "[✔] No records split by a line-break character.\n"
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				printf "[!] %s record berisi karakter pemisah baris, %s pecahan tersisa:\n" \
					"$broken_count" "$orphan_count"
			else
				printf "[!] %s record(s) contain a line-break character; %s leftover fragment(s):\n" \
					"$broken_count" "$orphan_count"
			fi
			printf '%s\n' "$scan_out" | awk -F '\t' '
				$1=="BROKEN" { printf "      line %-5s %-13s id=%-5s %-34s %s\n", $2, $3, $4, $5, $6 }
				$1=="ORPHAN" { printf "      line %-5s %-13s %s\n", $2, "FRAGMENT", $3 }
			'
			if [ "$SPM_LANG" = "id" ]; then
				printf "    Entry ini tidak terlihat di SPM Dashboard. Vault TIDAK diubah.\n"
				printf "    Perbaiki dengan menyimpan ulang tiap entry lewat CLI (spm edit <id>).\n"
			else
				printf "    These entries are invisible in the SPM Dashboard. The vault was NOT changed.\n"
				printf "    Repair by re-saving each one from the CLI (spm edit <id>), which\n"
				printf "    rewrites the field through the 2.10.12 sanitiser.\n"
			fi
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "[!] Pemindaian record terpotong gagal dijalankan.\n"
		else
			printf "[!] Split-record scan could not be run.\n"
		fi
	fi

	# Report the vault format version, and whether the next write upgrades it.
	# Stated rather than acted on: doctor is a diagnostic and must never be the
	# thing that rewrites a vault.
	local fmt
	fmt="$(vault_format_version "$tmp")"
	local current_fmt
	current_fmt="$(core current-version 2>/dev/null || printf '%s' "$fmt")"
	if [ "$fmt" -ge "$current_fmt" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✔] Format vault versi %s (terbaru).\n" "$fmt"
		else
			printf "[✔] Vault format version %s (current).\n" "$fmt"
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "[!] Format vault versi %s; versi %s tersedia.\n" "$fmt" "$current_fmt"
			printf "    Perubahan berikutnya akan memutakhirkan vault otomatis.\n"
			printf "    Kunci diturunkan memakai default GnuPG lama (digest SHA1).\n"
		else
			printf "[!] Vault format version %s; version %s is available.\n" "$fmt" "$current_fmt"
			printf "    The next change upgrades this vault in place; no migration step.\n"
			printf "    Its key was derived with GnuPG's older default digest (SHA1).\n"
		fi
	fi

	# Check recovery meta public key
	local pub_b64
	pub_b64="$(get_recovery_pub_b64_from_vault "$tmp")"
	if [ -z "$pub_b64" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✖] Baris META_RECOVERY_PUBKEY tidak ditemukan di vault.\n"
		else
			printf "[✖] META_RECOVERY_PUBKEY row not found in vault.\n"
		fi
	else
		local tmp_pub
		tmp_pub="$(make_tmp)"
		if printf '%s' "$pub_b64" | base64 -d >"$tmp_pub" 2>/dev/null; then
			if openssl rsa -pubin -in "$tmp_pub" -text -noout >/dev/null 2>&1; then
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✔] Public key pemulihan valid dan bisa dibaca.\n"
				else
					printf "[✔] Recovery public key is valid and readable.\n"
				fi
			else
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✖] Public key pemulihan ada, tapi tidak valid.\n"
				else
					printf "[✖] Recovery public key present but not valid.\n"
				fi
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				printf "[✖] Gagal decode base64 public key pemulihan.\n"
			else
				printf "[✖] Failed to base64-decode recovery public key.\n"
			fi
		fi
		secure_wipe "$tmp_pub"
	fi

	# Check recovery file + private key
	if [ -f "$RECOVERY_FILE" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✔] File recovery ditemukan: %s\n" "$RECOVERY_FILE"
		else
			printf "[✔] Recovery file found    : %s\n" "$RECOVERY_FILE"
		fi

		if [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "[ ] Menguji pasangan PRIVATE KEY + recovery file...\n"
			else
				printf "[ ] Testing PRIVATE KEY + recovery file pair...\n"
			fi
			local recovered_secret=""
			if recovered_secret="$(openssl rsautl -decrypt -inkey "$RECOVERY_PRIV_DEFAULT" -in "$RECOVERY_FILE" 2>/dev/null)"; then
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✔] Private key dan file recovery cocok.\n"
				else
					printf "[✔] Private key and recovery file match.\n"
				fi
				# Holding a decryptable recovery file is not the same as
				# holding a USEFUL one. Since 3.0.0 it must contain the vault
				# key; one still holding a master password recovers a vault
				# only until the next password change, and nothing else in the
				# tool can tell the user which of the two they have.
				if is_vault_container "$VAULT_FILE"; then
					if [ -n "${VAULT_KEY:-}" ] && [ "$recovered_secret" = "$VAULT_KEY" ]; then
						if [ "$SPM_LANG" = "id" ]; then
							printf "[✔] File recovery berisi kunci vault saat ini.\n"
						else
							printf "[✔] Recovery file holds the current vault key.\n"
						fi
					else
						if [ "$SPM_LANG" = "id" ]; then
							printf "[✖] File recovery tidak berisi kunci vault ini; jalankan '%s change-master' untuk memperbaruinya.\n" "$0"
						else
							printf "[✖] Recovery file does not hold this vault's key; run '%s change-master' to refresh it.\n" "$0"
						fi
					fi
				fi
				recovered_secret=""
			else
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✖] Private key tidak cocok dengan file recovery.\n"
				else
					printf "[✖] Private key does NOT match the recovery file.\n"
				fi
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				printf "[✖] PRIVATE KEY default tidak ditemukan di: %s\n" "$RECOVERY_PRIV_DEFAULT"
			else
				printf "[✖] Default PRIVATE KEY not found at: %s\n" "$RECOVERY_PRIV_DEFAULT"
			fi
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "[✖] File recovery tidak ditemukan di: %s\n" "$RECOVERY_FILE"
		else
			printf "[✖] Recovery file not found at: %s\n" "$RECOVERY_FILE"
		fi
	fi

	# Check on-disk permissions of the sensitive files. A vault last written by
	# a web session before 2.9.1 kept the umask default (usually 0644) instead
	# of 0600, and that stays wrong until someone fixes it by hand.
	if [ "$SPM_LANG" = "id" ]; then
		printf "\n[ ] Memeriksa izin file sensitif...\n"
	else
		printf "\n[ ] Checking sensitive file permissions...\n"
	fi

	local perm_bad=0
	local perm_fix=""
	local pf pmode
	# Here-string, not a pipe: a piped 'while' runs in a subshell and would
	# discard perm_bad/perm_fix.
	while IFS= read -r pf; do
		[ -n "$pf" ] || continue
		pmode="$(file_mode "$pf")"
		if [ -z "$pmode" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "[!] Tidak bisa membaca izin: %s\n" "$pf"
			else
				printf "[!] Could not read permissions: %s\n" "$pf"
			fi
			continue
		fi
		if mode_is_exposed "$pmode"; then
			perm_bad=$((perm_bad + 1))
			perm_fix="${perm_fix}$(printf '%q' "$pf") "
			if [ "$SPM_LANG" = "id" ]; then
				printf "[✖] %s terbuka untuk pengguna lain (mode %s, seharusnya 600).\n" "$pf" "$pmode"
			else
				printf "[✖] %s is readable by other users (mode %s, expected 600).\n" "$pf" "$pmode"
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				printf "[✔] Izin aman (%s): %s\n" "$pmode" "$pf"
			else
				printf "[✔] Permissions OK (%s): %s\n" "$pmode" "$pf"
			fi
		fi
	done <<<"$(sensitive_files)"

	if [ "$perm_bad" -gt 0 ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "[!] Perbaiki dengan: chmod 600 %s\n" "${perm_fix% }"
		else
			printf "[!] Fix with: chmod 600 %s\n" "${perm_fix% }"
		fi
	fi

	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\n[DOCTOR] Pemeriksaan selesai.\n"
	else
		printf "\n[DOCTOR] Health check finished.\n"
	fi
}

cmd_export() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	require_cmd python3

	local format="${1:-csv}"
	format="$(printf '%s' "$format" | tr '[:upper:]' '[:lower:]')"
	local outfile="${2:-}"
	case "$format" in
		csv|json|tsv|ndjson|jsonl|md|markdown|html|txt|yaml|yml|xml|sql|ini|psv|rst|toml|org|scsv|csv-noheader|jsonc) ;;
		*) die "Unsupported format '$format'. Use: csv, json, tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, or jsonc." ;;
	esac

	if [ -z "$outfile" ]; then
		outfile="spm_export_$(date +%Y%m%d_%H%M%S).${format}"
	else
		case "$outfile" in
			*."$format") ;;  # already has correct extension
			*.csv|*.json|*.tsv|*.ndjson|*.jsonl|*.md|*.markdown|*.html|*.htm|*.txt|*.yaml|*.yml|*.xml|*.sql|*.ini|*.psv|*.rst|*.toml|*.org) ;;
			md|markdown) outfile="export.md" ;;
			html|htm) outfile="export.html" ;;
			txt) outfile="export.txt" ;;
			yaml|yml) outfile="export.yaml" ;;
			xml) outfile="export.xml" ;;
			sql) outfile="export.sql" ;;
			ini) outfile="export.ini" ;;
			psv) outfile="export.psv" ;;
			scsv) outfile="export.scsv" ;;
			toml) outfile="export.toml" ;;
			org) outfile="export.org" ;;
			"csv-noheader") outfile="export.csv" ;;
			jsonc) outfile="export.json" ;;
			rst) outfile="export.rst" ;;
			*) outfile="${outfile}.${format}" ;;
		esac
	fi

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

if ! python3 - "$format" "$tmp" "$outfile" <<'PY'
import sys, json, base64, csv, html, datetime
fmt, vault_path, out_path = sys.argv[1:]

def decode_b64(val):
    try:
        return base64.b64decode(val.encode("utf-8")).decode("utf-8", errors="replace")
    except Exception:
        return ""

rows = []
with open(vault_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag.isdigit():  # password
            rows.append({
                "type": "password",
                "id": parts[0],
                "label": parts[1] if len(parts) > 1 else "",
                "username": parts[2] if len(parts) > 2 else "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": parts[4] if len(parts) > 4 else "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": "",
                "url": parts[6] if len(parts) > 6 else ""
            })
        elif tag == "NOTE":
            rows.append({
                "type": "note",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": decode_b64(parts[3]) if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "PASSPHRASE":
            rows.append({
                "type": "passphrase",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": decode_b64(parts[3]) if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "BACKUP_CODE":
            rows.append({
                "type": "backup_code",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": decode_b64(parts[3]) if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "AUTH":
            rows.append({
                "type": "authenticator",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": "period=%s;algo=%s" % (
                    parts[4] if len(parts) > 4 else "",
                    parts[6] if len(parts) > 6 else "sha1"
                ),
                "url": ""
            })

fieldnames = ["type","id","label","username","secret","notes","created","extra","url"]

if fmt == "json":
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
elif fmt in ("ndjson", "jsonl"):
    with open(out_path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
elif fmt == "tsv":
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
elif fmt in ("md", "markdown"):
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("| " + " | ".join(fieldnames) + " |\n")
        f.write("|" + "|".join([" --- "]*len(fieldnames)) + "|\n")
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            f.write("| " + " | ".join(cells) + " |\n")
elif fmt == "html":
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("<table border='1' cellpadding='4' cellspacing='0'>\n")
        f.write("<tr>" + "".join(f"<th>{html.escape(k)}</th>" for k in fieldnames) + "</tr>\n")
        for r in rows:
            f.write("<tr>" + "".join(f"<td>{html.escape((r.get(k,'') or ''))}</td>" for k in fieldnames) + "</tr>\n")
        f.write("</table>\n")
elif fmt == "toml":
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write("[[item]]\n")
            for k in fieldnames:
                val = (r.get(k, "") or "").replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
                f.write(f'{k} = "{val}"\n')
            f.write("\n")
elif fmt == "org":
    header = "| " + " | ".join(fieldnames) + " |\n"
    sep = "|" + "+".join("-" * (len(k)+2) for k in fieldnames) + "|\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(sep)
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            f.write("| " + " | ".join(cells) + " |\n")
elif fmt == "scsv":
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)
elif fmt == "csv-noheader":
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=",")
        writer.writerows(rows)
elif fmt == "jsonc":
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False)
elif fmt in ("yaml", "yml"):
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write("-\n")
            for k in fieldnames:
                val = r.get(k, "") or ""
                f.write(f"  {k}: {json.dumps(val, ensure_ascii=False)}\n")
elif fmt == "xml":
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<data>\n")
        for r in rows:
            f.write("  <item>\n")
            for k in fieldnames:
                val = html.escape(r.get(k, "") or "")
                f.write(f"    <{k}>{val}</{k}>\n")
            f.write("  </item>\n")
        f.write("</data>\n")
elif fmt == "sql":
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("CREATE TABLE spm_export(type TEXT,id TEXT,label TEXT,username TEXT,secret TEXT,notes TEXT,created TEXT,extra TEXT);\n")
        for r in rows:
            vals = [r.get(k, "") or "" for k in fieldnames]
            safe = [v.replace("'", "''") for v in vals]
            f.write("INSERT INTO spm_export(type,id,label,username,secret,notes,created,extra) VALUES ('%s');\n" % ("','".join(safe)))
elif fmt == "ini":
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            sect = f"{r.get('type','unknown')}_{r.get('id','')}"
            f.write(f"[{sect}]\n")
            for k in fieldnames:
                val = json.dumps(str(r.get(k,'') or ''), ensure_ascii=False)
                f.write(f"{k}={val}\n")
            f.write("\n")
elif fmt == "psv":
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="|")
        writer.writeheader()
        writer.writerows(rows)
elif fmt == "rst":
    encoded_rows = [{k: json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames} for r in rows]
    widths = {k: max(len(k), max(len(r[k]) for r in encoded_rows) if encoded_rows else 0) for k in fieldnames}
    def sep(char="+"):
        return char + char.join("-" * (widths[k]+2) for k in fieldnames) + char + "\n"
    def row(vals):
        return "|" + "|".join(" " + v.ljust(widths[k]) + " " for k,v in vals) + "|\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(sep())
        f.write(row([(k,k) for k in fieldnames]))
        f.write(sep("+"))
        for r in encoded_rows:
            f.write(row([(k, r[k]) for k in fieldnames]))
            f.write(sep())
else:  # csv or txt fallback
    delim = "," if fmt == "csv" else ","
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delim)
        writer.writeheader()
        writer.writerows(rows)
PY
then
		secure_wipe "$tmp"
		die "Export failed."
	fi

	secure_wipe "$tmp"
	chmod 600 "$outfile" 2>/dev/null || true

	if [ "$SPM_LANG" = "id" ]; then
		printf "Export selesai: %s (%s)\n" "$outfile" "$format"
	else
		printf "Export complete: %s (%s)\n" "$outfile" "$format"
	fi
}

cmd_import() {
	[ -f "$VAULT_FILE" ] || die "Vault not found. Run '$0 init' first."
	require_cmd python3

	local format="${1:-csv}"
	format="$(printf '%s' "$format" | tr '[:upper:]' '[:lower:]')"
	local infile="${2:-}"
	[ -n "$infile" ] || die "Usage: $0 import <format> <file>"
	[ -f "$infile" ] || die "Input file '$infile' not found."

	case "$format" in
		csv|json|tsv|ndjson|jsonl|md|markdown|html|txt|yaml|yml|xml|sql|ini|psv|rst|toml|org|scsv|csv-noheader|jsonc) ;;
		*) die "Unsupported format '$format' for import." ;;
	esac

	local tmp
	tmp="$(make_tmp)"
	decrypt_vault_to_file "$tmp"

	if ! python3 - "$format" "$infile" "$tmp" <<'PY'
import sys, json, csv, base64, configparser, io, re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
fmt, src_path, vault_path = sys.argv[1:]

def load_vault_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f]

lines = load_vault_lines(vault_path)

# Every character str.splitlines() treats as a line break. Stripping only
# \t \r \n left eight more that pass through and split a record on read, so the
# entry silently vanished from the vault. Keep this in step with _VAULT_BREAKS
# in the web server.
_VAULT_BREAKS = "\t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"

def _read_text(path):
    # errors="ignore" silently dropped every non-UTF-8 byte, so a cp1252 export
    # imported as success with characters missing from the stored secrets.
    # Fail closed and say exactly how to convert instead.
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        line = raw.count(b"\n", 0, exc.start) + 1
        raise SystemExit(
            "Import aborted: %s is not valid UTF-8 (byte 0x%02x at line %d).\n"
            "Nothing was written to the vault. Convert it first, for example:\n"
            "  iconv -f WINDOWS-1252 -t UTF-8 %s > converted.csv"
            % (path, raw[exc.start], line, path)
        )

def _vf(value):
    # Vault records are TAB-delimited and line-based, so a field holding a raw
    # separator splits the record. Quoted multi-line notes are ordinary in CSV
    # exports from other managers, and used to land as extra broken rows.
    text = str(value or "")
    for ch in _VAULT_BREAKS:
        text = text.replace(ch, " ")
    return text


def next_id(tag):
    max_id = 0
    for ln in lines:
        if not ln:
            continue
        parts = ln.split("\t")
        if tag == "PASS" and parts[0].isdigit():
            max_id = max(max_id, int(parts[0]))
        elif parts[0] == tag and len(parts) > 1 and parts[1].isdigit():
            max_id = max(max_id, int(parts[1]))
    return max_id + 1

def _vurl(value):
    # Same allowlist as the CLI's sanitize_url and SPM Dashboard's form validation.
    # An import is the least trusted way a value enters the vault, so a foreign
    # CSV carrying "javascript:..." in its url column is dropped rather than
    # stored -- the field is rendered as a link and will feed the extension.
    text = _vf(value).strip()
    if not text:
        return ""
    return text if re.match(r"(?i)^https?://[^\s/]+", text) else ""

def add_password(r):
    pid = str(next_id("PASS"))
    lines.append("\t".join([
        pid,
        _vf(r.get("label","")),
        _vf(r.get("username","")),
        _vf(r.get("secret","")),
        _vf(r.get("notes","")),
        _vf(r.get("created","")),
        _vurl(r.get("url",""))
    ]))

def add_note(r):
    nid = str(next_id("NOTE"))
    body_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "NOTE",
        nid,
        _vf(r.get("label","")),
        body_b64,
        _vf(r.get("created","")),
        "-"
    ]))

def add_passphrase(r):
    pid = str(next_id("PASSPHRASE"))
    secret_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "PASSPHRASE",
        pid,
        _vf(r.get("label","")),
        secret_b64,
        _vf(r.get("created","")),
        "-"
    ]))

def add_backup(r):
    bid = str(next_id("BACKUP_CODE"))
    codes_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "BACKUP_CODE",
        bid,
        _vf(r.get("label","")),
        codes_b64,
        _vf(r.get("created","")),
        "-"
    ]))

def add_auth(r):
    aid = str(next_id("AUTH"))
    def parse_extra(val):
        out = {}
        for part in str(val or "").split(";"):
            if "=" in part:
                k,v = part.split("=",1)
                out[k.strip().lower()] = v.strip()
        return out
    extra_map = parse_extra(r.get("extra",""))
    algo = (extra_map.get("algo") or r.get("algorithm","") or "sha1").lower()
    if algo not in ("sha1","sha256","sha512"):
        algo = "sha1"
    period = extra_map.get("period") or r.get("extra","").replace("period=","") or "30"
    lines.append("\t".join([
        "AUTH",
        aid,
        _vf(r.get("label","")),
        _vf(r.get("secret","")),
        _vf(period),
        _vf(r.get("created","")),
        algo
    ]))

def parse_structured():
    return json.loads(_read_text(src_path))

def parse_rows():
    if fmt in ("json","jsonc"):
        return parse_structured()
    if fmt in ("ndjson","jsonl"):
        out = []
        for line in _read_text(src_path).splitlines():
            if True:
                line=line.strip()
                if not line: continue
                out.append(json.loads(line))
        return out
    delim = "," if fmt in ("csv","csv-noheader","jsonc") else ";" if fmt=="scsv" else "\t" if fmt=="tsv" else "|"
    rows=[]
    with io.StringIO(_read_text(src_path), newline="") as f:
        reader = csv.DictReader(f, delimiter=delim) if fmt!="csv-noheader" else csv.reader(f, delimiter=delim)
        if fmt=="csv-noheader":
            for row in reader:
                rows.append({
                    "type": row[0] if len(row)>0 else "",
                    "id": row[1] if len(row)>1 else "",
                    "label": row[2] if len(row)>2 else "",
                    "username": row[3] if len(row)>3 else "",
                    "secret": row[4] if len(row)>4 else "",
                    "notes": row[5] if len(row)>5 else "",
                    "created": row[6] if len(row)>6 else "",
                    "extra": row[7] if len(row)>7 else "",
                    "url": row[8] if len(row)>8 else "",
                })
        else:
            rows = list(reader)
    return rows

def parse_advanced_rows():
    content = _read_text(src_path)
    if fmt in ("txt",):
        return list(csv.DictReader(io.StringIO(content), delimiter=","))
    if fmt in ("md", "markdown", "org", "rst"):
        return parse_plain_table()
    if fmt == "html":
        class TableParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.rows=[]; self.row=[]; self.cell=[]; self.in_cell=False
            def handle_starttag(self, tag, attrs):
                if tag.lower() in ("td", "th"): self.in_cell=True; self.cell=[]
            def handle_data(self, data):
                if self.in_cell: self.cell.append(data)
            def handle_endtag(self, tag):
                tag=tag.lower()
                if tag in ("td", "th") and self.in_cell:
                    self.row.append("".join(self.cell)); self.in_cell=False
                elif tag == "tr" and self.row:
                    self.rows.append(self.row); self.row=[]
        parser=TableParser(); parser.feed(content)
        if not parser.rows: return []
        headers=parser.rows[0]
        return [dict(zip(headers, row)) for row in parser.rows[1:]]
    if fmt in ("yaml", "yml"):
        rows=[]; current=None
        for line in content.splitlines():
            if line.strip() == "-":
                if current is not None: rows.append(current)
                current={}
            elif current is not None and ":" in line:
                key, value=line.strip().split(":", 1)
                value=value.strip()
                try: value=json.loads(value)
                except json.JSONDecodeError: value=value.strip('"')
                current[key]=value
        if current is not None: rows.append(current)
        return rows
    if fmt == "xml":
        root=ET.fromstring(content)
        return [{child.tag: (child.text or "") for child in item} for item in root.findall("item")]
    if fmt == "sql":
        rows=[]; fields=["type","id","label","username","secret","notes","created","extra","url"]
        for values in re.findall(r"INSERT\s+INTO\s+spm_export\s*\([^)]*\)\s*VALUES\s*\((.*?)\)\s*;", content, re.I | re.S):
            parsed=next(csv.reader([values], delimiter=",", quotechar="'", doublequote=True, skipinitialspace=True))
            rows.append(dict(zip(fields, parsed)))
        return rows
    if fmt == "ini":
        cfg=configparser.ConfigParser(interpolation=None); cfg.optionxform=str; cfg.read_string(content)
        return [{k: (json.loads(v) if v.startswith('"') and v.endswith('"') else v) for k,v in cfg.items(section)} for section in cfg.sections()]
    if fmt == "toml":
        try:
            import tomllib
            return tomllib.loads(content).get("item", [])
        except ModuleNotFoundError:
            # Python 3.10 and older have no tomllib. SPM's own TOML export is a
            # deliberately small [[item]] + quoted-string subset, so parse that
            # subset without adding a network-installed dependency.
            rows=[]; current=None
            for raw in content.splitlines():
                line=raw.strip()
                if not line or line.startswith("#"): continue
                if line == "[[item]]":
                    if current is not None: rows.append(current)
                    current={}; continue
                if current is None or "=" not in line: continue
                key,value=line.split("=",1); key=key.strip(); value=value.strip()
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
                    raise ValueError("Invalid TOML key")
                current[key]=json.loads(value)
            if current is not None: rows.append(current)
            return rows
    return []

def parse_plain_table():
    rows = []
    headers = None
    with open(src_path,"r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            ln=ln.strip()
            if not ln or ln.startswith("#") or ln.startswith("| ---") or ln.startswith("+"): continue
            if "|" in ln:
                parts=[p.strip() for p in ln.strip("|").split("|")]
            else:
                parts=[p.strip() for p in ln.split()]
            if len(parts) < 2:
                continue
            if parts[0].lower() == "type":
                headers = [p.lower() for p in parts]
                continue
            parts = [json.loads(p) if p.startswith('"') and p.endswith('"') else p for p in parts]
            if headers:
                rows.append(dict(zip(headers, parts)))
            else:
                rows.append({
                    "type": parts[0],
                    "label": parts[1] if len(parts)>1 else "",
                    "username": parts[2] if len(parts)>2 else "",
                    "secret": parts[3] if len(parts)>3 else "",
                    "notes": parts[4] if len(parts)>4 else "",
                    "created": parts[5] if len(parts)>5 else "",
                    "extra": parts[6] if len(parts)>6 else "",
                    "url": parts[7] if len(parts)>7 else "",
                })
    return rows

def load_rows():
    if fmt in ("json","jsonc","ndjson","jsonl","csv","csv-noheader","tsv","scsv","psv"):
        return parse_rows()
    return parse_advanced_rows()

rows = load_rows()
if not rows:
    raise ValueError("No records detected in import.")

added = 0
skipped = {}
for row in rows:
    t = (row.get("type","") or "").lower()
    if t in ("password","pass"):
        add_password(row)
        added += 1
    elif t in ("note","notes"):
        add_note(row)
        added += 1
    elif t in ("passphrase","phrase","secret"):
        add_passphrase(row)
        added += 1
    elif t in ("backup_code","backup","codes","backupcode"):
        add_backup(row)
        added += 1
    elif t in ("authenticator","auth"):
        add_auth(row)
        added += 1
    else:
        # Rows used to be dropped in silence, so a partial import looked
        # identical to a complete one. Name the types that were not understood.
        skipped[t or "(blank)"] = skipped.get(t or "(blank)", 0) + 1

if added == 0:
    raise ValueError("No supported records found in import.")

sys.stderr.write("Imported %d of %d record(s).\n" % (added, len(rows)))
if skipped:
    detail = ", ".join("%s x%d" % (k, v) for k, v in sorted(skipped.items()))
    sys.stderr.write("Skipped %d record(s) with unrecognised type: %s\n"
                     % (sum(skipped.values()), detail))

with open(vault_path, "w", encoding="utf-8") as f:
    for ln in lines:
        f.write(ln + "\n")
PY
	then
		secure_wipe "$tmp"
		die "Import failed."
	fi

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Import selesai dari %s (%s)\n" "$infile" "$format"
	else
		printf "Import complete from %s (%s)\n" "$infile" "$format"
	fi
}

# ----- Local-first advanced capabilities (2.10) ------------------------------

cmd_security_dashboard() {
	[ -f "$VAULT_FILE" ] || die "Vault not found."
	local tmp
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	python3 - "$tmp" <<'PY'
import base64, collections, datetime, re, sys
path=sys.argv[1]; today=datetime.datetime.now(datetime.timezone.utc)
rows=[]; malformed=[]
for raw in open(path,encoding="utf-8",errors="replace"):
    line=raw.rstrip("\n")
    if not line or line.startswith("#") or line.startswith("META_"): continue
    p=line.split("\t"); tag=p[0]
    if tag.isdigit() and len(p)>=6: rows.append((tag,p[1],p[2],p[3],p[5]))
    elif tag=="AUTH" and (len(p)<7 or p[6] not in ("sha1","sha256","sha512") or not p[3]): malformed.append(("authenticator",p[1] if len(p)>1 else "?"))
weak=[]; old=[]; incomplete=[]; groups=collections.defaultdict(list)
for rid,label,user,secret,created in rows:
    groups[secret].append(rid)
    score=sum(bool(re.search(x,secret)) for x in (r"[a-z]",r"[A-Z]",r"\d",r"[^A-Za-z0-9]"))
    if len(secret)<12 or score<3: weak.append(rid)
    if not label or not user: incomplete.append(rid)
    try:
        stamp=datetime.datetime.fromisoformat(created.replace("Z","+00:00"))
        if stamp.tzinfo is None: stamp=stamp.replace(tzinfo=datetime.timezone.utc)
        if (today-stamp).days>365: old.append(rid)
    except Exception: pass
reused=[ids for secret,ids in groups.items() if secret and len(ids)>1]
penalty=min(100,len(weak)*12+sum(len(x) for x in reused)*10+len(old)*4+len(incomplete)*3+len(malformed)*8)
print("Security dashboard")
print("==================")
print(f"Score: {100-penalty}/100")
print(f"Passwords: {len(rows)}")
print("Weak IDs:", ", ".join(weak) or "none")
print("Reused groups:", "; ".join(",".join(x) for x in reused) or "none")
print("Older than 365 days:", ", ".join(old) or "none")
print("Incomplete IDs:", ", ".join(incomplete) or "none")
print("Malformed protected records:", ", ".join(f"{t}:{i}" for t,i in malformed) or "none")
print("Secrets and fingerprints are never printed or persisted.")
PY
	secure_wipe "$tmp"
}

cmd_history_list() {
	local dir
	dir="$(history_dir)"
	[ -d "$dir" ] || { printf 'No encrypted history snapshots.\n'; return 0; }
	find "$dir" -maxdepth 1 -type f -name '*.gpg' -print 2>/dev/null \
		| while IFS= read -r snapshot; do basename "$snapshot"; done | sort -r
}

cmd_history_restore() {
	local name="${1:-}" dir source answer staged verify_tmp
	[ -n "$name" ] || die "Usage: $0 history-restore <snapshot-name>"
	case "$name" in */*|*\\*|.|..) die "Invalid snapshot name." ;; esac
	dir="$(history_dir)"; source="$dir/$name"
	[ -f "$source" ] || die "History snapshot not found."
	printf "Restore encrypted snapshot %s? (yes/NO): " "$name"; read -r answer || answer=no
	case "$answer" in yes|y|YES|Y) ;; *) return 1 ;; esac
	ensure_master_password_loaded; verify_tmp="$(make_tmp)"
	# No key variable: a snapshot carries its own vault key, and letting that
	# key escape into the next write would seal the live vault under it.
	decrypt_vault_container "$source" "$verify_tmp" "$MASTER_PW" \
		|| { secure_wipe "$verify_tmp"; die "History snapshot failed authentication or uses a different master password."; }
	secure_wipe "$verify_tmp"
	staged="$(mktemp "$(dirname "$VAULT_FILE")/.spm_history_restore.XXXXXX")"
	cp "$source" "$staged" || { rm -f "$staged"; die "Failed to stage history snapshot."; }
	chmod 600 "$staged" 2>/dev/null || true
	archive_current_vault
	mv -f "$staged" "$VAULT_FILE" || { rm -f "$staged"; die "Failed to restore history snapshot."; }
	printf 'History snapshot restored.\n'
}

cmd_backup_now() {
	[ -f "$VAULT_FILE" ] || die "Vault not found."
	local target="${1:-$SPM_DATA_DIR/backups}" name digest
	mkdir -p "$target" || die "Failed to create backup directory."
	chmod 700 "$target" 2>/dev/null || true
	name="spm-$(vault_scope_id)-$(date -u +%Y%m%dT%H%M%SZ)-$$.gpg"
	cp "$VAULT_FILE" "$target/$name" || die "Backup failed."
	chmod 600 "$target/$name" 2>/dev/null || true
	digest="$(sha256sum "$VAULT_FILE" | awk '{print $1}')"
	[ "$digest" = "$(sha256sum "$target/$name" | awk '{print $1}')" ] || die "Backup verification failed."
	printf '%s\n' "$target/$name"
}

cmd_backup_auto() {
	local action="${1:-status}" cfg target hours retention
	cfg="$(auto_backup_config)"; mkdir -p "$SPM_CONFIG_DIR"; chmod 700 "$SPM_CONFIG_DIR" 2>/dev/null || true
	case "$action" in
		enable)
			target="${2:-$SPM_DATA_DIR/backups}"; hours="${3:-24}"; retention="${4:-14}"
			printf '%s' "$hours$retention" | grep -Eq '^[0-9]+$' || die "Hours and retention must be positive integers."
			if [ "$hours" -le 0 ] || [ "$retention" -le 0 ]; then die "Hours and retention must be positive."; fi
			mkdir -p "$target" || die "Cannot create automatic-backup directory."
			printf 'enabled\n%s\n%s\n%s\n0\n' "$(canon_path "$target")" "$hours" "$retention" > "$cfg"
			chmod 600 "$cfg"; maybe_auto_backup; printf 'Automatic encrypted backups enabled.\n' ;;
		disable) printf 'disabled\n' > "$cfg"; chmod 600 "$cfg"; printf 'Automatic backups disabled.\n' ;;
		status) [ -f "$cfg" ] && sed -n '1,4p' "$cfg" || printf 'disabled\n' ;;
		*) die "Usage: $0 backup-auto enable [directory] [hours] [retention] | disable | status" ;;
	esac
}

validate_profile_name() {
	printf '%s' "$1" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$' || die "Invalid profile name."
}

cmd_vault_profile() {
	local action="${1:-list}" name path tmp
	mkdir -p "$SPM_CONFIG_DIR"; chmod 700 "$SPM_CONFIG_DIR" 2>/dev/null || true
	[ -f "$SPM_PROFILE_FILE" ] || : > "$SPM_PROFILE_FILE"; chmod 600 "$SPM_PROFILE_FILE"
	case "$action" in
		list) awk -F '\t' '{printf "%-20s %s\n",$1,$2}' "$SPM_PROFILE_FILE" ;;
		add)
			name="${2:-}"; path="${3:-}"; validate_profile_name "$name"; [ -n "$path" ] || die "Vault path required."
			if printf '%s' "$path" | LC_ALL=C grep -q '[[:cntrl:]]'; then die "Vault paths cannot contain control characters."; fi
			path="$(canon_path "$path")"; awk -F '\t' -v n="$name" '$1==n{found=1} END{exit found?0:1}' "$SPM_PROFILE_FILE" && die "Profile already exists."
			printf '%s\t%s\n' "$name" "$path" >> "$SPM_PROFILE_FILE"; printf 'Profile added.\n' ;;
		use)
			name="${2:-}"; validate_profile_name "$name"; profile_vault_path "$name" >/dev/null || die "Unknown profile."
			printf '%s\n' "$name" > "$SPM_DEFAULT_PROFILE_FILE"; chmod 600 "$SPM_DEFAULT_PROFILE_FILE"; printf 'Default profile set; restart SPM to apply.\n' ;;
		remove)
			name="${2:-}"; validate_profile_name "$name"; tmp="$(make_tmp)"; awk -F '\t' -v n="$name" '$1!=n' "$SPM_PROFILE_FILE" > "$tmp"; mv "$tmp" "$SPM_PROFILE_FILE"; chmod 600 "$SPM_PROFILE_FILE"
			if [ -f "$SPM_DEFAULT_PROFILE_FILE" ] && [ "$(sed -n '1p' "$SPM_DEFAULT_PROFILE_FILE")" = "$name" ]; then rm -f "$SPM_DEFAULT_PROFILE_FILE"; fi
			printf 'Profile removed; vault data was not deleted.\n' ;;
		*) die "Usage: $0 vault-profile list|add <name> <path>|use <name>|remove <name>" ;;
	esac
}

next_tag_id() {
	local tag="$1" file="$2"
	awk -F '\t' -v tag="$tag" '$1==tag && $2~/^[0-9]+$/ && $2>m{m=$2} END{print m+1}' "$file"
}

cmd_attachment_add() {
	local file="${1:-}" label="${2:-}" size tmp id encoded filename mime digest created
	[ -f "$file" ] || die "Attachment file not found."
	size="$(wc -c < "$file" | tr -d ' ')"; [ "$size" -le 1048576 ] || die "Attachment exceeds the 1 MiB limit."
	[ -n "$label" ] || label="$(basename "$file")"; label="$(sanitize_field "$label")"
	filename="$(printf '%s' "$(basename "$file")" | base64 | tr -d '\n')"
	mime="$(file -b --mime-type "$file" 2>/dev/null || printf 'application/octet-stream')"; mime="$(sanitize_field "$mime")"
	encoded="$(base64 < "$file" | tr -d '\n')"; digest="$(sha256sum "$file" | awk '{print $1}')"; created="$(now_iso)"
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"; id="$(next_tag_id ATTACHMENT "$tmp")"
	printf 'ATTACHMENT\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" "$filename" "$mime" "$encoded" "$digest" "$created" >> "$tmp"
	encrypt_file_to_vault "$tmp"; secure_wipe "$tmp"; printf 'Attachment added with ID %s.\n' "$id"
}

cmd_attachment_list() {
	local tmp; tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	awk -F '\t' '$1=="ATTACHMENT"{printf "%s\t%s\t%s\t%s\n",$2,$3,$5,$8}' "$tmp"; secure_wipe "$tmp"
}

cmd_attachment_extract() {
	local id="${1:-}" out="${2:-}" tmp payload filename digest actual
	printf '%s' "$id" | grep -Eq '^[0-9]+$' || die "Numeric attachment ID required."
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	payload="$(awk -F '\t' -v id="$id" '$1=="ATTACHMENT"&&$2==id{print $6;exit}' "$tmp")"
	filename="$(awk -F '\t' -v id="$id" '$1=="ATTACHMENT"&&$2==id{print $4;exit}' "$tmp" | base64 -d 2>/dev/null || true)"
	digest="$(awk -F '\t' -v id="$id" '$1=="ATTACHMENT"&&$2==id{print $7;exit}' "$tmp")"; secure_wipe "$tmp"
	[ -n "$payload" ] || die "Attachment not found."; [ -n "$out" ] || out="./$filename"; [ ! -e "$out" ] || die "Destination already exists."
	printf '%s' "$payload" | base64 -d > "$out" || { rm -f "$out"; die "Attachment decode failed."; }
	actual="$(sha256sum "$out" | awk '{print $1}')"; [ "$actual" = "$digest" ] || { secure_wipe "$out"; die "Attachment integrity check failed."; }
	chmod 600 "$out" 2>/dev/null || true; printf '%s\n' "$out"
}

cmd_tag_delete() {
	local tag="$1" id="$2" label="$3" tmp next found=0
	printf '%s' "$id" | grep -Eq '^[0-9]+$' || die "Numeric ID required."
	tmp="$(make_tmp)"; next="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	while IFS= read -r line || [ -n "$line" ]; do
		if [ "${line%%$'\t'*}" = "$tag" ] && [ "$(printf '%s' "$line" | cut -f2)" = "$id" ]; then found=1; else printf '%s\n' "$line" >> "$next"; fi
	done < "$tmp"
	[ "$found" = 1 ] || { secure_wipe "$tmp"; secure_wipe "$next"; die "$label not found."; }
	encrypt_file_to_vault "$next"; secure_wipe "$tmp"; secure_wipe "$next"; printf '%s deleted.\n' "$label"
}

cmd_passkey_add() {
	local rp="${1:-}" account="${2:-}" credential="${3:-}" notes="${4:-}" tmp id created encoded
	if [ -z "$rp" ] || [ -z "$account" ] || [ -z "$credential" ]; then die "Usage: $0 passkey-add <rp-id> <account> <credential-id> [notes]"; fi
	rp="$(sanitize_field "$rp")"; account="$(sanitize_field "$account")"; credential="$(sanitize_field "$credential")"; encoded="$(printf '%s' "$notes" | base64 | tr -d '\n')"; created="$(now_iso)"
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"; id="$(next_tag_id PASSKEY "$tmp")"
	printf 'PASSKEY\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$rp" "$account" "$credential" "$encoded" "$created" >> "$tmp"
	encrypt_file_to_vault "$tmp"; secure_wipe "$tmp"; printf 'Passkey metadata added with ID %s; private key remains in the platform authenticator.\n' "$id"
}

cmd_passkey_list() {
	local tmp; tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"; awk -F '\t' '$1=="PASSKEY"{printf "%s\t%s\t%s\t%s\n",$2,$3,$4,$7}' "$tmp"; secure_wipe "$tmp"
}

# SPM Dashboard biometric unlock credentials. A separate row type from PASSKEY on
# purpose: a PASSKEY row describes a passkey held somewhere else, while these
# open this vault. The public key column is deliberately not printed -- it is
# long, it is never useful to read by eye, and the list is for deciding what to
# revoke. Registration is browser-only, so there is no matching add command.
cmd_webauthn_list() {
	local tmp; tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	awk -F '\t' '$1=="WEBAUTHN"{printf "%s\t%s\t%s\t%s\n",$2,$6,$5,$7}' "$tmp"
	secure_wipe "$tmp"
}

sync_paths() {
	local target="$1" channel="$2" target_id
	printf '%s' "$channel" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' || die "Invalid sync channel."
	target_id="$(printf '%s\t%s' "$target" "$channel" | sha256sum | awk '{print substr($1,1,16)}')"
	mkdir -p "$SPM_CONFIG_DIR"; chmod 700 "$SPM_CONFIG_DIR" 2>/dev/null || true
	SYNC_REMOTE="$target/spm-$channel.gpg"; SYNC_STATE="$SPM_CONFIG_DIR/sync-$target_id.base-sha256"
}

write_sync_state() {
	local digest="$1" staged_state
	staged_state="$(mktemp "$SPM_CONFIG_DIR/.spm-sync-state.XXXXXX")" || die "Cannot stage sync state."
	printf '%s\n' "$digest" > "$staged_state"; chmod 600 "$staged_state"
	mv -f "$staged_state" "$SYNC_STATE" || { rm -f "$staged_state"; die "Cannot install sync state."; }
}

cmd_sync() {
	local action="${1:-status}" target="${2:-}" channel="${3:-default}" local_sha remote_sha base_sha staged tmp
	[ -n "$target" ] || die "Usage: $0 sync status|push|pull <directory> [channel]"
	mkdir -p "$target" || die "Cannot create sync target."; target="$(canon_path "$target")"; sync_paths "$target" "$channel"
	local_sha=""; remote_sha=""; base_sha=""
	if [ -f "$VAULT_FILE" ]; then local_sha="$(sha256sum "$VAULT_FILE" | awk '{print $1}')"; fi
	if [ -f "$SYNC_REMOTE" ]; then remote_sha="$(sha256sum "$SYNC_REMOTE" | awk '{print $1}')"; fi
	if [ -f "$SYNC_STATE" ]; then base_sha="$(sed -n '1p' "$SYNC_STATE")"; fi
	case "$action" in
		status) printf 'local=%s\nremote=%s\nbase=%s\n' "${local_sha:-missing}" "${remote_sha:-missing}" "${base_sha:-none}" ;;
		push)
			[ -n "$local_sha" ] || die "Local vault missing."
			if [ -n "$remote_sha" ] && [ -z "$base_sha" ] && [ "$local_sha" != "$remote_sha" ] && [ "${SPM_SYNC_FORCE_INITIAL:-0}" != 1 ]; then die "Initial sync conflict: remote differs; pull or set SPM_SYNC_FORCE_INITIAL=1 after verification."; fi
			if [ -n "$remote_sha" ] && [ -n "$base_sha" ] && [ "$remote_sha" != "$base_sha" ] && [ "$local_sha" != "$base_sha" ]; then die "Sync conflict: local and remote both changed."; fi
			staged="$(mktemp "$target/.spm-sync.XXXXXX")"; cp "$VAULT_FILE" "$staged" || { rm -f "$staged"; die "Cannot stage sync push."; }; chmod 600 "$staged"
			[ "$(sha256sum "$staged" | awk '{print $1}')" = "$local_sha" ] || { secure_wipe "$staged"; die "Staged sync push failed verification."; }
			mv -f "$staged" "$SYNC_REMOTE"; write_sync_state "$local_sha"; printf 'Encrypted vault pushed.\n' ;;
		pull)
			[ -n "$remote_sha" ] || die "Remote vault missing."
			if [ -n "$local_sha" ] && [ -z "$base_sha" ] && [ "$local_sha" != "$remote_sha" ] && [ "${SPM_SYNC_FORCE_INITIAL:-0}" != 1 ]; then die "Initial sync conflict: local differs; set SPM_SYNC_FORCE_INITIAL=1 only after verification."; fi
			if [ -n "$local_sha" ] && [ -n "$base_sha" ] && [ "$local_sha" != "$base_sha" ] && [ "$remote_sha" != "$base_sha" ]; then die "Sync conflict: local and remote both changed."; fi
			tmp="$(make_tmp)"; ensure_master_password_loaded
			decrypt_vault_container "$SYNC_REMOTE" "$tmp" "$MASTER_PW" || { secure_wipe "$tmp"; die "Remote vault cannot be decrypted with this master password."; }
			secure_wipe "$tmp"; archive_current_vault; staged="$(mktemp "$(dirname "$VAULT_FILE")/.spm-sync.XXXXXX")"; cp "$SYNC_REMOTE" "$staged" || { rm -f "$staged"; die "Cannot stage sync pull."; }; chmod 600 "$staged"
			[ "$(sha256sum "$staged" | awk '{print $1}')" = "$remote_sha" ] || { secure_wipe "$staged"; die "Staged sync pull failed verification."; }
			mv -f "$staged" "$VAULT_FILE"; write_sync_state "$remote_sha"; printf 'Encrypted vault pulled.\n' ;;
		*) die "Usage: $0 sync status|push|pull <directory> [channel]" ;;
	esac
}

cmd_emergency_create() {
	local id="${1:-}" public_key="${2:-}" activation="${3:-}" output="${4:-}" tmp payload key_file kit_dir
	printf '%s' "$id" | grep -Eq '^[0-9]+$' || die "Numeric password ID required."
	[ -f "$public_key" ] || die "Recipient RSA public key not found."
	[ -n "$activation" ] || die "Activation date required (YYYY-MM-DD)."
	python3 - "$activation" <<'PY' >/dev/null || die "Invalid activation date."
import datetime,sys
datetime.date.fromisoformat(sys.argv[1])
PY
	[ -n "$output" ] || output="emergency-$id-$activation.tar.gz"; [ ! -e "$output" ] || die "Emergency archive already exists."
	tmp="$(make_tmp)"; payload="$(make_tmp)"; key_file="$(make_tmp)"; kit_dir="$(mktemp -d "${TMPDIR:-/tmp}/spm-emergency.XXXXXX")"; chmod 700 "$kit_dir"
	decrypt_vault_to_file "$tmp"
	python3 - "$tmp" "$id" > "$payload" <<'PY'
import json,sys
for line in open(sys.argv[1],encoding="utf-8"):
 p=line.rstrip("\n").split("\t")
 if p and p[0]==sys.argv[2] and len(p)>=6:
  print(json.dumps({"type":"password","label":p[1],"username":p[2],"secret":p[3],"notes":p[4],"created":p[5],"url":p[6] if len(p)>6 else ""},ensure_ascii=False));break
else: raise SystemExit("record not found")
PY
	openssl rand -hex 32 > "$key_file"
	openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass file:"$key_file" -in "$payload" -out "$kit_dir/payload.enc"
	openssl pkeyutl -encrypt -pubin -inkey "$public_key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in "$key_file" -out "$kit_dir/key.enc"
	printf 'SPM emergency kit\nactivation=%s\ncreated=%s\nnotice=Activation is advisory; offline recipients can decrypt early.\nfiles=key.enc,payload.enc,payload.hmac\n' "$activation" "$(now_iso)" > "$kit_dir/manifest.txt"
	python3 - "$key_file" "$kit_dir/manifest.txt" "$kit_dir/payload.enc" "$kit_dir/payload.hmac" <<'PY'
import hashlib,hmac,sys
key=bytes.fromhex(open(sys.argv[1],encoding="ascii").read().strip())
data=open(sys.argv[2],"rb").read()+open(sys.argv[3],"rb").read()
open(sys.argv[4],"w",encoding="ascii").write(hmac.new(key,data,hashlib.sha256).hexdigest()+"\n")
PY
	chmod 600 "$kit_dir"/*; tar -czf "$output" -C "$kit_dir" manifest.txt key.enc payload.enc payload.hmac
	chmod 600 "$output" 2>/dev/null || true; secure_wipe "$tmp"; secure_wipe "$payload"; secure_wipe "$key_file"; secure_wipe "$kit_dir/key.enc"; secure_wipe "$kit_dir/payload.enc"; secure_wipe "$kit_dir/payload.hmac"; secure_wipe "$kit_dir/manifest.txt"; rmdir "$kit_dir"
	printf '%s\n' "$output"
}

cmd_emergency_open() {
	local archive="${1:-}" private_key="${2:-}" output="${3:-./spm-emergency-record.json}" manifest activation activation_epoch now key_file plain_key payload_file hmac_file manifest_file
	if [ ! -f "$archive" ] || [ ! -f "$private_key" ]; then
		die "Usage: $0 emergency-open <archive> <private.pem> [output.json]"
	fi
	[ ! -e "$output" ] || die "Output file already exists."
	manifest="$(tar -xOf "$archive" manifest.txt 2>/dev/null)" || die "Invalid emergency archive."
	activation="$(printf '%s\n' "$manifest" | awk -F= '$1=="activation"{print $2;exit}')"
	activation_epoch="$(python3 - "$activation" <<'PY'
import datetime,sys
print(int(datetime.datetime.combine(datetime.date.fromisoformat(sys.argv[1]),datetime.time(),tzinfo=datetime.timezone.utc).timestamp()))
PY
)" || die "Invalid emergency activation date."
	now="$(date +%s)"; [ "$now" -ge "$activation_epoch" ] || die "Emergency kit is scheduled for $activation."
	key_file="$(make_tmp)"; plain_key="$(make_tmp)"; payload_file="$(make_tmp)"; hmac_file="$(make_tmp)"; manifest_file="$(make_tmp)"
	printf '%s\n' "$manifest" > "$manifest_file"
	tar -xOf "$archive" key.enc > "$key_file" 2>/dev/null || die "Emergency key payload missing."
	tar -xOf "$archive" payload.enc > "$payload_file" 2>/dev/null || die "Emergency record payload missing."
	tar -xOf "$archive" payload.hmac > "$hmac_file" 2>/dev/null || die "Emergency integrity tag missing."
	openssl pkeyutl -decrypt -inkey "$private_key" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -in "$key_file" -out "$plain_key" || die "Emergency private key does not match."
	python3 - "$plain_key" "$manifest_file" "$payload_file" "$hmac_file" <<'PY'
import hashlib,hmac,sys
key=bytes.fromhex(open(sys.argv[1],encoding="ascii").read().strip())
data=open(sys.argv[2],"rb").read()+open(sys.argv[3],"rb").read()
expected=open(sys.argv[4],encoding="ascii").read().strip()
if not hmac.compare_digest(hmac.new(key,data,hashlib.sha256).hexdigest(),expected):
 raise SystemExit("emergency kit authentication failed")
PY
	openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"$plain_key" -in "$payload_file" -out "$output" || { secure_wipe "$output"; die "Emergency payload decryption failed."; }
	chmod 600 "$output" 2>/dev/null || true; secure_wipe "$key_file"; secure_wipe "$plain_key"; secure_wipe "$payload_file"; secure_wipe "$hmac_file"; secure_wipe "$manifest_file"; printf '%s\n' "$output"
}

cmd_bridge_get() {
	local id="${1:-}" host="${2:-}" tmp
	printf '%s' "$id" | grep -Eq '^[0-9]+$' || die "Numeric record ID required."
	[ -n "$host" ] || die "Browser hostname required."
	IFS= read -r MASTER_PW || die "Master password required on stdin."
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	local status=0
	python3 - "$tmp" "$id" "$host" <<'PY' || status=$?
import json,re,sys,urllib.parse
path,rid,requested=sys.argv[1:]; requested=requested.lower().strip(".")
for line in open(path,encoding="utf-8",errors="replace"):
 p=line.rstrip("\n").split("\t")
 if p and p[0]==rid and len(p)>=6:
  label,user,secret,notes=p[1:5]
  url=p[6] if len(p)>6 else ""
  candidates={label.lower().strip(".")}
  # The url field is the intended binding source. Notes are still scanned so
  # that vaults written before 2.12.0 -- where a URL could only live in the
  # notes -- keep matching exactly as they did, with no rewrite on upgrade.
  for token in ([url] if url else [])+re.findall(r"https?://[^\s]+",notes):
   if not re.match(r"(?i)^https?://",token):continue
   try:candidates.add((urllib.parse.urlparse(token).hostname or "").lower().strip("."))
   except ValueError:pass
  candidates.discard("")
  if requested not in candidates:
   print(json.dumps({"ok":False,"error":"record is not bound to this hostname"}));raise SystemExit(2)
  print(json.dumps({"ok":True,"username":user,"password":secret}));break
else:
 print(json.dumps({"ok":False,"error":"record not found"}));raise SystemExit(1)
PY
	secure_wipe "$tmp"; MASTER_PW=""
	# Report the helper's status rather than the cleanup's. As a command,
	# `spm bridge-get` already exited non-zero on a refusal because errexit
	# aborted here; called as a shell function inside an `if`, errexit is
	# suppressed and the old ending returned the status of MASTER_PW="",
	# i.e. success, for a record bound to a different hostname. Capturing it
	# explicitly makes both callers agree and keeps the wipe unconditional.
	return "$status"
}

cmd_bridge_list() {
	local host="${1:-}" tmp
	[ -n "$host" ] || die "Browser hostname required."
	IFS= read -r MASTER_PW || die "Master password required on stdin."
	tmp="$(make_tmp)"; decrypt_vault_to_file "$tmp"
	local status=0
	python3 - "$tmp" "$host" <<'PY' || status=$?
import json,re,sys,urllib.parse
path,requested=sys.argv[1:]; requested=requested.lower().strip(".")
if not requested or any(c.isspace() for c in requested):
 print(json.dumps({"ok":False,"error":"invalid browser hostname"}));raise SystemExit(2)
matches=[]
for line in open(path,encoding="utf-8",errors="replace"):
 p=line.rstrip("\n").split("\t")
 if not p or not p[0].isdigit() or len(p)<6:continue
 rid,label,user,notes=p[0],p[1],p[2],p[4]
 url=p[6] if len(p)>6 else ""
 candidates={label.lower().strip(".")}
 for token in ([url] if url else [])+re.findall(r"https?://[^\s]+",notes):
  if not re.match(r"(?i)^https?://",token):continue
  try:candidates.add((urllib.parse.urlparse(token).hostname or "").lower().strip("."))
  except ValueError:pass
 candidates.discard("")
 if requested in candidates:
  matches.append({"id":rid,"label":label,"username":user,"url":url})
print(json.dumps({"ok":True,"matches":matches}))
PY
	secure_wipe "$tmp"; MASTER_PW=""
	return "$status"
}

cmd_help() {
	print_banner

	if [ "$SPM_LANG" = "id" ]; then
		cat <<EOF
[ID] Panduan Singkat
====================

Sans Password Manager (SPM) v$VERSION

Perintah utama (CLI):
  ./spm.sh                 → Menu interaktif (TUI)
  ./spm.sh init            → Inisialisasi vault baru + buat pasangan kunci pemulihan
  ./spm.sh add             → Tambah entry password
  ./spm.sh list            → List semua entry password
  ./spm.sh get <id|pola>   → Lihat entry / cari (dengan helper clipboard + auto-bersihkan)
  ./spm.sh edit            → Edit vault mentah dengan editor teks
  ./spm.sh delete <id>     → Hapus entry password
  ./spm.sh change-master   → Ganti kata sandi utama (re-encrypt vault)
  ./spm.sh portable [nama] → Buat bundle portable (script + vault + file pemulihan)
  ./spm.sh save [nama]     → Buat bundle portable lalu hapus vault lokal
  ./spm.sh restore         → Pindahkan vault bundle ke lokasi default (~/.spm_vault.gpg)
  ./spm.sh export [fmt] [file]
                            → Ekspor semua data (password/catatan/passphrase/authenticator/kode backup) ke csv/json
  ./spm.sh import [fmt] <file>
                            → Impor data (password/catatan/passphrase/authenticator/kode backup) dari csv/json dan format lain
  ./spm.sh update          → Cek & auto-install rilis terbaru dari GitHub
  ./spm.sh auto-update [status|off|notify|auto]
                           → Aktifkan cek rilis harian saat mulai
  ./spm.sh forgot          → Reset kata sandi utama dengan private key
  ./spm.sh doctor          → Health / integrity check vault
  ./spm.sh doctor --json   → the same checks as JSON, for scripts
  ./spm.sh generate        → Generator kata sandi (panjang, mode mudah/aman/angka, simbol opsional)
  ./spm.sh web|dashboard   → SPM Dashboard (sementara / background via pm2)
  ./spm.sh help            → Tampilkan bantuan ini

Fitur lokal 2.10:
  ./spm.sh security                     → Dashboard keamanan vault
  ./spm.sh history-list                 → Daftar histori vault terenkripsi
  ./spm.sh history-restore <snapshot>   → Pulihkan snapshot setelah konfirmasi
  ./spm.sh backup-now [dir]             → Backup terenkripsi terverifikasi
  ./spm.sh backup-auto enable [dir] [jam] [retensi]
  ./spm.sh vault-profile list|add|use|remove
  ./spm.sh attachment-add <file> [label]
  ./spm.sh attachment-list|attachment-extract|attachment-delete
  ./spm.sh passkey-add <rp> <akun> <credential-id> [catatan]
  ./spm.sh passkey-list|passkey-delete
  ./spm.sh webauthn-list|webauthn-delete <id>
  ./spm.sh sync status|push|pull <direktori> [channel]
  ./spm.sh emergency-create <id> <public.pem> <YYYY-MM-DD> [arsip]
  ./spm.sh emergency-open <arsip> <private.pem> [output.json]

Catatan Aman (Secure Notes):
  ./spm.sh notes-add       → Tambah catatan aman
  ./spm.sh notes-list      → List catatan aman
  ./spm.sh notes-view <id> → Lihat isi catatan aman
  ./spm.sh notes-delete <id>
                           → Hapus catatan aman

Passphrase:
  ./spm.sh passphrase-add       → Tambah passphrase
  ./spm.sh passphrase-list      → List passphrase
  ./spm.sh passphrase-view <id> → Lihat passphrase (minta verifikasi master password)
  ./spm.sh passphrase-delete <id>
                                 → Hapus passphrase

Authenticator (TOTP):
  ./spm.sh authenticator-add        → Tambah kode authenticator (Base32 secret + interval)
  ./spm.sh authenticator-list       → List authenticator
  ./spm.sh authenticator-view <id>  → Lihat detail + kode OTP
  ./spm.sh authenticator-edit <id>  → Edit label/secret/interval
  ./spm.sh authenticator-delete <id>→ Hapus authenticator

Kode Backup (Backup Codes):
  ./spm.sh backup-codes-add       → Tambah kode backup
  ./spm.sh backup-codes-list      → List kode backup
  ./spm.sh backup-codes-view <id> → Lihat kode backup
  ./spm.sh backup-codes-delete <id>
                                  → Hapus kode backup

Mode Web:
  - Menjalankan HTTP server ringan untuk melihat vault lewat browser.
  - Login memakai kata sandi utama.
  - Pilihan mode:
      • Mode sementara (jalan di foreground, stop dengan Ctrl + C)
      • Mode background (menggunakan pm2; akan di-install otomatis jika memungkinkan)
  - Antarmuka:
      • Tabel password (ID, service, username – password tidak ditampilkan)
      • Bagian Secure Notes (lihat / tambah / edit / hapus catatan)
  - Sesi web otomatis terkunci jika tidak ada aktivitas ~30 detik.

Clipboard & Coaching Password:
  - Saat password disalin, clipboard akan dibersihkan otomatis setelah beberapa detik:
      • macOS  : pbcopy < /dev/null
      • Linux  : xclip /dev/null
      • Termux : termux-clipboard-set ""
  - Jika helper clipboard tidak tersedia, akan menampilkan:
        "Tidak ada helper clipboard tersedia"
    (termasuk saat memakai menu interaktif).
  - Saat membuat password, SPM menampilkan:
      • estimasi entropy
      • estimasi waktu tebak (guess time)
      • analisis jenis karakter (huruf kecil/besar, angka, simbol)
      • saran penguatan password dengan penjelasan Indonesia + Inggris.

Format internal vault:
  - Baris password:
      id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at
  - Baris note:
      NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-
  - Baris passphrase:
      PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-
  - Baris meta:
      META_RECOVERY_PUBKEY=...   (kunci publik pemulihan disimpan di vault)

EOF
	else
		cat <<EOF
[EN] Quick Guide
================

Sans Password Manager (SPM) v$VERSION

Main commands (CLI):
  ./spm.sh                 → Interactive TUI menu
  ./spm.sh init            → Initialize a new vault + generate recovery key pair
  ./spm.sh add             → Add a password entry
  ./spm.sh list            → List password entries
  ./spm.sh get <id|pattern>→ View entry / search (with clipboard helper + auto wipe)
  ./spm.sh edit            → Edit raw vault with your editor
  ./spm.sh delete <id>     → Delete a password entry
  ./spm.sh change-master   → Change master password (re-encrypt vault)
  ./spm.sh portable [name] → Create portable bundle (script + vault + recovery files)
  ./spm.sh save [name]     → Create portable bundle and wipe local vault
  ./spm.sh restore         → Move bundle vault back to default location (~/.spm_vault.gpg)
  ./spm.sh export [fmt] [file]
                            → Export all data (passwords/notes/passphrases/authenticators/backup codes) to csv/json
  ./spm.sh import [fmt] <file>
                             → Import data (passwords/notes/passphrases/authenticators/backup codes) from csv/json and other supported formats
  ./spm.sh update          → Check & auto-install latest GitHub release
  ./spm.sh forgot          → Reset master password using the private key
  ./spm.sh doctor          → Vault health / integrity check
  ./spm.sh doctor --json   → the same checks as JSON, for scripts
  ./spm.sh generate        → Password generator (length, easy/secure/numeric, optional symbols/upper/lower/digits)
  ./spm.sh web|dashboard   → SPM Dashboard (foreground or pm2 background)
  ./spm.sh help            → Show this help

Local-first 2.10 capabilities:
  ./spm.sh security                     → Vault security dashboard
  ./spm.sh history-list                 → List encrypted vault history
  ./spm.sh history-restore <snapshot>   → Restore after confirmation
  ./spm.sh backup-now [dir]             → Verified encrypted backup
  ./spm.sh backup-auto enable [dir] [hours] [retention]
  ./spm.sh vault-profile list|add|use|remove
  ./spm.sh attachment-add <file> [label]
  ./spm.sh attachment-list|attachment-extract|attachment-delete
  ./spm.sh passkey-add <rp> <account> <credential-id> [notes]
  ./spm.sh passkey-list|passkey-delete
  ./spm.sh webauthn-list|webauthn-delete <id>
  ./spm.sh sync status|push|pull <directory> [channel]
  ./spm.sh emergency-create <id> <public.pem> <YYYY-MM-DD> [archive]
  ./spm.sh emergency-open <archive> <private.pem> [output.json]

Secure Notes:
  ./spm.sh notes-add       → Add secure note
  ./spm.sh notes-list      → List secure notes
  ./spm.sh notes-view <id> → View secure note content
  ./spm.sh notes-delete <id>
                           → Delete secure note

Passphrases:
  ./spm.sh passphrase-add       → Add a passphrase
  ./spm.sh passphrase-list      → List passphrases
  ./spm.sh passphrase-view <id> → View passphrase (requires re-verification)
  ./spm.sh passphrase-delete <id>
                                 → Delete passphrase

Authenticator (TOTP):
  ./spm.sh authenticator-add        → Add an authenticator (Base32 secret + interval)
  ./spm.sh authenticator-list       → List authenticators
  ./spm.sh authenticator-view <id>  → View details + OTP code
  ./spm.sh authenticator-edit <id>  → Edit label/secret/interval
  ./spm.sh authenticator-delete <id>→ Delete an authenticator

Backup Codes:
  ./spm.sh backup-codes-add       → Add backup codes
  ./spm.sh backup-codes-list      → List backup codes
  ./spm.sh backup-codes-view <id> → View backup codes content
  ./spm.sh backup-codes-delete <id>
                                  → Delete backup codes

SPM Dashboard:
  - Runs a lightweight HTTP server so you can inspect your vault from a browser.
  - Protected by your master password.
  - Modes:
      • temporary (foreground, stop with Ctrl + C)
      • background (managed by pm2; installed automatically when possible)
  - UI:
      • Password entries table (ID, service, username / email, URL – passwords are not shown)
      • Secure notes section (view / add / edit / delete)
  - The dashboard session auto-locks after ~30 seconds of inactivity in the browser;
    the server also expires an idle session after 5 minutes on its own.
  - Register a device on the Biometric Unlock page and the idle lock resumes
    with Face ID or Touch ID instead of a retyped master password. Suspension
    is enforced by the server, not the browser; the master password is still
    required for the first sign-in and once the session hits its 12-hour cap.
    Needs a relying-party id (SPM_WEB_RP_ID, or SPM's own domain setup).
    Tune how long a locked session stays resumable with SPM_WEB_SUSPEND_MAX
    (seconds, default 28800).

Clipboard & Password Coaching:
  - When copying a password, clipboard is auto-cleared after a short delay:
      • macOS  : pbcopy < /dev/null
      • Linux  : xclip /dev/null
      • Termux : termux-clipboard-set ""
  - If no clipboard helper is available, you will see:
        "No clipboard helper available"
    (including when using the interactive menu).
  - When creating a password, SPM shows:
      • entropy estimate
      • guess time estimate
      • character type analysis (lower/upper/digits/symbols)
      • strengthening suggestions with both English + Indonesian explanation.

Internal vault format:
  - Password line:
      id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at
  - Note line:
      NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-
  - Passphrase line:
      PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-
  - Meta line:
      META_RECOVERY_PUBKEY=...   (recovery public key stored inside the vault)

EOF
	fi
}

configure_firewall_for_web() {
	local bind_addr="$1"
	local bind_port="$2"

	# Only care if binding to non-local address
	if [ "$bind_addr" = "127.0.0.1" ] || [ "$bind_addr" = "localhost" ]; then
		return 0
	fi
	[ -z "$bind_port" ] && return 0

	if [ "$SPM_LANG" = "id" ]; then
		echo
		echo ">> SPM tidak mengubah firewall secara otomatis."
		echo "   Jika diperlukan, izinkan port ${bind_port}/tcp hanya dari jaringan tepercaya."
	else
		echo
		echo ">> SPM does not modify your firewall automatically."
		echo "   If needed, allow port ${bind_port}/tcp only from a trusted network."
	fi
}
ensure_pm2_installed() {
	# If already installed, done.
	if command -v pm2 >/dev/null 2>&1; then
		return 0
	fi

	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "⚠️  PM2 belum terpasang. Mencoba menginstall otomatis..."
	else
		echo "⚠️  PM2 is not installed. Trying to install it automatically..."
	fi

	local pm2_ok=1

	# Termux branch (Android)
	if [ "$ENV_FLAVOR" = "termux" ] && command -v pkg >/dev/null 2>&1; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "→ Terdeteksi Termux. Menginstall nodejs..."
		else
			echo "→ Detected Termux. Installing nodejs..."
		fi
		pkg update -y || true
		pkg install -y nodejs || true

		if command -v npm >/dev/null 2>&1; then
			npm install -g pm2 && pm2_ok=0
		fi
	else
		# Generic Linux (Debian-like + npm)
		if command -v npm >/dev/null 2>&1; then
			npm install -g pm2 && pm2_ok=0
		elif command -v apt-get >/dev/null 2>&1 || command -v apt >/dev/null 2>&1; then
			if [ "${SPM_LANG:-en}" = "id" ]; then
				echo "→ Mencoba menginstall nodejs & npm via apt..."
			else
				echo "→ Trying to install nodejs & npm via apt..."
			fi

			if command -v sudo >/dev/null 2>&1; then
				sudo apt-get update || true
				sudo apt-get install -y nodejs npm || true
			else
				apt-get update || true
				apt-get install -y nodejs npm || true
			fi

			if command -v npm >/dev/null 2>&1; then
				npm install -g pm2 && pm2_ok=0
			fi
		fi
	fi

	if [ $pm2_ok -ne 0 ]; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "❌ Gagal menginstall PM2 secara otomatis."
			echo "   Silakan install nodejs/npm dan pm2 secara manual lalu coba lagi."
			read -r -p "Tekan Enter untuk kembali ke menu..." _
		else
			echo "❌ Failed to install PM2 automatically."
			echo "   Please install nodejs/npm and pm2 manually, then try again."
			read -r -p "Press Enter to return to menu..." _
		fi
		return 1
	fi

	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "✅ PM2 berhasil diinstall."
	else
		echo "✅ PM2 installed successfully."
	fi
	return 0
}


# ----- Domain / TLS publishing for SPM Dashboard ----------------------------------
#
# SPM Dashboard speaks plain HTTP and always will: adding TLS to the embedded Python
# server would mean shipping certificate handling inside the vault process. The
# safer arrangement is the conventional one - nginx terminates TLS on the public
# interface and proxies to SPM on loopback, so the vault itself is never exposed
# to the network directly.

SPM_WEB_DOMAIN_FILE="$SPM_CONFIG_DIR/web-domain.conf"
SPM_ACME_WEBROOT="${SPM_ACME_WEBROOT:-/var/www/html}"
SPM_CF_CREDENTIALS="${SPM_CF_CREDENTIALS:-$SPM_CONFIG_DIR/cloudflare.ini}"

nginx_bin() {
	if command -v nginx >/dev/null 2>&1; then command -v nginx; return 0; fi
	# nginx normally lives in sbin, which is off a non-root PATH.
	for candidate in /usr/sbin/nginx /usr/local/sbin/nginx /sbin/nginx; do
		[ -x "$candidate" ] && { printf '%s' "$candidate"; return 0; }
	done
	return 1
}

domain_get() {
	local key="$1" default="${2:-}" val=""
	if [ -f "$SPM_WEB_DOMAIN_FILE" ]; then
		val="$(sed -n "s/^${key}=//p" "$SPM_WEB_DOMAIN_FILE" 2>/dev/null | tail -n1)"
	fi
	if [ -n "$val" ]; then printf '%s' "$val"; else printf '%s' "$default"; fi
}

domain_put() {
	local key="$1" val="$2" tmp
	mkdir -p "$SPM_CONFIG_DIR" 2>/dev/null || return 1
	chmod 700 "$SPM_CONFIG_DIR" 2>/dev/null || true
	tmp="$(mktemp "$SPM_CONFIG_DIR/.web-domain.XXXXXX" 2>/dev/null)" || return 1
	if [ -f "$SPM_WEB_DOMAIN_FILE" ]; then
		grep -v "^${key}=" "$SPM_WEB_DOMAIN_FILE" > "$tmp" 2>/dev/null || true
	fi
	printf '%s=%s\n' "$key" "$val" >> "$tmp"
	mv -f "$tmp" "$SPM_WEB_DOMAIN_FILE" || { rm -f "$tmp"; return 1; }
	chmod 600 "$SPM_WEB_DOMAIN_FILE" 2>/dev/null || true
}

domain_is_valid() {
	[ ${#1} -le 253 ] || return 1
	[[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

# Installing a public-facing web server and an ACME client is invasive enough
# that it is never done silently, and on a host already serving other sites an
# unexpected nginx install could disrupt them.
domain_require_tools() {
	local missing=() answer
	nginx_bin >/dev/null 2>&1 || missing+=("nginx")
	command -v certbot >/dev/null 2>&1 || missing+=("certbot")
	[ ${#missing[@]} -eq 0 ] && return 0

	printf 'Missing required package(s): %s\n' "${missing[*]}"
	printf 'Publishing on a domain needs a TLS reverse proxy and an ACME client.\n\n'
	if [ "$PKG_TYPE" = "unknown" ]; then
		printf 'No supported package manager detected; install them manually.\n'
		return 1
	fi
	printf 'Install them now with %s? (yes/NO): ' "$PKG_TYPE"
	read -r answer || answer="no"
	case "$answer" in yes|y|Y|YES) ;; *) printf 'Cancelled.\n'; return 1 ;; esac

	local certbot_pkg="certbot"
	[ "$PKG_TYPE" = "apt" ] && certbot_pkg="certbot python3-certbot-nginx"
	# shellcheck disable=SC2086
	case "$PKG_TYPE" in
		apt) sudo apt-get update && sudo apt-get install -y nginx $certbot_pkg ;;
		dnf) sudo dnf install -y nginx certbot ;;
		yum) sudo yum install -y nginx certbot ;;
		pacman) sudo pacman -S --noconfirm nginx certbot ;;
		apk) sudo apk add --no-cache nginx certbot ;;
		pkg) pkg install -y nginx certbot ;;
		brew) brew install nginx certbot ;;
		*) printf 'Unsupported package manager: %s\n' "$PKG_TYPE"; return 1 ;;
	esac || { printf 'Installation failed.\n'; return 1; }

	nginx_bin >/dev/null 2>&1 && command -v certbot >/dev/null 2>&1
}

# Advisory only. Split-horizon DNS and freshly changed records are legitimate,
# so a mismatch warns rather than blocks.
domain_dns_report() {
	local domain="$1" proxied="$2" resolved public
	command -v dig >/dev/null 2>&1 || return 0
	# grep exits 1 when the name has no A record yet. Under pipefail that fails
	# the assignment, and errexit then kills the whole run -- which is exactly
	# the case this function exists to report on.
	resolved="$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9.]+$' | head -n3 | tr '\n' ' ' || true)"
	if [ -z "$resolved" ]; then
		printf 'DNS      : %s has no A record yet.\n' "$domain"
		return 1
	fi
	printf 'DNS      : %s -> %s\n' "$domain" "$resolved"
	if [ "$proxied" = "1" ]; then
		printf '           (Cloudflare-proxied, so these are Cloudflare edge addresses)\n'
		return 0
	fi
	public="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
	if [ -n "$public" ]; then
		printf 'This host: %s\n' "$public"
		case " $resolved " in
			*" $public "*) ;;
			*) printf 'WARNING  : the record does not point at this host; ACME will fail.\n' ;;
		esac
	fi
}

# Cloudflare rewrites the source address, so without this every request appears
# to come from an edge node and SPM cannot tell clients apart in its logs.
domain_write_cloudflare_realip() {
	local snippet="/etc/nginx/snippets/spm-cloudflare-realip.conf" tmp
	tmp="$(make_tmp)"
	{
		printf '# Generated by Sans Password Manager. Restores the visitor address\n'
		printf '# from CF-Connecting-IP for requests arriving through Cloudflare.\n'
		# Both fetches may fail offline. Let them: the grep guard below turns an
		# empty snippet into a clean skip, which errexit would otherwise
		# pre-empt by killing the run here.
		curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null |
			sed -e '/^$/d' -e 's/^/set_real_ip_from /' -e 's/$/;/' || true
		curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 2>/dev/null |
			sed -e '/^$/d' -e 's/^/set_real_ip_from /' -e 's/$/;/' || true
		printf 'real_ip_header CF-Connecting-IP;\n'
	} > "$tmp"
	if ! grep -q '^set_real_ip_from' "$tmp"; then
		printf 'Could not fetch Cloudflare IP ranges; skipping real-IP restoration.\n'
		secure_wipe "$tmp"
		return 1
	fi
	sudo mkdir -p /etc/nginx/snippets
	sudo cp "$tmp" "$snippet" && sudo chmod 0644 "$snippet"
	secure_wipe "$tmp"
}

# Fetches a throwaway file through the public internet exactly the way Let's
# Encrypt will. Failed validations count against the rate limit and certbot's
# own error says little about why, so it is worth one request to find out first.
domain_preflight_challenge() {
	local domain="$1" proxied="$2" token dir url out code final body attempt
	dir="$SPM_ACME_WEBROOT/.well-known/acme-challenge"
	token="spm-preflight-$$"
	sudo mkdir -p "$dir" || return 1
	printf 'spm-preflight-ok\n' | sudo tee "$dir/$token" >/dev/null || return 1
	sudo chmod 0644 "$dir/$token"

	url="http://$domain/.well-known/acme-challenge/$token"
	out="$(make_tmp)"
	# "systemctl reload" returns before the new workers are serving, so the
	# first probe can still be answered by the pre-install configuration.
	for attempt in 1 2 3 4 5; do
		read -r code final <<<"$(curl -sL --max-time 20 -o "$out" \
			-w '%{http_code} %{url_effective}' "$url" 2>/dev/null || printf '000 %s' "$url")"
		body="$(cat "$out" 2>/dev/null || true)"
		case "$body" in
			*spm-preflight-ok*)
				secure_wipe "$out"
				sudo rm -f "$dir/$token"
				return 0
				;;
		esac
		[ "$attempt" -lt 5 ] && sleep 2
	done
	secure_wipe "$out"
	sudo rm -f "$dir/$token"

	printf '\nPre-flight: the challenge file is not reachable from the internet.\n'
	printf '  requested : %s\n' "$url"
	[ "$final" != "$url" ] && printf '  ended at  : %s\n' "$final"
	printf '  status    : %s\n' "$code"
	case "$final" in
		https://*)
			printf '\nSomething redirected the plain-HTTP challenge to HTTPS. The\n'
			printf 'certificate does not exist yet, so that request cannot succeed.\n'
			[ "$proxied" = "1" ] &&
				printf "Turn off Cloudflare's \"Always Use HTTPS\" until the certificate is issued.\n"
			;;
	esac
	case "$body" in
		*"Just a moment"*|*"Attention Required"*|*"cf-mitigated"*|*"Cloudflare"*)
			printf '\nCloudflare answered with a challenge page rather than passing the\n'
			printf 'request through. Its validator cannot solve one, so issuance fails.\n'
			printf 'Add a Configuration Rule that disables Bot Fight Mode, Browser\n'
			printf 'Integrity Check and WAF for /.well-known/acme-challenge/*, or set the\n'
			printf 'record to DNS-only (grey cloud) until the certificate is issued.\n'
			;;
	esac
	return 1
}

domain_restore_vhost() {
	local domain="$1" prior="$2" had_available="$3" enabled_target="$4"
	local available="/etc/nginx/sites-available/$domain" enabled="/etc/nginx/sites-enabled/$domain"
	if [ "$had_available" = "1" ]; then
		sudo cp "$prior" "$available" || return 1
		sudo chmod 0644 "$available" || return 1
	else
		sudo rm -f "$available" || return 1
	fi
	sudo rm -f "$enabled" || return 1
	if [ -n "$enabled_target" ]; then
		sudo ln -s "$enabled_target" "$enabled" || return 1
	fi
	local nginx_exe; nginx_exe="$(nginx_bin)" || return 1
	sudo "$nginx_exe" -t >/dev/null 2>&1 || return 1
	domain_reload_nginx
}

# Compares the running nginx against a minimum version. Absent or unparsable
# version output answers "no", which keeps the widely compatible syntax.
domain_nginx_at_least() {
	local want="$1.$2.$3" have exe
	exe="$(nginx_bin)" || return 1
	have="$("$exe" -v 2>&1 | sed -n 's|.*nginx/\([0-9][0-9.]*\).*|\1|p')"
	[ -n "$have" ] || return 1
	[ "$(version_compare "$have" "$want")" != "-1" ]
}

# Two phases are unavoidable: nginx must already answer on port 80 to serve the
# ACME challenge, but a TLS server block referencing a certificate that does not
# exist yet fails "nginx -t". So port 80 goes up first, the certificate is
# issued, and only then is the TLS block written.
domain_render_vhost() {
	local names="$1" port="$2" proxied="$3" phase="$4" domain
	domain="${names%% *}"
	printf '# %s\n' "$names"
	printf '# Generated by Sans Password Manager %s.\n' "$VERSION"
	printf '# TLS terminates here; the vault itself listens only on 127.0.0.1:%s.\n\n' "$port"
	printf 'server {\n'
	printf '    listen 80;\n    listen [::]:80;\n'
	printf '    server_name %s;\n\n' "$names"
	printf '    location /.well-known/acme-challenge/ {\n        root %s;\n    }\n\n' "$SPM_ACME_WEBROOT"
	if [ "$phase" = "http" ]; then
		printf '    location / {\n        return 404;\n    }\n}\n'
		return 0
	fi
	printf '    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n\n'
	printf 'server {\n'
	# nginx 1.25.1 deprecated "listen ... http2" in favour of a separate
	# directive, and warns on every reload if the old form is used.
	if domain_nginx_at_least 1 25 1; then
		printf '    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;\n'
	else
		printf '    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n'
	fi
	printf '    server_name %s;\n\n' "$names"
	printf '    ssl_certificate     /etc/letsencrypt/live/%s/fullchain.pem;\n' "$domain"
	printf '    ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;\n' "$domain"
	[ -f /etc/letsencrypt/options-ssl-nginx.conf ] &&
		printf '    include /etc/letsencrypt/options-ssl-nginx.conf;\n'
	[ -f /etc/letsencrypt/ssl-dhparams.pem ] &&
		printf '    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;\n'
	printf '\n'
	if [ "$proxied" = "1" ] && [ -f /etc/nginx/snippets/spm-cloudflare-realip.conf ]; then
		printf '    include /etc/nginx/snippets/spm-cloudflare-realip.conf;\n\n'
	fi
	# HSTS only. The vault already emits X-Frame-Options, nosniff,
	# Referrer-Policy and a CSP on every response; adding them here too would
	# send each one twice, and browsers may ignore a duplicated
	# X-Frame-Options entirely rather than honour it.
	printf '    add_header Strict-Transport-Security "max-age=31536000" always;\n\n'
	printf '    # Vault imports are uploaded through this proxy.\n'
	printf '    client_max_body_size 32m;\n\n'
	printf '    location / {\n'
	printf '        proxy_pass http://127.0.0.1:%s;\n' "$port"
	printf '        proxy_http_version 1.1;\n'
	printf '        proxy_set_header Host              $host;\n'
	printf '        proxy_set_header X-Real-IP         $remote_addr;\n'
	printf '        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;\n'
	printf '        # SPM reads this to decide whether the session cookie is Secure.\n'
	printf '        proxy_set_header X-Forwarded-Proto $scheme;\n'
	printf '        proxy_read_timeout 300s;\n'
	printf '    }\n}\n'
}

# Installs a candidate vhost, validates it, and restores whatever was there
# before if validation fails. The host may be serving unrelated sites, so a bad
# generated file must never be left where a later reload would pick it up.
domain_install_vhost() {
	local domain="$1" body="$2" backup="" nginx_exe available enabled
	available="/etc/nginx/sites-available/$domain"
	enabled="/etc/nginx/sites-enabled/$domain"
	nginx_exe="$(nginx_bin)" || return 1

	if [ -f "$available" ]; then
		backup="$(mktemp "${TMPDIR:-/tmp}/spm-vhost.XXXXXX")"
		sudo cp "$available" "$backup" 2>/dev/null || true
	fi
	sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
	printf '%s\n' "$body" | sudo tee "$available" >/dev/null || return 1
	sudo chmod 0644 "$available"
	sudo ln -sfn "$available" "$enabled"

	if ! sudo "$nginx_exe" -t >/dev/null 2>&1; then
		printf 'Generated nginx configuration failed validation; rolling back.\n' >&2
		sudo "$nginx_exe" -t 2>&1 | sed 's/^/  /' >&2
		sudo rm -f "$enabled"
		if [ -n "$backup" ]; then
			sudo cp "$backup" "$available"; rm -f "$backup"
			sudo ln -sfn "$available" "$enabled"
		else
			sudo rm -f "$available"
		fi
		sudo "$nginx_exe" -t >/dev/null 2>&1 && domain_reload_nginx
		return 1
	fi
	[ -n "$backup" ] && rm -f "$backup"
	domain_reload_nginx
}

domain_reload_nginx() {
	if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
		sudo systemctl reload nginx
	else
		local nginx_exe; nginx_exe="$(nginx_bin)" || return 1
		sudo "$nginx_exe" -s reload 2>/dev/null || sudo "$nginx_exe"
	fi
}

# DNS-01 proves ownership with a TXT record instead of a file fetched over
# HTTP. That matters behind a CDN: "Always Use HTTPS", bot protection and WAF
# rules all sit on the HTTP path and none of them can interfere with a DNS
# lookup. It is also the only method that works when port 80 is unreachable.
domain_dns01_available() {
	certbot plugins 2>/dev/null | grep -q 'dns-cloudflare'
}

domain_dns01_install_plugin() {
	local answer
	printf 'The certbot Cloudflare DNS plugin is not installed.\n'
	if [ "$PKG_TYPE" = "unknown" ]; then
		printf 'Install python3-certbot-dns-cloudflare manually, then run this again.\n'
		return 1
	fi
	printf 'Install it now with %s? (yes/NO): ' "$PKG_TYPE"
	read -r answer || answer="no"
	case "$answer" in yes|y|Y|YES) ;; *) printf 'Cancelled.\n'; return 1 ;; esac
	case "$PKG_TYPE" in
		apt) sudo apt-get update && sudo apt-get install -y python3-certbot-dns-cloudflare ;;
		dnf) sudo dnf install -y python3-certbot-dns-cloudflare ;;
		yum) sudo yum install -y python3-certbot-dns-cloudflare ;;
		pacman) sudo pacman -S --noconfirm certbot-dns-cloudflare ;;
		apk) sudo apk add --no-cache py3-certbot-dns-cloudflare ;;
		brew) brew install certbot-dns-cloudflare ;;
		*) printf 'No package known for %s; install it manually.\n' "$PKG_TYPE"; return 1 ;;
	esac || { printf 'Installation failed.\n'; return 1; }
	domain_dns01_available
}

# The token is written straight to a 0600 file and never echoed, so it stays
# out of the terminal, out of shell history and out of the process list.
domain_dns01_credentials() {
	local token confirm tmp
	if [ -f "$SPM_CF_CREDENTIALS" ]; then
		printf 'Using the saved Cloudflare API token at %s\n' "$SPM_CF_CREDENTIALS"
		printf 'Replace it? (yes/NO): '
		read -r confirm || confirm="no"
		case "$confirm" in yes|y|Y|YES) ;; *) return 0 ;; esac
	fi
	printf '\n'
	printf 'A Cloudflare API token is needed to write the validation TXT record.\n'
	printf 'Create one at Cloudflare > My Profile > API Tokens with exactly:\n'
	printf '  Zone > Zone > Read      and      Zone > DNS > Edit\n'
	printf 'scoped to this zone. Nothing broader is required, and a broader token\n'
	printf 'would let anything holding this file repoint your whole domain.\n\n'
	printf 'Paste the token (input stays hidden): '
	read -rs token || token=""
	printf '\n'
	[ -n "$token" ] || { printf 'Nothing entered.\n'; return 1; }

	mkdir -p "$SPM_CONFIG_DIR"
	tmp="$(mktemp "$SPM_CONFIG_DIR/.cf.XXXXXX")" || return 1
	chmod 0600 "$tmp"
	printf 'dns_cloudflare_api_token = %s\n' "$token" > "$tmp"
	token=""
	mv -f "$tmp" "$SPM_CF_CREDENTIALS"
	chmod 0600 "$SPM_CF_CREDENTIALS"
	printf 'Saved to %s (0600). Renewals reuse it, so keep it.\n' "$SPM_CF_CREDENTIALS"
}

domain_issue_certificate() {
	local names="$1" email="$2" method="${3:-http}" name args=()
	# --cert-name pins the lineage to the primary name. Without it a changed
	# name set makes certbot invent "<domain>-0001", and the vhost's
	# hardcoded /etc/letsencrypt/live/<domain>/ path would then be stale.
	args=(certonly --cert-name "${names%% *}"
		--non-interactive --agree-tos --keep-until-expiring)
	if [ "$method" = "dns-cloudflare" ]; then
		args+=(--dns-cloudflare
			--dns-cloudflare-credentials "$SPM_CF_CREDENTIALS"
			--dns-cloudflare-propagation-seconds "${SPM_ACME_DNS_WAIT:-30}")
	else
		sudo mkdir -p "$SPM_ACME_WEBROOT"
		args+=(--webroot -w "$SPM_ACME_WEBROOT")
	fi
	for name in $names; do args+=(-d "$name"); done
	# Let's Encrypt rate-limits duplicate certificates; a dry run exercises the
	# whole challenge path without spending one.
	[ "${SPM_ACME_DRY_RUN:-0}" = "1" ] && args+=(--dry-run)
	if [ -n "$email" ]; then
		args+=(-m "$email")
	else
		args+=(--register-unsafely-without-email)
	fi
	sudo certbot "${args[@]}"
}

# Returns 0 with SPM_DOMAIN_READY set when the domain is serving TLS and the
# caller should bind the vault to loopback behind it.
domain_setup_flow() {
	local port="$1" domain names proxied answer email body prior dns_ok method
	local had_available=0 enabled_target="" existing_vhost
	SPM_DOMAIN_READY=""

	domain="$(domain_get DOMAIN "")"
	if [ -n "$domain" ]; then
		printf 'Configured domain: %s\n' "$domain"
		printf 'Use it again? (YES/no): '
		read -r answer || answer="yes"
		case "$answer" in no|n|N|NO) domain="" ;; *) ;; esac
	fi
	if [ -z "$domain" ]; then
		printf 'Domain or subdomain (e.g. vault.example.com): '
		read -r domain || domain=""
	fi
	domain="$(printf '%s' "$domain" | tr -d '[:space:]' | tr 'A-Z' 'a-z')"
	domain="${domain#http://}"; domain="${domain#https://}"; domain="${domain%%/*}"
	if ! domain_is_valid "$domain"; then
		printf 'That does not look like a domain name.\n'
		return 1
	fi
	existing_vhost="/etc/nginx/sites-available/$domain"
	if sudo test -f "$existing_vhost" &&
		! sudo grep -Fq '# Generated by Sans Password Manager' "$existing_vhost"; then
		printf '\nWARNING: nginx already has a non-SPM site for %s.\n' "$domain"
		printf 'Publishing here will replace it if certificate setup succeeds.\n'
		printf "Type 'replace' to continue: "
		read -r answer || answer=""
		[ "$answer" = "replace" ] || { printf 'Cancelled.\n'; return 1; }
	fi

	# The host's existing certificates all carry the www alias, so offer it
	# rather than making people rerun this for the second name.
	names="$domain"
	case "$domain" in
		www.*) ;;
		*)
			printf 'Also cover www.%s? (YES/no): ' "$domain"
			read -r answer || answer="yes"
			case "$answer" in no|n|N|NO) ;; *) names="$domain www.$domain" ;; esac
			;;
	esac

	proxied="$(domain_get CLOUDFLARE 0)"
	printf '\nIs %s proxied through Cloudflare (orange cloud)? (yes/NO): ' "$domain"
	read -r answer || answer="no"
	case "$answer" in yes|y|Y|YES) proxied=1 ;; *) proxied=0 ;; esac

	if [ "$proxied" = "1" ]; then
		printf '\n'
		printf 'WARNING: Cloudflare terminates TLS at its edge and re-encrypts to this\n'
		printf 'host. It can therefore read every request in plaintext, including the\n'
		printf 'login POST carrying your master password and every secret the vault\n'
		printf 'renders. End-to-end encryption between your browser and this server\n'
		printf 'requires DNS-only mode (grey cloud).\n\n'
		printf "Type 'yes' to accept Cloudflare inside your trust boundary: "
		read -r answer || answer="no"
		[ "$answer" = "yes" ] || { printf 'Cancelled.\n'; return 1; }
	fi

	# Cloudflare's Universal SSL covers example.com and *.example.com only.
	# A name one level deeper -- www.vault.example.com -- has no edge
	# certificate, so browsers get a handshake failure however correct the
	# origin is. Better to drop the alias than to publish a broken name.
	if [ "$proxied" = "1" ] && [ "$names" != "$domain" ] &&
		[ "$(printf '%s' "$domain" | tr -cd '.' | wc -c)" -ge 2 ]; then
		printf '\n'
		printf 'NOTE: www.%s is two levels below the zone apex.\n' "$domain"
		printf "Cloudflare's Universal SSL covers only the apex and one level of\n"
		printf 'subdomain, so the edge has no certificate for that name and browsers\n'
		printf 'will fail the TLS handshake. Advanced Certificate Manager or a custom\n'
		printf 'certificate lifts the limit.\n'
		printf 'Drop the www alias? (YES/no): '
		read -r answer || answer="yes"
		case "$answer" in no|n|N|NO) ;; *) names="$domain" ;; esac
	fi

	domain_require_tools || return 1

	# Behind a proxy the HTTP challenge has to survive the CDN's redirect and
	# bot rules; a TXT record does not, so it is the sane default there.
	method="$(domain_get METHOD http)"
	printf '\nHow should ownership be proved?\n'
	printf '  1) HTTP file on port 80 (works for a plain DNS record)\n'
	printf '  2) DNS TXT record via the Cloudflare API (works behind a proxy)\n'
	if [ "$proxied" = "1" ]; then
		printf 'Choice [2]: '
		read -r answer || answer="2"
		[ -n "$answer" ] || answer="2"
	else
		printf 'Choice [1]: '
		read -r answer || answer="1"
		[ -n "$answer" ] || answer="1"
	fi
	case "$answer" in
		2) method="dns-cloudflare" ;;
		*) method="http" ;;
	esac

	if [ "$method" = "dns-cloudflare" ]; then
		if ! domain_dns01_available && ! domain_dns01_install_plugin; then
			return 1
		fi
		domain_dns01_credentials || return 1
	fi

	printf '\n'
	dns_ok=1
	for answer in $names; do
		domain_dns_report "$answer" "$proxied" || dns_ok=0
	done
	if [ "$dns_ok" -eq 0 ] && [ "$method" = "dns-cloudflare" ]; then
		# DNS-01 certifies a name that does not resolve yet -- only the TXT
		# record matters. Worth saying, because the A record still has to
		# exist before anyone can reach the vault.
		printf '\nDNS validation does not need an A record, so the certificate can be\n'
		printf 'issued now. Create the record before you try to reach the vault.\n'
		dns_ok=1
	fi
	if [ "$dns_ok" -eq 0 ]; then
		# ACME validates over the public internet, so a name that does not
		# resolve cannot be certified. Failed validations count against the
		# Let's Encrypt rate limit, so stopping here is cheaper than trying.
		printf '\nThat name cannot be certified until it resolves. Create the DNS\n'
		printf 'record first, then run this again.\n'
		printf 'Continue anyway? (yes/NO): '
		read -r answer || answer="no"
		case "$answer" in yes|y|Y|YES) ;; *) printf 'Cancelled.\n'; return 1 ;; esac
	fi

	printf '\nContact email for Let'"'"'s Encrypt expiry notices (blank to skip): '
	read -r email || email=""

	# A dry run must not downgrade a domain that is already serving TLS: the
	# phase-1 vhost overwrites the live one, and a dry run never reaches the
	# phase-3 rewrite that would put it back.
	prior="$(mktemp "${TMPDIR:-/tmp}/spm-vhost-prior.XXXXXX")"
	if sudo test -f "/etc/nginx/sites-available/$domain"; then
		had_available=1
		sudo cp "/etc/nginx/sites-available/$domain" "$prior" || { rm -f "$prior"; return 1; }
	fi
	if sudo test -L "/etc/nginx/sites-enabled/$domain"; then
		enabled_target="$(sudo readlink "/etc/nginx/sites-enabled/$domain")"
	fi

	if [ "$method" = "dns-cloudflare" ]; then
		# No HTTP phase at all: nothing has to be reachable on port 80, so the
		# existing site (if any) is left untouched until the certificate is in
		# hand. That is what makes this safe to run against a live domain.
		printf '\nPhase 1/2: proving ownership with a DNS TXT record...\n'
			if ! domain_issue_certificate "$names" "$email" "$method"; then
				printf '\nCertificate request failed. Nothing was changed.\n'
				printf 'Check that the token has Zone:Read and DNS:Edit on this zone.\n'
				rm -f "$prior"
				return 1
		fi
	else
		printf '\nPhase 1/3: serving the ACME challenge on port 80...\n'
		body="$(domain_render_vhost "$names" "$port" "$proxied" http)"
		domain_install_vhost "$domain" "$body" || { rm -f "$prior"; return 1; }

		if ! domain_preflight_challenge "$domain" "$proxied"; then
			printf '\nStopping before the certificate request: a failed validation counts\n'
			printf 'against the rate limit. Restoring the previous nginx state.\n'
			printf 'DNS validation avoids all of this -- choose option 2 next time.\n'
			domain_restore_vhost "$domain" "$prior" "$had_available" "$enabled_target" ||
				printf 'WARNING: automatic nginx rollback failed; restore %s manually.\n' "$domain" >&2
			rm -f "$prior"
			return 1
		fi

		printf 'Phase 2/3: requesting a certificate for %s...\n' "$domain"
		if ! domain_issue_certificate "$names" "$email" "$method"; then
			printf '\nCertificate request failed. Restoring the previous nginx state.\n'
			domain_restore_vhost "$domain" "$prior" "$had_available" "$enabled_target" ||
				printf 'WARNING: automatic nginx rollback failed; restore %s manually.\n' "$domain" >&2
			rm -f "$prior"
			return 1
		fi
	fi

	[ "$proxied" = "1" ] && domain_write_cloudflare_realip || true

	if [ "${SPM_ACME_DRY_RUN:-0}" = "1" ]; then
		printf '\nDry run complete: the %s challenge works. No certificate was\n' \
			"$([ "$method" = "dns-cloudflare" ] && printf 'DNS' || printf 'HTTP')"
		printf 'issued and TLS was not enabled. Re-run without SPM_ACME_DRY_RUN\n'
		printf 'to finish.\n'
		domain_restore_vhost "$domain" "$prior" "$had_available" "$enabled_target" >/dev/null &&
			printf 'The previous nginx state for %s was restored.\n' "$domain"
		rm -f "$prior"
		return 0
	fi

	# /etc/letsencrypt/live is root-only (0700), so a plain -f test always
	# fails for an unprivileged caller even when the certificate is there.
	if ! sudo test -f "/etc/letsencrypt/live/$domain/fullchain.pem"; then
		printf '\nNo certificate found at /etc/letsencrypt/live/%s/fullchain.pem.\n' "$domain"
		printf 'TLS was not enabled. Restoring the previous nginx state.\n'
		domain_restore_vhost "$domain" "$prior" "$had_available" "$enabled_target" || true
		rm -f "$prior"
		return 1
	fi

	if [ "$method" = "dns-cloudflare" ]; then
		printf 'Phase 2/2: enabling TLS and the reverse proxy...\n'
	else
		printf 'Phase 3/3: enabling TLS and the reverse proxy...\n'
	fi
	body="$(domain_render_vhost "$names" "$port" "$proxied" https)"
	if ! domain_install_vhost "$domain" "$body"; then
		domain_restore_vhost "$domain" "$prior" "$had_available" "$enabled_target" || true
		rm -f "$prior"
		return 1
	fi
	rm -f "$prior"

	domain_put DOMAIN "$domain" || true
	domain_put NAMES "$names" || true
	domain_put CLOUDFLARE "$proxied" || true
	domain_put PORT "$port" || true
	domain_put METHOD "$method" || true
	SPM_DOMAIN_READY="$domain"
	printf '\nPublished: https://%s/\n' "$domain"
	printf 'The vault listens on 127.0.0.1:%s only; nginx handles the public side.\n' "$port"
	if [ "$proxied" = "1" ]; then
		printf 'Set Cloudflare SSL/TLS mode to "Full (strict)" so the edge verifies\n'
		printf 'this certificate instead of accepting any origin.\n'
		printf 'If Bot Fight Mode or a managed challenge is enabled on this zone, the\n'
		printf 'edge answers with a challenge page before the vault is reached; exempt\n'
		printf 'this hostname if logins stall.\n'
	fi
	return 0
}

start_web_mode() {
	clear
	echo "==========================================="
	echo "  SPM Dashboard"
	echo "==========================================="
	echo
	if [ "$SPM_LANG" = "id" ]; then
		printf "\n\033[0;31mPERINGATAN: Menjalankan mode web akan mengekspos vault Anda melalui server HTTP. Lanjutkan hanya jika Anda berada di jaringan yang terpercaya.\033[0m\n\n"
	else
		printf "\n\033[0;31mWARNING: Running the SPM Dashboard will expose your vault over an HTTP server. Only proceed if you are on a trusted network.\033[0m\n\n"
	fi

	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "Mode ini akan menjalankan HTTP server sehingga kamu"
		echo "bisa mengakses vault lewat browser."
		echo
		echo "Pilih mode:"
		echo "  1) Jalankan sementara (foreground, Ctrl+C untuk berhenti)"
		echo "  2) Jalankan di background dengan PM2"
		echo "  3) Hentikan web server background (PM2)"
		echo "  0) Kembali"
	else
		echo "This will start an HTTP server so you can"
		echo "access your vault from a browser."
		echo
		echo "Choose mode:"
		echo "  1) Temporary (foreground, Ctrl+C to stop)"
		echo "  2) Run in background using PM2"
		echo "  3) Stop background web server (PM2)"
		echo "  0) Back"
	fi
	echo

	local mode
	if [ "${SPM_LANG:-en}" = "id" ]; then
		read -r -p "Pilihan: " mode
	else
		read -r -p "Choice: " mode
	fi

	case "$mode" in
		0)
			return
			;;
		3)
			# Stop / delete PM2 process
			if ! command -v pm2 >/dev/null 2>&1; then
				if [ "${SPM_LANG:-en}" = "id" ]; then
					echo "❌ PM2 tidak ditemukan. Tidak ada proses background untuk dihentikan."
					read -r -p "Tekan Enter untuk kembali ke menu..." _
				else
					echo "❌ PM2 not found. No background process to stop."
					read -r -p "Press Enter to return to menu..." _
				fi
				return
			fi

			if pm2 describe spm-web >/dev/null 2>&1; then
				pm2 delete spm-web >/dev/null 2>&1 || true
				if [ "${SPM_LANG:-en}" = "id" ]; then
					echo "✅ Proses web SPM (spm-web) di PM2 telah dihentikan dan dihapus."
					read -r -p "Tekan Enter untuk kembali ke menu..." _
				else
					echo "✅ SPM web process (spm-web) in PM2 has been stopped and deleted."
					read -r -p "Press Enter to return to menu..." _
				fi
			else
				if [ "${SPM_LANG:-en}" = "id" ]; then
					echo "ℹ Tidak ada proses spm-web di PM2."
					read -r -p "Tekan Enter untuk kembali ke menu..." _
				else
					echo "ℹ No spm-web process found in PM2."
					read -r -p "Press Enter to return to menu..." _
				fi
			fi
			return
			;;
		1|2)
			# continue
			;;
		*)
			if [ "${SPM_LANG:-en}" = "id" ]; then
				echo "Pilihan tidak valid."
				read -r -p "Tekan Enter untuk kembali ke menu..." _
			else
				echo "Invalid choice."
				read -r -p "Press Enter to return to menu..." _
			fi
			return
			;;
	esac

	# Check vault file
	if [ ! -f "$VAULT_FILE" ]; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "❌ File vault tidak ditemukan: $VAULT_FILE"
			echo "   Buat atau buka vault terlebih dahulu."
			read -r -p "Tekan Enter untuk kembali ke menu..." _
		else
			echo "❌ Vault file not found: $VAULT_FILE"
			echo "   Create or unlock your vault first."
			read -r -p "Press Enter to return to menu..." _
		fi
		return
	fi

	# Check python3
	if ! command -v python3 >/dev/null 2>&1; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "❌ python3 diperlukan untuk mode web tetapi tidak ditemukan."
			echo "   Install python3 lalu coba lagi."
			read -r -p "Tekan Enter untuk kembali ke menu..." _
		else
			echo "❌ python3 is required for the SPM Dashboard but not found."
			echo "   Install python3 and retry."
			read -r -p "Press Enter to return to menu..." _
		fi
		return
	fi

	# Ask bind address & port
	echo
	local bind_addr bind_port allow_insecure_remote=0 want_domain=0
	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "Pilih alamat bind:"
		echo "  1) Lokal (127.0.0.1)"
		echo "  2) Global (0.0.0.0)"
		echo "  3) Masukkan IP sendiri"
		echo "  4) Domain/subdomain dengan HTTPS (nginx + Let's Encrypt)"
		read -r -p "Pilihan [1]: " bind_addr
	else
		echo "Choose bind address:"
		echo "  1) Localhost (127.0.0.1)"
		echo "  2) Global (0.0.0.0)"
		echo "  3) Enter custom IP"
		echo "  4) Domain/subdomain with HTTPS (nginx + Lets Encrypt)"
		read -r -p "Choice [1]: " bind_addr
	fi
	case "$bind_addr" in
		""|1)
			bind_addr="127.0.0.1"
			;;
		2)
			bind_addr="0.0.0.0"
			;;
		3)
			if [ "${SPM_LANG:-en}" = "id" ]; then
				read -r -p "Masukkan IP bind: " bind_addr
			else
				read -r -p "Enter bind IP: " bind_addr
			fi
			;;
		4)
			# nginx owns the public interface here, so the vault itself stays on
			# loopback and is never reachable from the network directly. The
			# setup itself has to wait until the port is known, since the
			# generated vhost proxies to it.
			want_domain=1
			bind_addr="127.0.0.1"
			;;
		*)
			# Preserve the previous direct-IP input behavior.
			;;
	esac
	local valid_bind=0 octet
	if [[ "$bind_addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		valid_bind=1
		IFS='.' read -r -a octets <<< "$bind_addr"
		for octet in "${octets[@]}"; do
			if [ "$octet" -gt 255 ]; then
				valid_bind=0
				break
			fi
		done
	elif [[ "$bind_addr" = "0.0.0.0" || "$bind_addr" = "localhost" || "$bind_addr" =~ ^\[?[0-9A-Fa-f:]+\]?$ ]]; then
		valid_bind=1
	fi
	if [ "$valid_bind" -ne 1 ]; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "Alamat bind tidak valid, memakai 127.0.0.1."
		else
			echo "Invalid bind address, using 127.0.0.1."
		fi
		bind_addr="127.0.0.1"
	fi
	case "$bind_addr" in
		localhost|127.*|::1|\[::1\]) ;;
		*)
			if [ "${SPM_WEB_ALLOW_INSECURE_REMOTE:-0}" = "1" ]; then
				allow_insecure_remote=1
			else
				if [ "${SPM_LANG:-en}" = "id" ]; then
					printf "\nPERINGATAN: %s akan membuka vault melalui HTTP tanpa enkripsi transport.\n" "$bind_addr"
					printf "Gunakan hanya pada jaringan terisolasi/tepercaya. Untuk akses internet, gunakan proxy TLS.\n"
					printf "Ketik 'yes' untuk menerima risiko dan melanjutkan: "
				else
					printf "\nWARNING: %s exposes the vault over HTTP without transport encryption.\n" "$bind_addr"
					printf "Use this only on an isolated trusted network. For internet access, use a TLS reverse proxy.\n"
					printf "Type 'yes' to accept the risk and continue: "
				fi
				local remote_confirm
				read -r remote_confirm || remote_confirm=""
				if [ "$remote_confirm" != "yes" ]; then
					if [ "${SPM_LANG:-en}" = "id" ]; then
						printf "Bind global dibatalkan; tidak ada server yang dijalankan.\n"
					else
						printf "Global bind cancelled; no server was started.\n"
					fi
					return 1
				fi
				allow_insecure_remote=1
			fi
			;;
	esac

	if [ "${SPM_LANG:-en}" = "id" ]; then
		read -r -p "Port [8080]: " bind_port
	else
		read -r -p "Port [8080]: " bind_port
	fi
	[ -z "$bind_port" ] && bind_port="8080"
	if ! [[ "$bind_port" =~ ^[0-9]+$ ]] || [ "$bind_port" -lt 1 ] || [ "$bind_port" -gt 65535 ]; then
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "Port tidak valid, memakai 8080."
		else
			echo "Invalid port, using 8080."
		fi
		bind_port="8080"
	fi

	if [ "$want_domain" -eq 1 ]; then
		if ! domain_setup_flow "$bind_port"; then
			if [ "${SPM_LANG:-en}" = "id" ]; then
				printf "Penyiapan domain dibatalkan; tidak ada server yang dijalankan.\n"
			else
				printf "Domain setup cancelled; no server was started.\n"
			fi
			return 1
		fi
	fi

	# Figure out which host to show to user
	local display_host
	if [ "$bind_addr" = "127.0.0.1" ] || [ "$bind_addr" = "localhost" ]; then
		display_host="127.0.0.1"
	elif [ "$bind_addr" = "0.0.0.0" ]; then
		display_host="$(get_external_ip)"
		[ -z "$display_host" ] && display_host="YOUR_SERVER_IP"
		[ "$display_host" = "UNKNOWN_IP" ] && display_host="YOUR_SERVER_IP"
	else
		display_host="$bind_addr"
	fi

	# Behind nginx the vault is reached at its public HTTPS name, not at the
	# loopback address it happens to listen on.
	local display_url="http://${display_host}:${bind_port}/"
	local webauthn_rp_id=""
	if [ -n "${SPM_DOMAIN_READY:-}" ]; then
		display_url="https://${SPM_DOMAIN_READY}/"
		# A WebAuthn credential is bound to the relying-party id in force when
		# it was registered, and the server refuses to guess one from the Host
		# header. The public name the domain flow already established is the
		# only trustworthy source for it.
		webauthn_rp_id="$SPM_DOMAIN_READY"
	fi
	# An explicit override wins, so a deployment fronted by something other
	# than SPM's own domain flow can still name its relying party.
	webauthn_rp_id="${SPM_WEB_RP_ID:-$webauthn_rp_id}"

	# Try to configure firewall automatically if binding to non-local
	configure_firewall_for_web "$bind_addr" "$bind_port"

	# Ensure Python web script exists (and updated)
	local spm_web_script
	spm_web_script="$(write_spm_web_script)" || {
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "❌ Gagal menulis script Python SPM Dashboard."
			read -r -p "Tekan Enter untuk kembali ke menu..." _
		else
			echo "❌ Failed to write Python web script."
			read -r -p "Press Enter to return to menu..." _
		fi
		return
	}

	if [ "$mode" = "2" ]; then
		# Background mode via PM2
		ensure_pm2_installed || return

		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo
			echo "Menjalankan SPM web server di background (PM2, nama proses: spm-web)..."
			echo "Akses via browser:"
			echo "  → ${display_url}"
			echo
			echo "Gunakan menu ini lagi (opsi 3) untuk menghentikan proses background."
		else
			echo
			echo "Starting SPM web server in background (PM2, process name: spm-web)..."
			echo "Access it from your browser:"
			echo "  → ${display_url}"
			echo
			echo "Use this menu again (option 3) to stop the background process."
		fi

		# Replace only SPM's own named process so changed bind/port settings are
		# guaranteed to take effect. Never hide PM2 startup errors: otherwise the
		# menu claims success and immediately returns while no server is running.
		local pm2_output pm2_pid probe_host web_ready=0
		pm2_output="$(make_tmp)"
		if pm2 describe spm-web >/dev/null 2>&1; then
			if ! pm2 delete spm-web >"$pm2_output" 2>&1; then
				printf "Failed to replace the existing spm-web process:\n" >&2
				tail -n 20 "$pm2_output" >&2
				secure_wipe "$pm2_output"
				return 1
			fi
		fi

		SPM_VAULT_PATH="$VAULT_FILE" \
		SPM_WEB_BIND="$bind_addr" \
		SPM_WEB_PORT="$bind_port" \
		SPM_VERSION="$VERSION" \
		SPM_WEB_ALLOW_INSECURE_REMOTE="$allow_insecure_remote" \
		SPM_WEB_RP_ID="$webauthn_rp_id" \
		pm2 start "$spm_web_script" \
			--name "spm-web" \
			--interpreter python3 >"$pm2_output" 2>&1 || {
				printf "Failed to start SPM Dashboard with PM2:\n" >&2
				tail -n 20 "$pm2_output" >&2
				secure_wipe "$pm2_output"
				return 1
			}

		pm2_pid=""
		case "$bind_addr" in
			0.0.0.0|127.*|localhost) probe_host="127.0.0.1" ;;
			::|\[::\]|::1|\[::1\]) probe_host="::1" ;;
			*) probe_host="${bind_addr#[}"; probe_host="${probe_host%]}" ;;
		esac
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			pm2_pid="$(pm2 pid spm-web 2>/dev/null | tail -n 1)"
			if printf '%s' "$pm2_pid" | grep -Eq '^[1-9][0-9]*$'; then
				if python3 - "$probe_host" "$bind_port" <<'PY' >/dev/null 2>&1
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), timeout=1) as sock:
    sock.sendall(b"GET /login HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    response = b""
    while len(response) < 128 * 1024:
        chunk = sock.recv(8192)
        if not chunk:
            break
        response += chunk
    if (not response.startswith(b"HTTP/1.0 200")
            or b">Sans Password Manager</h1>" not in response):
        raise SystemExit(1)
PY
				then
					web_ready=1
					break
				fi
			fi
			sleep 0.25
		done
		if [ "$web_ready" -ne 1 ]; then
			printf "SPM Dashboard did not remain online. PM2 output:\n" >&2
			tail -n 20 "$pm2_output" >&2
			pm2 logs spm-web --nostream --lines 20 >&2 || true
			secure_wipe "$pm2_output"
			return 1
		fi
		secure_wipe "$pm2_output"
		printf "SPM Dashboard is online (PID %s).\n" "$pm2_pid"

		if [ "${SPM_LANG:-en}" = "id" ]; then
			read -r -p "Tekan Enter untuk kembali ke menu..." _
		else
			read -r -p "Press Enter to return to menu..." _
		fi
		return
	fi

	# Foreground / temporary mode
	echo
	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "Menjalankan SPM web server pada ${bind_addr}:${bind_port}..."
		echo "Buka di browser kamu:"
		echo "  → ${display_url}"
		echo
		echo "Tekan Ctrl + C di sini untuk menghentikan server."
	else
		echo "Starting SPM web server on ${bind_addr}:${bind_port}..."
		echo "Open this in your browser:"
		echo "  → ${display_url}"
		echo
		echo "Press Ctrl + C here to stop the server."
	fi
	echo

	SPM_VAULT_PATH="$VAULT_FILE" \
	SPM_WEB_BIND="$bind_addr" \
	SPM_WEB_PORT="$bind_port" \
	SPM_VERSION="$VERSION" \
	SPM_WEB_ALLOW_INSECURE_REMOTE="$allow_insecure_remote" \
	SPM_WEB_RP_ID="$webauthn_rp_id" \
	python3 "$spm_web_script"

	echo
	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "SPM web server dihentikan."
		read -r -p "Tekan Enter untuk kembali ke menu..." _
	else
		echo "SPM web server stopped."
		read -r -p "Press Enter to return to menu..." _
	fi
}

write_spm_web_script() {
	# Where to store the Python web server script
	local base_dir
	base_dir="${SPM_WEB_SCRIPT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/spm}"
	mkdir -p "$base_dir" || return 1

	# The dashboard imports the trusted core by path from its own directory,
	# so the core has to be in place before the server is written, let alone
	# started.
	ensure_core_script "$base_dir" || return 1

	local script_path="${base_dir}/spm_web_server.py"

	cat >"$script_path" <<'PY'
import http.server
import socketserver
import urllib.parse
import subprocess
import os
import secrets
import hmac
import html
import sys
import time
import base64
import json as jsonlib
import urllib.request
import re
import io
import email.parser
import email.policy
import warnings
import threading
import tempfile
import shutil
import fcntl
import ipaddress
import hashlib

VAULT_PATH = os.environ.get("SPM_VAULT_PATH")
BIND_ADDR  = os.environ.get("SPM_WEB_BIND", "127.0.0.1")
PORT       = int(os.environ.get("SPM_WEB_PORT", "8080"))
VERSION    = os.environ.get("SPM_VERSION", "")

def _is_loopback_bind(value):
    value = (value or "").strip().strip("[]")
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False

if not _is_loopback_bind(BIND_ADDR) and os.environ.get("SPM_WEB_ALLOW_INSECURE_REMOTE") != "1":
    raise SystemExit(
        "Refusing non-loopback plain HTTP. Bind localhost behind TLS, or explicitly "
        "set SPM_WEB_ALLOW_INSECURE_REMOTE=1 for an isolated trusted network."
    )

if not VAULT_PATH or not os.path.isfile(VAULT_PATH):
    raise SystemExit(f"Vault file not found: {VAULT_PATH!r}")

# WebAuthn relying-party id for biometric unlock. Deliberately NOT derived from
# the Host header: a header rewrite would otherwise move the relying party, and
# every credential is bound to whatever value was in force at registration. No
# id configured means the whole unlock feature stays off rather than guessing.
def _webauthn_config():
    rp = (os.environ.get("SPM_WEB_RP_ID") or "").strip().lower()
    if not rp:
        # No default is inferred, not even on loopback. The obvious guess there
        # is the bind address, but "127.0.0.1" is not a valid relying-party id
        # -- browsers require a domain -- so guessing would enable a feature
        # whose ceremony can only ever fail. Local development sets
        # SPM_WEB_RP_ID=localhost and browses to http://localhost:PORT.
        return "", ""
    # A relying-party id is a bare domain: no scheme, no port, no path.
    if not re.match(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", rp):
        return "", ""
    # An explicit origin wins, for a deployment whose public URL this cannot be
    # derived from -- a proxy on a non-default port, say.
    override = (os.environ.get("SPM_WEB_ORIGIN") or "").strip()
    if override:
        if not re.match(r"^https?://[A-Za-z0-9.\-\[\]]+(:[0-9]{1,5})?$", override):
            return "", ""
        return rp, override.rstrip("/")
    # The scheme follows the RELYING PARTY, never the bind address. SPM's
    # documented deployment binds loopback behind a TLS reverse proxy, so the
    # bind says nothing about what the browser connected to: it is 127.0.0.1
    # while the origin the browser reports is https://<public name>. Deriving
    # the scheme from the bind produced http://<public name>:<port> there and
    # every assertion failed on an origin mismatch.
    #
    # localhost is the one host a browser treats as a secure context over plain
    # HTTP, which is what makes local development and the regression suite work
    # without TLS. Everything else is https by definition -- WebAuthn will not
    # run in an insecure context, so no other answer could ever verify.
    if rp == "localhost":
        origin = "http://%s:%d" % (rp, PORT)
    else:
        origin = "https://%s" % rp
    return rp, origin

WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN = _webauthn_config()
WEBAUTHN_ENABLED = bool(WEBAUTHN_RP_ID)
# How long a server-issued ceremony challenge stays usable. Long enough for a
# Face ID prompt the user has to notice, short enough to be worthless later.
WEBAUTHN_CHALLENGE_TTL = 120

LATEST_CACHE = {"value": "", "ts": 0}

SUPPORTED_WEB_LANGS = {"en", "id", "ja"}
DEFAULT_WEB_LANG = "en"

def sanitize_lang(value):
    value = (value or "").strip().lower()
    if value in SUPPORTED_WEB_LANGS:
        return value
    return DEFAULT_WEB_LANG

# str.splitlines() breaks on eleven characters; collapsing only \t \r \n let the
# other eight split a record when it was read back, dropping the entry.
_VAULT_BREAKS = "\t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"

def _vf(value):
    # Vault records are TAB-delimited and line-based, so any character that
    # splitlines() honours has to be collapsed before the record is written.
    text = str(value or "")
    for ch in _VAULT_BREAKS:
        text = text.replace(ch, " ")
    return text


_URL_RE = re.compile(r"^https?://[^\s/]+", re.IGNORECASE)


def _vurl(value):
    """Sanitise a URL field; None means "present but unusable".

    The scheme is an allowlist, not a denylist. This value is rendered as an
    href on the entry page and will be handed to the browser extension as a
    match target, so "javascript:" or "data:" here is code execution and an
    exfiltration path rather than merely a bad link. Empty is always valid --
    the field is optional. None is distinct from "" so the form can say why it
    rejected the input instead of silently blanking it.
    """
    text = _vf(value).strip()
    if not text:
        return ""
    return text if _URL_RE.match(text) else None

def fetch_latest_version():
    now = time.time()
    if now - LATEST_CACHE.get("ts", 0) < 300 and LATEST_CACHE.get("value"):
        return LATEST_CACHE["value"]
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/sansyourways/Sans_Password_Manager/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "SPM"},
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = resp.read().decode("utf-8", "ignore")
        m = re.search(r'"tag_name"\\s*:\\s*"v?([^"]+)"', data)
        if m:
            LATEST_CACHE["value"] = m.group(1)
            LATEST_CACHE["ts"] = now
            return LATEST_CACHE["value"]
    except Exception:
        pass
    return ""

# ---------- HTML templates (liquid glass, icons, auto-lock) ------------------


I18N_SCRIPT = """
<script>
(function() {
  const DICT = {
    "en": {
      "nav.security": "Security",
      "nav.history": "History",
      "nav.unlock": "Biometric Unlock",
      "page.unlock.desc": "Resume the idle lock with this device instead of your master password.",
      "unlock.registered": "Registered",
      "unlock.empty": "No device registered yet",
      "unlock.empty_sub": "Register one below, or keep using your master password",
      "unlock.field.label": "Label for this device",
      "unlock.register": "Register this device",
      "unlock.note": "The master password is still required for the first sign-in, once the session reaches its maximum age, and whenever a locked session goes unresumed for too long.",
      "unlock.title": "Vault locked",
      "unlock.sub": "Confirm with your device to continue where you left off.",
      "unlock.btn": "Unlock with biometrics",
      "unlock.fallback": "Use master password instead",
      "unlock.waiting": "Waiting for biometric confirmation...",
      "unlock.failed": "Unlock failed.",
      "unlock.nosupport": "This browser has no biometric support.",
      "register.waiting": "Waiting for the authenticator...",
      "register.failed": "Registration failed.",
      "security.sub": "What is pulling your vault score down.",
      "security.scope": "Only password entries are scored. IDs are shown; secrets never are.",
      "security.none": "Nothing to fix here.",
      "security.weak": "Weak passwords",
      "security.weak_d": "Shorter than 12 characters, or using fewer than three character classes.",
      "security.reused": "Reused passwords",
      "security.reused_d": "Each row below is one group of entries sharing a password.",
      "security.aging": "Due for rotation",
      "security.aging_d": "Older than the rotation threshold:",
      "security.incomplete": "Missing details",
      "security.incomplete_d": "No service name or no username.",
      "security.malformed": "Malformed authenticators",
      "security.malformed_d": "Missing a secret, or an algorithm SPM cannot generate codes for.",
      "page.history.desc": "Encrypted vault snapshots kept before each change.",
      "history.when": "When",
      "history.size": "Size",
      "history.name": "Snapshot",
      "history.newest": "newest",
      "btn.restore": "Restore",
      "confirm.restore_snapshot": "Restore this snapshot? The current vault is archived first.",
      "empty.history.t": "No snapshots yet",
      "empty.history.d": "SPM archives the vault before each change.",
      "search.title": "Search",
      "search.desc": "Look across every record type.",
      "search.kind": "Type",
      "empty.search.t": "Nothing found",
      "empty.search.d": "No label, name or username matches that text.",
      "badge.aging": "rotate",
      "tags.all": "All",
      "header.title": "Sans Password Manager",
      "header.subtitle": "Liquid-glass web interface · GPG encrypted",
      "header.check_update": "Check update",
      "header.logout": "Logout",
      "nav.collapse": "Collapse sidebar",
      "nav.expand": "Expand sidebar",
      "nav.open": "Menu",
      "nav.close": "Close menu",
      "header.vault": "Vault",
      "section.passwords": "Passwords",
      "chip.online": "Online · read / write",
      "btn.add_entry": "+ Add Entry",
      "table.id": "ID",
      "table.name": "Name",
      "table.username": "Username",
      "table.actions": "Actions",
      "table.title": "Title",
      "table.label": "Label",
      "table.every": "Every",
      "table.algo": "Algo",
      "passwords.footer": "Passwords are never sent anywhere else – all crypto stays on this host with GnuPG.",
      "section.secure_notes": "Secure Notes",
      "section.secure_notes_desc": "Encrypted notes stored inside the same vault.",
      "btn.add_note": "+ Add Note",
      "section.generator": "Password Generator",
      "section.generator_desc": "Create strong passwords with length, mode, and symbol toggles.",
      "btn.open_generator": "Open Generator",
      "import.title": "Export / Import",
      "import.subtitle": "Download or paste data (csv/json + extended formats).",
      "import.format_label": "Format",
      "import.download": "Download",
      "import.import_label": "Import format",
      "import.upload_label": "Upload export file",
      "import.paste_label": "Or paste file contents",
      "import.placeholder": "Paste exported data here",
      "import.submit": "Import",
      "import.supports": "Supports passwords, notes, passphrases, authenticators, backup codes.",
      "import.overlay_upload": "Uploading...",
      "import.overlay_success": "Import complete.",
      "import.overlay_error": "Import failed.",
      "import.importing": "Importing...",
      "import.status_uploading": "Uploading...",
      "import.success_default": "Import complete.",
      "import.error_default": "Import failed.",
      "section.passphrases": "Passphrases",
      "section.passphrases_desc": "Store API tokens or recovery phrases. View prompts master re-check.",
      "btn.add_passphrase": "+ Add Passphrase",
      "section.authenticators": "Authenticators (TOTP)",
      "section.authenticators_desc": "Store 2FA secrets and view live codes.",
      "btn.add_authenticator": "+ Add Authenticator",
      "section.backups": "Backup Codes",
      "section.backups_desc": "Store recovery codes (view shows full codes).",
      "btn.add_backups": "+ Add Backup Codes",
      "section.session": "Web Session",
      "section.session_desc": "Protected by your master password. The interface auto-locks after 30 seconds of inactivity; the server expires an idle session after 5 minutes and any session after 12 hours.",
      "form.vault": "Vault:",
      "form.back_list": "\u2190 Back to list",
      "form.save": "Save",
      "link.back": "\u2190 Back",
      "entry.field.service": "Service / Name",
      "entry.field.username": "Username / Email",
      "entry.field.url": "URL",
      "entry.hint.url": "Used to match this entry to a site. http:// or https:// only.",
      "entry.field.password": "Password",
      "entry.field.notes": "Notes",
      "note.field.title": "Title",
      "note.field.content": "Content",
      "pass.field.label": "Label",
      "pass.field.secret_hint": "Passphrase (leave blank to auto-generate)",
      "backup.field.label": "Label",
      "backup.field.codes": "Backup codes (one per line)",
      "auth.field.label": "Label",
      "auth.field.secret": "Base32 Secret",
      "auth.field.period": "Refresh interval (seconds)",
      "auth.field.algorithm": "Algorithm",
      "auth.option.sha1": "SHA1 (default)",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "View Entry",
      "view.label.name": "Name",
      "view.label.username": "Username / Email",
      "view.label.url": "URL",
      "view.label.password": "Password",
      "view.label.notes": "Notes",
      "view.label.created": "Created at",
      "view.sub_prefix": "Vault:",
      "btn.copy_username": "Copy Username",
      "btn.copy_password": "Copy Password",
      "btn.copy_notes": "Copy Notes",
      "btn.copy_passphrase": "Copy",
      "btn.copy_codes": "Copy Codes",
      "btn.copy_code": "Copy Code",
      "btn.show": "Show",
      "btn.hide": "Hide",
      "btn.edit": "Edit",
      "btn.delete": "Delete",
      "pass.view.title": "Passphrase",
      "pass.view.label_field": "Label",
      "pass.view.created": "Created",
      "pass.view.secret": "Passphrase",
      "backup.view.title": "Backup Codes",
      "backup.view.label": "Label:",
      "backup.view.created": "Created:",
      "auth.view.title": "Authenticator",
      "auth.view.label": "Label",
      "auth.view.interval": "Interval",
      "auth.view.algo": "Algorithm",
      "auth.view.created": "Created",
      "auth.view.secret": "Base32 Secret",
      "auth.view.code": "Live Code",
      "auth.view.seconds_label": "seconds",
      "generator.title": "Password Generator",
      "generator.length": "Length",
      "generator.mode_secure": "Secure",
      "generator.mode_easy": "Easy / Memorable",
      "generator.opt.upper": "Uppercase",
      "generator.opt.lower": "Lowercase",
      "generator.opt.digits": "Numbers",
      "generator.opt.symbols": "Symbols",
      "generator.btn.regen": "Regenerate",
      "generator.btn.copy": "Copy",
      "generator.btn.back": "Back",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "bits",
      "generator.stats.suffix": "to brute-force (est.)",
      "generator.words_prefix": "Words",
      "generator.strength.very_weak": "Very weak",
      "generator.strength.weak": "Weak",
      "generator.strength.moderate": "Moderate",
      "generator.strength.strong": "Strong",
      "generator.strength.excellent": "Excellent",
      "generator.unit.sec": "sec",
      "generator.unit.min": "min",
      "generator.unit.hr": "hr",
      "generator.unit.day": "day",
      "generator.unit.yr": "yr",
      "generator.unit.century": "century",
      "import.placeholder": "Paste exported data here",
      "toast.copy_success": "Copied to clipboard.",
      "toast.copy_fail": "Copy failed.",
      "auth.countdown.refresh_in": "Refreshes in {n}s",
      "auth.countdown.refreshing": "Refreshing...",
      "auth.status.no_code": "No code yet",
      "auth.status.copy_ok": "Copied!",
      "auth.status.copy_fail": "Copy failed",
      "confirm.delete_entry": "Delete this entry?",
      "confirm.delete_passphrase": "Delete this passphrase?",
      "confirm.delete_backup": "Delete these backup codes?",
      "confirm.delete_authenticator": "Delete this authenticator?",
      "nav.group.vault": "Vault",
      "nav.group.tools": "Tools",
      "nav.group.settings": "Settings",
      "nav.master_password": "Master Password",
      "page.settings.title": "Master Password",
      "page.settings.desc": "Change the password that encrypts this vault.",
      "settings.current": "Current master password",
      "settings.new": "New master password",
      "settings.confirm": "Confirm new master password",
      "settings.submit": "Change master password",
      "settings.hint": "At least 12 characters. There is no way to recover a master password you forget \u2014 only the recovery file and its private key can reset it.",
      "settings.mismatch": "The two new passwords do not match.",
      "settings.effect": "What this does",
      "settings.effect_vault": "Re-encrypts the whole vault under the new password.",
      "settings.effect_recovery": "Rewrites the recovery file so \\"spm forgot\\" keeps working.",
      "settings.effect_sessions": "Signs out every other browser session.",
      "settings.effect_backup": "Keeps the previous vault as a .bak and a history snapshot.",
      "nav.overview": "Overview",
      "nav.passwords": "Passwords",
      "nav.notes": "Secure Notes",
      "nav.passphrases": "Passphrases",
      "nav.authenticators": "Authenticators",
      "nav.backup_codes": "Backup Codes",
      "nav.generator": "Generator",
      "nav.transfer": "Export / Import",
      "search.placeholder": "Search this vault...",
      "search.no_results": "Nothing matches your search",
      "lock.in": "Locks in",
      "lock.paused": "Lock paused",
      "overview.sub": "Everything in your encrypted vault at a glance.",
      "overview.recent": "Recently added",
      "overview.view_all": "View all",
      "overview.console_eyebrow": "session / local vault / authenticated",
      "overview.console_records": "encrypted records indexed",
      "overview.console_gpg": "GnuPG boundary active on this host",
      "overview.console_lock": "idle lock armed for 30 seconds",
      "overview.console_lede": "Inspect, generate, and maintain credentials from one auditable session.",
      "btn.view": "View",
      "generator.mode": "Mode",
      "login.sub": "Unlock your encrypted vault to continue.",
      "login.master": "Master password",
      "login.unlock": "Unlock",
      "login.note": "All decryption happens locally with GnuPG. Nothing leaves this host.",
      "empty.vault.t": "Your vault is empty",
      "empty.vault.d": "Add your first password to get started.",
      "empty.passwords.t": "No passwords yet",
      "empty.passwords.d": "Entries you add will appear here.",
      "empty.notes.t": "No secure notes",
      "empty.notes.d": "Encrypted notes live inside the same vault.",
      "empty.passphrases.t": "No passphrases",
      "empty.passphrases.d": "Store API tokens or recovery phrases here.",
      "empty.backups.t": "No backup codes",
      "empty.backups.d": "Keep one-time recovery codes safe here.",
      "empty.auth.t": "No authenticators",
      "empty.auth.d": "Add a TOTP secret to generate 2FA codes.",
      "page.passwords.desc": "Login credentials stored in your vault.",
      "page.notes.desc": "Encrypted notes stored inside the same vault.",
      "page.passphrases.desc": "API tokens and recovery phrases.",
      "page.authenticators.desc": "Time-based one-time password codes.",
      "page.backups.desc": "One-time recovery codes for your accounts.",
    },
    "id": {
      "nav.security": "Keamanan",
      "nav.history": "Riwayat",
      "nav.unlock": "Buka Biometrik",
      "page.unlock.desc": "Lanjutkan sesi terkunci dengan perangkat ini, bukan kata sandi master.",
      "unlock.registered": "Terdaftar",
      "unlock.empty": "Belum ada perangkat terdaftar",
      "unlock.empty_sub": "Daftarkan di bawah, atau tetap pakai kata sandi master",
      "unlock.field.label": "Label untuk perangkat ini",
      "unlock.register": "Daftarkan perangkat ini",
      "unlock.note": "Kata sandi master tetap diperlukan untuk masuk pertama kali, saat sesi mencapai usia maksimum, dan bila sesi terkunci terlalu lama tidak dilanjutkan.",
      "unlock.title": "Brankas terkunci",
      "unlock.sub": "Konfirmasi dengan perangkat Anda untuk melanjutkan.",
      "unlock.btn": "Buka dengan biometrik",
      "unlock.fallback": "Pakai kata sandi master saja",
      "unlock.waiting": "Menunggu konfirmasi biometrik...",
      "unlock.failed": "Gagal membuka.",
      "unlock.nosupport": "Peramban ini tidak mendukung biometrik.",
      "register.waiting": "Menunggu autentikator...",
      "register.failed": "Pendaftaran gagal.",
      "security.sub": "Hal yang menurunkan skor brankas Anda.",
      "security.scope": "Hanya entry password yang dinilai. ID ditampilkan; rahasia tidak pernah.",
      "security.none": "Tidak ada yang perlu diperbaiki.",
      "security.weak": "Password lemah",
      "security.weak_d": "Kurang dari 12 karakter, atau kurang dari tiga jenis karakter.",
      "security.reused": "Password dipakai ulang",
      "security.reused_d": "Tiap baris di bawah adalah satu grup entry dengan password sama.",
      "security.aging": "Saatnya diganti",
      "security.aging_d": "Lebih tua dari ambang rotasi:",
      "security.incomplete": "Detail belum lengkap",
      "security.incomplete_d": "Tidak ada nama layanan atau username.",
      "security.malformed": "Authenticator rusak",
      "security.malformed_d": "Secret hilang, atau algoritma tidak didukung SPM.",
      "page.history.desc": "Snapshot brankas terenkripsi sebelum tiap perubahan.",
      "history.when": "Waktu",
      "history.size": "Ukuran",
      "history.name": "Snapshot",
      "history.newest": "terbaru",
      "btn.restore": "Pulihkan",
      "confirm.restore_snapshot": "Pulihkan snapshot ini? Brankas saat ini diarsipkan dulu.",
      "empty.history.t": "Belum ada snapshot",
      "empty.history.d": "SPM mengarsipkan brankas sebelum tiap perubahan.",
      "search.title": "Cari",
      "search.desc": "Cari di semua jenis record.",
      "search.kind": "Jenis",
      "empty.search.t": "Tidak ditemukan",
      "empty.search.d": "Tidak ada label, nama, atau username yang cocok.",
      "badge.aging": "ganti",
      "tags.all": "Semua",
      "header.title": "Sans Password Manager",
      "header.subtitle": "Antarmuka web liquid-glass · terenkripsi GPG",
      "header.check_update": "Periksa pembaruan",
      "header.logout": "Keluar",
      "nav.collapse": "Ciutkan bilah sisi",
      "nav.expand": "Bentangkan bilah sisi",
      "nav.open": "Menu",
      "nav.close": "Tutup menu",
      "header.vault": "Brankas",
      "section.passwords": "Kata Sandi",
      "chip.online": "Online · baca / tulis",
      "btn.add_entry": "+ Tambah Entri",
      "table.id": "ID",
      "table.name": "Nama",
      "table.username": "Pengguna",
      "table.actions": "Aksi",
      "table.title": "Judul",
      "table.label": "Label",
      "table.every": "Interval",
      "table.algo": "Algo",
      "passwords.footer": "Kata sandi tidak pernah dikirim ke mana pun — seluruh kripto tetap di host ini dengan GnuPG.",
      "section.secure_notes": "Catatan Aman",
      "section.secure_notes_desc": "Catatan terenkripsi di dalam brankas yang sama.",
      "btn.add_note": "+ Tambah Catatan",
      "section.generator": "Pembuat Kata Sandi",
      "section.generator_desc": "Buat kata sandi kuat dengan panjang, mode, dan simbol.",
      "btn.open_generator": "Buka Generator",
      "import.title": "Ekspor / Impor",
      "import.subtitle": "Unduh atau tempel data (csv/json + format lainnya).",
      "import.format_label": "Format",
      "import.download": "Unduh",
      "import.import_label": "Format impor",
      "import.upload_label": "Unggah berkas ekspor",
      "import.paste_label": "Atau tempel isi berkas",
      "import.placeholder": "Tempel data hasil ekspor di sini",
      "import.submit": "Impor",
      "import.supports": "Mendukung kata sandi, catatan, frasa sandi, autentikator, kode cadangan.",
      "import.overlay_upload": "Mengunggah...",
      "import.overlay_success": "Impor selesai.",
      "import.overlay_error": "Impor gagal.",
      "import.importing": "Sedang mengimpor...",
      "import.status_uploading": "Mengunggah...",
      "import.success_default": "Impor selesai.",
      "import.error_default": "Impor gagal.",
      "section.passphrases": "Frasa Sandi",
      "section.passphrases_desc": "Simpan token API atau frasa pemulihan. Tampilan meminta master lagi.",
      "btn.add_passphrase": "+ Tambah Frasa Sandi",
      "section.authenticators": "Autentikator (TOTP)",
      "section.authenticators_desc": "Simpan rahasia 2FA dan lihat kode langsung.",
      "btn.add_authenticator": "+ Tambah Autentikator",
      "section.backups": "Kode Cadangan",
      "section.backups_desc": "Simpan kode pemulihan (tampilan memperlihatkan penuh).",
      "btn.add_backups": "+ Tambah Kode Cadangan",
      "section.session": "Sesi Web",
      "section.session_desc": "Dilindungi kata sandi master. Terkunci otomatis setelah 30 detik tidak aktif; server menutup sesi menganggur setelah 5 menit dan sesi apa pun setelah 12 jam.",
      "form.vault": "Brankas:",
      "form.back_list": "\u2190 Kembali ke daftar",
      "form.save": "Simpan",
      "link.back": "\u2190 Kembali",
      "entry.field.service": "Layanan / Nama",
      "entry.field.username": "Pengguna / Email",
      "entry.field.url": "URL",
      "entry.hint.url": "Dipakai untuk mencocokkan entry ini dengan situs. Hanya http:// atau https://.",
      "entry.field.password": "Kata sandi",
      "entry.field.notes": "Catatan",
      "note.field.title": "Judul",
      "note.field.content": "Konten",
      "pass.field.label": "Label",
      "pass.field.secret_hint": "Frasa sandi (kosongkan untuk membuat otomatis)",
      "backup.field.label": "Label",
      "backup.field.codes": "Kode cadangan (satu per baris)",
      "auth.field.label": "Label",
      "auth.field.secret": "Rahasia Base32",
      "auth.field.period": "Interval penyegaran (detik)",
      "auth.field.algorithm": "Algoritma",
      "auth.option.sha1": "SHA1 (default)",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "Lihat Entri",
      "view.label.name": "Nama",
      "view.label.username": "Pengguna / Email",
      "view.label.url": "URL",
      "view.label.password": "Kata sandi",
      "view.label.notes": "Catatan",
      "view.label.created": "Dibuat",
      "view.sub_prefix": "Brankas:",
      "btn.copy_username": "Salin pengguna",
      "btn.copy_password": "Salin kata sandi",
      "btn.copy_notes": "Salin catatan",
      "btn.copy_passphrase": "Salin",
      "btn.copy_codes": "Salin kode",
      "btn.copy_code": "Salin kode",
      "btn.show": "Tampilkan",
      "btn.hide": "Sembunyikan",
      "btn.edit": "Ubah",
      "btn.delete": "Hapus",
      "pass.view.title": "Frasa sandi",
      "pass.view.label_field": "Label",
      "pass.view.created": "Dibuat",
      "pass.view.secret": "Frasa sandi",
      "backup.view.title": "Kode Cadangan",
      "backup.view.label": "Label:",
      "backup.view.created": "Dibuat:",
      "auth.view.title": "Autentikator",
      "auth.view.label": "Label",
      "auth.view.interval": "Interval",
      "auth.view.algo": "Algoritma",
      "auth.view.created": "Dibuat",
      "auth.view.secret": "Rahasia Base32",
      "auth.view.code": "Kode langsung",
      "auth.view.seconds_label": "detik",
      "generator.title": "Pembuat Kata Sandi",
      "generator.length": "Panjang",
      "generator.mode_secure": "Aman",
      "generator.mode_easy": "Mudah / Mudah diingat",
      "generator.opt.upper": "Huruf besar",
      "generator.opt.lower": "Huruf kecil",
      "generator.opt.digits": "Angka",
      "generator.opt.symbols": "Simbol",
      "generator.btn.regen": "Buat ulang",
      "generator.btn.copy": "Salin",
      "generator.btn.back": "Kembali",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "bit",
      "generator.stats.suffix": "untuk brute-force (perk.)",
      "generator.words_prefix": "Kata",
      "generator.strength.very_weak": "Sangat lemah",
      "generator.strength.weak": "Lemah",
      "generator.strength.moderate": "Sedang",
      "generator.strength.strong": "Kuat",
      "generator.strength.excellent": "Sangat kuat",
      "generator.unit.sec": "detik",
      "generator.unit.min": "menit",
      "generator.unit.hr": "jam",
      "generator.unit.day": "hari",
      "generator.unit.yr": "tahun",
      "generator.unit.century": "abad",
      "import.placeholder": "Tempel data hasil ekspor di sini",
      "toast.copy_success": "Disalin ke clipboard.",
      "toast.copy_fail": "Gagal menyalin.",
      "auth.countdown.refresh_in": "Segar ulang dalam {n}dtk",
      "auth.countdown.refreshing": "Sedang menyegarkan...",
      "auth.status.no_code": "Belum ada kode",
      "auth.status.copy_ok": "Disalin!",
      "auth.status.copy_fail": "Gagal menyalin",
      "confirm.delete_entry": "Hapus entri ini?",
      "confirm.delete_passphrase": "Hapus frasa sandi ini?",
      "confirm.delete_backup": "Hapus kode cadangan ini?",
      "confirm.delete_authenticator": "Hapus autentikator ini?",
      "nav.group.vault": "Brankas",
      "nav.group.tools": "Alat",
      "nav.group.settings": "Pengaturan",
      "nav.master_password": "Kata Sandi Utama",
      "page.settings.title": "Kata Sandi Utama",
      "page.settings.desc": "Ubah kata sandi yang mengenkripsi brankas ini.",
      "settings.current": "Kata sandi utama saat ini",
      "settings.new": "Kata sandi utama baru",
      "settings.confirm": "Konfirmasi kata sandi utama baru",
      "settings.submit": "Ubah kata sandi utama",
      "settings.hint": "Minimal 12 karakter. Kata sandi utama yang lupa tidak bisa dipulihkan \u2014 hanya file pemulihan dan kunci privatnya yang bisa meresetnya.",
      "settings.mismatch": "Kedua kata sandi baru tidak sama.",
      "settings.effect": "Yang akan terjadi",
      "settings.effect_vault": "Mengenkripsi ulang seluruh brankas dengan kata sandi baru.",
      "settings.effect_recovery": "Menulis ulang file pemulihan agar \\"spm forgot\\" tetap berfungsi.",
      "settings.effect_sessions": "Mengeluarkan semua sesi browser lain.",
      "settings.effect_backup": "Menyimpan brankas lama sebagai .bak dan snapshot riwayat.",
      "nav.overview": "Ringkasan",
      "nav.passwords": "Kata Sandi",
      "nav.notes": "Catatan Aman",
      "nav.passphrases": "Frasa Sandi",
      "nav.authenticators": "Autentikator",
      "nav.backup_codes": "Kode Cadangan",
      "nav.generator": "Generator",
      "nav.transfer": "Ekspor / Impor",
      "search.placeholder": "Cari di brankas ini...",
      "search.no_results": "Tidak ada yang cocok dengan pencarian",
      "lock.in": "Terkunci dalam",
      "lock.paused": "Kunci dijeda",
      "overview.sub": "Semua isi brankas terenkripsi Anda sekilas.",
      "overview.recent": "Baru ditambahkan",
      "overview.view_all": "Lihat semua",
      "overview.console_eyebrow": "sesi / brankas lokal / terautentikasi",
      "overview.console_records": "rekaman terenkripsi terindeks",
      "overview.console_gpg": "Batas GnuPG aktif pada host ini",
      "overview.console_lock": "kunci diam disiapkan selama 30 detik",
      "overview.console_lede": "Periksa, buat, dan kelola kredensial dari satu sesi yang dapat diaudit.",
      "btn.view": "Lihat",
      "generator.mode": "Mode",
      "login.sub": "Buka brankas terenkripsi Anda untuk melanjutkan.",
      "login.master": "Kata sandi utama",
      "login.unlock": "Buka",
      "login.note": "Semua dekripsi dilakukan lokal dengan GnuPG. Tidak ada data yang keluar dari host ini.",
      "empty.vault.t": "Brankas Anda kosong",
      "empty.vault.d": "Tambahkan kata sandi pertama untuk memulai.",
      "empty.passwords.t": "Belum ada kata sandi",
      "empty.passwords.d": "Entri yang Anda tambahkan akan muncul di sini.",
      "empty.notes.t": "Belum ada catatan aman",
      "empty.notes.d": "Catatan terenkripsi tersimpan di brankas yang sama.",
      "empty.passphrases.t": "Belum ada frasa sandi",
      "empty.passphrases.d": "Simpan token API atau frasa pemulihan di sini.",
      "empty.backups.t": "Belum ada kode cadangan",
      "empty.backups.d": "Simpan kode pemulihan sekali pakai dengan aman di sini.",
      "empty.auth.t": "Belum ada autentikator",
      "empty.auth.d": "Tambahkan secret TOTP untuk membuat kode 2FA.",
      "page.passwords.desc": "Kredensial login yang tersimpan di brankas Anda.",
      "page.notes.desc": "Catatan terenkripsi di dalam brankas yang sama.",
      "page.passphrases.desc": "Token API dan frasa pemulihan.",
      "page.authenticators.desc": "Kode sekali pakai berbasis waktu.",
      "page.backups.desc": "Kode pemulihan sekali pakai untuk akun Anda.",
    },
    "ja": {
      "nav.security": "セキュリティ",
      "nav.history": "履歴",
      "nav.unlock": "生体認証ロック解除",
      "page.unlock.desc": "マスターパスワードの代わりに、この端末でロックを解除します。",
      "unlock.registered": "登録日時",
      "unlock.empty": "登録済みの端末はありません",
      "unlock.empty_sub": "下から登録するか、マスターパスワードを使い続けてください",
      "unlock.field.label": "この端末のラベル",
      "unlock.register": "この端末を登録",
      "unlock.note": "初回サインイン時、セッションが最大有効期間に達したとき、およびロックされたセッションが長時間再開されなかった場合は、引き続きマスターパスワードが必要です。",
      "unlock.title": "保管庫はロック中",
      "unlock.sub": "端末で確認して、続きから再開します。",
      "unlock.btn": "生体認証で解除",
      "unlock.fallback": "マスターパスワードを使う",
      "unlock.waiting": "生体認証の確認を待っています...",
      "unlock.failed": "ロック解除に失敗しました。",
      "unlock.nosupport": "このブラウザは生体認証に対応していません。",
      "register.waiting": "認証器を待っています...",
      "register.failed": "登録に失敗しました。",
      "security.sub": "ボールトのスコアを下げている項目。",
      "security.scope": "評価対象はパスワードのみ。IDのみ表示し、シークレットは表示しません。",
      "security.none": "修正すべき項目はありません。",
      "security.weak": "弱いパスワード",
      "security.weak_d": "12文字未満、または文字種が3種類未満。",
      "security.reused": "使い回しパスワード",
      "security.reused_d": "以下の各行は同じパスワードを共有するグループです。",
      "security.aging": "更新が必要",
      "security.aging_d": "ローテーション期限を超過:",
      "security.incomplete": "情報が不足",
      "security.incomplete_d": "サービス名またはユーザー名がありません。",
      "security.malformed": "不正な認証アプリ",
      "security.malformed_d": "シークレットが無いか、SPMが対応しないアルゴリズムです。",
      "page.history.desc": "変更前に保存される暗号化スナップショット。",
      "history.when": "日時",
      "history.size": "サイズ",
      "history.name": "スナップショット",
      "history.newest": "最新",
      "btn.restore": "復元",
      "confirm.restore_snapshot": "このスナップショットを復元しますか？現在のボールトは先に保存されます。",
      "empty.history.t": "スナップショットなし",
      "empty.history.d": "SPMは変更前にボールトを保存します。",
      "search.title": "検索",
      "search.desc": "すべての種類のレコードを検索します。",
      "search.kind": "種類",
      "empty.search.t": "見つかりません",
      "empty.search.d": "一致するラベル・名前・ユーザー名がありません。",
      "badge.aging": "更新",
      "tags.all": "すべて",
      "header.title": "Sans Password Manager",
      "header.subtitle": "リキッドガラス風Webインターフェース · GPG暗号化",
      "header.check_update": "アップデートを確認",
      "header.logout": "ログアウト",
      "nav.collapse": "サイドバーを折りたたむ",
      "nav.expand": "サイドバーを展開",
      "nav.open": "メニュー",
      "nav.close": "メニューを閉じる",
      "header.vault": "ボールト",
      "section.passwords": "パスワード",
      "chip.online": "オンライン · 読み/書き",
      "btn.add_entry": "+ エントリ追加",
      "table.id": "ID",
      "table.name": "名前",
      "table.username": "ユーザー名",
      "table.actions": "操作",
      "table.title": "タイトル",
      "table.label": "ラベル",
      "table.every": "周期",
      "table.algo": "方式",
      "passwords.footer": "パスワードはどこにも送信されません。暗号化はすべてこのホスト上で完結します。",
      "section.secure_notes": "セキュアノート",
      "section.secure_notes_desc": "同じボールト内に暗号化して保存されます。",
      "btn.add_note": "+ ノート追加",
      "section.generator": "パスワード生成",
      "section.generator_desc": "長さ・モード・記号を調整して強力なパスワードを生成。",
      "btn.open_generator": "ジェネレーターを開く",
      "import.title": "エクスポート / インポート",
      "import.subtitle": "データをダウンロードまたは貼り付け（csv/json + 拡張フォーマット）。",
      "import.format_label": "フォーマット",
      "import.download": "ダウンロード",
      "import.import_label": "インポート形式",
      "import.upload_label": "エクスポートファイルをアップロード",
      "import.paste_label": "または内容を貼り付け",
      "import.placeholder": "ここにエクスポートデータを貼り付け",
      "import.submit": "インポート",
      "import.supports": "パスワード、ノート、パスフレーズ、認証器、バックアップコードに対応。",
      "import.overlay_upload": "アップロード中...",
      "import.overlay_success": "インポート完了。",
      "import.overlay_error": "インポート失敗。",
      "import.importing": "インポート中...",
      "import.status_uploading": "アップロード中...",
      "import.success_default": "インポート完了。",
      "import.error_default": "インポート失敗。",
      "section.passphrases": "パスフレーズ",
      "section.passphrases_desc": "APIトークンや復旧フレーズを保存。閲覧時に再確認します。",
      "btn.add_passphrase": "+ パスフレーズ追加",
      "section.authenticators": "認証アプリ (TOTP)",
      "section.authenticators_desc": "2FAシークレットを保存しライブコードを表示。",
      "btn.add_authenticator": "+ 認証を追加",
      "section.backups": "バックアップコード",
      "section.backups_desc": "復旧コードを保存（表示時は全文表示）。",
      "btn.add_backups": "+ コード追加",
      "section.session": "Webセッション",
      "section.session_desc": "マスターパスワードで保護。30秒間操作がないと自動ロックされ、サーバーも5分でアイドルセッションを、12時間で全セッションを失効させます。",
      "form.vault": "ボールト:",
      "form.back_list": "\u2190 一覧に戻る",
      "form.save": "保存",
      "link.back": "\u2190 戻る",
      "entry.field.service": "サービス / 名称",
      "entry.field.username": "ユーザー名 / メール",
      "entry.field.url": "URL",
      "entry.hint.url": "このエントリをサイトに紐づけるために使用します。http:// または https:// のみ。",
      "entry.field.password": "パスワード",
      "entry.field.notes": "メモ",
      "note.field.title": "タイトル",
      "note.field.content": "内容",
      "pass.field.label": "ラベル",
      "pass.field.secret_hint": "パスフレーズ（空欄で自動生成）",
      "backup.field.label": "ラベル",
      "backup.field.codes": "バックアップコード（1行1コード）",
      "auth.field.label": "ラベル",
      "auth.field.secret": "Base32シークレット",
      "auth.field.period": "更新間隔（秒）",
      "auth.field.algorithm": "アルゴリズム",
      "auth.option.sha1": "SHA1（標準）",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "エントリ表示",
      "view.label.name": "名前",
      "view.label.username": "ユーザー名 / メール",
      "view.label.url": "URL",
      "view.label.password": "パスワード",
      "view.label.notes": "メモ",
      "view.label.created": "作成日時",
      "view.sub_prefix": "ボールト:",
      "btn.copy_username": "ユーザー名をコピー",
      "btn.copy_password": "パスワードをコピー",
      "btn.copy_notes": "ノートをコピー",
      "btn.copy_passphrase": "コピー",
      "btn.copy_codes": "コードをコピー",
      "btn.copy_code": "コードをコピー",
      "btn.show": "表示",
      "btn.hide": "非表示",
      "btn.edit": "編集",
      "btn.delete": "削除",
      "pass.view.title": "パスフレーズ",
      "pass.view.label_field": "ラベル",
      "pass.view.created": "作成日",
      "pass.view.secret": "パスフレーズ",
      "backup.view.title": "バックアップコード",
      "backup.view.label": "ラベル:",
      "backup.view.created": "作成:",
      "auth.view.title": "認証アプリ",
      "auth.view.label": "ラベル",
      "auth.view.interval": "間隔",
      "auth.view.algo": "アルゴリズム",
      "auth.view.created": "作成日",
      "auth.view.secret": "Base32シークレット",
      "auth.view.code": "ライブコード",
      "auth.view.seconds_label": "秒",
      "generator.title": "パスワード生成",
      "generator.length": "長さ",
      "generator.mode_secure": "強力",
      "generator.mode_easy": "簡単 / 覚えやすい",
      "generator.opt.upper": "大文字",
      "generator.opt.lower": "小文字",
      "generator.opt.digits": "数字",
      "generator.opt.symbols": "記号",
      "generator.btn.regen": "再生成",
      "generator.btn.copy": "コピー",
      "generator.btn.back": "戻る",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "ビット",
      "generator.stats.suffix": "推定総当たり時間",
      "generator.words_prefix": "単語",
      "generator.strength.very_weak": "とても弱い",
      "generator.strength.weak": "弱い",
      "generator.strength.moderate": "普通",
      "generator.strength.strong": "強い",
      "generator.strength.excellent": "最強",
      "generator.unit.sec": "秒",
      "generator.unit.min": "分",
      "generator.unit.hr": "時間",
      "generator.unit.day": "日",
      "generator.unit.yr": "年",
      "generator.unit.century": "世紀",
      "import.placeholder": "ここにエクスポートデータを貼り付け",
      "toast.copy_success": "クリップボードにコピーしました。",
      "toast.copy_fail": "コピーに失敗しました。",
      "auth.countdown.refresh_in": "{n}秒で更新",
      "auth.countdown.refreshing": "更新中...",
      "auth.status.no_code": "まだコードがありません",
      "auth.status.copy_ok": "コピーしました",
      "auth.status.copy_fail": "コピー失敗",
      "confirm.delete_entry": "このエントリを削除しますか？",
      "confirm.delete_passphrase": "このパスフレーズを削除しますか？",
      "confirm.delete_backup": "これらのバックアップコードを削除しますか？",
      "confirm.delete_authenticator": "この認証情報を削除しますか？",
      "nav.group.vault": "\u4fdd\u7ba1\u5eab",
      "nav.group.tools": "\u30c4\u30fc\u30eb",
      "nav.group.settings": "\u8a2d\u5b9a",
      "nav.master_password": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "page.settings.title": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "page.settings.desc": "\u3053\u306e\u4fdd\u7ba1\u5eab\u3092\u6697\u53f7\u5316\u3057\u3066\u3044\u308b\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5909\u66f4\u3057\u307e\u3059\u3002",
      "settings.current": "\u73fe\u5728\u306e\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "settings.new": "\u65b0\u3057\u3044\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "settings.confirm": "\u65b0\u3057\u3044\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\uff08\u78ba\u8a8d\uff09",
      "settings.submit": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5909\u66f4",
      "settings.hint": "12\u6587\u5b57\u4ee5\u4e0a\u3002\u5fd8\u308c\u305f\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5fa9\u5143\u3059\u308b\u65b9\u6cd5\u306f\u3042\u308a\u307e\u305b\u3093\u3002\u30ea\u30ab\u30d0\u30ea\u30d5\u30a1\u30a4\u30eb\u3068\u79d8\u5bc6\u9375\u3060\u3051\u304c\u30ea\u30bb\u30c3\u30c8\u3067\u304d\u307e\u3059\u3002",
      "settings.mismatch": "\u65b0\u3057\u3044\u30d1\u30b9\u30ef\u30fc\u30c9\u304c\u4e00\u81f4\u3057\u307e\u305b\u3093\u3002",
      "settings.effect": "\u5b9f\u884c\u3055\u308c\u308b\u5185\u5bb9",
      "settings.effect_vault": "\u4fdd\u7ba1\u5eab\u5168\u4f53\u3092\u65b0\u3057\u3044\u30d1\u30b9\u30ef\u30fc\u30c9\u3067\u518d\u6697\u53f7\u5316\u3057\u307e\u3059\u3002",
      "settings.effect_recovery": "\\"spm forgot\\" \u304c\u5f15\u304d\u7d9a\u304d\u4f7f\u3048\u308b\u3088\u3046\u30ea\u30ab\u30d0\u30ea\u30d5\u30a1\u30a4\u30eb\u3092\u66f8\u304d\u63db\u3048\u307e\u3059\u3002",
      "settings.effect_sessions": "\u4ed6\u306e\u3059\u3079\u3066\u306e\u30d6\u30e9\u30a6\u30b6\u30bb\u30c3\u30b7\u30e7\u30f3\u3092\u30b5\u30a4\u30f3\u30a2\u30a6\u30c8\u3057\u307e\u3059\u3002",
      "settings.effect_backup": "\u4ee5\u524d\u306e\u4fdd\u7ba1\u5eab\u3092 .bak \u3068\u5c65\u6b74\u30b9\u30ca\u30c3\u30d7\u30b7\u30e7\u30c3\u30c8\u3068\u3057\u3066\u4fdd\u6301\u3057\u307e\u3059\u3002",
      "nav.overview": "\u6982\u8981",
      "nav.passwords": "\u30d1\u30b9\u30ef\u30fc\u30c9",
      "nav.notes": "\u30bb\u30ad\u30e5\u30a2\u30e1\u30e2",
      "nav.passphrases": "\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba",
      "nav.authenticators": "\u8a8d\u8a3c\u30a2\u30d7\u30ea",
      "nav.backup_codes": "\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u30b3\u30fc\u30c9",
      "nav.generator": "\u30b8\u30a7\u30cd\u30ec\u30fc\u30bf\u30fc",
      "nav.transfer": "\u30a8\u30af\u30b9\u30dd\u30fc\u30c8 / \u30a4\u30f3\u30dd\u30fc\u30c8",
      "search.placeholder": "\u3053\u306e\u4fdd\u7ba1\u5eab\u3092\u691c\u7d22...",
      "search.no_results": "\u691c\u7d22\u6761\u4ef6\u306b\u4e00\u81f4\u3059\u308b\u9805\u76ee\u306f\u3042\u308a\u307e\u305b\u3093",
      "lock.in": "\u30ed\u30c3\u30af\u307e\u3067",
      "lock.paused": "\u30ed\u30c3\u30af\u4e00\u6642\u505c\u6b62\u4e2d",
      "overview.sub": "\u6697\u53f7\u5316\u3055\u308c\u305f\u4fdd\u7ba1\u5eab\u306e\u5185\u5bb9\u3092\u4e00\u89a7\u3067\u304d\u307e\u3059\u3002",
      "overview.recent": "\u6700\u8fd1\u8ffd\u52a0\u3057\u305f\u9805\u76ee",
      "overview.view_all": "\u3059\u3079\u3066\u8868\u793a",
      "overview.console_eyebrow": "\u30bb\u30c3\u30b7\u30e7\u30f3 / \u30ed\u30fc\u30ab\u30eb\u4fdd\u7ba1\u5eab / \u8a8d\u8a3c\u6e08\u307f",
      "overview.console_records": "\u4ef6\u306e\u6697\u53f7\u5316\u30ec\u30b3\u30fc\u30c9\u3092\u7d22\u5f15\u6e08\u307f",
      "overview.console_gpg": "\u3053\u306e\u30db\u30b9\u30c8\u3067 GnuPG \u5883\u754c\u304c\u6709\u52b9",
      "overview.console_lock": "30 \u79d2\u306e\u30a2\u30a4\u30c9\u30eb\u30ed\u30c3\u30af\u3092\u6709\u52b9\u5316",
      "overview.console_lede": "\u76e3\u67fb\u53ef\u80fd\u306a1\u3064\u306e\u30bb\u30c3\u30b7\u30e7\u30f3\u3067\u8a8d\u8a3c\u60c5\u5831\u3092\u78ba\u8a8d\u3001\u751f\u6210\u3001\u7ba1\u7406\u3057\u307e\u3059\u3002",
      "btn.view": "\u8868\u793a",
      "generator.mode": "\u30e2\u30fc\u30c9",
      "login.sub": "\u7d9a\u884c\u3059\u308b\u306b\u306f\u4fdd\u7ba1\u5eab\u306e\u30ed\u30c3\u30af\u3092\u89e3\u9664\u3057\u3066\u304f\u3060\u3055\u3044\u3002",
      "login.master": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "login.unlock": "\u30ed\u30c3\u30af\u89e3\u9664",
      "login.note": "\u5fa9\u53f7\u306f\u3059\u3079\u3066 GnuPG \u306b\u3088\u308a\u30ed\u30fc\u30ab\u30eb\u3067\u884c\u308f\u308c\u3001\u30c7\u30fc\u30bf\u304c\u30db\u30b9\u30c8\u5916\u3078\u51fa\u308b\u3053\u3068\u306f\u3042\u308a\u307e\u305b\u3093\u3002",
      "empty.vault.t": "\u4fdd\u7ba1\u5eab\u306f\u7a7a\u3067\u3059",
      "empty.vault.d": "\u6700\u521d\u306e\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u8ffd\u52a0\u3057\u3066\u59cb\u3081\u307e\u3057\u3087\u3046\u3002",
      "empty.passwords.t": "\u30d1\u30b9\u30ef\u30fc\u30c9\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.passwords.d": "\u8ffd\u52a0\u3057\u305f\u9805\u76ee\u304c\u3053\u3053\u306b\u8868\u793a\u3055\u308c\u307e\u3059\u3002",
      "empty.notes.t": "\u30bb\u30ad\u30e5\u30a2\u30e1\u30e2\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.notes.d": "\u6697\u53f7\u5316\u3055\u308c\u305f\u30e1\u30e2\u306f\u540c\u3058\u4fdd\u7ba1\u5eab\u306b\u4fdd\u5b58\u3055\u308c\u307e\u3059\u3002",
      "empty.passphrases.t": "\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.passphrases.d": "API \u30c8\u30fc\u30af\u30f3\u3084\u5fa9\u65e7\u30d5\u30ec\u30fc\u30ba\u3092\u3053\u3053\u306b\u4fdd\u5b58\u3067\u304d\u307e\u3059\u3002",
      "empty.backups.t": "\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u30b3\u30fc\u30c9\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.backups.d": "\u4f7f\u3044\u6368\u3066\u306e\u5fa9\u65e7\u30b3\u30fc\u30c9\u3092\u3053\u3053\u306b\u5b89\u5168\u306b\u4fdd\u7ba1\u3057\u307e\u3059\u3002",
      "empty.auth.t": "\u8a8d\u8a3c\u30a2\u30d7\u30ea\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.auth.d": "TOTP \u30b7\u30fc\u30af\u30ec\u30c3\u30c8\u3092\u8ffd\u52a0\u3057\u3066 2FA \u30b3\u30fc\u30c9\u3092\u751f\u6210\u3057\u307e\u3059\u3002",
      "page.passwords.desc": "\u4fdd\u7ba1\u5eab\u306b\u4fdd\u5b58\u3055\u308c\u3066\u3044\u308b\u30ed\u30b0\u30a4\u30f3\u60c5\u5831\u3002",
      "page.notes.desc": "\u540c\u3058\u4fdd\u7ba1\u5eab\u5185\u306b\u4fdd\u5b58\u3055\u308c\u305f\u6697\u53f7\u5316\u30e1\u30e2\u3002",
      "page.passphrases.desc": "API \u30c8\u30fc\u30af\u30f3\u3068\u5fa9\u65e7\u30d5\u30ec\u30fc\u30ba\u3002",
      "page.authenticators.desc": "\u6642\u523b\u30d9\u30fc\u30b9\u306e\u30ef\u30f3\u30bf\u30a4\u30e0\u30d1\u30b9\u30ef\u30fc\u30c9\u30b3\u30fc\u30c9\u3002",
      "page.backups.desc": "\u30a2\u30ab\u30a6\u30f3\u30c8\u7528\u306e\u4f7f\u3044\u6368\u3066\u5fa9\u65e7\u30b3\u30fc\u30c9\u3002",
    }
  };
  const FALLBACK = "en";
  const SUPPORTED = Object.keys(DICT);
  function normalize(lang) {
    lang = (lang || "").toLowerCase();
    if (SUPPORTED.includes(lang)) return lang;
    return FALLBACK;
  }
  function lookup(key, lang) {
    const dict = DICT[normalize(lang)] || {};
    if (Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    const fb = DICT[FALLBACK] || {};
    if (Object.prototype.hasOwnProperty.call(fb, key)) return fb[key];
    return null;
  }
  let current = normalize(window.SPM_LANG);
  function applyTranslations(lang) {
    current = normalize(lang);
    if (document.documentElement) document.documentElement.setAttribute("lang", current);
    if (document.body) document.body.setAttribute("data-lang", current);
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.getAttribute("data-i18n");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.textContent = text;
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      const key = node.getAttribute("data-i18n-placeholder");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.setAttribute("placeholder", text);
    });
    /* Collapsed to a rail, a nav item's only remaining label is its tooltip.
       Leaving that untranslated would make the icon-only sidebar English-only. */
    document.querySelectorAll("[data-i18n-title]").forEach((node) => {
      const key = node.getAttribute("data-i18n-title");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.setAttribute("title", text);
    });
    const picker = document.getElementById("lang-picker");
    if (picker) picker.value = current;
  }
  function persist(lang) {
    try {
      fetch("/lang", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Requested-With": "fetch"
        },
        body: "lang=" + encodeURIComponent(lang),
        credentials: "same-origin"
      }).catch(() => {});
    } catch (e) {}
  }
  function setLang(lang) {
    const normalized = normalize(lang);
    applyTranslations(normalized);
    persist(normalized);
  }
  document.addEventListener("DOMContentLoaded", () => {
    applyTranslations(current);
    const picker = document.getElementById("lang-picker");
    if (picker) {
      picker.value = current;
      picker.addEventListener("change", () => setLang(picker.value));
    }
  });
  window.SPM_I18N = {
    dict: DICT,
    t: function(key, fallback) {
      const text = lookup(key, current);
      if (text !== null && text !== undefined) return text;
      return fallback !== undefined ? fallback : key;
    },
    setLang: setLang,
    getLang: function() { return current; },
    apply: applyTranslations
  };
})();

// Inline handlers were removed so the CSP no longer needs 'unsafe-inline'.
// One delegated listener covers every control, including markup added later.
(function () {
  document.addEventListener("click", function (ev) {
    // WebKit can report an SVG <use> (and older builds occasionally a text
    // node) as the tap target. Those targets do not reliably implement
    // Element.closest(), so walk to an Element before delegating actions.
    var target = ev.target;
    if (target && target.nodeType !== 1) target = target.parentElement;
    const el = target && target.closest ? target.closest("[data-act]") : null;
    if (!el) return;
    const act = el.getAttribute("data-act");
    const id = el.getAttribute("data-target");
    const node = id ? document.getElementById(id) : null;
    if (act === "reveal") { if (window.SPM_reveal) SPM_reveal(id, el); }
    else if (act === "copy-val") { if (node && window.SPM_copy) SPM_copy(node.dataset.val); }
    else if (act === "copy-text") { if (node && window.SPM_copy) SPM_copy(node.textContent); }
    else if (act === "regen") { if (window.SPM_regen) SPM_regen(); }
    else if (act === "copy-pw") { if (window.SPM_copyPw) SPM_copyPw(); }
    else if (act === "tag") {
      // A tag chip drives the search box that already filters this table,
      // rather than adding a second filtering path that could disagree with it.
      var box = document.getElementById("q");
      if (box) {
        box.value = el.getAttribute("data-tag") || "";
        box.dispatchEvent(new Event("input", { bubbles: true }));
      }
      document.querySelectorAll("[data-act='tag']").forEach(function (c) {
        c.classList.toggle("chip-on", c === el);
      });
    }
    else return;
    ev.preventDefault();
  });
  document.addEventListener("submit", function (ev) {
    const form = ev.target.closest("form[data-confirm-key]");
    if (!form) return;
    const key = form.getAttribute("data-confirm-key");
    const fallback = form.getAttribute("data-confirm-text") || "";
    const text = window.SPM_I18N ? SPM_I18N.t(key, fallback) : fallback;
    if (!confirm(text)) ev.preventDefault();
  });
})();
</script>
"""

DESIGN_CSS = """
<style>
/* ============================================================
   SPM design system - one stylesheet for every page.
   Tokens first, then primitives, then components, then layout.
   Console is intentionally dark-only. Components consume semantic
   action, emitted-value, state, surface, and text roles.
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; }

:root {
  --sp-1: 4px;  --sp-2: 8px;  --sp-3: 12px; --sp-4: 16px;
  --sp-5: 24px; --sp-6: 32px; --sp-7: 48px;
  --r-sm: 8px; --r-md: 12px; --r-lg: 16px; --r-full: 999px;
  --fs-xs: 11px; --fs-sm: 12px; --fs-md: 13px; --fs-base: 14px;
  --fs-lg: 16px; --fs-xl: 20px; --fs-2xl: 26px; --fs-3xl: 34px;
  --sidebar-w: 260px;
  --topbar-h: 60px;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --ease: cubic-bezier(.4, 0, .2, 1);
  --motion-instant: 80ms;
  --motion-fast: 140ms;
  --motion-base: 200ms;
  --motion-live: 320ms;
  /* A07 durations. Exits are faster than entrances on purpose: a departing
     surface has already been decided about, and equal timings make dismissal
     feel sticky. --motion-reveal fires once per element, ever; --motion-ambient
     is reserved for state that is genuinely live. */
  --motion-slow: 320ms;
  --motion-reveal: 500ms;
  --motion-ambient: 8s;
  --motion-tick: 950ms;
  --stagger: 40ms;
  --ease-entrance: cubic-bezier(.2, .7, .3, 1);
  --ease-exit: cubic-bezier(.4, 0, 1, 1);
  --rail-w: 68px;
}

/* ---- Theme: dark (default) ---- */
body, body.theme-dark {
  --bg:        #0d1017;
  --bg-grad:   radial-gradient(1200px 600px at 15% -10%, #1b2540 0%, transparent 60%), #0d1017;
  --surface:   #151a24;
  --surface-2: #1c2230;
  --surface-3: #232b3b;
  --border:    #262e3d;
  --border-hi: #364157;
  --text:      #e8ecf5;
  --text-dim:  #98a3b8;
  --text-faint:#6b7688;
  --accent:    #5b8cff;
  --accent-hi: #7aa2ff;
  --accent-fg: #ffffff;
  --accent-soft:rgba(91,140,255,.14);
  --ok:        #3ecf8e;
  --ok-soft:   rgba(62,207,142,.14);
  --warn:      #f5b544;
  --warn-soft: rgba(245,181,68,.14);
  --danger:    #f2555a;
  --danger-soft:rgba(242,85,90,.14);
  --shadow:    0 1px 2px rgba(0,0,0,.4), 0 4px 16px rgba(0,0,0,.28);
  --shadow-lg: 0 12px 40px rgba(0,0,0,.5);
}

/* ---- Theme: AMOLED ---- */
body.theme-amoled {
  --bg:        #000000;
  --bg-grad:   radial-gradient(900px 500px at 20% -15%, #0d1424 0%, transparent 62%), #000000;
  --surface:   #08090c;
  --surface-2: #101319;
  --surface-3: #171b23;
  --border:    #1b1f28;
  --border-hi: #2b3140;
  --text:      #f2f5fa;
  --text-dim:  #94a0b4;
  --text-faint:#636d7e;
  --accent:    #4f8bff;
  --accent-hi: #74a6ff;
  --accent-soft:rgba(79,139,255,.16);
  --shadow:    0 1px 2px rgba(0,0,0,.9), 0 4px 18px rgba(0,0,0,.7);
  --shadow-lg: 0 14px 44px rgba(0,0,0,.85);
}

/* ---- Theme: cyberpunk ---- */
body.theme-cyberpunk {
  --bg:        #0a0713;
  --bg-grad:   radial-gradient(1000px 520px at 12% -10%, #2a0f47 0%, transparent 58%), radial-gradient(800px 400px at 95% 8%, #06303a 0%, transparent 55%), #0a0713;
  --surface:   #140d22;
  --surface-2: #1c1230;
  --surface-3: #26193f;
  --border:    #33204f;
  --border-hi: #4b2f70;
  --text:      #f6ecff;
  --text-dim:  #b19ad0;
  --text-faint:#8875a3;
  --accent:    #f637d4;
  --accent-hi: #ff6ae0;
  --accent-fg: #ffffff;
  --accent-soft:rgba(246,55,212,.16);
  --ok:        #35f0c0;
  --ok-soft:   rgba(53,240,192,.14);
  --warn:      #ffcc4d;
  --danger:    #ff4d6d;
  --shadow:    0 1px 2px rgba(0,0,0,.6), 0 4px 20px rgba(120,20,140,.3);
  --shadow-lg: 0 14px 46px rgba(140,20,160,.42);
}

/* ---- Theme: light ---- */
body.theme-light {
  --bg:        #f4f6fa;
  --bg-grad:   radial-gradient(1100px 560px at 12% -12%, #e2eaff 0%, transparent 60%), #f4f6fa;
  --surface:   #ffffff;
  --surface-2: #f7f9fc;
  --surface-3: #eef2f8;
  --border:    #dfe5ee;
  --border-hi: #c4cede;
  --text:      #131822;
  --text-dim:  #5a6577;
  --text-faint:#8b95a6;
  --accent:    #2f6bf0;
  --accent-hi: #1d55d4;
  --accent-fg: #ffffff;
  --accent-soft:rgba(47,107,240,.10);
  --ok:        #14915c;
  --ok-soft:   rgba(20,145,92,.12);
  --warn:      #b57611;
  --warn-soft: rgba(181,118,17,.12);
  --danger:    #d3323b;
  --danger-soft:rgba(211,50,59,.10);
  --shadow:    0 1px 2px rgba(16,24,40,.06), 0 4px 14px rgba(16,24,40,.07);
  --shadow-lg: 0 14px 40px rgba(16,24,40,.16);
}

/* ---- Base ---- */
html, body { height: 100%; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: var(--fs-base);
  line-height: 1.55;
  color: var(--text);
  background: var(--bg-grad, var(--bg));
  background-attachment: fixed;
  -webkit-font-smoothing: antialiased;
  transition: background-color .25s var(--ease), color .25s var(--ease);
}
a { color: inherit; text-decoration: none; }
h1, h2, h3, h4 { margin: 0; font-weight: 650; letter-spacing: -.01em; }
p  { margin: 0; }
::selection { background: var(--accent-soft); }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: var(--r-sm);
}

/* Scrollbars */
* { scrollbar-width: thin; scrollbar-color: var(--border-hi) transparent; }
*::-webkit-scrollbar { width: 10px; height: 10px; }
*::-webkit-scrollbar-track { background: transparent; }
*::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: var(--r-full); border: 3px solid transparent; background-clip: content-box; }
*::-webkit-scrollbar-thumb:hover { background: var(--text-faint); background-clip: content-box; }

/* ============================ Layout ============================ */
.app { display: grid; grid-template-columns: var(--sidebar-w) 1fr; min-height: 100vh; }

.sidebar {
  position: sticky; top: 0; height: 100vh;
  display: flex; flex-direction: column;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: var(--sp-4) var(--sp-3);
  gap: var(--sp-4);
  overflow-y: auto;
  z-index: 40;
}
.brand { display: flex; align-items: center; gap: var(--sp-3); padding: var(--sp-2); }
.brand-mark {
  width: 36px; height: 36px; flex: none; border-radius: 10px;
  display: grid; place-items: center;
  background: linear-gradient(135deg, var(--accent), var(--accent-hi));
  color: var(--accent-fg); font-size: 17px; font-weight: 700;
  box-shadow: var(--shadow);
}
.brand-text { min-width: 0; }
.brand-name { font-size: var(--fs-base); font-weight: 650; line-height: 1.25; }
.brand-meta { font-size: var(--fs-xs); color: var(--text-faint); }

.nav { display: flex; flex-direction: column; gap: 2px; }
.nav-label {
  font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .07em;
  color: var(--text-faint); padding: var(--sp-3) var(--sp-2) var(--sp-1);
  font-weight: 600;
}
.nav-item {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: 9px var(--sp-3); border-radius: var(--r-md);
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 500;
  transition: background .16s var(--ease), color .16s var(--ease);
  position: relative;
}
.nav-item:hover { background: var(--surface-2); color: var(--text); }
.nav-item.active { background: var(--accent-soft); color: var(--accent-hi); font-weight: 600; }
.nav-item.active::before {
  content: ""; position: absolute; left: -12px;
  top: 50%; transform: translateY(-50%);
  width: 3px; height: 18px; border-radius: 0 3px 3px 0; background: var(--accent);
}
.nav-ico { width: 18px; text-align: center; font-size: 15px; flex: none; }
.nav-count {
  margin-left: auto; font-size: var(--fs-xs); font-variant-numeric: tabular-nums;
  background: var(--surface-3); color: var(--text-dim);
  padding: 1px 7px; border-radius: var(--r-full); font-weight: 600;
}
.nav-item.active .nav-count { background: var(--accent); color: var(--accent-fg); }

.sidebar-foot { margin-top: auto; display: flex; flex-direction: column; gap: var(--sp-2); }
.vault-chip {
  display: flex; align-items: center; gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3); border-radius: var(--r-md);
  background: var(--surface-2); border: 1px solid var(--border);
  font-size: var(--fs-xs); color: var(--text-dim); min-width: 0;
}
.vault-chip .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); flex: none; box-shadow: 0 0 0 3px var(--ok-soft); }
.vault-chip .path { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: 10px; }

.main { display: flex; flex-direction: column; min-width: 0; }

.topbar {
  position: sticky; top: 0; z-index: 30;
  height: var(--topbar-h); flex: none;
  display: flex; align-items: center; gap: var(--sp-3);
  padding: 0 var(--sp-5);
  background: var(--surface);
  background: color-mix(in srgb, var(--bg) 86%, transparent);
  backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--border);
}
@supports not (backdrop-filter: blur(4px)) { .topbar { background: var(--bg); } }

/* Shown at every width. Under 900px it opens the drawer; above, it collapses
   the sidebar to an icon rail. It used to be display:none until 900px, which
   left the desktop button in the markup but invisible and inert. */
.menu-btn { display: inline-grid; }

.search {
  position: relative; flex: 1; max-width: 460px;
}
.search input {
  width: 100%; height: 38px;
  padding: 0 var(--sp-3) 0 36px;
  border-radius: var(--r-md);
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text); font-size: var(--fs-md); font-family: inherit;
  transition: border-color .16s var(--ease), box-shadow .16s var(--ease);
}
.search input::placeholder { color: var(--text-faint); }
.search input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
.search-ico { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-faint); font-size: 14px; pointer-events: none; }
.search kbd {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  font-family: var(--font); font-size: 10px; color: var(--text-faint);
  border: 1px solid var(--border); border-radius: 5px; padding: 1px 5px; background: var(--surface-2);
}
.search input:focus ~ kbd { opacity: 0; }

.topbar-right { margin-left: auto; display: flex; align-items: center; gap: var(--sp-2); }

.select {
  height: 34px; padding: 0 26px 0 var(--sp-3);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
  font-size: var(--fs-sm); font-family: inherit; cursor: pointer;
  appearance: none; -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%), linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 14px) 50%, calc(100% - 9px) 50%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
  transition: border-color .16s var(--ease);
}
.select:hover { border-color: var(--border-hi); }
.select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }

.content { padding: var(--sp-5); max-width: 1280px; width: 100%; margin: 0 auto; flex: 1; }

.page-head { display: flex; align-items: flex-start; gap: var(--sp-4); margin-bottom: var(--sp-5); flex-wrap: wrap; }
.page-title { font-size: var(--fs-2xl); line-height: 1.2; }
.page-sub { color: var(--text-dim); font-size: var(--fs-md); margin-top: 2px; }
.page-actions { margin-left: auto; display: flex; gap: var(--sp-2); flex-wrap: wrap; }

/* ============================ Components ============================ */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 7px;
  height: 36px; padding: 0 var(--sp-4);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
  font-size: var(--fs-md); font-weight: 550; font-family: inherit;
  cursor: pointer; white-space: nowrap;
  transition: background .16s var(--ease), border-color .16s var(--ease), transform .08s var(--ease), box-shadow .16s var(--ease);
}
.btn:hover { background: var(--surface-2); border-color: var(--border-hi); }
.btn:active { transform: translateY(1px); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); box-shadow: var(--shadow); }
.btn-primary:hover { background: var(--accent-hi); border-color: var(--accent-hi); }
.btn-danger { background: transparent; border-color: var(--danger); color: var(--danger); }
.btn-danger:hover { background: var(--danger-soft); border-color: var(--danger); }
.btn-ghost { background: transparent; border-color: transparent; color: var(--text-dim); }
.btn-ghost:hover { background: var(--surface-2); color: var(--text); }
.btn-sm { height: 30px; padding: 0 var(--sp-3); font-size: var(--fs-sm); }
.btn-block { width: 100%; }
.btn[disabled] { opacity: .5; cursor: not-allowed; }

.icon-btn {
  display: inline-grid; place-items: center;
  width: 30px; height: 30px; flex: none;
  border-radius: var(--r-sm); border: 1px solid transparent;
  background: transparent; color: var(--text-dim);
  cursor: pointer; font-size: 14px; line-height: 1;
  transition: background .14s var(--ease), color .14s var(--ease), border-color .14s var(--ease);
}
.icon-btn:hover { background: var(--surface-3); color: var(--text); border-color: var(--border); }
.icon-btn.danger:hover { background: var(--danger-soft); color: var(--danger); border-color: transparent; }
.icon-row { display: flex; gap: 2px; justify-content: flex-end; align-items: center; }
form.inline { display: inline; margin: 0; }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.card-head {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-4) var(--sp-5);
  border-bottom: 1px solid var(--border);
}
.card-head h2, .card-head h3 { font-size: var(--fs-lg); }
.card-head .spacer { margin-left: auto; }
.card-body { padding: var(--sp-5); }
.card-foot {
  padding: var(--sp-3) var(--sp-5);
  border-top: 1px solid var(--border);
  background: var(--surface-2);
  font-size: var(--fs-xs); color: var(--text-faint);
}

/* Stat tiles */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: var(--sp-4); margin-bottom: var(--sp-5); }
.stat {
  display: flex; align-items: center; gap: var(--sp-4);
  padding: var(--sp-4) var(--sp-5);
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r-lg); box-shadow: var(--shadow);
  transition: border-color .16s var(--ease), transform .16s var(--ease);
}
.stat:hover { border-color: var(--border-hi); transform: translateY(-2px); }
.stat-ico {
  width: 42px; height: 42px; flex: none; border-radius: var(--r-md);
  display: grid; place-items: center; font-size: 19px;
  background: var(--accent-soft); color: var(--accent-hi);
}
.stat-n { font-size: var(--fs-2xl); font-weight: 680; line-height: 1.1; font-variant-numeric: tabular-nums; }
.stat-l { font-size: var(--fs-sm); color: var(--text-dim); }

/* Tables */
.table-wrap { overflow-x: auto; }
table.t { width: 100%; border-collapse: collapse; font-size: var(--fs-md); }
table.t th {
  text-align: left; font-weight: 600; font-size: var(--fs-xs);
  text-transform: uppercase; letter-spacing: .05em; color: var(--text-faint);
  padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border);
  white-space: nowrap; background: var(--surface-2);
  position: sticky; top: 0; z-index: 1;
}
table.t td { padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border); vertical-align: middle; }
table.t tbody tr { transition: background .13s var(--ease); }
table.t tbody tr:hover { background: var(--surface-2); }
table.t tbody tr:last-child td { border-bottom: none; }
table.t td.num { font-variant-numeric: tabular-nums; color: var(--text-faint); width: 56px; }
table.t td.actions { text-align: right; width: 1%; white-space: nowrap; }
table.t td.strong { font-weight: 550; }
.mono { font-family: var(--mono); font-size: var(--fs-sm); }

.empty { padding: var(--sp-7) var(--sp-5); text-align: center; color: var(--text-dim); }
.empty-ico { font-size: 34px; opacity: .5; margin-bottom: var(--sp-3); }
.empty-t { font-weight: 600; color: var(--text); margin-bottom: var(--sp-1); }
.empty-d { font-size: var(--fs-md); margin-bottom: var(--sp-4); }

/* Forms */
.field { margin-bottom: var(--sp-4); }
.field > label { display: block; font-size: var(--fs-sm); font-weight: 550; color: var(--text-dim); margin-bottom: 6px; }
.input, textarea.input, select.input {
  width: 100%; min-height: 38px; padding: 8px var(--sp-3);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text);
  font-size: var(--fs-base); font-family: inherit; line-height: 1.5;
  transition: border-color .16s var(--ease), box-shadow .16s var(--ease), background .16s var(--ease);
}
.input::placeholder { color: var(--text-faint); }
.input:focus { outline: none; border-color: var(--accent); background: var(--surface); box-shadow: 0 0 0 3px var(--accent-soft); }
textarea.input { min-height: 120px; resize: vertical; font-family: var(--mono); font-size: var(--fs-md); }
.hint { font-size: var(--fs-xs); color: var(--text-faint); margin-top: 5px; }
.form-actions { display: flex; gap: var(--sp-2); margin-top: var(--sp-5); flex-wrap: wrap; }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); }

/* Chips / badges */
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: var(--r-full);
  font-size: var(--fs-xs); font-weight: 600;
  background: var(--surface-3); color: var(--text-dim); border: 1px solid var(--border);
}
.chip.ok { background: var(--ok-soft); color: var(--ok); border-color: transparent; }
.chip.warn { background: var(--warn-soft); color: var(--warn); border-color: transparent; }
.chip-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

/* Flash / alerts */
.flash {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4); margin-bottom: var(--sp-4);
  border-radius: var(--r-md); font-size: var(--fs-md);
  background: var(--ok-soft); color: var(--ok);
  border: 1px solid transparent;
}
.flash.error { background: var(--danger-soft); color: var(--danger); }
.msg {
  padding: var(--sp-3) var(--sp-4); margin-bottom: var(--sp-4);
  border-radius: var(--r-md); font-size: var(--fs-md);
  background: var(--danger-soft); color: var(--danger);
}

/* Secret reveal field */
.secret {
  display: flex; align-items: center; gap: var(--sp-2);
  padding: var(--sp-3) var(--sp-4);
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: var(--r-md);
}
.secret-val { font-family: var(--mono); font-size: var(--fs-base); word-break: break-all; flex: 1; min-width: 0; }
.secret-val.masked { letter-spacing: .18em; color: var(--text-faint); }

/* Definition list for view pages */
.dl { display: grid; grid-template-columns: 150px 1fr; gap: var(--sp-3) var(--sp-4); align-items: start; }
.dl dt { font-size: var(--fs-sm); color: var(--text-dim); font-weight: 550; }
.dl dd { margin: 0; font-size: var(--fs-base); word-break: break-word; }

/* Toast */
#toast {
  position: fixed; left: 50%; bottom: 26px; transform: translate(-50%, 14px);
  background: var(--surface-3); color: var(--text);
  border: 1px solid var(--border-hi); border-radius: var(--r-md);
  padding: 10px var(--sp-4); font-size: var(--fs-md); font-weight: 550;
  box-shadow: var(--shadow-lg); z-index: 200;
  opacity: 0; pointer-events: none;
  transition: opacity .2s var(--ease), transform .2s var(--ease);
}
#toast.show { opacity: 1; transform: translate(-50%, 0); }
#toast.error { border-color: var(--danger); color: var(--danger); }

/* Auto-lock countdown */
.lockbar { display: flex; align-items: center; gap: 7px; font-size: var(--fs-xs); color: var(--text-faint); }
.lockbar.warn { color: var(--warn); font-weight: 600; }
.lockbar .track { width: 44px; height: 4px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; }
/* scaleX, not width: width relayouts the track on every one of these frames,
   and this one repaints once a second for the life of the session (A07 4.6). */
.lockbar .fill { height: 100%; width: 100%; transform-origin: left center; background: var(--ok); transition: transform var(--motion-tick) linear, background var(--motion-base) var(--ease); }
.lockbar.warn .fill { background: var(--warn); }

/* TOTP */
.totp {
  display: flex; flex-direction: column; align-items: center; gap: var(--sp-3);
  padding: var(--sp-6) var(--sp-5);
}
.totp-code {
  font-family: var(--mono); font-size: 44px; font-weight: 600;
  letter-spacing: .14em; color: var(--accent-hi);
  font-variant-numeric: tabular-nums; line-height: 1;
}
.totp-ring { --pct: 100; width: 100%; max-width: 240px; height: 5px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; }
.totp-ring i { display: block; height: 100%; width: 100%; transform-origin: left center; transform: scaleX(calc(var(--pct) / 100)); background: var(--accent); transition: transform var(--motion-tick) linear; }

/* Login */
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: var(--sp-5); }
.login-card { width: 100%; max-width: 400px; }
.login-brand { text-align: center; margin-bottom: var(--sp-5); }
.login-brand .brand-mark { margin: 0 auto var(--sp-3); width: 52px; height: 52px; font-size: 24px; border-radius: 14px; }
.login-brand h1 { font-size: var(--fs-xl); }
.login-brand p { color: var(--text-dim); font-size: var(--fs-md); margin-top: 4px; }

/* Generator */
.gen-out {
  font-family: var(--mono); font-size: var(--fs-xl); font-weight: 600;
  padding: var(--sp-4); border-radius: var(--r-md);
  background: var(--surface-2); border: 1px dashed var(--border-hi);
  word-break: break-all; text-align: center; min-height: 62px;
  display: grid; place-items: center;
}
.meter { height: 6px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; margin-top: var(--sp-3); }
.meter i { display: block; height: 100%; width: 100%; transform-origin: left center; transform: scaleX(0); transition: transform var(--motion-base) var(--ease), background var(--motion-base) var(--ease); }
.switch-row { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--border); }
.switch-row:last-child { border-bottom: none; }
.switch-row span { font-size: var(--fs-md); }
input[type="range"] { width: 100%; accent-color: var(--accent); }
input[type="checkbox"] { accent-color: var(--accent); width: 16px; height: 16px; cursor: pointer; }

/* Overlay (import progress) */
.overlay {
  position: absolute; inset: 0; z-index: 5;
  display: none; place-items: center;
  background: var(--surface);
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
  border-radius: var(--r-lg);
}
.overlay.on { display: grid; }
.spinner {
  width: 30px; height: 30px; border-radius: 50%;
  border: 3px solid var(--border-hi); border-top-color: var(--accent);
  animation: spin .8s linear infinite; margin: 0 auto var(--sp-3);
}
@keyframes spin { to { transform: rotate(360deg); } }
.overlay-in { text-align: center; font-size: var(--fs-md); color: var(--text-dim); }

/* Utilities */
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: var(--sp-4); }
.stack { display: flex; flex-direction: column; gap: var(--sp-4); }
.muted { color: var(--text-dim); }
.faint { color: var(--text-faint); font-size: var(--fs-sm); }
.hidden { display: none !important; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.icon { inline-size:20px; block-size:20px; flex:none; fill:none; stroke:currentColor;
  stroke-width:1.5; stroke-linecap:butt; stroke-linejoin:miter; }
.icon-sm { inline-size:16px; block-size:16px; }
.icon-lg { inline-size:32px; block-size:32px; stroke-width:2; }
.brand-mark .icon { inline-size:24px; block-size:24px; stroke-width:1.75; }
.nav-ico .icon, .icon-btn .icon { inline-size:16px; block-size:16px; }
.stat-ico .icon { inline-size:20px; block-size:20px; }
.empty-ico .icon { inline-size:32px; block-size:32px; stroke-width:2; }

/* ============================ Responsive ============================ */
.scrim { display: none; }

@media (max-width: 900px) {
  .app { grid-template-columns: 1fr; }
  .sidebar {
    position: fixed; inset: 0 auto 0 0; width: 272px;
    transform: translateX(-100%);
    transition: transform .24s var(--ease);
    box-shadow: var(--shadow-lg);
  }
  body.nav-open .sidebar { transform: translateX(0); }
  .scrim {
    display: block; position: fixed; inset: 0; z-index: 35;
    background: rgba(0,0,0,.5); opacity: 0; pointer-events: none;
    transition: opacity var(--motion-base) var(--ease);
  }
  body.nav-open .scrim { opacity: 1; pointer-events: auto; }
  .menu-btn { display: inline-grid; }
  .content { padding: var(--sp-4); }
  .search kbd { display: none; }
  .dl { grid-template-columns: 1fr; gap: var(--sp-1); }
  .dl dt { margin-top: var(--sp-3); }
  .row2 { grid-template-columns: 1fr; }
  .page-actions { width: 100%; }
}
@media (max-width: 620px) {
  .topbar { padding: 0 var(--sp-3); gap: var(--sp-2); }
  /* Only the lockbar track is in the narrow main column. The vault chip
     sits in the sidebar drawer, which is a fixed 272px panel, so hiding
     its path here left an empty box holding a lone status dot. The path
     already ellipsises, which is the right degradation. */
  .lockbar .track { display: none; }
  .totp-code { font-size: 34px; }
  .stats { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: var(--sp-3); }
  .stat { padding: var(--sp-3) var(--sp-4); gap: var(--sp-3); }
  .stat-ico { width: 36px; height: 36px; font-size: 16px; }
  .stat-n { font-size: var(--fs-xl); }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
}

/* Console / CNS-18: the interface is a transcript. */
:root {
  --bg:#0a0e0c; --surface:#121815; --surface-2:#0f1412; --surface-3:#18201c;
  --border:#232e28; --border-hi:#3b4a42; --text:#d8e8dc; --text-dim:#9aada1; --text-faint:#84968b;
  --accent:#5fd095; --accent-hi:#7be0aa; --accent-fg:#05120b; --accent-soft:#10251a;
  --ok:#5fd095; --ok-soft:#10251a; --warn:#dda95e; --warn-soft:#1c1610;
  --danger:#ff8b84; --danger-soft:#291311; --shadow:none; --shadow-lg:none;
  --r-sm:0; --r-md:0; --r-lg:0; --r-full:0;
  --font:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;
  --mono:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;
  --ease:cubic-bezier(.2,.7,.3,1); --sidebar-w:248px; color-scheme:dark;
}
body, body.theme-dark, body.theme-amoled, body.theme-cyberpunk, body.theme-light {
  --bg:#0a0e0c; --surface:#121815; --surface-2:#0f1412; --surface-3:#18201c;
  --border:#232e28; --border-hi:#3b4a42; --text:#d8e8dc; --text-dim:#9aada1; --text-faint:#84968b;
  --accent:#5fd095; --accent-hi:#7be0aa; --accent-fg:#05120b; --accent-soft:#10251a;
  --ok:#5fd095; --ok-soft:#10251a; --warn:#dda95e; --warn-soft:#1c1610;
  --danger:#ff8b84; --danger-soft:#291311; --shadow:none; --shadow-lg:none;
  background:var(--bg); color:var(--text);
}
body { font-variant-numeric:tabular-nums; transition:none; }
body::before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.16;
  background-image:repeating-linear-gradient(to bottom,var(--border) 0 1px,transparent 1px 4px); }
.skip-link { position:fixed; top:var(--sp-2); left:var(--sp-2); z-index:300; padding:var(--sp-2) var(--sp-3);
  background:var(--accent); color:var(--accent-fg); transform:translateY(-160%); }
.skip-link:focus { transform:translateY(0); }
.sidebar { background:var(--bg); padding:var(--sp-4); }
.brand { border-bottom:1px solid var(--border); padding:var(--sp-2) 0 var(--sp-4); }
.brand-mark { width:36px; height:36px; border:1px solid var(--accent); background:transparent; color:var(--accent); box-shadow:none; }
.brand-name::before { content:"$ "; color:var(--accent); }
.brand-meta { color:var(--warn); }
.nav { gap:0; }
.nav-label { padding:var(--sp-4) 0 var(--sp-2); color:var(--text-faint); }
.nav-label::before { content:"# "; color:var(--warn); }
.nav-item { border-left:2px solid transparent; padding:var(--sp-2) var(--sp-3); }
.nav-item:hover { background:var(--surface-2); color:var(--accent); }
.nav-item.active { border-left-color:var(--accent); background:var(--accent-soft); color:var(--accent); }
.nav-item.active::before { display:none; }
.nav-count, .nav-item.active .nav-count { background:var(--warn-soft); color:var(--warn); border:1px solid var(--border); }
.vault-chip { border-left:2px solid var(--warn); background:var(--surface-2); }
.vault-chip .dot { background:var(--ok); box-shadow:none; }
.topbar { background:var(--bg); backdrop-filter:none; -webkit-backdrop-filter:none; }
.content { max-width:1180px; padding:var(--sp-6); position:relative; }
.page-head { border-bottom:1px solid var(--border); padding-bottom:var(--sp-4); }
.page-title { font-weight:500; letter-spacing:-.01em; }
.page-title::before { content:"$ "; color:var(--accent); }
.page-sub { color:var(--text-dim); margin-top:var(--sp-2); }
.page-sub::before { content:"> "; color:var(--warn); }
.console-hero { border-left:2px solid var(--accent); padding:var(--sp-5); margin-bottom:var(--sp-5); background:var(--surface-2); }
.console-hero .eyebrow { color:var(--text-dim); font-size:var(--fs-sm); margin-bottom:var(--sp-3); }
.console-hero .eyebrow::before { content:"> "; color:var(--accent); }
.console-hero h1 { font-size:clamp(24px,4vw,42px); font-weight:500; margin-bottom:var(--sp-3); }
.console-hero h1::before { content:"$ "; color:var(--accent); }
.console-output { display:grid; gap:var(--sp-1); color:var(--warn); margin-bottom:var(--sp-3); }
.console-output span::before { content:"[emit] "; color:var(--text-faint); }
.console-output i { font-style:normal; }
.console-hero .lede { max-width:66ch; color:var(--text-dim); }
.console-hero .lede::after { content:""; display:inline-block; width:.55em; height:1em; margin-left:.25em;
  vertical-align:-.14em; background:var(--accent); animation:cnsblink 1.1s steps(2,end) infinite; }
@keyframes cnsblink { 50% { opacity:0; } }
.card, .stat { border-left:2px solid var(--accent); box-shadow:none; background:var(--surface); }
.card-head h2::before, .card-head h3::before { content:"* "; color:var(--warn); }
.stat { display:block; }
.stat:hover { transform:none; border-color:var(--border); border-left-color:var(--accent); background:var(--surface-2); }
.stat-ico { width:auto; height:auto; display:inline; background:none; color:var(--text-faint); margin-right:var(--sp-2); }
.stat-n { display:block; color:var(--warn); margin-top:var(--sp-2); }
.stat-l { display:block; margin-top:var(--sp-1); }
.btn, .icon-btn, .select, .input, textarea.input, select.input, .search input { border-radius:0; }
.btn-primary { box-shadow:none; }
.chip { border-radius:0; background:var(--warn-soft); color:var(--warn); }
.flash, .msg { border-radius:0; border-left:2px solid currentColor; }
.secret-val, .totp-code, .gen-out, .stat-n, .num, .faint.mono { color:var(--warn); }
#toast { left:auto; right:var(--sp-4); bottom:var(--sp-4); transform:none; border-left:2px solid var(--accent); box-shadow:none; }
#toast { transform:translateY(var(--sp-2)); transition:opacity var(--motion-fast) var(--ease), transform var(--motion-base) var(--ease); }
#toast.show { transform:translateY(0); }
.overlay { border-radius:0; backdrop-filter:none; -webkit-backdrop-filter:none; background:var(--surface); border-left:2px solid var(--accent); }
.overlay { display:grid; visibility:hidden; opacity:0; pointer-events:none;
  transition:opacity var(--motion-base) var(--ease), visibility 0s linear var(--motion-base); }
.overlay.on { visibility:visible; opacity:1; pointer-events:auto; transition-delay:0s; }
.spinner { border-radius:0; }
.totp-code.code-updated { animation:code-updated var(--motion-live) var(--ease); }
@keyframes code-updated {
  0% { opacity:.45; transform:translateY(var(--sp-1)); }
  100% { opacity:1; transform:translateY(0); }
}

@media (max-width:620px) {
  .content, .console-hero { padding:var(--sp-4); }
  .stats { grid-template-columns:1fr; }
  table.t thead { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); }
  table.t, table.t tbody, table.t tr, table.t td { display:block; width:100%; }
  table.t tr { border-bottom:1px solid var(--border); padding:var(--sp-2) 0; }
  table.t td { border:0; padding:var(--sp-1) var(--sp-3); white-space:normal; }
  table.t td.actions { width:100%; text-align:left; }
  .icon-row { justify-content:flex-start; }
}
@media (prefers-reduced-motion:reduce) {
  .console-hero .lede::after, .totp-code.code-updated { animation:none; }
  .scrim, #toast, .overlay { transition:none; }
}

@media print { .sidebar, .topbar, .page-actions, #toast { display: none !important; } .app { grid-template-columns: 1fr; } }

/* viewport-fit=cover lets the page paint under the status bar, the notch and
   the home indicator, and a home screen launch has no browser chrome holding
   them off. env() resolves to 0 wherever the browser already reserves that
   space, so these are unconditional rather than scoped to standalone.

   The sidebar needs insets of its own: under 900px it is position:fixed, so
   padding on body does not reach it. It also cannot keep height:100vh, which
   on iOS measures the largest possible viewport rather than the visible one
   and pushed .sidebar-foot -- the vault chip and the logout button -- off the
   bottom of the screen. 100dvh tracks the viewport actually on display, and
   browsers without dvh keep the 100vh above. */
.sidebar {
  height: 100dvh;
  padding-top: calc(var(--sp-4) + env(safe-area-inset-top));
  padding-bottom: calc(var(--sp-4) + env(safe-area-inset-bottom));
  padding-left: calc(var(--sp-4) + env(safe-area-inset-left));
}
/* The topbar sets an explicit height and box-sizing is border-box, so the
   inset has to grow the box or it would eat into the row and squash it. */
.topbar {
  height: calc(var(--topbar-h) + env(safe-area-inset-top));
  padding-top: env(safe-area-inset-top);
}
body { padding-bottom: env(safe-area-inset-bottom); }

/* Tag chips, rotation badges and the security score.
   Declared last on purpose: the console block above restyles every .chip to
   the warn colour, so these variants have to come after it to win. */
.tagbar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: var(--sp-3); }
.chip-btn { cursor: pointer; font-family: inherit; }
.chip-btn:hover { border-color: var(--accent); }
.chip-on { background: var(--accent); color: var(--bg); border-color: transparent; }
.chip-warn { background: var(--warn-soft); color: var(--warn); border-color: transparent; }
tr[data-row] .chip { margin-left: 6px; vertical-align: middle; }
.score-ok { color: var(--ok); }
.score-warn { color: var(--warn); }
.score-bad { color: var(--danger); }

/* ============================================================
   Desktop rail, and the motion layer.
   Declared last for the same reason the chips above are: the console
   block restyles most of these selectors, so anything that has to win
   over it comes after it.
   ============================================================ */

/* ---- Sidebar rail (>= 901px) ----
   Under 900px the sidebar is an off-canvas drawer and the hamburger opens
   it. Above that there is nothing to open, so the same control collapses
   the sidebar to an icon rail instead.

   Labels are clipped, not display:none, so they stay in the accessibility
   tree -- a screen reader still reads "Passwords", and the tooltip is a
   convenience for pointer users rather than the only remaining name.

   The collapse is deliberately instant. The sidebar is a grid column, so
   animating it would animate grid-template-columns and relayout the whole
   page on every frame, which A07 4.6 forbids outright. */
@media (min-width: 901px) {
  body.rail { --sidebar-w: var(--rail-w); }
  body.rail .sidebar { padding-left: var(--sp-2); padding-right: var(--sp-2); }
  body.rail .brand { justify-content: center; }
  body.rail .nav-item { justify-content: center; padding-left: 0; padding-right: 0; }
  body.rail .vault-chip { justify-content: center; padding-left: 0; padding-right: 0; }
  body.rail .sidebar-foot .btn { padding-left: 0; padding-right: 0; }
  body.rail .brand-text,
  body.rail .nav-text,
  body.rail .nav-label,
  body.rail .nav-count,
  body.rail .vault-chip .path,
  body.rail .rail-label {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  /* With the label gone, the left rule and the tinted ground are the only
     things left saying which page you are on, so both have to stay. */
  body.rail .nav-item.active .nav-ico { color: var(--accent); }
}

/* ---- First-sight reveal: the transcript prints ----
   Blocks arrive in reading order, one stagger step apart, once per load.
   A07 4.2 forbids entrance animation that re-fires on scroll, so this is
   bound to load and never to an IntersectionObserver; 4.4 caps the stagger
   at eight items, past which the group arrives as one.

   The static state is the truth. These rules only ever *add* motion: they
   sit behind an explicit no-preference query and behind a class that only
   JS sets. With JS off, motion off, or the query unsupported, every block
   is already at its final position -- which is the failure A07 4.5 calls
   the single most common bug in this area. */
@media (prefers-reduced-motion: no-preference) {
  body.can-reveal .content > [data-reveal] {
    opacity: 0;
    transform: translateY(var(--sp-2));
    transition: opacity var(--motion-reveal) var(--ease-entrance),
                transform var(--motion-reveal) var(--ease-entrance);
    transition-delay: var(--reveal-delay, 0ms);
  }
  body.can-reveal .content > [data-reveal][data-seen] { opacity: 1; transform: none; }
}

/* ---- Live session indicator ----
   A07 4.2 permits a loop only on something genuinely live. This tracks the
   idle countdown and stops the moment it is paused, so it reports session
   state rather than decorating the sidebar. */
@keyframes sessionpulse {
  0%, 92%, 100% { opacity: 1; }
  96%           { opacity: .3; }
}
@media (prefers-reduced-motion: no-preference) {
  body:not(.lock-paused) .vault-chip .dot {
    animation: sessionpulse var(--motion-ambient) var(--ease) infinite;
  }
}

/* ---- Row hover ----
   The border is always present and always the same width, so hovering a row
   repaints a colour instead of reflowing the table. */
table.t tbody tr[data-row] td:first-child {
  border-left: 2px solid transparent;
  transition: border-color var(--motion-base) var(--ease);
}
table.t tbody tr[data-row]:hover td:first-child { border-left-color: var(--accent); }

/* ---- Entrances are slower than exits ----
   A07 4.3. A departing surface has already been decided about; matching the
   two durations is what makes dismissal feel sticky. */
@media (max-width: 900px) {
  .sidebar { transition: transform var(--motion-fast) var(--ease-exit); }
  .scrim { transition: opacity var(--motion-fast) var(--ease-exit); }
  body.nav-open .sidebar { transition: transform var(--motion-slow) var(--ease-entrance); }
  body.nav-open .scrim { transition: opacity var(--motion-slow) var(--ease-entrance); }
}

@media (prefers-reduced-motion: reduce) {
  .vault-chip .dot { animation: none; }
  /* Belt and braces: the reveal rules above cannot strand content because
     they only exist under no-preference, but stating the final state here
     means a future edit that moves them cannot either. */
  .content > [data-reveal] { opacity: 1; transform: none; }
}
</style>
"""


SHELL_SCRIPT = """
<script>
(function () {
  /* ---- toast ---------------------------------------------------------- */
  var toastTimer;
  function toast(msg, isErr) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.toggle("error", !!isErr);
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2000);
  }
  window.SPM_toast = toast;

  /* ---- clipboard ------------------------------------------------------ */
  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }
  window.SPM_copy = function (text, label) {
    function ok() { toast(label || t("toast.copy_success", "Copied to clipboard.")); }
    function bad() { toast(t("toast.copy_fail", "Copy failed."), true); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(ok).catch(fallback);
    } else { fallback(); }
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        var done = document.execCommand("copy");
        document.body.removeChild(ta);
        done ? ok() : bad();
      } catch (e) { bad(); }
    }
  };

  /* ---- sidebar: a drawer under 900px, an icon rail above ---------------
     One control, two jobs, because the sidebar has two shapes. Below 900px
     it is off-canvas and the button opens it; above, it is always on screen
     and there is nothing to open, so the button collapses it to icons
     instead. That upper half did not exist -- the button was rendered and
     then hidden by CSS, so on a desktop it was dead markup. */
  var DESKTOP = "(min-width: 901px)";
  function isDesktop() {
    return !!(window.matchMedia && window.matchMedia(DESKTOP).matches);
  }
  function syncTrigger() {
    var trigger = document.querySelector(".menu-btn");
    if (!trigger || !document.body) return;
    var desktop = isDesktop();
    var expanded = desktop
      ? !document.body.classList.contains("rail")
      : document.body.classList.contains("nav-open");
    /* aria-expanded describes the sidebar either way: on desktop "expanded"
       means showing labels, on mobile it means on screen. */
    trigger.setAttribute("aria-expanded", expanded ? "true" : "false");
    var key, fb;
    if (desktop) {
      key = expanded ? "nav.collapse" : "nav.expand";
      fb = expanded ? "Collapse sidebar" : "Expand sidebar";
    } else {
      key = expanded ? "nav.close" : "nav.open";
      fb = expanded ? "Close menu" : "Menu";
    }
    trigger.setAttribute("aria-label", t(key, fb));
    trigger.setAttribute("title", t(key, fb));
    trigger.setAttribute("data-i18n-title", key);
  }
  function setNav(open) {
    document.body.classList.toggle("nav-open", open);
    syncTrigger();
  }
  function setRail(on) {
    document.body.classList.toggle("rail", on);
    /* Storage can throw outright where site data is blocked, and a sidebar
       that refuses to collapse because a preference could not be saved is a
       worse failure than one that forgets. */
    try { localStorage.setItem("spm.rail", on ? "1" : "0"); } catch (e) {}
    syncTrigger();
  }
  window.SPM_toggleNav = function () {
    if (isDesktop()) setRail(!document.body.classList.contains("rail"));
    else setNav(!document.body.classList.contains("nav-open"));
  };
  function wireMobileNav() {
    // Navigation is deliberately wired directly. Delegating through an SVG
    // event target made the installed iOS web app's hamburger a no-op.
    var trigger = document.querySelector(".menu-btn");
    var scrim = document.querySelector(".scrim");
    if (trigger) trigger.addEventListener("click", function (e) {
      e.preventDefault();
      window.SPM_toggleNav();
    });
    if (scrim) scrim.addEventListener("click", function (e) {
      e.preventDefault();
      setNav(false);
    });
    /* Crossing the breakpoint with the drawer open would otherwise leave
       nav-open set on a layout that has no drawer, and the button's label
       would still describe the other mode. */
    if (window.matchMedia) {
      var mq = window.matchMedia(DESKTOP);
      var onChange = function () {
        if (mq.matches) document.body.classList.remove("nav-open");
        syncTrigger();
      };
      if (mq.addEventListener) mq.addEventListener("change", onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
    syncTrigger();
  }

  /* ---- first-sight reveal ---------------------------------------------
     The transcript prints: the page's top-level blocks arrive in reading
     order, once per load. Bound to load and never to scroll position --
     A07 4.2 prohibits entrance animation that re-fires as content scrolls
     into view.

     Everything here only ever adds motion on top of a finished page. The
     hiding rules live behind a no-preference query *and* behind the
     can-reveal class set below, so with JS off, motion off, or the query
     unsupported, the content was never hidden in the first place. */
  function wireReveal() {
    var main = document.querySelector(".content");
    if (!main || !window.matchMedia) return;
    if (!window.matchMedia("(prefers-reduced-motion: no-preference)").matches) return;
    var kids = [];
    for (var i = 0; i < main.children.length; i++) {
      var el = main.children[i];
      /* The import overlay is positioned over the card it belongs to and is
         shown by its own class; giving it an entrance would fight that. */
      if (el.classList && el.classList.contains("overlay")) continue;
      kids.push(el);
    }
    if (!kids.length) return;
    /* A07 4.4 caps the stagger at about eight items. Past that the delay on
       the last item reads as the page being slow rather than as sequence,
       so the group arrives together instead. */
    var stagger = kids.length <= 8;
    kids.forEach(function (el, i) {
      el.setAttribute("data-reveal", "");
      if (stagger) el.style.setProperty("--reveal-delay", "calc(var(--stagger) * " + i + ")");
    });
    document.body.classList.add("can-reveal");
    var shown = false;
    function show() {
      if (shown) return;
      shown = true;
      kids.forEach(function (el) { el.setAttribute("data-seen", ""); });
    }
    /* requestAnimationFrame does not fire in a background tab, so a page
       opened in one would sit at opacity 0 until it was focused. The timer
       is the guarantee; the frames are just the fast path. */
    setTimeout(show, 1000);
    requestAnimationFrame(function () { requestAnimationFrame(show); });
  }

  /* ---- instant table filter ------------------------------------------- */
  function wireSearch() {
    var box = document.getElementById("q");
    if (!box) return;
    function run() {
      var term = box.value.trim().toLowerCase();
      var any = false;
      document.querySelectorAll("[data-searchable] tbody tr[data-row]").forEach(function (tr) {
        var hit = !term || (tr.getAttribute("data-row") || "").indexOf(term) >= 0;
        tr.classList.toggle("hidden", !hit);
        if (hit) any = true;
      });
      document.querySelectorAll("[data-empty-search]").forEach(function (n) {
        n.classList.toggle("hidden", any || !term);
      });
    }
    box.addEventListener("input", run);
    box.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { box.value = ""; run(); box.blur(); }
    });
    run();
  }

  /* ---- keyboard shortcuts --------------------------------------------- */
  document.addEventListener("keydown", function (e) {
    var tag = (e.target && e.target.tagName || "").toLowerCase();
    var typing = tag === "input" || tag === "textarea" || tag === "select";
    if (e.key === "/" && !typing) {
      var box = document.getElementById("q");
      if (box) { e.preventDefault(); box.focus(); box.select(); }
    }
    if (e.key === "Escape" && document.body.classList.contains("nav-open")) {
      setNav(false);
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    wireMobileNav();
    wireSearch();
    try { wireReveal(); } catch (e) { document.body.classList.remove("can-reveal"); }
  });
})();
</script>
"""

# Auto-lock with a visible countdown. Same 30s idle policy as before, but the
# user can now see it coming instead of being logged out with no warning.
LOCKBAR_SCRIPT = """
<script>
(function () {
  var IDLE_MS = 30000, WARN_AT = 10;
  var deadline = Date.now() + IDLE_MS, paused = false, locking = false, ticker;
  /* The session dot is allowed to pulse only while the session is actually
     counting down (A07 4.2 permits a loop on live state and nothing else),
     so the countdown owns the class and the stylesheet reads it. */
  function syncLive() {
    if (document.body) document.body.classList.toggle("lock-paused", paused || locking);
  }
  function reset() { if (!paused && !locking) deadline = Date.now() + IDLE_MS; }
  function render() {
    var left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    var bar = document.getElementById("lockbar");
    if (bar) {
      var fill = bar.querySelector(".fill");
      if (fill) fill.style.transform = "scaleX(" + (left / (IDLE_MS / 1000)) + ")";
      bar.classList.toggle("warn", left <= WARN_AT);
      var lbl = bar.querySelector(".lbl");
      if (lbl) {
        var t = (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.in", "Locks in") : "Locks in";
        lbl.textContent = paused ? ((window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.paused", "Lock paused") : "Lock paused") : (t + " " + left + "s");
      }
    }
    if (!paused && !locking && left <= 0) {
      locking = true;
      syncLive();
      clearInterval(ticker);
      lock();
    }
  }
  /* Suspending is a server-side state change, not a redirect. The 2.10.14 bug
     is the reason: a CDN rewrote these scripts out of existence and the lock
     silently stopped existing. If suspension lived in this file, anyone
     holding the phone could disable JavaScript and walk straight past it.
     This function only asks; the server is what enforces. Any failure falls
     through to a full logout, which is the safe direction. */
  function lock() {
    var cfg = window.SPM_UNLOCK;
    if (!cfg || !cfg.available || !window.PublicKeyCredential) {
      window.location.replace("/logout");
      return;
    }
    fetch("/unlock/suspend", {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({csrf: cfg.csrf})
    }).then(function (r) {
      window.location.replace(r.ok ? "/unlock" : "/logout");
    }).catch(function () {
      window.location.replace("/logout");
    });
  }
  window.SPM_AutoLock = {
    pause: function () { paused = true; syncLive(); render(); },
    resume: function () { paused = false; syncLive(); reset(); render(); },
    restart: reset
  };
  ["click", "keydown", "mousemove", "touchstart", "scroll"].forEach(function (ev) {
    window.addEventListener(ev, reset, { passive: true });
  });
  ticker = setInterval(render, 1000);
  document.addEventListener("DOMContentLoaded", render);
  window.addEventListener("pagehide", function () { clearInterval(ticker); });
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted || locking) return;
    /* Timers are frozen in the back/forward cache, so the interval never
       observed the idle time that elapsed while the page was away. The
       deadline is the only surviving evidence: honour it instead of
       resetting, or returning via Back would hand back an unlocked vault. */
    clearInterval(ticker);
    if (Date.now() >= deadline) {
      locking = true;
      lock();
      return;
    }
    ticker = setInterval(render, 1000);
    render();
  });
})();
</script>
"""

ICON_SPRITE = """
<svg class="icon-sprite" aria-hidden="true" width="0" height="0" style="position:absolute;overflow:hidden">
  <symbol id="i-brand" viewBox="0 0 24 24"><path d="M4 6l5 6-5 6M12 18h8M12 6h8"/></symbol>
  <symbol id="i-overview" viewBox="0 0 24 24"><path d="M3.5 3.5h7v7h-7zM13.5 3.5h7v7h-7zM3.5 13.5h7v7h-7zM13.5 13.5h7v7h-7z"/></symbol>
  <symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="12" r="4.5"/><path d="M12.5 12H21M17 12v3M20 12v2"/></symbol>
  <symbol id="i-note" viewBox="0 0 24 24"><path d="M4 3.5h16v17H4zM7 8h10M7 12h10M7 16h6"/></symbol>
  <symbol id="i-phrase" viewBox="0 0 24 24"><path d="M5 5H2.5v14H5M19 5h2.5v14H19M8 9h8M8 15h8"/></symbol>
  <symbol id="i-authenticator" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 6.5V12l4 2M8 3l-2-2M16 3l2-2"/></symbol>
  <symbol id="i-backup" viewBox="0 0 24 24"><path d="M3.5 5.5h17v13h-17zM3.5 12h17M9 5.5v13M15 5.5v13"/></symbol>
  <symbol id="i-generator" viewBox="0 0 24 24"><path d="M12 2.5V8M12 16v5.5M2.5 12H8M16 12h5.5M5.5 5.5l4 4M14.5 14.5l4 4M18.5 5.5l-4 4M9.5 14.5l-4 4"/></symbol>
  <symbol id="i-transfer" viewBox="0 0 24 24"><path d="M7 3v17M3 7l4-4 4 4M17 21V4M13 17l4 4 4-4"/></symbol>
  <symbol id="i-menu" viewBox="0 0 24 24"><path d="M3.5 7h17M3.5 12h17M3.5 17h17"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.1 15.1l5.4 5.4"/></symbol>
  <symbol id="i-view" viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z"/><circle cx="12" cy="12" r="2.5"/></symbol>
  <symbol id="i-hide" viewBox="0 0 24 24"><path d="M3 3l18 18M5.5 7.5C3.5 9 2.5 12 2.5 12s3.5 6 9.5 6c1.5 0 2.8-.4 4-1M9 6.5c.9-.3 1.9-.5 3-.5 6 0 9.5 6 9.5 6s-.8 1.4-2.3 2.9"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L20 8l-4-4L4 16zM15 5l4 4"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M3.5 6h17M6 6v14a1 1 0 001 1h10a1 1 0 001-1V6M9.5 6V4a1 1 0 011-1h3a1 1 0 011 1v2M10 10v7M14 10v7"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><path d="M8 3h13v13H8zM16 19v1a1 1 0 01-1 1H4a1 1 0 01-1-1V9a1 1 0 011-1h1"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><path d="M4.5 11h15v9.5h-15zM8 11V7.5a4 4 0 018 0V11"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M10 4H4v16h6M14 7l5 5-5 5M8 12h11"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 2.5l8 3v6.5c0 5-3.5 8-8 9.5C7.5 20 4 17 4 12V5.5zM8.5 12l2.5 2.5 4.5-5"/></symbol>
  <symbol id="i-history" viewBox="0 0 24 24"><path d="M12 7v5l3.5 2M3.5 12a8.5 8.5 0 1 0 2.6-6.1M3.5 4.5V10h5.5"/></symbol>
  <symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.25"/><path d="M19.9 15a1.7 1.7 0 00.34 1.87l.06.07a2.05 2.05 0 11-2.9 2.9l-.06-.07a1.7 1.7 0 00-1.88-.34 1.7 1.7 0 00-1.03 1.56v.18a2.05 2.05 0 11-4.1 0v-.1a1.7 1.7 0 00-1.11-1.55 1.7 1.7 0 00-1.88.34l-.06.07a2.05 2.05 0 11-2.9-2.9l.06-.07a1.7 1.7 0 00.34-1.88 1.7 1.7 0 00-1.55-1.03H3a2.05 2.05 0 110-4.1h.1A1.7 1.7 0 004.65 8.7a1.7 1.7 0 00-.34-1.88l-.06-.06a2.05 2.05 0 112.9-2.9l.06.06a1.7 1.7 0 001.88.34h.08A1.7 1.7 0 0010.2 2.7v-.18a2.05 2.05 0 114.1 0v.1a1.7 1.7 0 001.03 1.56 1.7 1.7 0 001.88-.34l.06-.06a2.05 2.05 0 112.9 2.9l-.06.06a1.7 1.7 0 00-.34 1.88v.08a1.7 1.7 0 001.56 1.03h.17a2.05 2.05 0 110 4.1h-.1A1.7 1.7 0 0019.9 15z"/></symbol>
  <symbol id="i-empty" viewBox="0 0 24 24"><path d="M3.5 5.5h17v13h-17zM3.5 12h17M12 5.5v13"/></symbol>
</svg>
"""

# The home screen / tab icon is the login page brand mark, reproduced from the
# CSS above rather than redrawn: a 52x52 box with a 14px radius and a 1px
# #5fd095 border over --bg, holding the 24x24 #i-brand glyph at stroke-width
# 1.75. Regenerate the PNG with tools/make-app-icon.sh.
#
# The sprite symbols cannot be reused here. They carry geometry only and
# inherit stroke:currentColor from DESIGN_CSS, which does not exist once the
# icon is fetched as a standalone file.
FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52" width="52" height="52">
  <rect width="52" height="52" fill="#0a0e0c"/>
  <rect x="0.5" y="0.5" width="51" height="51" rx="14" fill="none" stroke="#5fd095" stroke-width="1"/>
  <g transform="translate(14 14)" fill="none" stroke="#5fd095" stroke-width="1.75"
     stroke-linecap="butt" stroke-linejoin="miter">
    <path d="M4 6l5 6-5 6M12 18h8M12 6h8"/>
  </g>
</svg>
"""

# Same mark at 512x512, drawn at 70% of the canvas on the page background.
# The padding is required, not decoration: iOS masks home screen icons with a
# superellipse, so a mark drawn edge to edge loses its border at the corners.
# The same padding satisfies the Android maskable safe zone, so one asset
# serves both "any" and "maskable".
APP_ICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIABAMAAAAGVsnJAAAAJFBMVEUKDgwTJBsaMyYfQC4kSzc0b1E9hV9ElGpUuYRez5QqWUFNqXlY7PjJAAANFUlEQVR42u2dz28bxxXHuRT1+7JGUMRMLozbg4lehCI9KCc2/QEQvQhBVYnOxZe0IHJxkLoOfWLSJhbdi9o0Nre+KEANlzcWqFGwf101M7vkihYpUpz3Y7TfDyLJjsWZeW9n3q/ZnS2VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJhNdMXfbyRR7nt5SvDpn45bU5+b/gqF9w8/+eLkJPFM/+TJ7+59GEsLdxXll498Sz7WgP32zW9q0jLOYe2ISvo8r7Wq4K1jDvENXzekZb2Mf3GJb3gaS4s7zTsdTvmT5Pn30hJf5BWv+IbH0jLnKLfyIzt5eO/nP4lLeY8ep78YlS7GB/k/vvHbF4OF6Ifvvzy64Fy/i0tKKOem/5N771F29dbLL3LLoCYtuWNtNB7S6wZ9d5WJr+3vSctu2Ollw3lc4+mxfDTu8kxa+vMLkg3m65iv0/KxGg2UU/n7n/P2+8us31hW/qid2qMGd8+V1PI+k9XAIB1Fjb/rzPf8Q1L+H0t65CiNPv4sJ//bqfmT6j81hQ+k+k8NoOAcdAlYvybUvZuC38nJf26De4JDeFdW/U4DbhIOJfqu2K5f7EnKn40iaQh07SKAA1n5zyNx54f5O75tO/5MWv5sJf6bu9tI0vpcpCUSEt+VN4AZ7lr8lbfTsp1396Vld2zawdRY+2yaLv8uLfmF0fyNs0frfF7E0oJnlG1N6oyxx5ZoCP4mm8wWeUONB8ho85qklooQKM866yWpqLKAjianFWhKRd9zWGO8KGvsTmcR6nyxgA0CY2mBp4nMqL5i60ndBCiVqlzXxaaBe9LivoldmV8ydDTS5wIcxja/oO9mnTvqXG5kB+Td1LUFgRPaHMYpUpYF5NnkKIxs8iy069FjuDgD/uLL4lTpt2nKCqPgCRX6UGBbpgS9KCZN7ZL20JbahlmMLerrE6lMA6bGVyPsYFdrFJgxIJ6hTT218MvZIL5CZoZJyzgXswb6dM2va18Bbg0ckLVe1e0DDMZKnZK1PmLfgVoaE6k9p2q8ojsKcrQJyzW7mvOAjCphMNjUWgrJYwz1t0Rtj7Q7QUuPzAiU9TtBQ5PMUm/od4KGLbJotaptR/Ry1slMdTsIE2CjYZKqLVnDvmkRpex0U8szVEt1W3sqnLFBFAo1dReDJlC56zZhluGXDk3KQhhieqZJ4q7WSBNtr2yT7F1shGID3VAfeG91W+dtEZdBM1kHYcSBFpItQiLTSgKJwwrHCbibOHy3GZATcPaq5rnN9XCcgHMDB57b3NR8X8A0FQI/uB1KJmCICNYrhV2ho+f/drFWMKmQoeO/dtMJoiKcQXC5QikHOfwv2HJIYQBFILATUhjgAoEz5S2Ssu49EgoqDnKR0H2vLe6GFAc5kzX02uJ2UHGQdVqnXhusBqaAnm+vXVd8k/xljHzHws2A6kGGtu+iWCuQjVGy8baDSgVsCdevAjoBVQQN+76XbEflw6KzqftOB71b1QAVEFA2TOC2Q1NA1bcCekGVA2zo7vexgbDqIVCA/+QtNAVsESigKy3UMlDMAChAWqhloFgCp9JCSSugKy3UMhR+CcANFn0GFF4BhbcBvmcAxT0npBR+Bni/pSk0BRTeCBY+FC58IFR4BewW3QYU3g1SzIBTaaGWgWIGDKWFklbAqbRQy4AlgCXgPxc4lRZqGbzf1xiaAgofBxTeC8AIYgaEOgOi1ZswBBQIvTw8PPzkcIz549H512/Pvz66fqtb4bjBZDYr3O2rbgmUmRWgbV8gGsW8CtAWCNVn32VIowBlRrAy57bFcGbACgpoJbOfYgtHAcNrf3hznjThKKB73c9GIyvOHrcCYi0KqDtxZpjBMNzgSgroOHFmvP8lnCVwet3PVlN5HjAqQNXmaDmV5/KHeLI84OE4HRj/aYVcQJURdC9oTOY8fR3lvkql2MN4dQVC66kCGJ86UrY5Oko1ELMpQJURdNdjjickQJUbTN9+k3A+f63LCI5jIb5jSJTNAPcSsNU8+3JomwHuXdUJ3xtKlBnBNCFk9ITK3GBp7Am5zKC2muAkIRjyKEDdErgiIQhCAd3VWhhclRDcdAXwJgT6jOC4LsLjCRXOAGuYEw/tLITGW2SyhIDlZE59XqA0qYscMCiAIg7ortrITqoAjgOJVM6AcUKwR68AbdmgI0sIGOoiOmeAfTl6wvCGeG1F0THzdwh8ojEOKE0SAvqD6ZTOgKt3CHzhewb4enR2gyshoFDA0EdDWUIQEytApxs8512mhECpG+TbIaCYAUMvDe3zJASqtscvsMPjCZXGAYY2S11EsQKyjdIvSRWgdwmUoiwhIFWA4hnAkxBQKGDoqal6qAo49dMSzxLQmgyVJlURWiOoNRkqcW2U610CWSBEfKuEXiOYmcADWgWojQMyE0i9O0JhBIc+2tliMYGKbQBXXVirDWDbI9dqAwapAs4KqgC+srhSBdxl3RiJPSug66UVC7n8SmuCmQ8s7Obocdjb4ysrgCkNsKiMA5jSAIvGGcBTCSFUQNfDmDh2xSwajWC6L9qvhaqA4Wot/IArDbAotAFZKazBogCKmmB3pRayNIDpDe76ZsBttjTAoi8X4PSBGhXAeI+kRV0cwLMboFcB7A9OajOCnGkAmQK61//0+FmJmEsByuIArt0AOgWsuATSNIDxAAVd5wkKHKGhqybYvGI3IJ76qVQBp9f97PzdgPTInOP051Hub8qO0bm2ArI0oDur5VnclJOkTuamATQKUPX4/N25JjCMGbDS8wJpNbTBqQBdkaDAgYq64gCBIzVVuUG7JzSzEhKOAoYrfLw+ewGFYQRXrQdEJzVeBShbAvxHa1PMgKHXBokVoG4GzCY9Sv8w9zM7VFNZLtClUUBM0mpAM4AGXZHgDVCAlzNEOKGwAafSQkkroCst1DLACBZ9BsAGFH0GFH4JFF4BsAEENcGutFDLgCVQ9CWAGYAZAAVAAb4V0JUWahmQCxR9CWAGFH0GwAgWfQbABmAGFHwGwAYUfQbABvhWQA8KYHxdpAeqvs9uLrwCRqwPvChUQCcwBdSLroB93w/qt3leD+SNpu8X+7UZn/v1wcD3iW0tjiPgNI93wPauSD90fC/ZOt/hD17o+Tba3kNLYrznLt6zK1o8noSdU0BNWqzFWfP+fIN5Q9KZtFiLY07uu++1RfME/IG0WJLDNaegPJAWa3HMo5oNry2WwyoJbfs3WUlQBYG6f6fVCSoZGPg/tS2sWLjjP3UJKxb2HgkT3HtKif9A0L2y4UxasEXZIXDa695jK0I2CMK2tZACAZLMJQmoLLpPkbsSeBYy2hQ+uxlQRSChqGEThNdUVEjs1UY4boBmqDRqJcFM1j3/zZIsLBKIzFWH7VxsDyOlSNyaoVhBU7z5lqDdrVCs4CaRtVoPpShUJcrbTI4ZRCzYosrcW4HEgglV8aoaxt7ADtlS3QjjdtFtMmNdXu14Ly6adMW7URCF0Z7vG8QmNEMwAutEYZBhK4RIoEp38p9NCNXvjnS874tONR5LSzgfY6mpTIDbc+xKizifXdLi7YZ+RzggNdT2XSHSIs6HeIRN7TeKbBJnbLva18CA0Aka7MsiYmkpZ2PXaI2yh45uP2BeZkFbuLytOxZqk18fuwYa0nLOokK+AlxZSG0+UGWo2hk/ozYnHhH7AEuitzq+yRKn7estDrcISwET7IvDzqRlnTmyA/p+RlqjwQFpJjzBvjlrT1raN7E+kOONhjbcVOgJ62xhOl9Py1Dusd3HZqPBr6QFnqbOuDKbCq2AuZGT7Q6WHc7OFqTJmqS0mDzu4tgYgC8+M8VRXVlxm/mStJRlBJu8EyANOvjeI30V0Yg9Pt9XZQetBaRPg/K4V+keSEvusCaJ+xY+U3xJ+rG07Ab3TlO+95qnvSZqFkFT5lpYw6vBE7iBPODv2LrCfkNa/opdABIFCpt+JS9iWfmdB+zXJPp2c082GojaUgvAMLCdP5VUgBuCVIWubKdf8ic5+W08JrgMbQ6WJP+R6v/XiXQ89rYbwdNYpPdj1/tncvKnQUiSPBHQQGr/pItzLTeK5w3ujisd17P4LlU6juRz3m5/lXb7LJZWgIuHzvmmwdfpWjr9hSKgi1RG6WCSx0yjiV5lPb5oSEtvWMtWAY8K1o7G3fFbnsspTzSQ/PefMWVX0U8/nfT1rCYt+XhYrSTH64/uvHcrjtJ/mvyS+S+vHfNP6d/j8bcL3/O/Ht26c+eDT/P9yNu/3OheJez8QVroi7wzWlmipXj+vbTE0/BOgv/F0vJeQuWYS/zXP5OWdZYKPmYRvyEt5xzKH3zcoxS+/8dfxNIyXsmPDn//6MS7Gvp/efTw8ENp2a5FPPdnnPvKvt964//fCGYpAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDr8H/aXWn+0xtUwwAAAABJRU5ErkJggg=="
)
APP_ICON_PNG = base64.b64decode(APP_ICON_PNG_B64)

MANIFEST_JSON = """{
  "name": "Sans Password Manager",
  "short_name": "SPM",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#0a0e0c",
  "theme_color": "#0a0e0c",
  "icons": [
    {"src": "/apple-touch-icon.png", "sizes": "512x512", "type": "image/png",
     "purpose": "any maskable"}
  ]
}
"""

# render_shell() and login_page() each carry their own <head>; interpolate this
# into both so the two cannot drift apart.
HEAD_ICONS = """<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0a0e0c">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="SPM">"""


def _icon(name, cls="icon"):
    return f'<svg class="{cls}" aria-hidden="true"><use href="#i-{name}"></use></svg>'


# nav key -> (href, icon, i18n key, fallback label, counter name)
NAV_SECTIONS = [
    ("nav.group.vault", [
        ("overview",       "/",               "overview", "nav.overview",       "Overview",       None),
        ("passwords",      "/passwords",      "key", "nav.passwords",      "Passwords",      "passwords"),
        ("notes",          "/notes",          "note", "nav.notes",          "Secure Notes",   "notes"),
        ("passphrases",    "/passphrases",    "phrase", "nav.passphrases",    "Passphrases",    "passphrases"),
        ("authenticators", "/authenticators", "authenticator", "nav.authenticators", "Authenticators", "authenticators"),
        ("backup-codes",   "/backup-codes",   "backup", "nav.backup_codes",   "Backup Codes",   "backups"),
    ]),
    ("nav.group.tools", [
        ("security",  "/security",  "shield", "nav.security",  "Security",        None),
        ("history",   "/history",   "history", "nav.history",   "History",         None),
        ("generator", "/generator", "generator", "nav.generator", "Generator",       None),
        ("transfer",  "/transfer",  "transfer", "nav.transfer",  "Export / Import", None),
    ]),
    ("nav.group.settings", [
        ("settings", "/settings", "gear", "nav.master_password", "Master Password", None),
    ]),
]

if WEBAUTHN_ENABLED:
    # Only offered when a relying-party id is configured. Without one the
    # endpoints 404, and a nav entry pointing at a 404 is worse than no entry.
    # It sits in Settings next to the master password because both answer the
    # same question -- how this vault gets opened -- and having one of them
    # under Tools made the gear a half-answer.
    NAV_SECTIONS[2][1].append(
        ("unlock-settings", "/unlock/settings", "shield", "nav.unlock",
         "Biometric Unlock", None))


def _nav_html(active, counts):
    out = []
    for group_key, items in NAV_SECTIONS:
        label = {"nav.group.vault": "Vault", "nav.group.tools": "Tools",
                 "nav.group.settings": "Settings"}[group_key]
        out.append(f'<div class="nav-label" data-i18n="{group_key}">{label}</div>')
        out.append('<div class="nav">')
        for key, href, ico, i18n, fallback, counter in items:
            cls = "nav-item active" if key == active else "nav-item"
            badge = ""
            if counter is not None:
                n = counts.get(counter, 0)
                if n:
                    badge = f'<span class="nav-count">{n}</span>'
            out.append(
                f'<a class="{cls}" href="{href}" title="{html.escape(fallback)}" '
                f'data-i18n-title="{i18n}">'
                f'<span class="nav-ico" aria-hidden="true">{_icon(ico)}</span>'
                f'<span class="nav-text" data-i18n="{i18n}">{fallback}</span>{badge}</a>'
            )
        out.append("</div>")
    return "".join(out)


RAIL_BOOTSTRAP = """
<script>
/* Runs inline, immediately after <body> opens, because reading the
   preference in DOMContentLoaded paints the sidebar expanded and then snaps
   it to the rail -- which reads as the page glitching rather than as a
   remembered setting. Any storage failure leaves the sidebar expanded,
   which is the state that needs no explanation. */
(function () {
  try {
    if (localStorage.getItem("spm.rail") === "1" &&
        window.matchMedia && window.matchMedia("(min-width: 901px)").matches) {
      document.body.classList.add("rail");
    }
  } catch (e) {}
})();
</script>
"""


LANG_BOOTSTRAP = """
<script>
/* Resolve language from the cookie on the client. Keeping it out of the
   server response means no request-scoped state has to be threaded through
   every template - which matters because the server is threaded. */
window.SPM_LANG = (function () {
  var m = document.cookie.match(/(?:^|;\\s*)spm_lang=([^;]*)/);
  var v = m ? decodeURIComponent(m[1]) : "en";
  return ["en", "id", "ja"].indexOf(v) >= 0 ? v : "en";
})();
</script>
"""


def render_shell(content, active, version, vault_path, title="Sans Password Manager",
                 counts=None, flash="", searchable=False):
    """Wrap page content in the shared app shell (sidebar + topbar)."""
    counts = counts or {}
    search_html = ""
    if searchable:
        # A GET form, so typing still filters the current table instantly and
        # Enter escalates to the cross-type search. No JS is required for the
        # escalation, which keeps it working if a script is ever blocked.
        search_html = (
            '<form class="search" method="get" action="/search" role="search">'
            f'<span class="search-ico" aria-hidden="true">{_icon("search", "icon icon-sm")}</span>'
            '<input id="q" name="q" type="search" autocomplete="off" spellcheck="false" '
            'data-i18n-placeholder="search.placeholder" placeholder="Search this vault...">'
            '<kbd>/</kbd></form>'
        )
    else:
        search_html = '<div class="search" aria-hidden="true"></div>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)} · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{RAIL_BOOTSTRAP}
{ICON_SPRITE}
<a class="skip-link" href="#main-content">Skip to vault content</a>
<div class="scrim" aria-hidden="true"></div>
<div class="app">
  <aside class="sidebar" id="mobile-navigation">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <div class="brand-text">
        <div class="brand-name">SPM</div>
        <div class="brand-meta">v{html.escape(version)}</div>
      </div>
    </div>
    {_nav_html(active, counts)}
    <div class="sidebar-foot">
      <div class="vault-chip" title="{html.escape(vault_path)}">
        <span class="dot" aria-hidden="true"></span>
        <span class="path">{html.escape(vault_path)}</span>
      </div>
      <a class="btn btn-ghost btn-sm btn-block" href="/logout"
         title="Logout" data-i18n-title="header.logout">
        {_icon("logout", "icon icon-sm")}
        <span class="rail-label" data-i18n="header.logout">Logout</span>
      </a>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <button class="icon-btn menu-btn" type="button" aria-label="Menu"
        aria-controls="mobile-navigation" aria-expanded="false">{_icon("menu", "icon icon-sm")}</button>
      {search_html}
      <div class="topbar-right">
        <div class="lockbar" id="lockbar" title="Idle auto-lock">
          <span class="lbl" aria-live="off">Locks in 30s</span>
          <span class="track"><span class="fill"></span></span>
        </div>
        <select class="select" id="lang-picker" aria-label="Language">
          <option value="en">EN</option>
          <option value="id">ID</option>
          <option value="ja">JP</option>
        </select>
      </div>
    </header>

    <main class="content" id="main-content" tabindex="-1">
      {flash}
      {content}
    </main>
  </div>
</div>
<div id="toast" role="status" aria-live="polite"></div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
{UNLOCK_BOOTSTRAP}
{LOCKBAR_SCRIPT}
</body>
</html>"""


def _esc(v):
    return html.escape(v if v is not None else "")


def _empty(icon, title_key, title, desc_key, desc, cta_html="", colspan=4):
    return (
        f'<tr class="empty-row"><td colspan="{colspan}">'
        f'<div class="empty"><div class="empty-ico" aria-hidden="true">{_icon(icon, "icon icon-lg")}</div>'
        f'<div class="empty-t" data-i18n="{title_key}">{title}</div>'
        f'<div class="empty-d" data-i18n="{desc_key}">{desc}</div>{cta_html}</div>'
        f'</td></tr>'
    )


def _actions(view_href, edit_href, delete_action, item_id, confirm_key, confirm_text):
    bits = ['<div class="icon-row">']
    if view_href:
        bits.append(f'<a class="icon-btn" href="{view_href}" title="View" aria-label="View">{_icon("view", "icon icon-sm")}</a>')
    if edit_href:
        bits.append(f'<a class="icon-btn" href="{edit_href}" title="Edit" aria-label="Edit">{_icon("edit", "icon icon-sm")}</a>')
    if delete_action:
        bits.append(
            f'<form class="inline" method="post" action="{delete_action}" '
            f'data-confirm-key="{confirm_key}" data-confirm-text="{html.escape(confirm_text, quote=True)}">'
            f'<input type="hidden" name="id" value="{item_id}">'
            f'<button type="submit" class="icon-btn danger" title="Delete" aria-label="Delete">{_icon("trash", "icon icon-sm")}</button>'
            f'</form>'
        )
    bits.append("</div>")
    return "".join(bits)


# --------------------------------------------------------------------------
# Row builders  (each row carries data-row for the instant client-side filter)
# --------------------------------------------------------------------------
def build_rows_html(entries):
    if not entries:
        return _empty("key", "empty.passwords.t", "No passwords yet",
                      "empty.passwords.d", "Entries you add will appear here.",
                      '<a class="btn btn-primary btn-sm" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>', 4)
    rows = []
    now = time.time()
    limit = rotation_days()
    for _, parts in entries:
        eid, name, user = _esc(parts[0]), _esc(parts[1]), _esc(parts[2])
        tags = entry_tags(parts)
        # Tags join the filter key so the existing instant filter matches them
        # without a second mechanism.
        key = " ".join([f"{name} {user} {eid}".lower()] + ["#" + t for t in tags])
        # Display only -- the clickable chips live in the tag bar above the
        # table, which is the single control that drives filtering.
        chips = "".join(f'<span class="chip">#{_esc(t)}</span>' for t in tags)
        age = _entry_age_days(parts[5] if len(parts) > 5 else "", now)
        aging = ('<span class="chip chip-warn" data-i18n="badge.aging">rotate</span>'
                 if age is not None and age > limit else "")
        rows.append(
            f'<tr data-row="{key}">'
            f'<td class="num">{eid}</td>'
            f'<td class="strong">{name} {aging}{chips}</td>'
            f'<td class="muted">{user or "&mdash;"}</td>'
            f'<td class="actions">{_actions(f"/view?id={eid}", f"/edit?id={eid}", "/delete", eid, "confirm.delete_entry", "Delete this entry?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_tag_filter_html(entries):
    """Tag chips above the password table; filtering reuses the search box."""
    tags = []
    for _, parts in entries:
        for tag in entry_tags(parts):
            if tag not in tags:
                tags.append(tag)
    if not tags:
        return ""
    chips = "".join(
        f'<button class="chip chip-btn" type="button" data-act="tag" data-tag="#{_esc(t)}">#{_esc(t)}</button>'
        for t in sorted(tags))
    return (f'<div class="tagbar"><button class="chip chip-btn" type="button" data-act="tag" data-tag="" '
            f'data-i18n="tags.all">All</button>{chips}</div>')


def build_notes_rows_html(notes):
    if not notes:
        return _empty("note", "empty.notes.t", "No secure notes",
                      "empty.notes.d", "Encrypted notes live inside the same vault.",
                      '<a class="btn btn-primary btn-sm" href="/notes-add" data-i18n="btn.add_note">+ Add Note</a>', 3)
    rows = []
    for _, parts in notes:
        nid, title = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(title + " " + nid).lower()}">'
            f'<td class="num">{nid}</td>'
            f'<td class="strong">{title}</td>'
            f'<td class="actions">{_actions(f"/notes-view?id={nid}", None, "/notes-delete", nid, "confirm.delete_entry", "Delete this note?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_passphrase_rows_html(passphrases):
    if not passphrases:
        return _empty("phrase", "empty.passphrases.t", "No passphrases",
                      "empty.passphrases.d", "Store API tokens or recovery phrases here.",
                      '<a class="btn btn-primary btn-sm" href="/passphrase-add" data-i18n="btn.add_passphrase">+ Add Passphrase</a>', 3)
    rows = []
    for _, parts in passphrases:
        pid, label = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(label + " " + pid).lower()}">'
            f'<td class="num">{pid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td class="actions">{_actions(f"/passphrase-view?id={pid}", f"/passphrase-edit?id={pid}", "/passphrase-delete", pid, "confirm.delete_passphrase", "Delete this passphrase?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_backup_rows_html(backups):
    if not backups:
        return _empty("backup", "empty.backups.t", "No backup codes",
                      "empty.backups.d", "Keep one-time recovery codes safe here.",
                      '<a class="btn btn-primary btn-sm" href="/backup-codes-add" data-i18n="btn.add_backups">+ Add Backup Codes</a>', 3)
    rows = []
    for _, parts in backups:
        bid, label = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(label + " " + bid).lower()}">'
            f'<td class="num">{bid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td class="actions">{_actions(f"/backup-codes-view?id={bid}", f"/backup-codes-edit?id={bid}", "/backup-codes-delete", bid, "confirm.delete_backup", "Delete these backup codes?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_auth_rows_html(auths):
    if not auths:
        return _empty("authenticator", "empty.auth.t", "No authenticators",
                      "empty.auth.d", "Add a TOTP secret to generate 2FA codes.",
                      '<a class="btn btn-primary btn-sm" href="/authenticator-add" data-i18n="btn.add_authenticator">+ Add Authenticator</a>', 5)
    rows = []
    for _, parts in auths:
        aid, label = _esc(parts[1]), _esc(parts[2])
        interval = _esc(parts[4] if len(parts) > 4 else "30")
        algo = _esc(parts[6] if len(parts) > 6 else "sha1")
        rows.append(
            f'<tr data-row="{(label + " " + aid + " " + algo).lower()}">'
            f'<td class="num">{aid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td><span class="chip">{interval}s</span></td>'
            f'<td><span class="chip">{algo.upper()}</span></td>'
            f'<td class="actions">{_actions(f"/authenticator-view?id={aid}", f"/authenticator-edit?id={aid}", "/authenticator-delete", aid, "confirm.delete_authenticator", "Delete this authenticator?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


# --------------------------------------------------------------------------
# Generic list page
# --------------------------------------------------------------------------
def list_page(title_key, title, desc_key, desc, add_href, add_key, add_label, headers, rows_html):
    def _th(h):
        cls = ' class="num"' if h[2] == "num" else ""
        sty = ' style="text-align:right"' if h[2] == "act" else ""
        return '<th' + cls + sty + ' data-i18n="' + h[0] + '">' + h[1] + '</th>'
    ths = "".join(_th(h) for h in headers)
    add_btn = (
        f'<a class="btn btn-primary" href="{add_href}" data-i18n="{add_key}">{add_label}</a>'
        if add_href else ""
    )
    ncols = len(headers)
    return f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="{title_key}">{title}</h1>
    <div class="page-sub" data-i18n="{desc_key}">{desc}</div>
  </div>
  <div class="page-actions">{add_btn}</div>
</div>
<div class="card" data-searchable>
  <div class="table-wrap">
    <table class="t">
      <thead><tr>{ths}</tr></thead>
      <tbody>{rows_html}
        <tr class="hidden" data-empty-search>
          <td colspan="{ncols}"><div class="empty"><div class="empty-ico">{_icon("search", "icon icon-lg")}</div>
          <div class="empty-t" data-i18n="search.no_results">Nothing matches your search</div></div></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>"""


def _id_links(ids, key, label, hint_key, hint, suffix=""):
    """One security finding rendered as links into the offending entries.

    `suffix` carries values that must survive translation -- data-i18n replaces
    an element's whole text, so an interpolated number has to sit outside the
    translated node or switching language would silently drop it.
    """
    if not ids:
        return (f'<div class="field"><label data-i18n="{key}">{label}</label>'
                f'<div class="hint" data-i18n="security.none">Nothing to fix here.</div></div>')
    links = " ".join(
        f'<a class="btn btn-ghost btn-sm" href="/view?id={_esc(rid)}">{_esc(rid)}</a>'
        for rid in ids)
    tail = f' <span class="hint" style="display:inline">{_esc(suffix)}</span>' if suffix else ""
    return (f'<div class="field"><label data-i18n="{key}">{label}</label>'
            f'<div class="hint"><span data-i18n="{hint_key}">{hint}</span>{tail}</div>'
            f'<div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:6px">{links}</div></div>')


def security_page(audit):
    """The findings behind the overview's security score.

    Only IDs are rendered. The CLI dashboard states that secrets and
    fingerprints are never printed; this page holds the same line, so it stays
    safe to open on a phone in public.
    """
    score = audit["score"]
    tone = "ok" if score >= 80 else ("warn" if score >= 50 else "bad")
    reused_html = "".join(
        f'<div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:6px">'
        + " ".join(f'<a class="btn btn-ghost btn-sm" href="/view?id={_esc(rid)}">{_esc(rid)}</a>' for rid in group)
        + '</div>'
        for group in audit["reused"])
    if not reused_html:
        reused_html = ('<div class="hint" data-i18n="security.none">Nothing to fix here.</div>')
    days = audit["rotation_days"]
    return f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="nav.security">Security</h1>
    <div class="page-sub" data-i18n="security.sub">What is pulling your vault score down.</div>
  </div>
</div>
<div class="card">
  <div class="card-body">
    <div class="stat" style="pointer-events:none">
      <span class="stat-ico" aria-hidden="true">{_icon("shield")}</span>
      <span><span class="stat-n score-{tone}">{score}</span>
      <span class="stat-l" data-i18n="overview.security_score">Security score</span></span>
    </div>
    <div class="hint" data-i18n="security.scope">Only password entries are scored. IDs are shown; secrets never are.</div>
  </div>
</div>
<div class="card">
  <div class="card-body">
    {_id_links(audit["weak"], "security.weak", "Weak passwords",
               "security.weak_d", "Shorter than 12 characters, or using fewer than three character classes.")}
    <div class="field"><label data-i18n="security.reused">Reused passwords</label>
      <div class="hint" data-i18n="security.reused_d">Each row below is one group of entries sharing a password.</div>
      {reused_html}
    </div>
    {_id_links(audit["old"], "security.aging", "Due for rotation",
               "security.aging_d", "Older than the rotation threshold:", f"{days} days")}
    {_id_links(audit["incomplete"], "security.incomplete", "Missing details",
               "security.incomplete_d", "No service name or no username.")}
    {_id_links(audit["malformed"], "security.malformed", "Malformed authenticators",
               "security.malformed_d", "Missing a secret, or an algorithm SPM cannot generate codes for.")}
  </div>
</div>"""


def _fmt_size(n):
    return f"{n / 1024.0:.1f} KB" if n >= 1024 else f"{n} B"


def build_history_rows_html(snapshots):
    if not snapshots:
        return _empty("history", "empty.history.t", "No snapshots yet",
                      "empty.history.d", "SPM archives the vault before each change.", "", 4)
    rows = []
    for pos, (name, stamp, size) in enumerate(snapshots):
        try:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(stamp, "%Y%m%dT%H%M%S"))
        except ValueError:
            when = stamp
        newest = ' <span class="hint" data-i18n="history.newest">newest</span>' if pos == 0 else ""
        rows.append(
            f'<tr data-row="{_esc(when.lower())}">'
            f'<td class="strong">{_esc(when)} UTC{newest}</td>'
            f'<td class="muted">{_fmt_size(size)}</td>'
            f'<td class="muted">{_esc(name)}</td>'
            f'<td class="actions">'
            f'<form class="inline" method="post" action="/history-restore" '
            f'data-confirm-key="confirm.restore_snapshot" '
            f'data-confirm-text="Restore this snapshot? The current vault is archived first.">'
            f'<input type="hidden" name="name" value="{_esc(name)}">'
            f'<button class="btn btn-ghost btn-sm" type="submit" data-i18n="btn.restore">Restore</button>'
            f'</form></td>'
            f'</tr>')
    return "".join(rows)


def build_search_rows_html(results):
    if not results:
        return _empty("search", "empty.search.t", "Nothing found",
                      "empty.search.d", "No label, name or username matches that text.", "", 3)
    rows = []
    for kind_key, kind, rid, label, href in results:
        rows.append(
            f'<tr data-row="">'
            f'<td class="muted" data-i18n="{kind_key}">{_esc(kind)}</td>'
            f'<td class="num">{_esc(rid)}</td>'
            f'<td class="strong">{_esc(label) or "&mdash;"}</td>'
            f'<td class="actions"><a class="btn btn-ghost btn-sm" href="{href}" data-i18n="btn.view">View</a></td>'
            f'</tr>')
    return "".join(rows)


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
def overview_page(counts, recent):
    tiles = [
        ("shield", counts.get("security_score", 100), "overview.security_score", "Security score", "/security"),
        ("key", counts.get("passwords", 0), "nav.passwords", "Passwords", "/passwords"),
        ("note", counts.get("notes", 0), "nav.notes", "Secure Notes", "/notes"),
        ("phrase", counts.get("passphrases", 0), "nav.passphrases", "Passphrases", "/passphrases"),
        ("authenticator", counts.get("authenticators", 0), "nav.authenticators", "Authenticators", "/authenticators"),
        ("backup", counts.get("backups", 0), "nav.backup_codes", "Backup Codes", "/backup-codes"),
    ]
    stats = "".join(
        f'<a class="stat" href="{href}">'
        f'<span class="stat-ico" aria-hidden="true">{_icon(ico)}</span>'
        f'<span><span class="stat-n">{n}</span>'
        f'<span class="stat-l" data-i18n="{k}">{lbl}</span></span></a>'
        for ico, n, k, lbl, href in tiles
    )

    if recent:
        items = "".join(
            f'<tr data-row=""><td class="num">{_esc(p[0])}</td>'
            f'<td class="strong">{_esc(p[1])}</td>'
            f'<td class="muted">{_esc(p[2]) or "&mdash;"}</td>'
            f'<td class="actions"><a class="btn btn-ghost btn-sm" href="/view?id={_esc(p[0])}" data-i18n="btn.view">View</a></td></tr>'
            for _, p in recent
        )
        recent_html = f"""
<div class="card">
  <div class="card-head">
    <h2 data-i18n="overview.recent">Recently added</h2>
    <span class="spacer"></span>
    <a class="btn btn-ghost btn-sm" href="/passwords" data-i18n="overview.view_all">View all</a>
  </div>
  <div class="table-wrap"><table class="t"><tbody>{items}</tbody></table></div>
</div>"""
    else:
        recent_html = f"""
<div class="card"><div class="empty">
  <div class="empty-ico" aria-hidden="true">{_icon("lock", "icon icon-lg")}</div>
  <div class="empty-t" data-i18n="empty.vault.t">Your vault is empty</div>
  <div class="empty-d" data-i18n="empty.vault.d">Add your first password to get started.</div>
  <a class="btn btn-primary" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>
</div></div>"""

    total = sum(counts.get(k, 0) for k in ("passwords", "notes", "passphrases", "authenticators", "backups"))
    return f"""
<section class="console-hero" aria-labelledby="overview-command">
  <div class="eyebrow" data-i18n="overview.console_eyebrow">session / local vault / authenticated</div>
  <h1 id="overview-command">spm vault status</h1>
  <div class="console-output" aria-label="Vault status output">
    <span><b>{total}</b> <i data-i18n="overview.console_records">encrypted records indexed</i></span>
    <span data-i18n="overview.console_gpg">GnuPG boundary active on this host</span>
    <span data-i18n="overview.console_lock">idle lock armed for 30 seconds</span>
  </div>
  <p class="lede" data-i18n="overview.console_lede">Inspect, generate, and maintain credentials from one auditable session.</p>
</section>
<div class="page-head">
  <div>
    <h2 class="page-title" data-i18n="nav.overview">Overview</h2>
    <div class="page-sub" data-i18n="overview.sub">Everything in your encrypted vault at a glance.</div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/generator" data-i18n="btn.open_generator">Open Generator</a>
    <a class="btn btn-primary" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>
  </div>
</div>
<div class="stats">{stats}</div>
{recent_html}
<div class="card" style="margin-top:var(--sp-4)">
  <div class="card-foot" style="border-top:none">
    <span data-i18n="passwords.footer">Passwords are never sent anywhere else - all crypto stays on this host with GnuPG.</span>
  </div>
</div>"""


# --------------------------------------------------------------------------
# Forms
# --------------------------------------------------------------------------
def _form_page(title, action, fields_html, message="", back="/", active="overview"):
    msg = f'<div class="msg">{message}</div>' if message and "<div" not in message else (message or "")
    content = f"""
<div class="page-head">
  <div><h1 class="page-title">{html.escape(title)}</h1></div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="{back}" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
{msg}
<div class="card" style="max-width:640px">
  <div class="card-body">
    <form method="post" action="{action}">
      {fields_html}
      <div class="form-actions">
        <button class="btn btn-primary" type="submit" data-i18n="form.save">Save</button>
        <a class="btn btn-ghost" href="{back}" data-i18n="link.back">Cancel</a>
      </div>
    </form>
  </div>
</div>"""
    return render_shell(content, active, VERSION, VAULT_PATH, title=title)


def _field(name, label_key, label, value="", ftype="text", placeholder_key=None, hint=None, required=False, rows=0):
    req = " required" if required else ""
    ph = f' data-i18n-placeholder="{placeholder_key}"' if placeholder_key else ""
    if rows:
        ctrl = f'<textarea class="input" name="{name}" rows="{rows}"{ph}{req}>{html.escape(value)}</textarea>'
    else:
        ctrl = f'<input class="input" type="{ftype}" name="{name}" value="{html.escape(value)}"{ph}{req} autocomplete="off">'
    hint_html = f'<div class="hint">{hint}</div>' if hint else ""
    return f'<div class="field"><label data-i18n="{label_key}">{label}</label>{ctrl}{hint_html}</div>'


def build_entry_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("name", "entry.field.service", "Service", v.get("name", ""), required=True) +
        _field("user", "entry.field.username", "Username / Email", v.get("user", "")) +
        _field("password", "entry.field.password", "Password", v.get("password", "")) +
        # type="url" only nudges the browser; the server still validates, since
        # a form post is not obliged to come from this form.
        _field("url", "entry.field.url", "URL", v.get("url", ""), ftype="url",
               hint='<span data-i18n="entry.hint.url">Used to match this entry to a site. '
                    'http:// or https:// only.</span>') +
        _field("notes", "entry.field.notes", "Notes", v.get("notes", ""), rows=4)
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/passwords", "passwords")


def build_note_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("title", "note.field.title", "Title", v.get("title", ""), required=True) +
        _field("content", "note.field.content", "Content", v.get("content", ""), rows=8)
    )
    return _form_page(title, action, f, message, "/notes", "notes")


def build_passphrase_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("label", "pass.field.label", "Label", v.get("label", ""), required=True) +
        _field("secret", "pass.field.secret_hint", "Passphrase (leave blank to auto-generate)", v.get("secret", ""), rows=3)
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/passphrases", "passphrases")


def build_backup_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("label", "backup.field.label", "Label", v.get("label", ""), required=True) +
        _field("codes", "backup.field.codes", "Backup codes (one per line)", v.get("codes", ""), rows=8)
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/backup-codes", "backup-codes")


def build_auth_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    algo = (v.get("algo") or "sha1").lower()
    opts = "".join(
        f'<option value="{a}"{" selected" if algo == a else ""} data-i18n="auth.option.{a}">{a.upper()}</option>'
        for a in ("sha1", "sha256", "sha512")
    )
    f = (
        _field("label", "auth.field.label", "Label", v.get("label", ""), required=True) +
        _field("secret", "auth.field.secret", "Base32 secret", v.get("secret", ""), required=True,
               hint="e.g. JBSWY3DPEHPK3PXP") +
        '<div class="row2">' +
        _field("period", "auth.field.period", "Refresh interval (s)", v.get("period", "30") or "30", ftype="number") +
        f'<div class="field"><label data-i18n="auth.field.algorithm">Algorithm</label>'
        f'<select class="input" name="algo">{opts}</select></div>' +
        '</div>'
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/authenticators", "authenticators")


# --------------------------------------------------------------------------
# View pages
# --------------------------------------------------------------------------
def _secret_block(value, label_key, label, elem_id):
    return f"""
<div class="field">
  <label data-i18n="{label_key}">{label}</label>
  <div class="secret">
    <span class="secret-val masked" id="{elem_id}" data-val="{html.escape(value)}">{"•" * min(len(value), 24) if value else "&mdash;"}</span>
    <button class="icon-btn" type="button" data-act="reveal" data-target="{elem_id}" data-title-show="Show" aria-label="Show">{_icon("view", "icon icon-sm")}</button>
    <button class="icon-btn" type="button" data-act="copy-val" data-target="{elem_id}" aria-label="Copy">{_icon("copy", "icon icon-sm")}</button>
  </div>
</div>"""


REVEAL_SCRIPT = """
<script>
window.SPM_reveal = function (id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var masked = el.classList.contains("masked");
  if (masked) {
    el.textContent = el.dataset.val || "";
    el.classList.remove("masked");
    btn.setAttribute("aria-label", "Hide");
    var use = btn.querySelector("use");
    if (use) use.setAttribute("href", "#i-hide");
    if (window.SPM_AutoLock) window.SPM_AutoLock.restart();
  } else {
    var v = el.dataset.val || "";
    el.textContent = "\\u2022".repeat(Math.min(v.length, 24));
    el.classList.add("masked");
    btn.setAttribute("aria-label", "Show");
    var use = btn.querySelector("use");
    if (use) use.setAttribute("href", "#i-view");
  }
};
</script>
"""


def view_entry_page(parts):
    """Full page for a single password entry."""
    eid, name, user, pw = _esc(parts[0]), _esc(parts[1]), _esc(parts[2]), parts[3] if len(parts) > 3 else ""
    notes = parts[4] if len(parts) > 4 else ""
    created = _esc(parts[5] if len(parts) > 5 else "")
    # Re-checked at render time rather than trusted from the vault. A row can
    # reach this page from an editor session or a hand-edited file, neither of
    # which went through the form validator, and this value becomes an href.
    raw_url = parts[6] if len(parts) > 6 else ""
    safe_url = raw_url if _URL_RE.match(raw_url.strip()) else ""
    if safe_url:
        url_html = (f'<a href="{_esc(safe_url)}" target="_blank" '
                    f'rel="noopener noreferrer nofollow">{_esc(safe_url)}</a>')
    else:
        url_html = "&mdash;"
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title">{name}</h1>
    <div class="page-sub">{user or ""}</div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/edit?id={eid}" data-i18n="btn.edit">Edit</a>
    <a class="btn btn-ghost" href="/passwords" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:680px"><div class="card-body">
  <div class="field"><label data-i18n="view.label.username">Username / Email</label>
    <div class="secret"><span class="secret-val" id="username-value">{user or "&mdash;"}</span>
    <button class="icon-btn" type="button" data-act="copy-text" data-target="username-value" aria-label="Copy">{_icon("copy", "icon icon-sm")}</button></div>
  </div>
  {_secret_block(pw, "view.label.password", "Password", "pw")}
  <div class="field"><label data-i18n="view.label.url">URL</label>
    <div class="secret"><span class="secret-val">{url_html}</span></div>
  </div>
  <div class="field"><label data-i18n="view.label.notes">Notes</label>
    <div class="secret"><span class="secret-val" style="white-space:pre-wrap">{_esc(notes) or "&mdash;"}</span></div>
  </div>
  <div class="field"><label data-i18n="view.label.created">Created</label>
    <div class="faint mono">{created or "&mdash;"}</div>
  </div>
</div></div>
{REVEAL_SCRIPT}"""
    return render_shell(content, "passwords", VERSION, VAULT_PATH, title=name)


def view_simple_page(title, back, label_key, label, value, created, secret_key, secret_label, active="overview"):
    body = _secret_block(value, secret_key, secret_label, "sec")
    content = f"""
<div class="page-head">
  <div><h1 class="page-title">{html.escape(title)}</h1>
    <div class="page-sub">{html.escape(label)}</div></div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="{back}" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:680px"><div class="card-body">
  {body}
  <div class="field"><label data-i18n="view.label.created">Created</label>
    <div class="faint mono">{html.escape(created) or "&mdash;"}</div></div>
</div></div>
{REVEAL_SCRIPT}"""
    return render_shell(content, active, VERSION, VAULT_PATH, title=title)


def login_page(version, message=""):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Unlock Vault · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{ICON_SPRITE}
<a class="skip-link" href="#main-content">Skip to unlock form</a>
<div class="login-wrap">
  <main class="login-card" id="main-content">
    <div class="login-brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <h1 data-i18n="header.title">Sans Password Manager</h1>
      <p data-i18n="login.sub">Unlock your encrypted vault to continue.</p>
    </div>
    <div class="card"><div class="card-body">
      {message}
      <form method="post" action="/login">
        <div class="field">
          <label for="pw" data-i18n="login.master">Master password</label>
          <input class="input" id="pw" name="password" type="password"
                 autocomplete="current-password" autofocus required>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="login.unlock">Unlock</button>
      </form>
    </div>
    <div class="card-foot">
      <span data-i18n="login.note">All decryption happens locally with GnuPG. Nothing leaves this host.</span>
    </div></div>
    <div style="text-align:center;margin-top:var(--sp-4)">
      <select class="select" id="lang-picker" aria-label="Language">
        <option value="en">EN</option><option value="id">ID</option><option value="ja">JP</option>
      </select>
      <div class="faint" style="margin-top:var(--sp-2)">v{html.escape(version)}</div>
    </div>
  </main>
</div>
<div id="toast" role="status" aria-live="polite"></div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
</body>
</html>"""


# Stamped by _send_html the way __LANG__ is, so the lockbar on every page
# learns whether biometric unlock is usable without each page handler having to
# decrypt the vault to find out.
UNLOCK_BOOTSTRAP = """
<script>window.SPM_UNLOCK = __SPM_UNLOCK__;</script>
"""

UNLOCK_SCRIPT = """
<script>
(function () {
  var btn = document.getElementById("unlock-btn");
  var status = document.getElementById("unlock-status");
  if (!btn || !status) return;
  var CSRF = btn.getAttribute("data-csrf") || "";
  function t(key, fallback) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fallback) : fallback;
  }
  function b64urlToBytes(value) {
    var pad = value.replace(/-/g, "+").replace(/_/g, "/");
    while (pad.length % 4) pad += "=";
    var raw = atob(pad), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf: CSRF}, body || {}))
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || "unlock failed");
        return j;
      });
    });
  }
  function fail(message) {
    status.textContent = message;
    btn.disabled = false;
  }
  btn.addEventListener("click", function () {
    if (!window.PublicKeyCredential) { fail(t("unlock.nosupport", "This browser has no biometric support.")); return; }
    btn.disabled = true;
    status.textContent = t("unlock.waiting", "Waiting for biometric confirmation...");
    post("/unlock/challenge").then(function (c) {
      return navigator.credentials.get({publicKey: {
        challenge: b64urlToBytes(c.challenge),
        rpId: c.rp_id,
        userVerification: "required",
        timeout: 60000,
        allowCredentials: (c.allow || []).map(function (id) {
          return {type: "public-key", id: b64urlToBytes(id)};
        })
      }});
    }).then(function (cred) {
      if (!cred) throw new Error("no credential");
      return post("/unlock/verify", {
        credential_id: cred.id,
        client_data: bytesToB64url(cred.response.clientDataJSON),
        auth_data: bytesToB64url(cred.response.authenticatorData),
        signature: bytesToB64url(cred.response.signature)
      });
    }).then(function () {
      window.location.replace("/");
    }).catch(function (err) {
      fail((err && err.message) ? err.message : t("unlock.failed", "Unlock failed."));
    });
  });
})();
</script>
"""

UNLOCK_REGISTER_SCRIPT = """
<script>
(function () {
  var btn = document.getElementById("register-btn");
  var status = document.getElementById("register-status");
  if (!btn || !status) return;
  var CSRF = btn.getAttribute("data-csrf") || "";
  function t(key, fallback) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fallback) : fallback;
  }
  function b64urlToBytes(value) {
    var pad = value.replace(/-/g, "+").replace(/_/g, "/");
    while (pad.length % 4) pad += "=";
    var raw = atob(pad), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf: CSRF}, body || {}))
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || "registration failed");
        return j;
      });
    });
  }
  btn.addEventListener("click", function () {
    if (!window.PublicKeyCredential) { status.textContent = t("unlock.nosupport", "This browser has no biometric support."); return; }
    btn.disabled = true;
    status.textContent = t("register.waiting", "Waiting for the authenticator...");
    var label = (document.getElementById("register-label") || {}).value || "";
    post("/unlock/register/challenge").then(function (c) {
      return navigator.credentials.create({publicKey: {
        challenge: b64urlToBytes(c.challenge),
        rp: {id: c.rp_id, name: "Sans Password Manager"},
        user: {
          id: b64urlToBytes(c.user_id),
          name: c.user_name || "vault",
          displayName: c.user_name || "vault"
        },
        /* ES256 only: it is what every platform authenticator supports, and it
           keeps server-side verification to one openssl code path. */
        pubKeyCredParams: [{type: "public-key", alg: -7}],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "discouraged",
          userVerification: "required"
        },
        attestation: "none",
        timeout: 60000
      }});
    }).then(function (cred) {
      if (!cred) throw new Error("no credential");
      /* getPublicKey() hands back SPKI DER directly, which is what lets this
         server skip a CBOR decoder for the attestation object entirely. */
      var spki = cred.response.getPublicKey ? cred.response.getPublicKey() : null;
      if (!spki) throw new Error("this browser cannot export the credential key");
      return post("/unlock/register/verify", {
        credential_id: cred.id,
        client_data: bytesToB64url(cred.response.clientDataJSON),
        auth_data: bytesToB64url(cred.response.getAuthenticatorData()),
        public_key: bytesToB64url(spki),
        label: label
      });
    }).then(function () {
      window.location.replace("/unlock/settings?msg=registered");
    }).catch(function (err) {
      status.textContent = (err && err.message) ? err.message : t("register.failed", "Registration failed.");
      btn.disabled = false;
    });
  });
})();
</script>
"""


def unlock_page(version, csrf):
    """The locked screen.

    Renders no vault content at all -- a button, a status line and a way out.
    It must also be usable with no JavaScript, so the master-password route is
    a plain link rather than something the script has to enable.
    """
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Locked · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{ICON_SPRITE}
<div class="login-wrap">
  <main class="login-card" id="main-content">
    <div class="login-brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <h1 data-i18n="unlock.title">Vault locked</h1>
      <p data-i18n="unlock.sub">Confirm with your device to continue where you left off.</p>
    </div>
    <div class="card"><div class="card-body">
      <button class="btn btn-primary btn-block" type="button" id="unlock-btn"
              data-csrf="{html.escape(csrf)}" data-i18n="unlock.btn">Unlock with biometrics</button>
      <div class="faint" id="unlock-status" role="status" aria-live="polite"
           style="margin-top:var(--sp-3);min-height:1.2em"></div>
    </div>
    <div class="card-foot">
      <a href="/logout" data-i18n="unlock.fallback">Use master password instead</a>
    </div></div>
    <div style="text-align:center;margin-top:var(--sp-4)">
      <select class="select" id="lang-picker" aria-label="Language">
        <option value="en">EN</option><option value="id">ID</option><option value="ja">JP</option>
      </select>
      <div class="faint" style="margin-top:var(--sp-2)">v{html.escape(version)}</div>
    </div>
  </main>
</div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
{UNLOCK_SCRIPT}
</body>
</html>"""


def unlock_settings_page(creds, csrf, flash=""):
    """Manage registered unlock credentials.

    Built with list_page like every other listing page rather than a bespoke
    card, so the header, table styling and empty state match the rest of the
    app instead of drifting into a second look.
    """
    rows = []
    for _, cred in creds:
        rows.append(
            # method="post" in double quotes on purpose: _POST_FORM_RE stamps
            # the CSRF token by matching that exact spelling, and a
            # single-quoted form silently receives no token. Same-origin
            # desktop requests would still pass on the Origin check alone, so
            # the breakage would only ever show up on iOS, where a home-screen
            # web app sends Origin: null and the token is all that is left.
            '<tr data-row><td class="num">%s</td><td><strong>%s</strong></td>'
            '<td class="faint">%s</td>'
            '<td style="text-align:right"><form method="post" '
            'action="/unlock/delete" style="display:inline" '
            "onsubmit=\"return confirm('Remove this unlock credential?')\">"
            '<input type="hidden" name="id" value="%s">'
            '<button class="btn btn-danger btn-sm" type="submit" '
            'data-i18n="btn.delete">Delete</button>'
            "</form></td></tr>"
            % (_esc(cred[1]), _esc(cred[5]), _esc(cred[6]), _esc(cred[1]))
        )
    if not rows:
        rows.append(
            '<tr><td colspan="4"><div class="empty">'
            '<div class="empty-ico">%s</div>'
            '<div class="empty-t" data-i18n="unlock.empty">'
            'No device registered yet</div>'
            '<div class="empty-s" data-i18n="unlock.empty_sub">'
            'Register one below, or keep using your master password</div>'
            "</div></td></tr>" % _icon("shield", "icon icon-lg")
        )
    page = list_page(
        "nav.unlock", "Biometric Unlock",
        "page.unlock.desc",
        "Resume the idle lock with this device instead of your master password.",
        "", "", "",
        [("table.id", "ID", "num"),
         ("table.label", "Label", ""),
         ("unlock.registered", "Registered", ""),
         ("table.actions", "Actions", "act")],
        "".join(rows))
    return f"""{flash}{page}
<div class="card" style="margin-top:var(--sp-4)"><div class="card-body">
  <div class="field">
    <label for="register-label" data-i18n="unlock.field.label">Label for this device</label>
    <input class="input" id="register-label" maxlength="64" placeholder="iPhone">
  </div>
  <button class="btn btn-primary" type="button" id="register-btn"
          data-csrf="{html.escape(csrf)}" data-i18n="unlock.register">Register this device</button>
  <div class="faint" id="register-status" role="status" aria-live="polite"
       style="margin-top:var(--sp-3);min-height:1.2em"></div>
  <p class="faint" style="margin-top:var(--sp-3)" data-i18n="unlock.note">The master
  password is still required for the first sign-in, once the session reaches its
  maximum age, and whenever a locked session goes unresumed for too long.</p>
</div></div>
{UNLOCK_REGISTER_SCRIPT}
"""


def settings_page(flash=""):
    """Change the master password.

    Built from the same page-head / card / field primitives as every other form
    page rather than a bespoke layout, so it inherits the focus ring, the
    dark-only palette and the split accent for free. Nothing on this page is an
    emitted value, so nothing here is painted with the value role -- the submit
    is the only accent, and it is a control.
    """
    return f"""{flash}
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="page.settings.title">Master Password</h1>
    <div class="page-sub" data-i18n="page.settings.desc">Change the password that
      encrypts this vault.</div>
  </div>
</div>
<div class="card"><div class="card-body">
  <form method="post" action="/settings/master-password" autocomplete="off">
    <div class="field">
      <label for="mp-current" data-i18n="settings.current">Current master password</label>
      <input class="input" id="mp-current" name="current" type="password"
             autocomplete="current-password" required autofocus>
    </div>
    <div class="field">
      <label for="mp-new" data-i18n="settings.new">New master password</label>
      <input class="input" id="mp-new" name="new" type="password"
             autocomplete="new-password" minlength="{MASTER_MIN_LEN}" required>
    </div>
    <div class="field">
      <label for="mp-confirm" data-i18n="settings.confirm">Confirm new master password</label>
      <input class="input" id="mp-confirm" name="confirm" type="password"
             autocomplete="new-password" minlength="{MASTER_MIN_LEN}" required>
    </div>
    <p class="faint" style="margin-bottom:var(--sp-4)" data-i18n="settings.hint">At least
      {MASTER_MIN_LEN} characters. There is no way to recover a master password you
      forget &mdash; only the recovery file and its private key can reset it.</p>
    <div class="faint" id="mp-status" role="status" aria-live="polite"
         style="margin-bottom:var(--sp-3);min-height:1.2em"></div>
    <button class="btn btn-primary" type="submit"
            data-i18n="settings.submit">Change master password</button>
  </form>
</div></div>
<div class="card" style="margin-top:var(--sp-4)">
  <div class="card-head"><h2 data-i18n="settings.effect">What this does</h2></div>
  <div class="card-body">
    <ul style="margin:0;padding-left:var(--sp-5);line-height:1.9">
      <li data-i18n="settings.effect_vault">Re-encrypts the whole vault under the
        new password.</li>
      <li data-i18n="settings.effect_recovery">Rewrites the recovery file so
        &quot;spm forgot&quot; keeps working.</li>
      <li data-i18n="settings.effect_sessions">Signs out every other browser
        session.</li>
      <li data-i18n="settings.effect_backup">Keeps the previous vault as a .bak
        and a history snapshot.</li>
    </ul>
  </div>
</div>
{SETTINGS_SCRIPT}
"""


SETTINGS_SCRIPT = """
<script>
(function () {
  var form = document.querySelector('form[action="/settings/master-password"]');
  if (!form) return;
  var pw = document.getElementById("mp-new");
  var cf = document.getElementById("mp-confirm");
  var out = document.getElementById("mp-status");
  if (!pw || !cf || !out) return;

  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }

  // Mirror only, never gate: the server re-checks both of these. If this
  // script is blocked the form still submits and still gets a real answer.
  function check() {
    if (!cf.value) { out.textContent = ""; return true; }
    var same = pw.value === cf.value;
    out.textContent = same ? "" : t("settings.mismatch", "The two new passwords do not match.");
    return same;
  }
  pw.addEventListener("input", check);
  cf.addEventListener("input", check);
})();
</script>"""


GENERATOR_SCRIPT = """
<script>
(function () {
  var WORDS = ["sun","moon","star","river","ocean","cloud","stone","tree","leaf","fern","fire","ember",
    "storm","wind","breeze","shadow","light","silver","gold","amber","flame","nova","comet","aurora",
    "pulse","echo","vapor","wave","mist","dawn","dusk","zen","sage","whale","lynx","orca","hawk","raven"];

  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }

  /* Uniform random int in [0, bound) from the platform CSPRNG.
     Rejection sampling keeps the distribution flat - a plain % bound would
     bias the low end of the charset. */
  function randBelow(bound) {
    if (bound <= 0) return 0;
    var limit = Math.floor(4294967296 / bound) * bound;
    var buf = new Uint32Array(1);
    for (var i = 0; i < 64; i++) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % bound;
    }
    return buf[0] % bound;
  }

  function charset(sym, up, low, dig) {
    var b = "";
    if (up)  b += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (low) b += "abcdefghijklmnopqrstuvwxyz";
    if (dig) b += "0123456789";
    if (sym) b += "!@#$%^&*()_-+=[]{}:;,.?/|~";
    if (!b) b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return b;
  }

  function genSecure(len, o) {
    var chars = charset(o.symbols, o.upper, o.lower, o.digits), out = "";
    for (var i = 0; i < len; i++) out += chars.charAt(randBelow(chars.length));
    return { pw: out, size: chars.length };
  }

  function genEasy(count, o) {
    count = Math.min(8, Math.max(2, count));
    var parts = [];
    for (var i = 0; i < count; i++) {
      var w = WORDS[randBelow(WORDS.length)];
      if (o.upper && !o.lower) w = w.toUpperCase();
      else if (o.upper) w = w.charAt(0).toUpperCase() + w.slice(1);
      else if (!o.lower) w = w.toUpperCase();
      parts.push(w);
    }
    var pw = parts.join("-");
    if (o.digits) pw += "-" + String(randBelow(100)).padStart(2, "0");
    if (o.symbols) { var s = "!@#$%^&*"; pw += s.charAt(randBelow(s.length)); }
    var size = 0;
    if (o.upper) size += 26;
    if (o.lower) size += 26;
    if (o.digits) size += 10;
    if (o.symbols) size += 10;
    return { pw: pw, size: size || 26 };
  }

  function entropy(pw, size) {
    if (!pw || size <= 1) return 0;
    return pw.length * Math.log(size) / Math.log(2);
  }

  /* NOTE: the local accumulator must not be named `t` - it would shadow the
     translation helper above and throw "t is not a function". */
  function crackTime(bits) {
    var seconds = Math.pow(2, bits) / 1e10;
    var units = [["sec", 60], ["min", 60], ["hr", 24], ["day", 365], ["yr", 100], ["century", 10]];
    var val = seconds, label = "sec";
    for (var i = 0; i < units.length; i++) {
      if (val >= units[i][1]) { val /= units[i][1]; label = units[i][0]; }
      else break;
    }
    return val.toFixed(1) + " " + t("generator.unit." + label, label);
  }

  function updateStats(pw, size) {
    var bits = entropy(pw, size), key = "generator.strength.weak", fb = "Weak", pct = 25, col = "var(--danger)";
    if (bits >= 100)     { key = "generator.strength.excellent"; fb = "Excellent"; pct = 100; col = "var(--ok)"; }
    else if (bits >= 80) { key = "generator.strength.strong";    fb = "Strong";    pct = 78;  col = "var(--ok)"; }
    else if (bits >= 60) { key = "generator.strength.moderate";  fb = "Moderate";  pct = 55;  col = "var(--warn)"; }
    else if (bits < 40)  { key = "generator.strength.very_weak"; fb = "Very weak"; pct = 15;  col = "var(--danger)"; }
    var meter = document.getElementById("meter-fill");
    if (meter) { meter.style.transform = "scaleX(" + (pct / 100) + ")"; meter.style.background = col; }
    var el = document.getElementById("pw-stats");
    if (el) {
      el.textContent = t(key, fb) + " \\u00b7 ~" + bits.toFixed(1) + " " + t("generator.stats.bits", "bits") +
                       " \\u00b7 ~" + crackTime(bits) + " " + t("generator.stats.suffix", "to brute-force (est.)");
    }
  }

  function opts() {
    return {
      symbols: document.getElementById("symbols").checked,
      upper:   document.getElementById("upper").checked,
      lower:   document.getElementById("lower").checked,
      digits:  document.getElementById("digits").checked
    };
  }

  function mode() {
    var m = document.querySelector('input[name="gmode"]:checked');
    return m ? m.value : "secure";
  }

  function regen() {
    var len = parseInt(document.getElementById("len").value, 10) || 16, r;
    if (mode() === "easy") {
      var words = Math.min(8, Math.max(2, Math.round(len / 6)));
      document.getElementById("len-label").textContent = t("generator.words_prefix", "Words") + ": " + words;
      r = genEasy(words, opts());
    } else {
      if (len < 4) len = 4;
      document.getElementById("len-label").textContent = len;
      r = genSecure(len, opts());
    }
    document.getElementById("pw-out").textContent = r.pw;
    updateStats(r.pw, r.size);
  }

  window.SPM_regen = regen;
  window.SPM_copyPw = function () {
    var pw = document.getElementById("pw-out").textContent || "";
    if (pw) window.SPM_copy(pw, t("toast.copy_success", "Copied to clipboard."));
  };

  document.addEventListener("DOMContentLoaded", function () {
    ["len", "symbols", "upper", "lower", "digits"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener("input", regen);
    });
    document.querySelectorAll('input[name="gmode"]').forEach(function (el) {
      el.addEventListener("change", regen);
    });
    regen();
  });
})();
</script>
"""


def generator_page():
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="generator.title">Password Generator</h1>
    <div class="page-sub" data-i18n="section.generator_desc">Create strong passwords with length, mode, and symbol toggles.</div>
  </div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="/" data-i18n="link.back">Back</a>
  </div>
</div>
<div class="grid2">
  <div class="card"><div class="card-body">
    <div class="gen-out" id="pw-out">&nbsp;</div>
    <div class="meter"><i id="meter-fill"></i></div>
    <div class="faint" id="pw-stats" style="margin-top:var(--sp-3);text-align:center"
         data-i18n="generator.stats.placeholder">Adjust the options to see strength.</div>
    <div class="form-actions" style="justify-content:center">
      <button class="btn btn-primary" type="button" data-act="regen" data-i18n="generator.btn.regen">Regenerate</button>
      <button class="btn" type="button" data-act="copy-pw" data-i18n="generator.btn.copy">Copy</button>
    </div>
  </div></div>

  <div class="card"><div class="card-body">
    <div class="field">
      <label><span data-i18n="generator.length">Length</span> &middot; <b id="len-label">16</b></label>
      <input id="len" type="range" min="4" max="64" value="16">
    </div>
    <div class="field">
      <label data-i18n="generator.mode">Mode</label>
      <div style="display:flex;gap:var(--sp-4)">
        <label style="display:flex;gap:6px;align-items:center;font-weight:400">
          <input type="radio" name="gmode" value="secure" checked>
          <span data-i18n="generator.mode_secure">Secure</span></label>
        <label style="display:flex;gap:6px;align-items:center;font-weight:400">
          <input type="radio" name="gmode" value="easy">
          <span data-i18n="generator.mode_easy">Memorable</span></label>
      </div>
    </div>
    <div class="switch-row"><span data-i18n="generator.opt.upper">Uppercase</span><input id="upper" type="checkbox" checked></div>
    <div class="switch-row"><span data-i18n="generator.opt.lower">Lowercase</span><input id="lower" type="checkbox" checked></div>
    <div class="switch-row"><span data-i18n="generator.opt.digits">Digits</span><input id="digits" type="checkbox" checked></div>
    <div class="switch-row"><span data-i18n="generator.opt.symbols">Symbols</span><input id="symbols" type="checkbox" checked></div>
  </div></div>
</div>
{GENERATOR_SCRIPT}"""
    return render_shell(content, "generator", VERSION, VAULT_PATH, title="Password Generator")


EXPORT_FORMATS = ["csv", "json", "tsv", "ndjson", "jsonl", "md", "html", "txt", "yaml", "yml",
                  "xml", "sql", "ini", "psv", "rst", "toml", "org", "scsv", "csv-noheader", "jsonc"]


def transfer_page():
    opts = "".join(
        f'<option value="{f}">{f}{" (default)" if f == "csv" else ""}</option>'
        for f in EXPORT_FORMATS
    )
    # The import picker carries the Bitwarden entries as well, labelled so it
    # is obvious which file each one wants.
    bitwarden_labels = {
        "bitwarden-json": "Bitwarden — JSON export",
        "bitwarden-csv": "Bitwarden — CSV export",
        "bitwarden-protected": "Bitwarden — password-protected JSON",
    }
    import_opts = opts + "".join(
        f'<option value="{f}">{bitwarden_labels[f]}</option>'
        for f in BITWARDEN_FORMATS
    )
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="import.title">Export / Import</h1>
    <div class="page-sub" data-i18n="import.subtitle">Download or paste data (csv/json + extended formats).</div>
  </div>
</div>
<div class="grid2">
  <div class="card">
    <div class="card-head"><h2 data-i18n="import.download">Download</h2></div>
    <div class="card-body">
      <form method="get" action="/export">
        <div class="field">
          <label data-i18n="import.format_label">Format</label>
          <select class="input" name="fmt" id="import-fmt">{import_opts}</select>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="import.download">Download</button>
      </form>
    </div>
    <div class="card-foot"><span data-i18n="import.supports">Supports passwords, notes, passphrases, authenticators, backup codes.</span></div>
  </div>

  <div class="card" style="position:relative" id="import-card">
    <div class="overlay" id="import-overlay" aria-live="polite">
      <div class="overlay-in">
        <div class="spinner"></div>
        <div id="import-overlay-text" data-i18n="import.overlay_upload">Uploading...</div>
      </div>
    </div>
    <div class="card-head"><h2 data-i18n="import.submit">Import</h2></div>
    <div class="card-body">
      <form method="post" action="/import" enctype="multipart/form-data" id="import-form">
        <div class="field">
          <label data-i18n="import.import_label">Import format</label>
          <select class="input" name="fmt">{opts}</select>
        </div>
        <div class="field">
          <label data-i18n="import.upload_label">Upload export file</label>
          <input class="input" type="file" name="file">
        </div>
        <div class="field hidden" id="import-pw-field">
          <label data-i18n="import.export_password">Export password</label>
          <input class="input" type="password" name="export_password" autocomplete="off"
                 data-i18n-placeholder="import.export_password_hint"
                 placeholder="The password you set when exporting from Bitwarden">
          <div class="hint" data-i18n="import.export_password_note">Only needed for a password-protected Bitwarden export. It is used to read the file and is never stored.</div>
        </div>
        <div class="field">
          <label data-i18n="import.paste_label">Or paste file contents</label>
          <textarea class="input" name="data" rows="6"
                    data-i18n-placeholder="import.placeholder" placeholder="Paste exported data here"></textarea>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="import.submit">Import</button>
      </form>
    </div>
  </div>
</div>
<script>
(function () {{
  var form = document.getElementById("import-form");
  if (!form) return;
  // The export password applies to exactly one format, so asking for it the
  // rest of the time would be a field nobody can answer.
  var fmt = document.getElementById("import-fmt");
  var pwField = document.getElementById("import-pw-field");
  function syncPasswordField() {{
    if (!fmt || !pwField) return;
    pwField.classList.toggle("hidden", fmt.value !== "bitwarden-protected");
  }}
  if (fmt) fmt.addEventListener("change", syncPasswordField);
  syncPasswordField();
  form.addEventListener("submit", function () {{
    var ov = document.getElementById("import-overlay");
    if (ov) ov.classList.add("on");
    if (window.SPM_AutoLock) window.SPM_AutoLock.pause();
  }});
}})();
</script>"""
    return render_shell(content, "transfer", VERSION, VAULT_PATH, title="Export / Import")


def auth_view_page(aid, label, secret, period, algo, created):
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title">{html.escape(label)}</h1>
    <div class="page-sub"><span class="chip">{html.escape(period)}s</span> <span class="chip">{html.escape(algo).upper()}</span></div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/authenticator-edit?id={html.escape(aid)}" data-i18n="btn.edit">Edit</a>
    <a class="btn btn-ghost" href="/authenticators" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:520px;margin:0 auto">
  <div class="totp">
    <div class="totp-code" id="code">------</div>
    <div class="totp-ring" id="ring"><i></i></div>
    <div class="faint" id="cd" data-i18n="auth.status.no_code">Waiting for code...</div>
    <button class="btn btn-primary" type="button" data-act="copy-text" data-target="code"
            data-i18n="btn.copy_code">Copy code</button>
  </div>
  <div class="card-body" style="border-top:1px solid var(--border)">
    {_secret_block(secret, "auth.view.secret", "Secret", "sec")}
    <div class="field"><label data-i18n="auth.view.created">Created</label>
      <div class="faint mono">{html.escape(created) or "&mdash;"}</div></div>
  </div>
</div>
{REVEAL_SCRIPT}
<script>
(function () {{
  var id = {jsonlib.dumps(aid)}, period = {jsonlib.dumps(int(period) if str(period).isdigit() else 30)};
  var left = 0;
  function t(k, fb) {{ return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(k, fb) : fb; }}
  function paint() {{
    var ring = document.getElementById("ring");
    if (ring) ring.style.setProperty("--pct", Math.max(0, left / period * 100));
    var cd = document.getElementById("cd");
    if (cd) {{
      /* The catalogue strings carry an {{n}} placeholder ("Refreshes in {{n}}s",
         "{{n}}秒で更新") and t() does no interpolation, so substitute here or the
         placeholder renders literally next to a stray count. */
      var secs = Math.max(0, left);
      var tpl = t("auth.countdown.refresh_in", "Refreshes in {{n}}s");
      cd.textContent = tpl.indexOf("{{n}}") >= 0
        ? tpl.replace("{{n}}", secs)
        : tpl + " " + secs + "s";
    }}
  }}
  function fetchCode() {{
    fetch("/authenticator-code?id=" + encodeURIComponent(id), {{ credentials: "same-origin" }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        var code = document.getElementById("code");
        var nextCode = d.code || "------";
        if (code && code.textContent !== nextCode) {{
          code.textContent = nextCode;
          code.classList.remove("code-updated");
          if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {{
            requestAnimationFrame(function () {{ code.classList.add("code-updated"); }});
          }}
        }}
        left = d.expires_in || period;
        paint();
      }})
      .catch(function () {{
        var cd = document.getElementById("cd");
        if (cd) cd.textContent = t("auth.status.no_code", "No code available");
      }});
  }}
  fetchCode();
  setInterval(function () {{
    left -= 1;
    if (left <= 0) fetchCode(); else paint();
  }}, 1000);
}})();
</script>"""
    return render_shell(content, "authenticators", VERSION, VAULT_PATH, title=label)


# ----- The trusted core ------------------------------------------------------
# The vault format, key wrapping, vault mutation, history archiving and the
# recovery file all live in spm_core.py, which the CLI half of SPM uses too.
# This file used to carry its own copy of every one of them, and the regression
# suite carried a test whose only job was to prove the two copies still agreed.
# What remains here is the adapter: the dashboard's call sites keep their names
# and the core keeps the decisions.

def _load_core():
    import importlib.util
    bases = [os.environ.get("SPM_CORE_DIR")]
    try:
        # Normally the core sits beside this file, installed by the same
        # function that wrote it. __file__ is absent when something execs this
        # source rather than importing it, which the test suite does.
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    except NameError:
        pass
    bases.append(os.path.join(
        os.environ.get("XDG_DATA_HOME")
        or os.path.join(os.path.expanduser("~"), ".local", "share"), "spm"))
    for base in bases:
        if not base:
            continue
        candidate = os.path.join(base, "spm_core.py")
        if os.path.isfile(candidate):
            spec = importlib.util.spec_from_file_location("spm_core", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("spm_core.py was not found; run `spm web` to install it")


core = _load_core()

VAULT_FORMAT_VERSION = core.VAULT_FORMAT_VERSION
RECOVERY_PATH = core.recovery_path(VAULT_PATH)
_fsync_path = core._fsync_path
_fsync_dir = core._fsync_dir
stamp_vault_version = core.stamp_version
vault_format_version = core.format_version
recovery_pubkey_pem = core.recovery_pubkey_pem


def decrypt_vault_file(path: str, master: str) -> str:
    return core.read_vault(path, master)[0]


def decrypt_vault(master: str) -> str:
    return core.read_vault(VAULT_PATH, master)[0]


def load_vault(master: str, session=None) -> str:
    """Vault plaintext, reusing this session's unwrapped vault key when it can.

    A format-3 read costs two gpg invocations: the key envelope under the
    master password, then the data under that key. The envelope's answer is
    the same for every request of a session, so holding the key removes that
    half from every read after the first -- measured at roughly half the time
    of a full read.

    The key lives in the session record and nowhere else, so it dies with the
    session, at the same moment the master password does. It is not a new
    class of exposure: the session already holds the password it derives from.

    A cached key that no longer opens the vault is not an error. A restore or
    a sync can replace the file under a live session, so the fallback
    re-derives from the master and re-caches, and the session keeps working.

    This is an adapter, not vault crypto -- every byte operation below it is
    still the core's.
    """
    if session is not None:
        cached = session.get("vault_key")
        if cached:
            try:
                plaintext = core.read_vault_with_key(VAULT_PATH, cached)
                if plaintext is not None:
                    return plaintext
            except Exception:
                pass
        plaintext, key = core.read_vault(VAULT_PATH, master)
        session["vault_key"] = key or ""
        return plaintext
    return decrypt_vault(master)


def unwrap_vault_key(master: str, path=None):
    return core.unwrap_key(path or VAULT_PATH, master)


def encrypt_vault(master: str, plaintext: str, vault_key=None) -> str:
    return core.write_vault(VAULT_PATH, master, plaintext, vault_key)


def save_vault(master: str, plaintext: str, session=None) -> None:
    """Write the vault, handing the core the session's key when it has one.

    Given no key, write_vault unwraps one from the master password first --
    the same expensive invocation the read path avoids, paid again on every
    save. The write returns the key it used, which is also how a session that
    has just migrated a legacy vault picks one up.
    """
    key = session.get("vault_key") or None if session is not None else None
    written = encrypt_vault(master, plaintext, key)
    if session is not None:
        session["vault_key"] = written or ""


def rewrap_vault_key(old_master: str, new_master: str) -> None:
    core.rewrap(VAULT_PATH, old_master, new_master)


def _archive_vault_generation():
    core.archive_generation(VAULT_PATH)


def rewrite_recovery_file(plaintext: str, vault_key: str) -> None:
    core.install_recovery(
        VAULT_PATH, core.stage_recovery(VAULT_PATH, plaintext, vault_key))


# A master password shorter than this is refused on the way in. Dashboard
# policy, not vault format: the CLI has no floor at all, which is a gap rather
# than a decision worth copying, since this is the one password that protects
# every other one and nothing rate-limits an attacker who holds the vault file.
MASTER_MIN_LEN = 12



def totp_code(secret_b32: str, period: int = 30, algo: str = "sha1") -> str:
    import hashlib, hmac, struct, base64
    secret = secret_b32.replace(" ", "").upper()
    if not secret:
        return ""
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(time.time() // max(period, 1))
    msg = struct.pack(">Q", counter)
    algo = (algo or "sha1").lower()
    digest_mod = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}.get(algo, hashlib.sha1)
    h = hmac.new(key, msg, digest_mod).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
    return str(code_int % 10**6).zfill(6)

SUPPORTED_FORMATS = ("csv","json","tsv","ndjson","jsonl","md","markdown","html","txt","yaml","yml","xml","sql","ini","psv","rst","toml","org","scsv","csv-noheader","jsonc",
                     "bitwarden-json","bitwarden-csv","bitwarden-protected")

# Import-only. There is no exporting *to* Bitwarden, so these belong in the
# import picker and nowhere else.
BITWARDEN_FORMATS = ("bitwarden-json", "bitwarden-csv", "bitwarden-protected")

def _export_rows(plaintext: str):
    import base64, html as htmlmod
    rows = []
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag.isdigit():  # password
            rows.append({
                "type": "password",
                "id": parts[0],
                "label": parts[1] if len(parts) > 1 else "",
                "username": parts[2] if len(parts) > 2 else "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": parts[4] if len(parts) > 4 else "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": "",
                "url": parts[6] if len(parts) > 6 else ""
            })
        elif tag == "NOTE":
            rows.append({
                "type": "note",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "PASSPHRASE":
            rows.append({
                "type": "passphrase",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "BACKUP_CODE":
            rows.append({
                "type": "backup_code",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "AUTH":
            rows.append({
                "type": "authenticator",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": f"period={parts[4] if len(parts)>4 else ''};algo={parts[6] if len(parts)>6 else 'sha1'}",
                "url": ""
            })
    return rows

def export_content(fmt: str, plaintext: str):
    import csv, json, html as htmlmod, io
    rows = _export_rows(plaintext)
    fieldnames = ["type","id","label","username","secret","notes","created","extra","url"]
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(rows, ensure_ascii=False, indent=2)
    if fmt in ("ndjson","jsonl"):
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
    if fmt == "tsv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt in ("md","markdown"):
        out = ["| " + " | ".join(fieldnames) + " |", "|" + "|".join([" --- "]*len(fieldnames)) + "|"]
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            out.append("| " + " | ".join(cells) + " |")
        return "\n".join(out) + "\n"
    if fmt == "html":
        out = ["<table border='1' cellpadding='4' cellspacing='0'>", "<tr>" + "".join(f"<th>{htmlmod.escape(k)}</th>" for k in fieldnames) + "</tr>"]
        for r in rows:
            out.append("<tr>" + "".join(f"<td>{htmlmod.escape(str(r.get(k,'') or ''))}</td>" for k in fieldnames) + "</tr>")
        out.append("</table>")
        return "\n".join(out)
    if fmt == "toml":
        out=[]
        for r in rows:
            out.append("[[item]]")
            for k in fieldnames:
                val = str(r.get(k, "") or "").replace("\\","\\\\").replace("\n","\\n").replace('"','\\"')
                out.append(f'{k} = "{val}"')
            out.append("")
        return "\n".join(out)
    if fmt == "org":
        header = "| " + " | ".join(fieldnames) + " |"
        sep = "|" + "+".join("-" * (len(k)+2) for k in fieldnames) + "|"
        out = [header, sep]
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            out.append("| " + " | ".join(cells) + " |")
        return "\n".join(out) + "\n"
    if fmt == "scsv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=";")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt == "csv-noheader":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=",")
        writer.writerows(rows)
        return buf.getvalue()
    if fmt == "jsonc":
        import json
        return json.dumps(rows, ensure_ascii=False)
    if fmt in ("yaml","yml"):
        out=[]
        for r in rows:
            out.append("-")
            for k in fieldnames:
                val = str(r.get(k, "") or "")
                out.append(f"  {k}: {json.dumps(val, ensure_ascii=False)}")
        return "\n".join(out) + "\n"
    if fmt == "xml":
        out=["<?xml version=\"1.0\" encoding=\"UTF-8\"?>","<data>"]
        for r in rows:
            out.append("  <item>")
            for k in fieldnames:
                val = htmlmod.escape(str(r.get(k,"") or ""))
                out.append(f"    <{k}>{val}</{k}>")
            out.append("  </item>")
        out.append("</data>")
        return "\n".join(out)
    if fmt == "sql":
        out=["CREATE TABLE spm_export(type TEXT,id TEXT,label TEXT,username TEXT,secret TEXT,notes TEXT,created TEXT,extra TEXT);"]
        for r in rows:
            vals=[str(r.get(k,"") or "") for k in fieldnames]
            safe=[v.replace("'", "''") for v in vals]
            out.append("INSERT INTO spm_export(type,id,label,username,secret,notes,created,extra) VALUES ('%s');" % ("','".join(safe)))
        return "\n".join(out) + "\n"
    if fmt == "ini":
        out=[]
        for r in rows:
            sect = f"{r.get('type','unknown')}_{r.get('id','')}"
            out.append(f"[{sect}]")
            for k in fieldnames:
                val = json.dumps(str(r.get(k,'') or ''), ensure_ascii=False)
                out.append(f"{k}={val}")
            out.append("")
        return "\n".join(out)
    if fmt == "psv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter="|")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt == "rst":
        encoded_rows=[{k:json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames} for r in rows]
        widths={k:max(len(k), max(len(r[k]) for r in encoded_rows) if encoded_rows else 0) for k in fieldnames}
        def sep(char="+"):
            return char + char.join("-" * (widths[k]+2) for k in fieldnames) + char
        def row(vals):
            return "|" + "|".join(" " + v.ljust(widths[k]) + " " for k,v in vals) + "|"
        out=[sep(), row([(k,k) for k in fieldnames]), sep("+")]
        for r in encoded_rows:
            out.append(row([(k, r[k]) for k in fieldnames]))
            out.append(sep())
        return "\n".join(out) + "\n"
    # default csv/txt
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=",")
    writer.writeheader(); writer.writerows(rows)
    return buf.getvalue()

def _parse_import_rows(fmt: str, content: str):
    import configparser, csv, json, re
    import xml.etree.ElementTree as ET
    from html.parser import HTMLParser
    fmt = fmt.lower()
    if fmt in ("json","jsonc"):
        return json.loads(content)
    if fmt in ("ndjson","jsonl"):
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    if fmt == "html":
        class TableParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.rows=[]; self.row=[]; self.cell=[]; self.in_cell=False
            def handle_starttag(self, tag, attrs):
                if tag.lower() in ("td", "th"): self.in_cell=True; self.cell=[]
            def handle_data(self, data):
                if self.in_cell: self.cell.append(data)
            def handle_endtag(self, tag):
                tag=tag.lower()
                if tag in ("td", "th") and self.in_cell:
                    self.row.append("".join(self.cell)); self.in_cell=False
                elif tag == "tr" and self.row:
                    self.rows.append(self.row); self.row=[]
        parser=TableParser(); parser.feed(content)
        if not parser.rows: return []
        return [dict(zip(parser.rows[0], row)) for row in parser.rows[1:]]
    if fmt in ("yaml", "yml"):
        rows=[]; current=None
        for line in content.splitlines():
            if line.strip() == "-":
                if current is not None: rows.append(current)
                current={}
            elif current is not None and ":" in line:
                key, value=line.strip().split(":", 1)
                value=value.strip()
                try: value=json.loads(value)
                except json.JSONDecodeError: value=value.strip('"')
                current[key]=value
        if current is not None: rows.append(current)
        return rows
    if fmt == "xml":
        root=ET.fromstring(content)
        return [{child.tag: (child.text or "") for child in item} for item in root.findall("item")]
    if fmt == "sql":
        rows=[]; fields=["type","id","label","username","secret","notes","created","extra","url"]
        for values in re.findall(r"INSERT\s+INTO\s+spm_export\s*\([^)]*\)\s*VALUES\s*\((.*?)\)\s*;", content, re.I | re.S):
            parsed=next(csv.reader([values], delimiter=",", quotechar="'", doublequote=True, skipinitialspace=True))
            rows.append(dict(zip(fields, parsed)))
        return rows
    if fmt == "ini":
        cfg=configparser.ConfigParser(interpolation=None); cfg.optionxform=str; cfg.read_string(content)
        return [{k: (json.loads(v) if v.startswith('"') and v.endswith('"') else v) for k,v in cfg.items(section)} for section in cfg.sections()]
    if fmt == "toml":
        import tomllib
        return tomllib.loads(content).get("item", [])
    delim = "," if fmt in ("csv","csv-noheader","jsonc","txt") else ";" if fmt=="scsv" else "\t" if fmt=="tsv" else "|"
    rows=[]
    if fmt=="csv-noheader":
        # StringIO, not splitlines(): csv needs the embedded newlines intact
        # to reassemble quoted multi-line fields into a single row.
        reader = csv.reader(io.StringIO(content), delimiter=delim)
        for row in reader:
            rows.append({
                "type": row[0] if len(row)>0 else "",
                "id": row[1] if len(row)>1 else "",
                "label": row[2] if len(row)>2 else "",
                "username": row[3] if len(row)>3 else "",
                "secret": row[4] if len(row)>4 else "",
                "notes": row[5] if len(row)>5 else "",
                "created": row[6] if len(row)>6 else "",
                "extra": row[7] if len(row)>7 else "",
                "url": row[8] if len(row)>8 else "",
            })
        return rows
    reader = csv.DictReader(io.StringIO(content), delimiter=delim)
    return list(reader)

def _detect_bitwarden(fmt: str, content: str):
    """The bitwarden-* format this content really is, or "" if it is not one."""
    import csv as csvlib
    if fmt in ("json", "jsonc"):
        try:
            payload = jsonlib.loads(content)
        except Exception:
            return ""
        if isinstance(payload, dict) and payload.get("encrypted"):
            return "bitwarden-protected"
        if core.looks_like_bitwarden_json(payload):
            return "bitwarden-json"
        return ""
    if fmt == "csv":
        try:
            reader = csvlib.DictReader(io.StringIO(content))
            if core.looks_like_bitwarden_csv_header(reader.fieldnames):
                return "bitwarden-csv"
        except Exception:
            return ""
    return ""


def _bitwarden_import_rows(fmt: str, content: str, export_password: str = ""):
    """Rows in SPM's import schema from any of Bitwarden's three export files.

    The mapping itself lives in the core, so the CLI and the dashboard cannot
    come to different conclusions about what a Bitwarden file contains.
    """
    import csv as csvlib
    if fmt == "bitwarden-csv":
        reader = csvlib.DictReader(io.StringIO(content))
        return core.bitwarden_csv_rows(list(reader))

    payload = jsonlib.loads(content)
    if fmt == "bitwarden-protected" or (isinstance(payload, dict) and payload.get("encrypted")):
        if not export_password:
            raise ValueError("This export is password-protected. Enter the export password.")
        payload = jsonlib.loads(core.decrypt_bitwarden_export(payload, export_password))
    if not core.looks_like_bitwarden_json(payload):
        raise ValueError("This does not look like a Bitwarden JSON export.")
    return core.bitwarden_rows(payload)


def _apply_import(fmt: str, content: str, plaintext: str, export_password: str = ""):
    import base64
    tab = "\t"
    fmt = fmt.lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError("Unsupported format")

    def next_id(tag, lines):
        max_id = 0
        for ln in lines:
            if not ln:
                continue
            parts = ln.split(tab)
            if tag == "PASS" and parts[0].isdigit():
                max_id = max(max_id, int(parts[0]))
            elif parts[0] == tag and len(parts) > 1 and parts[1].isdigit():
                max_id = max(max_id, int(parts[1]))
        return max_id + 1

    lines = plaintext.splitlines()

    stats = {"passwords": 0, "notes": 0, "passphrases": 0, "backups": 0, "authenticators": 0}

    def _vurl(value):
        # Same allowlist as sanitize_url in the CLI. An import is the least
        # trusted way a value enters the vault, so a foreign CSV carrying
        # "javascript:..." in its url column is dropped rather than stored --
        # the field renders as a link and will feed the browser extension.
        text = _vf(value).strip()
        if not text:
            return ""
        return text if re.match(r"(?i)^https?://[^\s/]+", text) else ""

    def add_password(r):
        pid = str(next_id("PASS", lines))
        lines.append(tab.join([
            pid,
            _vf(r.get("label","")),
            _vf(r.get("username","")),
            _vf(r.get("secret","")),
            _vf(r.get("notes","")),
            _vf(r.get("created","")),
            _vurl(r.get("url",""))
        ]))
        stats["passwords"] += 1

    def add_note(r):
        nid = str(next_id("NOTE", lines))
        body_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "NOTE",
            nid,
            _vf(r.get("label","")),
            body_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["notes"] += 1

    def add_passphrase(r):
        pid = str(next_id("PASSPHRASE", lines))
        secret_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "PASSPHRASE",
            pid,
            _vf(r.get("label","")),
            secret_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["passphrases"] += 1

    def add_backup(r):
        bid = str(next_id("BACKUP_CODE", lines))
        codes_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "BACKUP_CODE",
            bid,
            _vf(r.get("label","")),
            codes_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["backups"] += 1

    def add_auth(r):
        aid = str(next_id("AUTH", lines))
        extra = str(r.get("extra","") or "")
        algo = "sha1"
        if "algo=" in extra:
            for part in extra.split(";"):
                if part.startswith("algo="):
                    algo = part.split("=",1)[1] or "sha1"
        algo = (r.get("algorithm","") or algo or "sha1").lower()
        if algo not in ("sha1","sha256","sha512"):
            algo = "sha1"
        period_val = ""
        if "period=" in extra:
            for part in extra.split(";"):
                if part.startswith("period="):
                    period_val = part.split("=",1)[1]
        period_val = period_val or str(r.get("period","") or r.get("extra","")).replace("period=","") or "30"
        lines.append(tab.join([
            "AUTH",
            aid,
            _vf(r.get("label","")),
            _vf(r.get("secret","")),
            _vf(period_val or "30"),
            _vf(r.get("created","")),
            algo
        ]))
        stats["authenticators"] += 1

    def parse_plain_table(text):
        import json
        rows=[]
        headers=None
        for ln in text.splitlines():
            ln=ln.strip()
            if not ln or ln.startswith("#") or ln.startswith("| ---") or ln.startswith("+"):
                continue
            if "|" in ln:
                parts=[p.strip() for p in ln.strip("|").split("|")]
            else:
                parts=[p.strip() for p in ln.split()]
            if len(parts) < 2:
                continue
            if parts[0].lower() == "type":
                headers=[p.lower() for p in parts]
                continue
            parts=[json.loads(p) if p.startswith('"') and p.endswith('"') else p for p in parts]
            if headers:
                rows.append(dict(zip(headers, parts)))
            else:
                rows.append({
                    "type": parts[0],
                    "label": parts[1] if len(parts)>1 else "",
                    "username": parts[2] if len(parts)>2 else "",
                    "secret": parts[3] if len(parts)>3 else "",
                    "notes": parts[4] if len(parts)>4 else "",
                    "created": parts[5] if len(parts)>5 else "",
                    "extra": parts[6] if len(parts)>6 else "",
                    "url": parts[7] if len(parts)>7 else "",
                })
        return rows

    if fmt in BITWARDEN_FORMATS:
        rows = _bitwarden_import_rows(fmt, content, export_password)
    elif fmt in ("json","jsonc","ndjson","jsonl","csv","csv-noheader","tsv","scsv","psv","txt","html","yaml","yml","xml","sql","ini","toml"):
        # A Bitwarden file picked as plain json or csv is still a Bitwarden
        # file. Detecting it rather than failing means choosing the wrong entry
        # in the dropdown is not a silent, partial import -- which is what a
        # Bitwarden CSV used to produce: one empty note and every login lost.
        detected = _detect_bitwarden(fmt, content)
        rows = (_bitwarden_import_rows(detected, content, export_password)
                if detected else _parse_import_rows(fmt, content))
    else:
        rows = parse_plain_table(content)

    if not rows:
        raise ValueError("No records detected in upload.")

    types_seen = set()
    for row in rows:
        t = (row.get("type","") or "").lower()
        if t:
            types_seen.add(t)
        if t in ("password","pass",""):
            add_password(row)
        elif t in ("note","notes"):
            add_note(row)
        elif t in ("passphrase","phrase","secret"):
            add_passphrase(row)
        elif t in ("backup_code","backup","codes","backupcode"):
            add_backup(row)
        elif t in ("authenticator","auth"):
            add_auth(row)

    total_added = sum(stats.values())
    if total_added == 0:
        raise ValueError("No supported records found in upload.")
    return "\n".join(lines) + "\n", stats

def parse_multipart(body_bytes: bytes, content_type: str):
	"""
	Minimal multipart/form-data parser using email.parser (avoids deprecated cgi).
	Returns dict name -> raw bytes.
	"""
	ctype = (content_type or "")
	if "multipart/form-data" not in ctype.lower():
		return {}
	boundary = ""
	for part in ctype.split(";"):
		part = part.strip()
		if part.lower().startswith("boundary="):
			boundary = part.split("=", 1)[1].strip()
			if boundary.startswith('"') and boundary.endswith('"'):
				boundary = boundary[1:-1]
			break
	if not boundary:
		return {}
	header = f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n".encode("utf-8", "ignore")
	msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(header + body_bytes)
	out = {}
	for part in msg.iter_parts():
		name = part.get_param("name", header="content-disposition") or ""
		if not name:
			continue
		payload = part.get_payload(decode=True) or b""
		out[name] = payload
	return out

def parse_entries(plaintext: str):
    """Password entries.

    A password row is identified the way the CLI identifies one: field 1 is a
    number. Listing every other row type by prefix was a denylist, and it had
    already fallen behind -- ATTACHMENT and PASSKEY rows are both six fields or
    longer, so they were being listed as passwords with their base64 payload
    sitting in the password column, and counted in the security score. Anything
    SPM adds later is excluded by default now instead of by remembering to add
    it here.
    """
    lines = plaintext.splitlines()
    entries = []
    for idx, line in enumerate(lines):
        if not line or line.startswith("#") or line.startswith("META_"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6 and parts[0].isdigit():
            entries.append((idx, parts))
    return lines, entries

def parse_notes(plaintext: str):
    """Secure notes with prefix NOTE."""
    lines = plaintext.splitlines()
    notes = []
    for idx, line in enumerate(lines):
        if not line.startswith("NOTE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            notes.append((idx, parts))
    return lines, notes

def parse_passphrases(plaintext: str):
    """Passphrases stored as PASSPHRASE rows."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("PASSPHRASE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items

def parse_backup_codes(plaintext: str):
    """Backup codes stored as BACKUP_CODE rows."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("BACKUP_CODE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items

def parse_authenticators(plaintext: str):
    """Authenticators stored as AUTH rows (TOTP)."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("AUTH\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items


def parse_webauthn(plaintext: str):
    """Unlock credentials stored as WEBAUTHN rows.

    Deliberately a separate row type from PASSKEY. A PASSKEY row is metadata
    about a passkey held somewhere else -- `spm passkey-add` says as much when
    it prints "private key remains in the platform authenticator". These are
    credentials to this vault, and listing SPM's own unlock keys in
    `spm passkey-list` would be actively misleading.

    Layout: WEBAUTHN, id, credential_id (b64url), public key (SPKI, b64),
    rp_id, label, created.
    """
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("WEBAUTHN\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            items.append((idx, parts))
    return lines, items


def _b64url_decode(value):
    """Decode base64url without padding, rejecting anything else."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    stripped = value.strip()
    if not stripped or not re.match(r"^[A-Za-z0-9_-]+=*$", stripped):
        raise ValueError("not base64url")
    padding = "=" * (-len(stripped.rstrip("=")) % 4)
    return base64.urlsafe_b64decode(stripped.rstrip("=") + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _spki_to_pem(spki_der: bytes) -> str:
    body = base64.b64encode(spki_der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def verify_es256(spki_der: bytes, signature: bytes, signed: bytes) -> bool:
    """Verify an ES256 signature against an SPKI public key.

    Python's standard library has no asymmetric verify, and this server has no
    third-party dependencies. openssl is already a hard requirement of SPM (it
    backs the recovery-key flow), so verification shells out the same way vault
    access already shells out to gpg.

    Only public data touches the filesystem here: an SPKI public key, a
    signature and the signed bytes. No secret is written.
    """
    if not spki_der or not signature or not signed:
        return False
    tmpdir = tempfile.mkdtemp(prefix="spm-webauthn-")
    try:
        pem_path = os.path.join(tmpdir, "key.pem")
        sig_path = os.path.join(tmpdir, "sig.der")
        msg_path = os.path.join(tmpdir, "msg.bin")
        with open(pem_path, "w", encoding="ascii") as handle:
            handle.write(_spki_to_pem(spki_der))
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        with open(msg_path, "wb") as handle:
            handle.write(signed)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pem_path,
             "-signature", sig_path, msg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except (OSError, ValueError):
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_authenticator_data(auth_data: bytes):
    """Split the fixed header of an authenticatorData blob.

    Only the header is needed: the RP id hash, the flag byte and the signature
    counter. Attested credential data and extensions sit past byte 37 and are
    not parsed, which is what keeps this server free of a CBOR decoder.
    """
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short")
    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    return rp_id_hash, flags, sign_count


def check_authenticator_data(auth_data: bytes):
    """Common authenticatorData checks for both ceremonies.

    User verification is required, not merely user presence. Without the UV
    check a bare tap on the authenticator satisfies the ceremony and Face ID
    becomes decoration on top of an unlock anyone holding the phone can do.
    """
    rp_id_hash, flags, sign_count = parse_authenticator_data(auth_data)
    if not hmac.compare_digest(rp_id_hash, hashlib.sha256(WEBAUTHN_RP_ID.encode("utf-8")).digest()):
        return None, "relying party mismatch"
    if not flags & 0x01:
        return None, "user presence flag not set"
    if not flags & 0x04:
        return None, "user verification flag not set"
    return sign_count, ""


def check_client_data(raw_json: bytes, expected_type: str, expected_challenge: bytes):
    """Validate clientDataJSON for either ceremony."""
    try:
        data = jsonlib.loads(raw_json.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "malformed clientDataJSON"
    if not isinstance(data, dict):
        return "malformed clientDataJSON"
    if data.get("type") != expected_type:
        return "wrong ceremony type"
    try:
        supplied = _b64url_decode(data.get("challenge") or "")
    except ValueError:
        return "malformed challenge"
    if not hmac.compare_digest(supplied, expected_challenge):
        return "challenge mismatch"
    # The Origin *header* is "null" inside an iOS home-screen web app, which is
    # why _write_authorized has a branch for it. The origin recorded in
    # clientDataJSON is the real one even there, so it can be compared exactly.
    if data.get("origin") != WEBAUTHN_ORIGIN:
        return "origin mismatch"
    return ""


def rotation_days():
    """Age after which a password is flagged for rotation."""
    try:
        value = int(os.environ.get("SPM_ROTATION_DAYS", "365"))
    except ValueError:
        return 365
    return value if value > 0 else 365


def _entry_age_days(created, now):
    """Age of a record in days, or None when the timestamp is unreadable."""
    try:
        stamp = time.mktime(time.strptime(created.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return None
    return (now - stamp) / 86400.0


def compute_security(entries, plaintext):
    """Score the vault and name the offending IDs.

    The CLI's `spm security-dashboard` and this function have to agree: two
    copies of the same weighting drifted apart once already (the CLI penalised
    malformed authenticators, the web did not, so the same vault scored
    differently depending on where you looked). This is now the single
    implementation for the SPM Dashboard, and the regression suite asserts parity with
    the CLI.

    Secrets are read to compare and measure them; only IDs are ever returned.
    """
    now = time.time()
    limit = rotation_days()
    seen = {}
    weak, old, incomplete, malformed = [], [], [], []
    for _, item in entries:
        rid = item[0]
        secret = item[3] if len(item) > 3 else ""
        seen.setdefault(secret, []).append(rid)
        classes = sum(bool(re.search(pattern, secret))
                      for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        if len(secret) < 12 or classes < 3:
            weak.append(rid)
        if not item[1] or not item[2]:
            incomplete.append(rid)
        age = _entry_age_days(item[5] if len(item) > 5 else "", now)
        if age is not None and age > limit:
            old.append(rid)
    for line in plaintext.split("\n"):
        if not line.startswith("AUTH\t"):
            continue
        parts = line.split("\t")
        if len(parts) < 7 or parts[6] not in ("sha1", "sha256", "sha512") or not parts[3]:
            malformed.append(parts[1] if len(parts) > 1 else "?")
    reused = [ids for secret, ids in seen.items() if secret and len(ids) > 1]
    reused_flat = [rid for ids in reused for rid in ids]
    penalty = min(100, len(weak) * 12 + len(reused_flat) * 10
                  + len(old) * 4 + len(incomplete) * 3 + len(malformed) * 8)
    return {
        "score": max(0, 100 - penalty),
        "weak": weak,
        "reused": reused,
        "reused_flat": reused_flat,
        "old": old,
        "incomplete": incomplete,
        "malformed": malformed,
        "rotation_days": limit,
    }


# A tag is a #word in a plaintext field. The lookbehind keeps "C#" and the
# fragment in "http://host/page#anchor" from becoming tags.
_TAG_RE = re.compile(r"(?<!\S)#([A-Za-z0-9][\w-]{0,31})")


def extract_tags(*fields):
    """Tags parsed from plaintext fields only -- never from a secret.

    SPM has no tag column. Rather than migrate every record, tags are a
    convention inside fields the user already edits: a password's service name
    and notes, and the title/label of every other record type. Secret fields
    and base64 bodies are never scanned, so a tag can never be a secret.
    """
    found = []
    for text in fields:
        for tag in _TAG_RE.findall(text or ""):
            tag = tag.lower()
            if tag not in found:
                found.append(tag)
    return found


def entry_tags(parts):
    """Tags for a password row: service name (field 2) and notes (field 5)."""
    name = parts[1] if len(parts) > 1 else ""
    notes = parts[4] if len(parts) > 4 else ""
    return extract_tags(name, notes)


def search_vault(plaintext, term):
    """Search every record type by label, name, username, url and id.

    Secret fields are deliberately not searched. If a query could match a
    password, the result count would answer "is this string in the vault?" for
    anyone who reached an unlocked session -- a confirmation oracle. The url is
    safe to index for the same reason the label is: it is not a secret, it is
    already shown on the entry page, and matching it is how you find the login
    for a site you are looking at.
    """
    needle = (term or "").strip().lower()
    if not needle:
        return []
    out = []
    _, entries = parse_entries(plaintext)
    for _, p in entries:
        url = p[6] if len(p) > 6 else ""
        if needle in " ".join((p[0], p[1], p[2], url)).lower():
            out.append(("nav.passwords", "Password", p[0], p[1], f"/view?id={urllib.parse.quote(p[0])}"))
    for kind_key, kind, parser, href in (
            ("nav.notes", "Note", parse_notes, "/notes-view?id="),
            ("nav.passphrases", "Passphrase", parse_passphrases, "/passphrase-view?id="),
            ("nav.backup_codes", "Backup codes", parse_backup_codes, "/backup-codes-view?id="),
            ("nav.authenticators", "Authenticator", parse_authenticators, "/authenticator-view?id=")):
        _, items = parser(plaintext)
        for _, p in items:
            rid = p[1] if len(p) > 1 else ""
            label = p[2] if len(p) > 2 else ""
            if needle in (rid + " " + label).lower():
                out.append((kind_key, kind, rid, label, href + urllib.parse.quote(rid)))
    return out


def _history_dir():
    """Where the CLI keeps encrypted vault generations.

    Must stay identical to _archive_vault_generation() below and to the CLI's
    history_dir(); a mismatch would silently show an empty history rather than
    fail, so both derivations live here.
    """
    data_dir = os.environ.get("SPM_DATA_DIR") or os.path.join(
        os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"), "spm")
    scope = hashlib.sha256(os.path.abspath(VAULT_PATH).encode("utf-8")).hexdigest()[:16]
    return os.path.join(data_dir, "history", scope)


# Snapshot names are generated, so they can be matched exactly rather than
# screened for traversal: an allowlist cannot be talked past with "..%2f".
_SNAPSHOT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}\.[0-9]+\.[0-9a-f]{6,64}\.gpg$")


def list_history_snapshots():
    """Newest-first list of (name, taken_utc, size) for the current vault.

    Ordered and dated by the timestamp inside the filename, not by mtime.
    Snapshots are made with shutil.copy2, which copies the *source* file's
    mtime, so an mtime sort returns the age of the vault each snapshot came
    from rather than the order they were taken -- which put an older snapshot
    at the top of the list. The name is generated as UTC %Y%m%dT%H%M%S, so a
    lexical sort on it is chronological.
    """
    hist = _history_dir()
    out = []
    try:
        names = os.listdir(hist)
    except OSError:
        return out
    for name in names:
        if not _SNAPSHOT_RE.match(name):
            continue
        try:
            size = os.stat(os.path.join(hist, name)).st_size
        except OSError:
            continue
        out.append((name, name.split(".", 1)[0], size))
    out.sort(key=lambda row: row[0], reverse=True)
    return out


class SPMServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}  # token -> {"master", "vault_key", "created", "last_seen", "state", ...}
        self.login_failures = {}  # client ip -> {"count": int, "until": float}
        self.webauthn_counters = {}  # credential id -> highest signature counter seen
        self.auth_lock = threading.RLock()
        # Every mutation is a decrypt -> modify -> encrypt transaction. Without
        # one lock around that whole sequence, concurrent requests calculate the
        # same next ID, overwrite each other's records, and race on .webtmp.
        self.vault_lock = threading.RLock()
        self.vault_lock_file = open(VAULT_PATH + ".lock", "a+", encoding="utf-8")
        os.chmod(VAULT_PATH + ".lock", 0o600)

# Idle timeout enforced by the server. The 30-second auto-lock users actually
# see is implemented in the browser, which means it is not a control at all
# against a client whose JavaScript does not run -- and that is not a
# hypothetical: a CDN rewriting inline scripts disabled it outright once. This
# is the backstop that holds when the browser lock does not. It cannot match
# the browser's 30 seconds, because the browser resets on mouse and touch
# activity that reaches no server; 5 minutes is long enough to read a page and
# far short of the half hour this used to grant.
SESSION_TTL = 300
# Absolute lifetime: the idle TTL above slides on every request, so without
# this a session (and the plaintext master password it holds) could live for
# as long as the browser kept poking it.
SESSION_MAX_AGE = 12 * 3600
# A suspended session still holds the plaintext master password in memory so a
# biometric can resume it without a retyped password. That memory residency is
# the entire cost of the feature, so it is bounded separately and does not
# slide: once this much time has passed since the screen locked, the session is
# swept and the master password is required again. SESSION_MAX_AGE still caps
# the total -- an unlock never resets "created".
def _suspend_max_age():
    try:
        value = int(os.environ.get("SPM_WEB_SUSPEND_MAX", "28800"))
    except ValueError:
        return 28800
    # Zero or negative would mean "resumable forever" if used as a comparison
    # bound; treat anything nonsensical as the default rather than as no limit.
    return value if 0 < value <= SESSION_MAX_AGE else 28800

SUSPEND_MAX_AGE = _suspend_max_age()
# Web mode can bind beyond loopback, so an unauthenticated master-password
# guess has to cost something. Lock a client out briefly once it burns through
# this many attempts.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
MAX_POST_BYTES = 2 * 1024 * 1024
MAX_IMPORT_BYTES = 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    # Set per request by _get_cookie_session(). None on every unauthenticated
    # path, which is what makes the vault helpers fall back to the master.
    _session_rec = None

    def log_message(self, fmt, *args):
        sys.stderr.write("[SPM Dashboard] " + fmt % args + "\n")

    def end_headers(self):
        # Decrypted credentials and one-time codes must never enter browser or
        # proxy caches. Apply the baseline to every response, including JSON,
        # downloads, redirects, and errors produced by BaseHTTPRequestHandler.
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # script-src carried 'unsafe-inline' until every inline handler was
        # replaced by a delegated listener. The remaining <script> blocks are
        # stamped with this response's nonce in _send_html.
        nonce = getattr(self, "_csp_nonce", "")
        script_src = "'self' 'nonce-%s'" % nonce if nonce else "'self'"
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src " + script_src + "; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    _POST_FORM_RE = re.compile(r'(<form\b[^>]*\bmethod="post"[^>]*>)', re.IGNORECASE)
    _SCRIPT_RE = re.compile(r'<script(?![^>]*\bnonce=)([^>]*)>', re.IGNORECASE)

    def _send_html(self, code, body):
        lang = html.escape(self._get_lang())
        if "__LANG__" in body:
            body = body.replace("__LANG__", lang)
        if "__SPM_UNLOCK__" in body:
            _, session = self._session_record()
            available = bool(
                WEBAUTHN_ENABLED and session is not None
                and session.get("has_cred")
            )
            body = body.replace("__SPM_UNLOCK__", jsonlib.dumps({
                "available": available,
                "csrf": (session or {}).get("csrf", ""),
            }))
        # A fresh nonce per response, stamped centrally so a page added later
        # cannot ship a script the CSP will refuse.
        #
        # data-cfasync="false" rides along because a CDN in front of this server
        # may rewrite inline scripts. Cloudflare's Rocket Loader replaces every
        # <script> type with a private token so the browser skips it, then
        # re-injects the code itself -- and the re-injected copy carries no
        # nonce, so our own CSP refuses it. The result is a page with no
        # JavaScript at all: the mobile nav never opens and, far worse, the
        # idle auto-lock never runs, because that lock lives entirely in the
        # browser. data-cfasync="false" is the documented opt-out and is inert
        # everywhere else, so it costs nothing to send unconditionally.
        self._csp_nonce = secrets.token_urlsafe(16)
        body = self._SCRIPT_RE.sub(
            lambda m: '<script nonce="%s" data-cfasync="false"%s>'
            % (self._csp_nonce, m.group(1)), body)
        # Stamp every POST form centrally rather than in each builder, so a
        # form added later cannot silently ship without a token.
        csrf = self._session_csrf()
        if csrf:
            field = '<input type="hidden" name="csrf" value="%s">' % csrf
            body = self._POST_FORM_RE.sub(lambda m: m.group(1) + field, body)
        self.send_response(code)
        self._add_cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_asset(self, content_type, body):
        # Static bytes: no session, no language substitution, and no CORS
        # headers, unlike _send_html above.
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_cookie_attrs(self):
        # A "Secure" cookie is withheld by browsers on plain HTTP, and this
        # server never speaks TLS itself. Sending it unconditionally made login
        # impossible on the non-loopback binds (0.0.0.0 / custom IP) that web
        # mode offers: the browser silently drops the session cookie and the
        # user is bounced back to the login form forever. Mark it Secure only
        # when the browser's origin really is HTTPS, i.e. behind a TLS reverse
        # proxy that sets X-Forwarded-Proto.
        proto = (self.headers.get("X-Forwarded-Proto", "") or "").split(",")[0].strip().lower()
        attrs = "HttpOnly; Path=/; SameSite=Strict"
        if proto == "https":
            attrs += "; Secure"
        return attrs

    def _expire_session(self):
        """Drop a session whose master password no longer opens the vault."""
        self.send_response(302)
        self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
        self.send_header("Location", "/login")
        self.end_headers()
        return

    def _counts(self, plaintext):
        """Sidebar badge counts, so a new page does not have to rebuild them."""
        _, entries = parse_entries(plaintext)
        _, notes = parse_notes(plaintext)
        _, passphrases = parse_passphrases(plaintext)
        _, backups = parse_backup_codes(plaintext)
        _, auths = parse_authenticators(plaintext)
        return {
            "passwords": len(entries), "notes": len(notes),
            "passphrases": len(passphrases), "backups": len(backups),
            "authenticators": len(auths),
        }

    def _add_cors(self):
        origin = self.headers.get("Origin", "")
        allowed = {"http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT}
        if origin in allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

    def _parse_cookies(self):
        cookie = self.headers.get("Cookie", "") or ""
        cookies = {}
        if not cookie:
            return cookies
        for part in cookie.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            cookies[name.strip()] = urllib.parse.unquote(value.strip())
        return cookies

    def _sweep_sessions(self, now):
        # Expired entries used to be dropped only when their own token came
        # back, so an abandoned session kept its master password in memory for
        # the life of the process. Sweep the whole table instead.
        for tok, sess in list(self.server.sessions.items()):
            if now - sess.get("created", 0) > SESSION_MAX_AGE:
                self.server.sessions.pop(tok, None)
                continue
            if sess.get("state") == "suspended":
                # A suspended session is idle by definition, so the idle TTL
                # would kill it within minutes and there would be nothing left
                # to resume. Its own bound applies instead, and unlike
                # last_seen it does not slide -- the clock starts when the
                # screen locks and runs regardless of what the browser does.
                if now - sess.get("suspended_at", 0) > SUSPEND_MAX_AGE:
                    self.server.sessions.pop(tok, None)
                continue
            if now - sess.get("last_seen", 0) > SESSION_TTL:
                self.server.sessions.pop(tok, None)

    def _login_client(self):
        try:
            peer = ipaddress.ip_address(self.client_address[0])
        except (AttributeError, IndexError, ValueError):
            return "unknown"
        # Only a loopback reverse proxy is trusted to identify the visitor. A
        # direct network client must never be able to choose its own throttle key.
        if peer.is_loopback:
            forwarded = (self.headers.get("X-Real-IP", "") or "").strip()
            try:
                return str(ipaddress.ip_address(forwarded)) if forwarded else str(peer)
            except ValueError:
                return str(peer)
        return str(peer)

    def _sweep_login_failures_locked(self, now):
        for client, entry in list(self.server.login_failures.items()):
            if now - entry.get("last_seen", 0) > LOGIN_LOCKOUT_SECONDS:
                self.server.login_failures.pop(client, None)
        if len(self.server.login_failures) > 4096:
            oldest = sorted(self.server.login_failures,
                key=lambda key: self.server.login_failures[key].get("last_seen", 0))
            for client in oldest[:-4096]:
                self.server.login_failures.pop(client, None)

    def _login_lockout_remaining(self):
        now = time.time()
        with self.server.auth_lock:
            self._sweep_login_failures_locked(now)
            entry = self.server.login_failures.get(self._login_client())
            if not entry:
                return 0
            return max(0, int(entry.get("until", 0) - now))

    def _record_login_failure(self):
        client = self._login_client()
        now = time.time()
        with self.server.auth_lock:
            self._sweep_login_failures_locked(now)
            entry = self.server.login_failures.get(client) or {"count": 0, "until": 0}
            entry["count"] = entry.get("count", 0) + 1
            entry["last_seen"] = now
            if entry["count"] >= LOGIN_MAX_FAILURES:
                entry["until"] = now + LOGIN_LOCKOUT_SECONDS
            self.server.login_failures[client] = entry
        self.log_message("failed login from %s (%d/%d)", client, entry["count"], LOGIN_MAX_FAILURES)

    def _clear_login_failures(self):
        with self.server.auth_lock:
            self.server.login_failures.pop(self._login_client(), None)

    def _get_cookie_session(self):
        """The master password for an ACTIVE session, else None.

        A suspended session returns None here on purpose. Every authenticated
        route already treats None as "not signed in", so suspension fails
        closed for routes written before this feature existed and for any route
        added after it -- no per-route opt-in to forget. The unlock endpoints
        reach past this with _session_record().
        """
        now = time.time()
        self._sweep_sessions(now)
        token = self._parse_cookies().get("spm_session")
        if not token:
            return None
        session = self.server.sessions.get(token)
        if not session:
            return None
        if session.get("state") == "suspended":
            return None
        session["last_seen"] = now
        # Held for this request only, so the read and write helpers can reach
        # the session's cached vault key without every call site threading the
        # record through. The handler instance is per-request, so this cannot
        # leak between connections.
        self._session_rec = session
        return session.get("master", "")

    def _session_record(self):
        """The raw session record whatever its state, plus its token."""
        now = time.time()
        self._sweep_sessions(now)
        token = self._parse_cookies().get("spm_session")
        if not token:
            return "", None
        return token, self.server.sessions.get(token)

    def _suspended_session(self):
        """The session record only when it is suspended."""
        token, session = self._session_record()
        if session and session.get("state") == "suspended":
            return token, session
        return "", None

    def _session_csrf(self):
        token = self._parse_cookies().get("spm_session")
        if not token:
            return ""
        session = self.server.sessions.get(token) or {}
        return session.get("csrf", "")

    def _read_body(self, limit=MAX_POST_BYTES):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (ValueError, TypeError):
            self.send_error(400, "Invalid Content-Length")
            return None
        if length < 0 or length > limit:
            self.send_error(413, "Request body too large")
            return None
        return self.rfile.read(length)

    def _get_lang(self):
        cookies = self._parse_cookies()
        return sanitize_lang(cookies.get("spm_lang"))

    def _deny_unauthenticated(self):
        """Answer a request that has no active session.

        A suspended session is a different situation from no session at all:
        the vault is still open in memory and a biometric can resume it, so
        send the visitor to the unlock page instead of asking for a password
        they do not need to retype yet.
        """
        _, suspended = self._suspended_session()
        if suspended is not None and WEBAUTHN_ENABLED:
            self.send_response(302)
            self.send_header("Location", "/unlock")
            self.end_headers()
            return
        page = login_page(VERSION)
        self._send_html(200, page)

    def _require_login(self):
        master = self._get_cookie_session()
        if not master:
            self._deny_unauthenticated()
            return None
        return master

    def _send_json(self, code, payload):
        body = jsonlib.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_authorized(self):
        """Read a JSON ceremony body after checking CSRF and origin.

        Returns None when the response has already been sent.
        """
        raw = self._read_body(limit=64 * 1024)
        if raw is None:
            return None
        if not self._write_authorized(raw, {}):
            self._send_json(403, {"error": "rejected"})
            return None
        try:
            payload = jsonlib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_json(400, {"error": "malformed request"})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "malformed request"})
            return None
        return payload

    def _issue_challenge(self, session, kind):
        challenge = secrets.token_bytes(32)
        session["challenge"] = challenge
        session["challenge_at"] = time.time()
        session["challenge_kind"] = kind
        return challenge

    def _take_challenge(self, session, kind):
        """Consume the stored challenge, whatever the caller then does with it.

        Reading it clears it unconditionally. A challenge that survived a failed
        verification could be replayed against a second guess, so failure has to
        burn it just as success does.
        """
        challenge = session.get("challenge") or b""
        issued_at = session.get("challenge_at", 0)
        stored_kind = session.get("challenge_kind", "")
        session["challenge"] = b""
        session["challenge_at"] = 0
        session["challenge_kind"] = ""
        if not challenge or stored_kind != kind:
            return b""
        if time.time() - issued_at > WEBAUTHN_CHALLENGE_TTL:
            return b""
        return challenge

    def _handle_unlock_post(self, path):
        """WebAuthn ceremonies. Returns False when the path is not one of them.

        These live above the normal session gate because two of them act on a
        suspended session, which _get_cookie_session deliberately reports as no
        session at all.
        """
        if not WEBAUTHN_ENABLED:
            return False
        if path not in ("/unlock/suspend", "/unlock/challenge", "/unlock/verify",
                        "/unlock/register/challenge", "/unlock/register/verify"):
            return False

        if path in ("/unlock/challenge", "/unlock/verify"):
            token, session = self._suspended_session()
        elif path == "/unlock/suspend":
            # Suspending accepts a session that is already suspended, because
            # two tabs share one session and both lock bars fire. Refusing the
            # second told it "no session", and the lock bar treats any refusal
            # as a reason to log out -- which destroyed the suspended session
            # the first tab was about to resume.
            token, session = self._session_record()
            if session is not None and session.get("state") not in ("active", "suspended"):
                session = None
        else:
            token, session = self._session_record()
            if session is not None and session.get("state") != "active":
                session = None
        if session is None:
            self._send_json(403, {"error": "no session"})
            return True

        payload = self._read_json_authorized()
        if payload is None:
            return True

        if path == "/unlock/suspend":
            if session.get("state") == "suspended":
                # Already locked by another tab. Deliberately does not touch
                # suspended_at: refreshing it every time a tab reports in would
                # let an idle browser hold the master password in memory past
                # SUSPEND_MAX_AGE indefinitely.
                self._send_json(200, {"ok": True, "already_suspended": True})
                return True
            # A suspended session can be resumed by nothing except a registered
            # credential, so suspending without one strands the user on a page
            # that cannot let them back in -- they can only log out and retype
            # the master password, which is the exact friction this feature
            # exists to remove.
            #
            # has_cred alone is not enough to decide: it is cached per session
            # at login, so a session that was already open when the credential
            # was deleted (or when SPM_WEB_RP_ID changed) still believes one
            # exists. Ask the vault, which is the only authority.
            try:
                plaintext = load_vault(session.get("master", ""), session)
            except Exception:
                self._send_json(403, {"error": "vault unavailable"})
                return True
            _, creds = parse_webauthn(plaintext)
            if not any(parts[4] == WEBAUTHN_RP_ID for _, parts in creds):
                # Correct the stale flag so later pages stop advertising it,
                # and refuse. The lock bar falls through to /logout, which is
                # exactly what it did before this feature existed.
                session["has_cred"] = False
                self.log_message("refusing to suspend: no usable unlock credential")
                self._send_json(409, {"error": "no credential registered"})
                return True
            session["has_cred"] = True
            session["state"] = "suspended"
            session["suspended_at"] = time.time()
            # Nothing may carry over from the active session into the locked
            # one: a challenge issued before the lock must not be spendable
            # after it.
            self._take_challenge(session, "")
            self.log_message("session suspended, awaiting biometric unlock")
            self._send_json(200, {"ok": True})
            return True

        if path == "/unlock/register/challenge":
            challenge = self._issue_challenge(session, "create")
            self._send_json(200, {
                "challenge": _b64url_encode(challenge),
                "rp_id": WEBAUTHN_RP_ID,
                "user_id": _b64url_encode(hashlib.sha256(
                    os.path.abspath(VAULT_PATH).encode("utf-8")).digest()[:16]),
                "user_name": os.path.basename(VAULT_PATH),
            })
            return True

        if path == "/unlock/register/verify":
            self._webauthn_register(session, payload)
            return True

        if path == "/unlock/challenge":
            try:
                plaintext = load_vault(session.get("master", ""), session)
            except Exception:
                self._send_json(403, {"error": "vault unavailable"})
                return True
            _, creds = parse_webauthn(plaintext)
            allowed = [parts[2] for _, parts in creds if parts[4] == WEBAUTHN_RP_ID]
            if not allowed:
                self._send_json(400, {"error": "no credential registered"})
                return True
            challenge = self._issue_challenge(session, "get")
            self._send_json(200, {
                "challenge": _b64url_encode(challenge),
                "rp_id": WEBAUTHN_RP_ID,
                "allow": allowed,
            })
            return True

        if path == "/unlock/verify":
            self._webauthn_unlock(token, session, payload)
            return True

        return False

    def _webauthn_register(self, session, payload):
        """Finish a registration ceremony and store the credential."""
        expected = self._take_challenge(session, "create")
        if not expected:
            self._send_json(400, {"error": "challenge expired"})
            return
        try:
            client_data = _b64url_decode(payload.get("client_data") or "")
            auth_data = _b64url_decode(payload.get("auth_data") or "")
            spki = _b64url_decode(payload.get("public_key") or "")
            cred_id = (payload.get("credential_id") or "").strip()
            _b64url_decode(cred_id)
        except ValueError:
            self._send_json(400, {"error": "malformed credential"})
            return
        if not spki:
            # getPublicKey() returned null: the browser could not export the
            # key. Reaching it would mean decoding the CBOR attestation object,
            # and a CBOR decoder is exactly the dependency this server does not
            # have. Fail with something the user can act on instead.
            self._send_json(400, {"error": "this browser cannot export the credential key"})
            return
        problem = check_client_data(client_data, "webauthn.create", expected)
        if problem:
            self._send_json(400, {"error": problem})
            return
        _, problem = check_authenticator_data(auth_data)
        if problem:
            self._send_json(400, {"error": problem})
            return

        label = (payload.get("label") or "").strip() or "Biometric unlock"
        label = re.sub(r"[\t\r\n]", " ", label)[:64]
        master = session.get("master", "")
        try:
            plaintext = load_vault(master, self._session_rec)
        except Exception:
            self._send_json(403, {"error": "vault unavailable"})
            return
        lines, creds = parse_webauthn(plaintext)
        if any(parts[2] == cred_id for _, parts in creds):
            self._send_json(400, {"error": "credential already registered"})
            return
        next_id = 1
        for _, parts in creds:
            try:
                next_id = max(next_id, int(parts[1]) + 1)
            except (TypeError, ValueError):
                continue
        row = "\t".join([
            "WEBAUTHN", str(next_id), cred_id,
            base64.b64encode(spki).decode("ascii"),
            WEBAUTHN_RP_ID, label,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ])
        lines.append(row)
        try:
            save_vault(master, "\n".join(lines) + "\n", self._session_rec)
        except Exception:
            self._send_json(500, {"error": "could not save credential"})
            return
        session["has_cred"] = True
        self.log_message("registered unlock credential %s", next_id)
        self._send_json(200, {"ok": True})

    def _webauthn_unlock(self, token, session, payload):
        """Verify an assertion and resume a suspended session."""
        locked_for = self._login_lockout_remaining()
        if locked_for > 0:
            self._send_json(429, {"error": "too many attempts", "retry_after": locked_for})
            return
        expected = self._take_challenge(session, "get")
        if not expected:
            self._send_json(400, {"error": "challenge expired"})
            return
        try:
            client_data = _b64url_decode(payload.get("client_data") or "")
            auth_data = _b64url_decode(payload.get("auth_data") or "")
            signature = _b64url_decode(payload.get("signature") or "")
            cred_id = (payload.get("credential_id") or "").strip()
            _b64url_decode(cred_id)
        except ValueError:
            self._record_login_failure()
            self._send_json(400, {"error": "malformed assertion"})
            return

        problem = check_client_data(client_data, "webauthn.get", expected)
        if problem:
            self._record_login_failure()
            self._send_json(403, {"error": problem})
            return
        sign_count, problem = check_authenticator_data(auth_data)
        if problem:
            self._record_login_failure()
            self._send_json(403, {"error": problem})
            return

        try:
            plaintext = load_vault(session.get("master", ""), session)
        except Exception:
            self._send_json(403, {"error": "vault unavailable"})
            return
        _, creds = parse_webauthn(plaintext)
        match = None
        for _, parts in creds:
            if hmac.compare_digest(parts[2], cred_id) and parts[4] == WEBAUTHN_RP_ID:
                match = parts
                break
        if match is None:
            self._record_login_failure()
            self._send_json(403, {"error": "unknown credential"})
            return
        try:
            spki = base64.b64decode(match[3].encode("ascii"), validate=True)
        except Exception:
            self._send_json(403, {"error": "unreadable credential"})
            return

        signed = auth_data + hashlib.sha256(client_data).digest()
        if not verify_es256(spki, signature, signed):
            self._record_login_failure()
            self._send_json(403, {"error": "signature rejected"})
            return

        # Signature counters are held per process rather than written back to
        # the vault: persisting one would mean a full read-modify-write of the
        # encrypted vault on every unlock, and Apple's platform authenticator
        # reports 0 forever anyway. Compare only when both sides are non-zero.
        counters = self.server.webauthn_counters
        previous = counters.get(cred_id, 0)
        if sign_count and previous and sign_count <= previous:
            self._record_login_failure()
            self.log_message("signature counter regression on credential %s", match[1])
            self._send_json(403, {"error": "signature counter regression"})
            return
        if sign_count:
            counters[cred_id] = sign_count

        self._clear_login_failures()
        session["state"] = "active"
        session["suspended_at"] = 0
        session["last_seen"] = time.time()
        # "created" is deliberately untouched: SESSION_MAX_AGE still caps the
        # session, so biometric unlocks cannot chain into an unbounded life.
        session["csrf"] = secrets.token_hex(32)
        self.log_message("session resumed by credential %s", match[1])
        self._send_json(200, {"ok": True})

    def _body_csrf(self, raw_body_bytes, data):
        token = (data.get("csrf") or [""])[0].strip()
        if token:
            return token
        ctype = self.headers.get("Content-Type", "") or ""
        # The import form is multipart, so its fields are not in parse_qs.
        if "multipart/form-data" in ctype.lower():
            try:
                fields = parse_multipart(raw_body_bytes, ctype)
            except Exception:
                return ""
            raw = fields.get("csrf")
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="ignore").strip()
            return ""
        # The WebAuthn ceremonies post JSON from fetch(), so their token is in
        # neither parse_qs output nor a multipart part. Read it from the object
        # itself. Only a string counts: a JSON body can carry a list or a dict
        # where a token is expected, and str() on either would produce
        # something that compares as a token-shaped value.
        if "application/json" in ctype.lower():
            try:
                payload = jsonlib.loads(raw_body_bytes.decode("utf-8"))
            except (AttributeError, UnicodeDecodeError, ValueError):
                return ""
            if not isinstance(payload, dict):
                return ""
            raw = payload.get("csrf")
            return raw.strip() if isinstance(raw, str) else ""
        return ""

    def _write_authorized(self, raw_body_bytes, data):
        """Authorise an authenticated write.

        Origin is checked when the browser sends it. Safari omits Origin on
        same-origin form submissions, which made every write fail with a 403,
        and Referer cannot cover the gap because this server sends
        Referrer-Policy: no-referrer. So a per-session CSRF token in the form
        is the primary defence and the Origin check is the second layer.
        """
        origin = (self.headers.get("Origin", "") or "").strip()
        # "null" is an opaque origin, not a foreign one: iOS home-screen web
        # apps send it for their own same-origin form posts, and so do
        # sandboxed contexts. It carries no information about the sender, so
        # treat it like an absent origin and let the token decide -- an
        # attacker in a sandboxed frame still cannot read the token.
        if origin and origin.lower() != "null":
            # Present, parseable and wrong is a genuine cross-origin attempt:
            # refuse it regardless of what token the body carries.
            return self._same_origin_post()
        expected = self._session_csrf()
        supplied = self._body_csrf(raw_body_bytes, data)
        return bool(expected) and hmac.compare_digest(expected, supplied)

    def _same_origin_post(self):
        """Require authenticated browser writes to come from this exact origin."""
        origin = (self.headers.get("Origin", "") or "").strip()
        host = (self.headers.get("Host", "") or "").strip().lower()
        if not origin or not host:
            return False
        try:
            parsed = urllib.parse.urlparse(origin)
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host

    def do_OPTIONS(self):
        self.send_response(200)
        self._add_cors()
        self.end_headers()
        return

    # ---- Handlers -----------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path or "/"

        if path == "/lang":
            params = urllib.parse.parse_qs(parsed.query)
            raw = (params.get("lang") or params.get("value") or [""])[0]
            lang = sanitize_lang(raw)
            self.send_response(200)
            self.send_header("Set-Cookie", f"spm_lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jsonlib.dumps({"ok": True, "lang": lang}).encode("utf-8"))
            return

        if path.startswith("/logout"):
            token = self._parse_cookies().get("spm_session")
            if token:
                self.server.sessions.pop(token, None)
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path == "/login":
            page = login_page(VERSION)
            self._send_html(200, page)
            return

        # These must answer above the login gate. Unknown paths fall through to
        # _require_login(), which replies with the login page as HTTP 200
        # rather than redirecting, so an icon request would be answered with
        # HTML and iOS would fall back to screenshotting the page instead of
        # showing the mark. /favicon.ico and the -precomposed alias are
        # requested unprompted by Safari, so both are handled here too.
        if path in ("/apple-touch-icon.png",
                    "/apple-touch-icon-precomposed.png",
                    "/favicon.ico"):
            self._send_asset("image/png", APP_ICON_PNG)
            return

        if path == "/favicon.svg":
            self._send_asset("image/svg+xml", FAVICON_SVG.encode("utf-8"))
            return

        if path == "/manifest.webmanifest":
            self._send_asset("application/manifest+json",
                             MANIFEST_JSON.encode("utf-8"))
            return

        # Above the login gate because a suspended session has no active
        # session by design, and this is the page that fixes that. It renders
        # no vault content -- only a button and a way out.
        if path == "/unlock":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            _, suspended = self._suspended_session()
            if suspended is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._send_html(200, unlock_page(VERSION, self._session_csrf()))
            return

        master = self._require_login()
        if master is None:
            return

        if path == "/":
            flash = ""
            note = (parsed.query or "")
            params = urllib.parse.parse_qs(parsed.query)
            msg = (params.get("msg") or [""])[0]
            err = (params.get("err") or [""])[0]
            if msg == "import-ok":
                flash = "<div class='flash'>Import completed.</div>"
            elif err:
                flash = f"<div class='flash error'>{html.escape(err)}</div>"
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                self.send_response(302)
                self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
                self.send_header("Location", "/login")
                self.end_headers()
                return

            _, entries = parse_entries(plaintext)
            _, notes = parse_notes(plaintext)
            _, passphrases = parse_passphrases(plaintext)
            _, backups = parse_backup_codes(plaintext)
            _, auths = parse_authenticators(plaintext)
            counts = {
                "passwords": len(entries), "notes": len(notes),
                "passphrases": len(passphrases), "backups": len(backups),
                "authenticators": len(auths),
            }
            audit = compute_security(entries, plaintext)
            counts["security_score"] = audit["score"]
            counts["aging"] = len(audit["old"])
            counts["attachments"] = sum(1 for line in plaintext.splitlines() if line.startswith("ATTACHMENT\t"))
            counts["passkeys"] = sum(1 for line in plaintext.splitlines() if line.startswith("PASSKEY\t"))
            recent = list(reversed(entries))[:5]
            body = render_shell(overview_page(counts, recent), "overview",
                                VERSION, VAULT_PATH, title="Overview",
                                counts=counts, flash=flash)
            self._send_html(200, body)
            return

        if path == "/transfer":
            self._send_html(200, transfer_page())
            return

        if path == "/security":
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            _, entries = parse_entries(plaintext)
            audit = compute_security(entries, plaintext)
            self._send_html(200, render_shell(
                security_page(audit), "security", VERSION, VAULT_PATH,
                title="Security", counts=self._counts(plaintext)))
            return

        if path == "/unlock/settings":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            _, creds = parse_webauthn(plaintext)
            params = urllib.parse.parse_qs(parsed.query)
            flash = ""
            if (params.get("msg") or [""])[0] == "registered":
                flash = "<div class='flash'>Unlock credential registered.</div>"
            elif (params.get("msg") or [""])[0] == "deleted":
                flash = "<div class='flash'>Unlock credential removed.</div>"
            self._send_html(200, render_shell(
                unlock_settings_page(creds, self._session_csrf(), flash),
                "unlock-settings", VERSION, VAULT_PATH,
                title="Biometric Unlock", counts=self._counts(plaintext)))
            return

        if path == "/settings":
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            params = urllib.parse.parse_qs(parsed.query)
            flash = ""
            if (params.get("msg") or [""])[0] == "changed":
                flash = ("<div class='flash'>Master password changed. The recovery "
                         "file was rewritten and every other session was signed "
                         "out.</div>")
            self._send_html(200, render_shell(
                settings_page(flash), "settings", VERSION, VAULT_PATH,
                title="Master Password", counts=self._counts(plaintext)))
            return

        if path == "/history":
            hist_flash = ""
            if (urllib.parse.parse_qs(parsed.query).get("flash") or [""])[0] == "restored":
                hist_flash = "<div class='flash'>Snapshot restored. The previous vault was archived.</div>"
            snapshots = list_history_snapshots()
            content = list_page(
                "nav.history", "History", "page.history.desc",
                "Encrypted vault snapshots kept before each change.", "", "", "",
                [("history.when", "When", ""), ("history.size", "Size", ""),
                 ("history.name", "Snapshot", ""), ("table.actions", "Actions", "act")],
                build_history_rows_html(snapshots))
            self._send_html(200, render_shell(
                content, "history", VERSION, VAULT_PATH,
                title="History", flash=hist_flash, searchable=True))
            return

        if path == "/search":
            term = (urllib.parse.parse_qs(parsed.query).get("q") or [""])[0].strip()
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            results = search_vault(plaintext, term) if term else []
            content = list_page(
                "search.title", "Search", "search.desc",
                f"Matches for “{html.escape(term)}” across every record type." if term
                else "Type in the search box to look across every record type.",
                "", "", "",
                [("search.kind", "Type", ""), ("table.id", "ID", "num"),
                 ("table.label", "Label", ""), ("table.actions", "Actions", "act")],
                build_search_rows_html(results))
            self._send_html(200, render_shell(
                content, "", VERSION, VAULT_PATH, title="Search",
                counts=self._counts(plaintext), searchable=True))
            return

        if path in ("/passwords", "/notes", "/passphrases", "/authenticators", "/backup-codes"):
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                self.send_response(302)
                self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
                self.send_header("Location", "/login")
                self.end_headers()
                return
            _, entries = parse_entries(plaintext)
            _, notes = parse_notes(plaintext)
            _, passphrases = parse_passphrases(plaintext)
            _, backups = parse_backup_codes(plaintext)
            _, auths = parse_authenticators(plaintext)
            counts = {
                "passwords": len(entries), "notes": len(notes),
                "passphrases": len(passphrases), "backups": len(backups),
                "authenticators": len(auths),
            }
            spec = {
                "/passwords": ("nav.passwords", "Passwords", "page.passwords.desc",
                               "Login credentials stored in your vault.", "/add",
                               "btn.add_entry", "+ Add Entry",
                               [("table.id", "ID", "num"), ("table.name", "Name", ""),
                                ("table.username", "Username", ""), ("table.actions", "Actions", "act")],
                               build_rows_html(entries), "passwords"),
                "/notes": ("nav.notes", "Secure Notes", "page.notes.desc",
                           "Encrypted notes stored inside the same vault.", "/notes-add",
                           "btn.add_note", "+ Add Note",
                           [("table.id", "ID", "num"), ("table.title", "Title", ""),
                            ("table.actions", "Actions", "act")],
                           build_notes_rows_html(notes), "notes"),
                "/passphrases": ("nav.passphrases", "Passphrases", "page.passphrases.desc",
                                 "API tokens and recovery phrases.", "/passphrase-add",
                                 "btn.add_passphrase", "+ Add Passphrase",
                                 [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                  ("table.actions", "Actions", "act")],
                                 build_passphrase_rows_html(passphrases), "passphrases"),
                "/authenticators": ("nav.authenticators", "Authenticators", "page.authenticators.desc",
                                    "Time-based one-time password codes.", "/authenticator-add",
                                    "btn.add_authenticator", "+ Add Authenticator",
                                    [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                     ("table.every", "Every", ""), ("table.algo", "Algo", ""),
                                     ("table.actions", "Actions", "act")],
                                    build_auth_rows_html(auths), "authenticators"),
                "/backup-codes": ("nav.backup_codes", "Backup Codes", "page.backups.desc",
                                  "One-time recovery codes for your accounts.", "/backup-codes-add",
                                  "btn.add_backups", "+ Add Backup Codes",
                                  [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                   ("table.actions", "Actions", "act")],
                                  build_backup_rows_html(backups), "backup-codes"),
            }[path]
            content = list_page(spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7], spec[8])
            if path == "/passwords":
                content = build_tag_filter_html(entries) + content
            self._send_html(200, render_shell(content, spec[9], VERSION, VAULT_PATH,
                                              title=spec[1], counts=counts, searchable=True))
            return

        if path == "/generator":
            page = generator_page()
            self._send_html(200, page)
            return

        query = urllib.parse.parse_qs(parsed.query)

        if path == "/add":
            page = build_entry_form(
                title="Add Entry",
                vault_path=VAULT_PATH,
                action="/add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/edit":
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)
            found = None
            for idx, parts in entries:
                if parts[0] == entry_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Entry not found")
                return

            values = {
                "name": found[1],
                "user": found[2],
                "password": found[3],
                "notes": found[4],
                "url": found[6] if len(found) > 6 else "",
            }
            page = build_entry_form(
                title=f"Edit Entry #{entry_id}",
                vault_path=VAULT_PATH,
                action="/edit?id=" + urllib.parse.quote(entry_id),
                values=values,
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/view":
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, entries = parse_entries(plaintext)
            found = None
            for _, parts in entries:
                if parts[0] == entry_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Entry not found")
                return

            page = view_entry_page(found)
            self._send_html(200, page)
            return

        if path == "/notes-add":
            page = build_note_form(
                title="Add Secure Note",
                vault_path=VAULT_PATH,
                action="/notes-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/notes-view":
            note_id = (query.get("id") or [""])[0]
            if not note_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, notes = parse_notes(plaintext)
            found = None
            for _, parts in notes:
                if parts[1] == note_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Note not found")
                return
            title = found[2]
            try:
                content = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                content = "[Decode error]"
            created = found[4]

            page = view_simple_page(title, "/notes", "note.field.title", title,
                                    content, created, "note.field.content", "Content", "notes")
            self._send_html(200, page)
            return

        if path == "/passphrase-add":
            page = build_passphrase_form(
                title="Add Passphrase",
                vault_path=VAULT_PATH,
                action="/passphrase-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/passphrase-edit":
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, passphrases = parse_passphrases(plaintext)
            found = None
            for _, parts in passphrases:
                if parts[1] == pid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Passphrase not found")
                return
            secret = ""
            try:
                secret = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                secret = ""
            page = build_passphrase_form(
                title=f"Edit Passphrase #{pid}",
                vault_path=VAULT_PATH,
                action="/passphrase-edit?id=" + urllib.parse.quote(pid),
                values={"label": found[2], "secret": secret},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/passphrase-view":
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, passphrases = parse_passphrases(plaintext)
            found = None
            for _, parts in passphrases:
                if parts[1] == pid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Passphrase not found")
                return
            secret = ""
            try:
                secret = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                secret = "[Decode error]"
            created = found[4]
            page = view_simple_page(found[2], "/passphrases", "pass.field.label", found[2],
                                    secret, created, "pass.view.secret", "Passphrase", "passphrases")
            self._send_html(200, page)
            return

        if path == "/authenticator-add":
            page = build_auth_form(
                title="Add Authenticator",
                vault_path=VAULT_PATH,
                action="/authenticator-add",
                values={"period": "30", "algo": "sha1"},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/authenticator-edit":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            algo = found[6] if len(found) > 6 else "sha1"
            page = build_auth_form(
                title=f"Edit Authenticator #{aid}",
                vault_path=VAULT_PATH,
                action="/authenticator-edit?id=" + urllib.parse.quote(aid),
                values={"label": found[2], "secret": found[3], "period": found[4], "algo": algo},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/authenticator-view":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            created = found[5] if len(found) > 5 else ""
            algo = (found[6] if len(found) > 6 else "sha1") or "sha1"
            page = auth_view_page(aid, found[2], found[3], found[4] or "30", algo, created)
            self._send_html(200, page)
            return

        if path == "/backup-codes-add":
            page = build_backup_form(
                title="Add Backup Codes",
                vault_path=VAULT_PATH,
                action="/backup-codes-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/backup-codes-edit":
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, backups = parse_backup_codes(plaintext)
            found = None
            for _, parts in backups:
                if parts[1] == bid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Backup code not found")
                return
            codes = ""
            try:
                codes = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                codes = ""
            page = build_backup_form(
                title=f"Edit Backup Codes #{bid}",
                vault_path=VAULT_PATH,
                action="/backup-codes-edit?id=" + urllib.parse.quote(bid),
                values={"label": found[2], "codes": codes},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/backup-codes-view":
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, backups = parse_backup_codes(plaintext)
            found = None
            for _, parts in backups:
                if parts[1] == bid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Backup code not found")
                return
            codes = ""
            try:
                codes = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                codes = "[Decode error]"
            created = found[4]
            page = view_simple_page(found[2], "/backup-codes", "backup.field.label", found[2],
                                    codes, created, "backup.field.codes", "Backup codes", "backup-codes")
            self._send_html(200, page)
            return

        if path == "/authenticator-code":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            period = 30
            algo = (found[6] if len(found) > 6 else "sha1") or "sha1"
            try:
                period = int(found[4])
            except Exception:
                period = 30
            try:
                code = totp_code(found[3], period, algo) or "------"
            except Exception:
                code = "------"
            expires_in = period - int(time.time()) % max(period, 1)
            import json
            body = jsonlib.dumps({"code": code, "expires_in": expires_in, "algo": algo})
            self.send_response(200)
            self._add_cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        if path == "/export":
            fmt = (query.get("fmt") or ["csv"])[0].lower()
            if fmt not in SUPPORTED_FORMATS:
                self.send_error(400, "Unsupported format")
                return
            plaintext = load_vault(master, self._session_rec)
            content = export_content(fmt, plaintext)
            filename = f"spm_export_{time.strftime('%Y%m%d_%H%M%S')}.{fmt if fmt!='csv-noheader' else 'csv'}"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path or "/"
        if path in ("/login", "/lang"):
            return self._do_POST()
        # Serialize the complete authenticated read-modify-write transaction,
        # not only the final os.replace, so no successful request is lost. The
        # file lock extends that guarantee across two server processes.
        with self.server.vault_lock:
            fcntl.flock(self.server.vault_lock_file.fileno(), fcntl.LOCK_EX)
            try:
                return self._do_POST()
            finally:
                fcntl.flock(self.server.vault_lock_file.fileno(), fcntl.LOCK_UN)

    def _do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path or "/"

        if path == "/lang":
            raw_body = self._read_body(limit=4096)
            if raw_body is None:
                return
            raw_body = raw_body.decode("utf-8", errors="ignore")
            data = urllib.parse.parse_qs(raw_body)
            lang = sanitize_lang((data.get("lang") or [""])[0])
            self.send_response(200)
            self.send_header("Set-Cookie", f"spm_lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jsonlib.dumps({"ok": True, "lang": lang}).encode("utf-8"))
            return

        if path == "/login":
            locked_for = self._login_lockout_remaining()
            if locked_for > 0:
                page = login_page(
                    VERSION,
                    "<div class='msg'>Too many failed attempts. Try again in %d seconds.</div>" % locked_for,
                )
                self._send_html(429, page)
                return

            raw_body = self._read_body(limit=64 * 1024)
            if raw_body is None:
                return
            body = raw_body.decode("utf-8", errors="ignore")
            data = urllib.parse.parse_qs(body)
            password = data.get("password", [""])[0]

            if not password:
                page = login_page(VERSION, "<div class='msg'>Password required.</div>")
                self._send_html(200, page)
                return

            try:
                # This read unwraps the key envelope anyway, so keep what it
                # produced; discarding it would make the first page render pay
                # for the same unwrap a second time.
                opened, opened_key = core.read_vault(VAULT_PATH, password)
            except subprocess.CalledProcessError:
                self._record_login_failure()
                page = login_page(VERSION, "<div class='msg'>Invalid master password.</div>")
                self._send_html(200, page)
                return

            # Counted once here rather than on every page render: the answer
            # only changes when a credential is registered or removed, and both
            # of those already hold the plaintext vault open.
            _, opened_creds = parse_webauthn(opened)
            has_cred = any(parts[4] == WEBAUTHN_RP_ID for _, parts in opened_creds)

            self._clear_login_failures()
            token = secrets.token_hex(32)
            self.server.sessions[token] = {
                "master": password,
                "vault_key": opened_key or "",
                "csrf": secrets.token_hex(32),
                "created": time.time(),
                "last_seen": time.time(),
                "state": "active",
                "suspended_at": 0,
                "challenge": b"",
                "challenge_at": 0,
                "challenge_kind": "",
                "has_cred": has_cred,
            }
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session={token}; {self._session_cookie_attrs()}")
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path.startswith("/unlock/"):
            handled = self._handle_unlock_post(path)
            if handled:
                return

        master = self._get_cookie_session()
        if not master:
            self._deny_unauthenticated()
            return

        raw_body_bytes = self._read_body()
        if raw_body_bytes is None:
            return
        raw_body = raw_body_bytes.decode("utf-8", errors="ignore")
        data = urllib.parse.parse_qs(raw_body)

        if not self._write_authorized(raw_body_bytes, data):
            self.send_error(403, "Cross-origin write rejected")
            return

        if path == "/settings/master-password":
            current = (data.get("current") or [""])[0]
            new_pw = (data.get("new") or [""])[0]
            confirm = (data.get("confirm") or [""])[0]

            def _reject(message):
                self._send_html(200, render_shell(
                    settings_page("<div class='flash error'>%s</div>" % message),
                    "settings", VERSION, VAULT_PATH, title="Master Password"))

            # Compared against the copy this session already proved at login
            # rather than by decrypting again: a typo should not cost a gpg
            # spawn, and the session holds the authoritative answer anyway.
            # Encoded first because compare_digest rejects non-ASCII str.
            if not hmac.compare_digest(current.encode("utf-8"),
                                       master.encode("utf-8")):
                self.log_message("master password change refused: wrong current password")
                _reject("Current master password is incorrect.")
                return
            if new_pw != confirm:
                _reject("The two new passwords do not match.")
                return
            if len(new_pw) < MASTER_MIN_LEN:
                _reject("The new master password must be at least %d characters."
                        % MASTER_MIN_LEN)
                return
            if hmac.compare_digest(new_pw.encode("utf-8"),
                                   current.encode("utf-8")):
                _reject("The new master password is the same as the current one.")
                return

            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()

            # Two steps, never one. A legacy vault is migrated to the
            # container format while `master` is STILL the live password, so
            # its key envelope and its recovery file agree at every instant;
            # only then is the envelope rewrapped to the new password. Sealing
            # the envelope under new_pw during the migration would leave a
            # window where .recovery names a password that opens nothing, and
            # that is the one state `spm forgot` cannot get out of.
            try:
                if unwrap_vault_key(master) is None:
                    save_vault(master, plaintext, self._session_rec)
            except Exception as exc:
                self.log_message("vault migration aborted before write: %s", exc)
                _reject("The vault could not be migrated to the current format, "
                        "so it was left unchanged. Run &#39;spm doctor&#39; to check it.")
                return

            try:
                # Only the small key envelope is rewritten. The vault
                # ciphertext and the recovery file both key off the vault key,
                # which does not change -- so a master-password change no
                # longer depends on the recovery pubkey being usable at all.
                rewrap_vault_key(master, new_pw)
            except Exception as exc:
                self.log_message("master password change failed on rewrap: %s", exc)
                _reject("The master password could not be changed and the vault "
                        "was left unchanged.")
                return

            # Every other session is holding the old password in memory, and
            # its next decrypt would fail anyway. Drop them now so the sign-out
            # is immediate rather than whenever they happen to poll.
            token = self._parse_cookies().get("spm_session")
            for other in list(self.server.sessions):
                if other != token:
                    self.server.sessions.pop(other, None)
            session = self.server.sessions.get(token)
            if session is not None:
                session["master"] = new_pw
                # rewrap re-seals the same key under the new password, so the
                # cached value stays correct -- but proving that here on every
                # future change is not worth one extra unwrap now.
                session["vault_key"] = ""
            self.log_message("master password changed; other sessions cleared")

            self.send_response(302)
            self.send_header("Location", "/settings?msg=changed")
            self.end_headers()
            return

        if path == "/add":
            name = (data.get("name") or [""])[0].strip()
            user = (data.get("user") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            notes = (data.get("notes") or [""])[0]
            url_raw = (data.get("url") or [""])[0]
            url = _vurl(url_raw)

            if not name or url is None:
                page = build_entry_form(
                    title="Add Entry",
                    vault_path=VAULT_PATH,
                    action="/add",
                    values={"name": name, "user": user, "password": password,
                            "notes": notes, "url": url_raw},
                    message=("<div class='msg'>Name / service is required.</div>"
                             if not name else
                             "<div class='msg'>URL must start with http:// or https://.</div>"),
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)
            max_id = 0
            for _, parts in entries:
                try:
                    max_id = max(max_id, int(parts[0]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            new_line = "\t".join([
                str(new_id),
                _vf(name),
                _vf(user),
                _vf(password),
                _vf(notes),
                now,
                url,
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return

            name = (data.get("name") or [""])[0].strip()
            user = (data.get("user") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            notes = (data.get("notes") or [""])[0]
            url_raw = (data.get("url") or [""])[0]
            url = _vurl(url_raw)

            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)

            idx_to_update = None
            old_created = ""
            for idx, parts in entries:
                if parts[0] == entry_id:
                    idx_to_update = idx
                    if len(parts) >= 6:
                        old_created = parts[5]
                    break

            if idx_to_update is None:
                self.send_error(404, "Entry not found")
                return

            if not name or url is None:
                values = {
                    "name": name,
                    "user": user,
                    "password": password,
                    "notes": notes,
                    "url": url_raw,
                }
                page = build_entry_form(
                    title=f"Edit Entry #{entry_id}",
                    vault_path=VAULT_PATH,
                    action="/edit?id=" + urllib.parse.quote(entry_id),
                    values=values,
                    message=("<div class='msg'>Name / service is required.</div>"
                             if not name else
                             "<div class='msg'>URL must start with http:// or https://.</div>"),
                )
                self._send_html(200, page)
                return

            new_line = "\t".join([
                entry_id,
                _vf(name),
                _vf(user),
                _vf(password),
                _vf(notes),
                old_created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                url,
            ])
            lines[idx_to_update] = new_line
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/delete":
            entry_id = (data.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return

            plaintext = load_vault(master, self._session_rec)
            lines, _ = parse_entries(plaintext)

            ids_to_remove = {entry_id}
            new_lines = []
            for line in lines:
                if not line or line.startswith("#") or line.startswith("META_") or line.startswith("NOTE\t"):
                    new_lines.append(line)
                    continue
                parts = line.split("\t")
                if parts and parts[0] in ids_to_remove:
                    continue
                new_lines.append(line)

            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/unlock/delete":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            target = (data.get("id") or [""])[0].strip()
            if not target.isdigit():
                self.send_error(400, "Invalid credential id")
                return
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            lines, creds = parse_webauthn(plaintext)
            drop = {idx for idx, parts in creds if parts[1] == target}
            if not drop:
                self.send_error(404, "Credential not found")
                return
            kept = [line for idx, line in enumerate(lines) if idx not in drop]
            save_vault(master, "\n".join(kept) + "\n", self._session_rec)
            _, remaining = parse_webauthn("\n".join(kept))
            _, current = self._session_record()
            if current is not None:
                current["has_cred"] = any(parts[4] == WEBAUTHN_RP_ID for _, parts in remaining)
            self.send_response(302)
            self.send_header("Location", "/unlock/settings?msg=deleted")
            self.end_headers()
            return

        if path == "/history-restore":
            name = (data.get("name") or [""])[0]
            # Match the generated snapshot name exactly. A traversal denylist
            # would have to anticipate every encoding of "..", an allowlist
            # does not.
            if not _SNAPSHOT_RE.match(name):
                self.send_error(400, "Invalid snapshot name")
                return
            source = os.path.join(_history_dir(), name)
            if not os.path.isfile(source):
                self.send_error(404, "Snapshot not found")
                return
            # Prove the snapshot opens with THIS master password before
            # touching the live vault: restoring a snapshot written under an
            # older password would lock the user out of their own vault with
            # no way back.
            # A snapshot is the same container the live vault is, and carries
            # its own vault key. Open it through the shared reader; the key it
            # yields is deliberately discarded, because restoring is a copy of
            # the file and not a re-encryption under the live vault's key.
            try:
                decrypt_vault_file(source, master)
            except Exception:
                self.send_error(409, "Snapshot does not open with the current master password; vault unchanged")
                return
            vault_dir = os.path.dirname(os.path.abspath(VAULT_PATH)) or "."
            # Archive first: restoring is itself an edit, and undoing a restore
            # has to be possible too.
            _archive_vault_generation()
            tmp_fd, tmp_path = tempfile.mkstemp(prefix=os.path.basename(VAULT_PATH) + ".restore.", dir=vault_dir)
            os.close(tmp_fd)
            try:
                shutil.copy2(source, tmp_path)
                os.chmod(tmp_path, 0o600)
                _fsync_path(tmp_path)
                os.replace(tmp_path, VAULT_PATH)
                _fsync_dir(vault_dir)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                self.send_error(500, "Restore failed; vault unchanged")
                return
            self.send_response(302)
            self.send_header("Location", "/history?flash=restored")
            self.end_headers()
            return

        if path == "/notes-add":
            title = (data.get("title") or [""])[0].strip()
            content = (data.get("content") or [""])[0]

            if not title:
                page = build_note_form(
                    title="Add Secure Note",
                    vault_path=VAULT_PATH,
                    action="/notes-add",
                    values={"title": title, "content": content},
                    message="<div class='msg'>Title is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, notes = parse_notes(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in notes:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "NOTE",
                str(new_id),
                _vf(title),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/notes-delete":
            note_id = (data.get("id") or [""])[0]
            if not note_id:
                self.send_error(400, "Missing id")
                return

            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("NOTE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == note_id:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/import":
            master = self._require_login()
            if master is None:
                return

            is_async = self.headers.get("X-Requested-With", "").lower() == "fetch"

            def respond_error(message, status=400):
                if is_async:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(jsonlib.dumps({"ok": False, "message": message}).encode("utf-8"))
                else:
                    self.send_response(302)
                    self.send_header("Location", f"/?err={urllib.parse.quote(message)}")
                    self.end_headers()

            def respond_success(message="Import complete."):
                if is_async:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(jsonlib.dumps({"ok": True, "message": message}).encode("utf-8"))
                else:
                    self.send_response(302)
                    self.send_header("Location", "/?msg=import-ok")
                    self.end_headers()

            content_type = (self.headers.get("Content-Type", "") or "")

            body_bytes = raw_body_bytes or b""
            body_len = len(body_bytes)

            if body_len <= 0:
                respond_error("No data provided.")
                return

            if body_len > MAX_IMPORT_BYTES:
                respond_error("Payload too large (max 1MB).", status=413)
                return

            sys.stderr.write(f'[import] Reading {body_len} bytes from request body...\n')

            fmt = "csv"
            content = ""
            export_password = ""

            if "multipart/form-data" in content_type.lower():
                try:
                    fields = parse_multipart(body_bytes, content_type)
                    fmt_raw = fields.get("fmt") or b"csv"
                    fmt = fmt_raw.decode("utf-8", "ignore").lower()
                    export_password = fields.get("export_password", b"").decode("utf-8", "ignore")
                    file_bytes = fields.get("file", b"")
                    if file_bytes:
                        content = file_bytes.decode("utf-8", "ignore")
                        sys.stderr.write('[import] Processed file upload via multipart parser\n')
                    elif fields.get("data"):
                        content = fields.get("data", b"").decode("utf-8", "ignore")
                        sys.stderr.write('[import] Processed pasted data via multipart parser\n')
                    else:
                        respond_error("Failed to parse upload.")
                        return
                except Exception as e:
                    sys.stderr.write(f"[import] Multipart parse failed: {e}\n")
                    respond_error("Failed to parse upload.")
                    return
            else:
                body_str = body_bytes.decode("utf-8", "ignore")
                data = urllib.parse.parse_qs(body_str)
                fmt = (data.get("fmt") or ["csv"])[0].lower()
                export_password = (data.get("export_password") or [""])[0]
                content = (data.get("data") or [""])[0]
                if not content and body_str:
                    content = body_str

            if fmt not in SUPPORTED_FORMATS:
                respond_error(f"Unsupported format {fmt}")
                return

            if not content.strip():
                respond_error("No content to import.")
                return

            try:
                sys.stderr.write('[import] Applying import data...\n')
                plaintext = load_vault(master, self._session_rec)
                new_plain, stats = _apply_import(fmt, content, plaintext, export_password)
                save_vault(master, new_plain, self._session_rec)
                sys.stderr.write(f"[import] Vault successfully updated ({stats}).\n")
                summary = ", ".join(f"{v} {k}" for k,v in stats.items() if v)
                respond_success(f"Import complete: {summary}.")
            except Exception as e:
                sys.stderr.write(f"[import] Import process failed: {e}\n")
                __import__("traceback").print_exc(file=sys.stderr)
                respond_error(str(e) or "Import failed.")
            return

        if path == "/passphrase-add":
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0]

            if not label:
                page = build_passphrase_form(
                    title="Add Passphrase",
                    vault_path=VAULT_PATH,
                    action="/passphrase-add",
                    values={"label": label, "secret": secret},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, passphrases = parse_passphrases(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in passphrases:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if not secret:
                secret = secrets.token_urlsafe(32)
            encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "PASSPHRASE",
                str(new_id),
                _vf(label),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/passphrase-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0]

            plaintext = load_vault(master, self._session_rec)
            lines, passphrases = parse_passphrases(plaintext)
            idx_to_update = None
            created = ""
            existing_secret = ""
            for idx, parts in passphrases:
                if parts[1] == pid:
                    idx_to_update = idx
                    if len(parts) >= 5:
                        created = parts[4]
                    if len(parts) >= 4:
                        existing_secret = parts[3]
                    break
            if idx_to_update is None:
                self.send_error(404, "Passphrase not found")
                return
            if not label:
                page = build_passphrase_form(
                    title=f"Edit Passphrase #{pid}",
                    vault_path=VAULT_PATH,
                    action="/passphrase-edit?id=" + urllib.parse.quote(pid),
                    values={"label": label, "secret": secret},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return
            if not secret:
                try:
                    # reuse existing secret if not provided
                    secret = base64.b64decode(existing_secret.encode("ascii"), validate=True).decode("utf-8", errors="strict")
                except Exception:
                    self.send_error(500, "Stored passphrase cannot be decoded; vault was not changed")
                    return
            encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
            lines[idx_to_update] = "\t".join([
                "PASSPHRASE",
                pid,
                _vf(label),
                encoded,
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "-",
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/passphrase-delete":
            pid = (data.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("PASSPHRASE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == pid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-add":
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0].replace(" ", "")
            period = (data.get("period") or ["30"])[0]
            algo_in = (data.get("algo") or [""])[0].lower()
            algo = ((data.get("algo") or ["sha1"])[0] or "sha1").lower()
            if algo not in ("sha1","sha256","sha512"):
                algo = "sha1"

            if not label or not secret:
                page = build_auth_form(
                    title="Add Authenticator",
                    vault_path=VAULT_PATH,
                    action="/authenticator-add",
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Label and secret are required.</div>",
                )
                self._send_html(200, page)
                return

            try:
                period_int = int(period)
                if period_int <= 0:
                    period_int = 30
            except Exception:
                period_int = 30

            try:
                _ = totp_code(secret, period_int, algo)
            except Exception:
                page = build_auth_form(
                    title="Add Authenticator",
                    vault_path=VAULT_PATH,
                    action="/authenticator-add",
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Invalid Base32 secret.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, auths = parse_authenticators(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in auths:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            new_line = "\t".join([
                "AUTH",
                str(new_id),
                _vf(label),
                _vf(secret),
                str(period_int),
                now,
                algo,
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0].replace(" ", "")
            period = (data.get("period") or ["30"])[0]
            algo_in = (data.get("algo") or [""])[0].lower()

            plaintext = load_vault(master, self._session_rec)
            lines, auths = parse_authenticators(plaintext)
            idx_to_update = None
            created = ""
            algo = "sha1"
            for idx, parts in auths:
                if parts[1] == aid:
                    idx_to_update = idx
                    if len(parts) >= 6:
                        created = parts[5]
                    if len(parts) >= 7 and parts[6]:
                        algo = parts[6].lower()
                    if not label:
                        label = parts[2]
                    if not secret:
                        secret = parts[3]
                    try:
                        if not period:
                            period = parts[4]
                    except Exception:
                        pass
                    break

            if algo_in in ("sha1","sha256","sha512"):
                algo = algo_in

            if idx_to_update is None:
                self.send_error(404, "Authenticator not found")
                return

            try:
                period_int = int(period)
                if period_int <= 0:
                    period_int = 30
            except Exception:
                period_int = 30

            try:
                _ = totp_code(secret, period_int, algo)
            except Exception:
                page = build_auth_form(
                    title=f"Edit Authenticator #{aid}",
                    vault_path=VAULT_PATH,
                    action="/authenticator-edit?id=" + urllib.parse.quote(aid),
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Invalid Base32 secret.</div>",
                )
                self._send_html(200, page)
                return

            lines[idx_to_update] = "\t".join([
                "AUTH",
                aid,
                _vf(label),
                _vf(secret),
                str(period_int),
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                algo,
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-delete":
            aid = (data.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            found = False
            for line in lines:
                if line.startswith("AUTH\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == aid:
                        found = True
                        continue
                new_lines.append(line)
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-add":
            label = (data.get("label") or [""])[0].strip()
            codes = (data.get("codes") or [""])[0]
            if not label:
                page = build_backup_form(
                    title="Add Backup Codes",
                    vault_path=VAULT_PATH,
                    action="/backup-codes-add",
                    values={"label": label, "codes": codes},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, backups = parse_backup_codes(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in backups:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            encoded = base64.b64encode(codes.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "BACKUP_CODE",
                str(new_id),
                _vf(label),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            codes = (data.get("codes") or [""])[0]

            plaintext = load_vault(master, self._session_rec)
            lines, backups = parse_backup_codes(plaintext)
            idx_to_update = None
            created = ""
            backups_by_id = {}
            for idx, parts in backups:
                if len(parts) >= 4:
                    backups_by_id[parts[1]] = parts[3]
                if parts[1] == bid:
                    idx_to_update = idx
                    if len(parts) >= 5:
                        created = parts[4]
                    break
            if idx_to_update is None:
                self.send_error(404, "Backup code not found")
                return
            if not label:
                page = build_backup_form(
                    title=f"Edit Backup Codes #{bid}",
                    vault_path=VAULT_PATH,
                    action="/backup-codes-edit?id=" + urllib.parse.quote(bid),
                    values={"label": label, "codes": codes},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return
            if not codes:
                # A blank field means "leave them alone", never "erase them".
                # Recovery codes cannot be regenerated from the vault, so an
                # unreadable stored value must stop rather than be replaced.
                stored = backups_by_id.get(bid, "")
                try:
                    codes = base64.b64decode(stored.encode("ascii"), validate=True).decode("utf-8", errors="strict")
                except Exception:
                    self.send_error(500, "Stored backup codes cannot be decoded; vault was not changed")
                    return
            encoded = base64.b64encode(codes.encode("utf-8")).decode("ascii")
            lines[idx_to_update] = "\t".join([
                "BACKUP_CODE",
                bid,
                _vf(label),
                encoded,
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "-",
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-delete":
            bid = (data.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("BACKUP_CODE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == bid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        self.send_error(404, "Not found")

def run():
    with SPMServer((BIND_ADDR, PORT), Handler) as httpd:
        print(f"[SPM Dashboard] Serving on http://{BIND_ADDR}:{PORT}/")
        print("[SPM Dashboard] Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SPM Dashboard] Shutting down...")

if __name__ == "__main__":
    run()
PY

	echo "$script_path"
}

get_external_ip() {
	# Keep the SPM Dashboard offline: never call a public IP-discovery service merely to
	# print the access URL. Prefer a LAN address already known by the device.
	local addr=""
	if command -v hostname >/dev/null 2>&1; then
		addr="$(hostname -I 2>/dev/null | awk '{print $1}')" || addr=""
	fi
	if [ -z "$addr" ] && command -v ip >/dev/null 2>&1; then
		addr="$(ip -o -4 addr show scope global 2>/dev/null | awk 'NR==1{sub(/\/.*/,"",$4);print $4}')" || addr=""
	fi
	printf '%s\n' "${addr:-YOUR_SERVER_IP}"
}

# ----- Interactive menu ------------------------------------------------------

interactive_menu_notes() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> MENU CATATAN AMAN (SECURE NOTES)\n\n"
			printf "  1) List catatan\n"
			printf "  2) Tambah catatan\n"
			printf "  3) Lihat catatan\n"
			printf "  4) Hapus catatan\n"
			printf "  0) Kembali\n\n"
			printf "Pilih menu: "
		else
			printf ">> SECURE NOTES MENU\n\n"
			printf "  1) List notes\n"
			printf "  2) Add note\n"
			printf "  3) View note\n"
			printf "  4) Delete note\n"
			printf "  0) Back\n\n"
			printf "Choose an option: "
		fi

		read -r c || true
		case "$c" in
			1)
				clear
				cmd_notes_list || true
				pause_menu
				;;
			2)
				clear
				cmd_notes_add || true
				pause_menu
				;;
			3)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID catatan: "
				else
					printf "Enter note ID: "
				fi
				read -r nid || true
				if [ -n "$nid" ]; then
					cmd_notes_view "$nid" || true
				fi
				pause_menu
				;;
			4)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID catatan yang akan dihapus: "
				else
					printf "Enter note ID to delete: "
				fi
				read -r nid || true
				if [ -n "$nid" ]; then
					cmd_notes_delete "$nid" || true
				fi
				pause_menu
				;;
			0)
				break
				;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}

interactive_menu_backup_codes() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> MENU KODE BACKUP (BACKUP CODES)\n\n"
			printf "  1) List kode backup\n"
			printf "  2) Tambah kode backup\n"
			printf "  3) Lihat kode backup\n"
			printf "  4) Hapus kode backup\n"
			printf "  0) Kembali\n\n"
			printf "Pilih menu: "
		else
			printf ">> BACKUP CODES MENU\n\n"
			printf "  1) List backup codes\n"
			printf "  2) Add backup codes\n"
			printf "  3) View backup codes\n"
			printf "  4) Delete backup codes\n"
			printf "  0) Back\n\n"
			printf "Choose an option: "
		fi

		read -r c || true
		case "$c" in
			1)
				clear
				cmd_backup_codes_list || true
				pause_menu
				;;
			2)
				clear
				cmd_backup_codes_add || true
				pause_menu
				;;
			3)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID kode backup: "
				else
					printf "Enter backup code ID: "
				fi
				read -r bcid || true
				if [ -n "$bcid" ]; then
					cmd_backup_codes_view "$bcid" || true
				fi
				pause_menu
				;;
			4)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID kode backup yang akan dihapus: "
				else
					printf "Enter backup code ID to delete: "
				fi
				read -r bcid || true
				if [ -n "$bcid" ]; then
					cmd_backup_codes_delete "$bcid" || true
				fi
				pause_menu
				;;
			0)
				break
				;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}

interactive_menu_passphrases() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> MENU PASSPHRASE\n\n"
			printf "  1) List passphrase\n"
			printf "  2) Tambah passphrase\n"
			printf "  3) Lihat passphrase\n"
			printf "  4) Hapus passphrase\n"
			printf "  0) Kembali\n\n"
			printf "Pilih menu: "
		else
			printf ">> PASSPHRASES MENU\n\n"
			printf "  1) List passphrases\n"
			printf "  2) Add passphrase\n"
			printf "  3) View passphrase\n"
			printf "  4) Delete passphrase\n"
			printf "  0) Back\n\n"
			printf "Choose an option: "
		fi

		read -r c || true
		case "$c" in
			1)
				clear
				cmd_passphrase_list || true
				pause_menu
				;;
			2)
				clear
				cmd_passphrase_add || true
				pause_menu
				;;
			3)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID passphrase: "
				else
					printf "Enter passphrase ID: "
				fi
				read -r pid || true
				if [ -n "$pid" ]; then
					cmd_passphrase_view "$pid" || true
				fi
				pause_menu
				;;
			4)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID passphrase yang akan dihapus: "
				else
					printf "Enter passphrase ID to delete: "
				fi
				read -r pid || true
				if [ -n "$pid" ]; then
					cmd_passphrase_delete "$pid" || true
				fi
				pause_menu
				;;
			0)
				break
				;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}

interactive_menu_generator() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> GENERATOR KATA SANDI\n\n"
			printf "  1) Buat password\n"
			printf "  0) Kembali\n\n"
			printf "Pilih menu: "
		else
			printf ">> PASSWORD GENERATOR\n\n"
			printf "  1) Generate password\n"
			printf "  0) Back\n\n"
			printf "Choose an option: "
		fi
		read -r c || true
		case "$c" in
			1)
				clear
				local length mode symbols symbols_flag
				symbols_flag=0
				if [ "$SPM_LANG" = "id" ]; then
					printf "Panjang password (4-128, default 16): "
				else
					printf "Password length (4-128, default 16): "
				fi
				read -r length || true
				[ -z "$length" ] && length=16
				if ! printf '%s' "$length" | grep -Eq '^[0-9]+$'; then
					length=16
				fi
				if [ "$length" -lt 4 ]; then length=4; fi
				if [ "$length" -gt 128 ]; then length=128; fi

				if [ "$SPM_LANG" = "id" ]; then
					printf "Mode (easy/secure/numeric) [secure]: "
				else
					printf "Mode (easy/secure/numeric) [secure]: "
				fi
				read -r mode || true
				[ -z "$mode" ] && mode="secure"

				if [ "$SPM_LANG" = "id" ]; then
					printf "Tambahkan simbol? (y/N): "
				else
					printf "Include symbols? (y/N): "
				fi
				read -r symbols || true
				if [ "$symbols" = "y" ] || [ "$symbols" = "Y" ]; then
					symbols_flag=1
				else
					symbols_flag=0
				fi

				local pw
				pw="$(generate_password "$length" "$mode" "$symbols_flag")"
				printf "\n%s\n\n" "$pw"
				password_strength_report "$pw"
				pause_menu
				;;
			0) break ;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}

interactive_menu_authenticators() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> MENU AUTHENTICATOR (TOTP)\n\n"
			printf "  1) List authenticator\n"
			printf "  2) Tambah authenticator\n"
			printf "  3) Lihat authenticator\n"
			printf "  4) Edit authenticator\n"
			printf "  5) Hapus authenticator\n"
			printf "  0) Kembali\n\n"
			printf "Pilih menu: "
		else
			printf ">> AUTHENTICATORS MENU\n\n"
			printf "  1) List authenticators\n"
			printf "  2) Add authenticator\n"
			printf "  3) View authenticator\n"
			printf "  4) Edit authenticator\n"
			printf "  5) Delete authenticator\n"
			printf "  0) Back\n\n"
			printf "Choose an option: "
		fi

		read -r c || true
		case "$c" in
			1) clear; cmd_authenticator_list || true; pause_menu ;;
			2) clear; cmd_authenticator_add || true; pause_menu ;;
			3)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID authenticator: "
				else
					printf "Enter authenticator ID: "
				fi
				read -r aid || true
				if [ -n "$aid" ]; then
					cmd_authenticator_view "$aid" || true
				fi
				pause_menu
				;;
			4)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID authenticator yang akan diedit: "
				else
					printf "Enter authenticator ID to edit: "
				fi
				read -r aid || true
				if [ -n "$aid" ]; then
					cmd_authenticator_edit "$aid" || true
				fi
				pause_menu
				;;
			5)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID authenticator yang akan dihapus: "
				else
					printf "Enter authenticator ID to delete: "
				fi
				read -r aid || true
				if [ -n "$aid" ]; then
					cmd_authenticator_delete "$aid" || true
				fi
				pause_menu
				;;
			0) break ;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}


interactive_menu_history() {
	local dir names count choice snapshot
	while true; do
		clear
		print_banner
		dir="$(history_dir)"
		# Newest first. Snapshot names begin with a UTC %Y%m%dT%H%M%S stamp, so
		# a reverse sort on the name is chronological -- unlike mtime, which
		# these files inherit from the vault they were copied from.
		names=""
		if [ -d "$dir" ]; then
			names="$(find "$dir" -maxdepth 1 -type f -name '*.gpg' -print 2>/dev/null \
				| while IFS= read -r snapshot; do basename "$snapshot"; done | sort -r)"
		fi
		count=0
		if [ "$SPM_LANG" = "id" ]; then
			printf ">> RIWAYAT VAULT (SNAPSHOT TERENKRIPSI)\n\n"
		else
			printf ">> VAULT HISTORY (ENCRYPTED SNAPSHOTS)\n\n"
		fi
		if [ -z "$names" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "  (belum ada snapshot)\n\n"
			else
				printf "  (no snapshots yet)\n\n"
			fi
		else
			while IFS= read -r snapshot; do
				[ -n "$snapshot" ] || continue
				count=$((count + 1))
				printf "  %2d) %s  %s\n" "$count" \
					"$(printf '%s' "$snapshot" | cut -d. -f1)" \
					"$(du -h "$dir/$snapshot" 2>/dev/null | cut -f1)"
			done <<-EOF
			$names
			EOF
			printf "\n"
		fi
		if [ "$SPM_LANG" = "id" ]; then
			printf "   0) Kembali\n\n"
			printf "Pilih nomor snapshot untuk dipulihkan: "
		else
			printf "   0) Back\n\n"
			printf "Choose a snapshot number to restore: "
		fi
		read -r choice || true
		case "$choice" in
			0|"") break ;;
		esac
		if ! printf '%s' "$choice" | grep -Eq '^[0-9]+$' \
			|| [ "$choice" -lt 1 ] || [ "$choice" -gt "$count" ]; then
			if [ "$SPM_LANG" = "id" ]; then
				printf "Pilihan tidak valid.\n"
			else
				printf "Invalid choice.\n"
			fi
			pause_menu
			continue
		fi
		# The name is never typed: the picker resolves it. The confirmation
		# inside cmd_history_restore stays, because this overwrites a live
		# vault.
		snapshot="$(printf '%s\n' "$names" | sed -n "${choice}p")"
		clear
		cmd_history_restore "$snapshot" || true
		pause_menu
	done
}

interactive_menu_autoupdate() {
	local mode choice
	while true; do
		clear
		print_banner
		mode="$(autoupdate_mode)"
		if [ "$SPM_LANG" = "id" ]; then
			printf "Update otomatis\n\n"
			printf "Mode sekarang : %s\n" "$mode"
			printf "Cek terakhir  : %s\n" "$(autoupdate_get LAST_CHECK belum)"
			printf "Rilis terbaru : %s\n\n" "$(autoupdate_get LAST_SEEN '-')"
			printf "  1) Mati      - tidak pernah menghubungi GitHub sendiri\n"
			printf "  2) Beritahu  - cek harian, tanya dulu sebelum memasang\n"
			printf "  3) Otomatis  - cek harian, langsung pasang rilis baru\n"
			printf "  4) Cek sekarang\n"
			printf "  0) Kembali\n\n"
			printf "Pilih: "
		else
			printf "Auto-update\n\n"
			printf "Current mode : %s\n" "$mode"
			printf "Last check   : %s\n" "$(autoupdate_get LAST_CHECK never)"
			printf "Latest seen  : %s\n\n" "$(autoupdate_get LAST_SEEN '-')"
			printf "  1) Off       - never contact GitHub on its own\n"
			printf "  2) Notify    - check daily, ask before installing\n"
			printf "  3) Automatic - check daily, install new releases without asking\n"
			printf "  4) Check now\n"
			printf "  0) Back\n\n"
			printf "Choice: "
		fi
		read -r choice || choice="0"
		case "$choice" in
			1) autoupdate_put MODE off || true ;;
			2|3)
				if [ "$choice" = "2" ]; then
					autoupdate_put MODE notify || true
				else
					autoupdate_put MODE auto || true
				fi
				# A mode change should take effect on the next launch rather
				# than whenever the daily window happens to reopen.
				autoupdate_put LAST_CHECK 0 || true
				if [ "$SPM_LANG" = "id" ]; then
					printf "\nSPM akan menghubungi GitHub Releases saat mulai, paling sering sekali sehari.\n"
				else
					printf "\nSPM will contact GitHub Releases at startup, at most once a day.\n"
				fi
				pause_menu
				;;
			4)
				clear
				cmd_update || true
				autoupdate_put LAST_CHECK "$(date +%s 2>/dev/null || printf 0)" || true
				pause_menu
				;;
			0) return ;;
			*) ;;
		esac
	done
}

interactive_menu() {
	while true; do
		clear
		print_banner
		if [ "$SPM_LANG" = "id" ]; then
			printf "Versi        : %s\n" "$VERSION"
			printf "Lokasi vault : %s\n" "$VAULT_FILE"
			if [ -f "$VAULT_FILE" ]; then
				printf "Vault ada    : ya\n"
			else
				printf "Vault ada    : tidak (jalankan INIT dulu)\n"
			fi
			printf "\n"
			printf "  1) List semua entry\n"
			printf "  2) Tambah entry\n"
			printf "  3) Lihat entry (ID / cari)\n"
			printf "  4) Hapus entry\n"
			printf "  5) Edit vault (RAW)\n"
			printf "  6) Ganti kata sandi utama\n"
			printf "  7) Buat bundle portable\n"
			printf "  8) SAVE (bundle + hapus vault lokal)\n"
			printf "  9) Export (csv/json)\n"
			printf " 10) Import (csv/json)\n"
			printf " 11) Help\n"
			printf " 12) Cek update\n"
			printf " 13) Lupa / Reset kata sandi utama (pemulihan)\n"
			printf " 14) Catatan aman (secure notes)\n"
			printf " 15) Passphrase\n"
			printf " 16) Authenticator (TOTP)\n"
			printf " 17) Kode backup\n"
			printf " 18) Generator password\n"
			printf " 19) Doctor / Health check\n"
			printf " 20) SPM Dashboard\n"
			printf " 21) Restore vault dari bundle portable/save\n"
			printf " 22) Pengaturan update otomatis [%s]\n" "$(autoupdate_mode)"
			printf " 23) Riwayat vault (snapshot)\n"
			printf "  0) Keluar\n\n"
			printf "Pilih menu: "
		else
			printf "Version    : %s\n" "$VERSION"
			printf "Vault path : %s\n" "$VAULT_FILE"
			if [ -f "$VAULT_FILE" ]; then
				printf "Vault exist: yes\n"
			else
				printf "Vault exist: no (run INIT first)\n"
			fi
			printf "\n"
			printf "  1) List entries\n"
			printf "  2) Add entry\n"
			printf "  3) Get entry (ID / search)\n"
			printf "  4) Delete entry\n"
			printf "  5) Edit raw vault\n"
			printf "  6) Change master password\n"
			printf "  7) Create portable bundle\n"
			printf "  8) SAVE (bundle + wipe local vault)\n"
			printf "  9) Export (csv/json)\n"
			printf " 10) Import (csv/json)\n"
			printf " 11) Help\n"
			printf " 12) Check for updates\n"
			printf " 13) Forgot / Reset master (use private key)\n"
			printf " 14) Secure notes\n"
			printf " 15) Passphrases\n"
			printf " 16) Authenticators (TOTP)\n"
			printf " 17) Backup codes\n"
			printf " 18) Password generator\n"
			printf " 19) Doctor / Health check\n"
			printf " 20) SPM Dashboard\n"
			printf " 21) Restore vault from bundle\n"
			printf " 22) Auto-update settings [%s]\n" "$(autoupdate_mode)"
			printf " 23) Vault history (snapshots)\n"
			printf "  0) Exit\n\n"
			printf "Choose an option: "
		fi

		read -r choice || true

		case "$choice" in
			1) clear; cmd_list || true; pause_menu ;;
			2) clear; cmd_add || true; pause_menu ;;
			3)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID atau kata kunci: "
				else
					printf "Enter ID or search pattern: "
				fi
				read -r q || true
				if [ -n "$q" ]; then
					cmd_get "$q" || true
				fi
				pause_menu
				;;
			4)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Masukkan ID yang akan dihapus: "
				else
					printf "Enter ID to delete: "
				fi
				read -r did || true
				if printf '%s' "$did" | grep -Eq '^[0-9]+$'; then
					cmd_delete "$did" || true
				fi
				pause_menu
				;;
			5) clear; cmd_edit || true; pause_menu ;;
			6) clear; cmd_change_master || true; pause_menu ;;
			7)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Nama bundle (kosong = auto): "
				else
					printf "Bundle name (blank = auto): "
				fi
				read -r bname || true
				if [ -n "$bname" ]; then
					cmd_portable "$bname" || true
				else
					cmd_portable || true
				fi
				pause_menu
				;;
			8)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "PERINGATAN: Ini akan menghapus vault lokal setelah membuat bundle.\n"
					printf "Lanjut? (yes/NO): "
				else
					printf "WARNING: This will wipe the local vault after creating a bundle.\n"
					printf "Continue? (yes/NO): "
				fi
				read -r conf || true
				if [ "$conf" = "yes" ] || [ "$conf" = "y" ]; then
					if [ "$SPM_LANG" = "id" ]; then
						printf "Nama bundle (kosong = auto): "
					else
						printf "Bundle name (blank = auto): "
					fi
					read -r sname || true
					if [ -n "$sname" ]; then
						cmd_save "$sname" || true
					else
						cmd_save || true
					fi
				fi
				pause_menu
				;;
			9)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Format (csv/json) [csv]: "
					printf "\nFormat lain tersedia: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc\n\n"
				else
					printf "Format (csv/json) [csv]: "
					printf "\nOther available: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc\n\n"
				fi
				read -r fmt || fmt="csv"
				if [ "$SPM_LANG" = "id" ]; then
					printf "Nama file keluaran (kosong=auto): "
				else
					printf "Output filename (blank=auto): "
				fi
				read -r oname || true
				if [ -n "$oname" ]; then
					cmd_export "$fmt" "$oname" || true
				else
					cmd_export "$fmt" || true
				fi
				pause_menu
				;;
			10)
				clear
				if [ "$SPM_LANG" = "id" ]; then
					printf "Format impor (csv/json) [csv]: "
					printf "\nFormat lain tersedia: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc\n\n"
				else
					printf "Import format (csv/json) [csv]: "
					printf "\nOther available: tsv, ndjson/jsonl, md, html, txt, yaml/yml, xml, sql, ini, psv, rst, toml, org, scsv, csv-noheader, jsonc\n\n"
				fi
				read -r ifmt || ifmt="csv"
				if [ "$SPM_LANG" = "id" ]; then
					printf "Path file sumber: "
				else
					printf "Source file path: "
				fi
				read -r ipath || true
				if [ -n "$ipath" ]; then
					cmd_import "$ifmt" "$ipath" || true
				fi
				pause_menu
				;;
			11) clear; cmd_help; pause_menu ;;
			12) clear; cmd_update || true; pause_menu ;;
			13) clear; cmd_forgot || true; pause_menu ;;
			14) interactive_menu_notes ;;
			15) interactive_menu_passphrases ;;
			16) interactive_menu_authenticators ;;
			17) interactive_menu_backup_codes ;;
			18) interactive_menu_generator ;;
			19) clear; cmd_doctor || true; pause_menu ;;
			20)
				clear
				release_cli_vault_lock
				start_web_mode || true
				acquire_cli_vault_lock
				;;
			21) clear; cmd_restore || true; pause_menu ;;
			22) interactive_menu_autoupdate ;;
			23) interactive_menu_history ;;
			0)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Keluar...\n"
				else
					printf "Exiting...\n"
				fi
				break
				;;
			*)
				if [ "$SPM_LANG" = "id" ]; then
					printf "Menu tidak valid.\n"
				else
					printf "Invalid choice.\n"
				fi
				pause_menu
				;;
		esac
	done
}

# ----- Main ------------------------------------------------------------------

main() {
	# Native messaging is a machine-readable protocol: never emit language or
	# consent prompts before its single JSON response.
	if [ "${1:-}" = "bridge-get" ] || [ "${1:-}" = "bridge-list" ]; then
		local bridge_cmd="$1"
		shift
		acquire_cli_vault_lock
		case "$bridge_cmd" in
			bridge-get) cmd_bridge_get "$@" ;;
			bridge-list) cmd_bridge_list "$@" ;;
		esac
		return
	fi
	# `doctor --json` makes the same promise bridge-* does: one JSON document on
	# stdout and nothing else. ensure_requirements prints a banner, and
	# choose_language and ensure_policy_consent both prompt -- all to stdout --
	# so a caller piping this into jq got a banner instead of a document. The
	# lock is still taken, because the report reads the vault.
	if [ "${1:-}" = "doctor" ] && [ "${2:-}" = "--json" ]; then
		acquire_cli_vault_lock
		cmd_doctor_json
		return
	fi
	# Help must remain available before dependency installation, language, or
	# policy prompts so users can inspect the CLI on a fresh platform.
	case "${1:-}" in
		help|-h|--help)
			cmd_help
			return
			;;
	esac
	ensure_requirements
	choose_language
	ensure_policy_consent

	if [ $# -eq 0 ]; then
		autoupdate_startup_check
		acquire_cli_vault_lock
		interactive_menu
		return
	fi

	local cmd="$1"
	shift || true
	case "$cmd" in
		update|auto-update|generate|password-generate|web|web-mode|help|-h|--help|vault-profile) ;;
		*) acquire_cli_vault_lock ;;
	esac

	case "$cmd" in
		init)             cmd_init "$@" ;;
		add)              cmd_add "$@" ;;
		list)             cmd_list "$@" ;;
		get)              cmd_get "$@" ;;
		edit)             cmd_edit "$@" ;;
		delete)           cmd_delete "$@" ;;
		change-master)    cmd_change_master "$@" ;;
		portable)         cmd_portable "$@" ;;
		save)             cmd_save "$@" ;;
		restore)          cmd_restore "$@" ;;
		update)           cmd_update "$@" ;;
		auto-update)      cmd_autoupdate "$@" ;;
		forgot|forgotten) cmd_forgot "$@" ;;
		doctor)           cmd_doctor "$@" ;;
		export)           cmd_export "$@" ;;
		import)           cmd_import "$@" ;;
		security|security-dashboard) cmd_security_dashboard "$@" ;;
		history-list)    cmd_history_list "$@" ;;
		history-restore) cmd_history_restore "$@" ;;
		backup-now)      cmd_backup_now "$@" ;;
		backup-auto)     cmd_backup_auto "$@" ;;
		vault-profile)   cmd_vault_profile "$@" ;;
		attachment-add)  cmd_attachment_add "$@" ;;
		attachment-list) cmd_attachment_list "$@" ;;
		attachment-extract) cmd_attachment_extract "$@" ;;
		attachment-delete) cmd_tag_delete ATTACHMENT "${1:-}" Attachment ;;
		passkey-add)     cmd_passkey_add "$@" ;;
		passkey-list)    cmd_passkey_list "$@" ;;
		passkey-delete)  cmd_tag_delete PASSKEY "${1:-}" 'Passkey metadata' ;;
		webauthn-list)   cmd_webauthn_list ;;
		webauthn-delete) cmd_tag_delete WEBAUTHN "${1:-}" 'Unlock credential' ;;
		sync)            cmd_sync "$@" ;;
		emergency-create) cmd_emergency_create "$@" ;;
		emergency-open)  cmd_emergency_open "$@" ;;
		generate|password-generate) cmd_generate_password "$@" ;;
		notes-add)        cmd_notes_add "$@" ;;
		notes-list)       cmd_notes_list "$@" ;;
		notes-view)       cmd_notes_view "$@" ;;
		notes-delete)     cmd_notes_delete "$@" ;;
		passphrase-add)   cmd_passphrase_add "$@" ;;
		passphrase-list)  cmd_passphrase_list "$@" ;;
		passphrase-view)  cmd_passphrase_view "$@" ;;
		passphrase-delete) cmd_passphrase_delete "$@" ;;
		authenticator-add) cmd_authenticator_add "$@" ;;
		authenticator-list) cmd_authenticator_list "$@" ;;
		authenticator-view) cmd_authenticator_view "$@" ;;
		authenticator-edit) cmd_authenticator_edit "$@" ;;
		authenticator-delete) cmd_authenticator_delete "$@" ;;
		backup-codes-add) cmd_backup_codes_add "$@" ;;
		backup-codes-list) cmd_backup_codes_list "$@" ;;
		backup-codes-view) cmd_backup_codes_view "$@" ;;
		backup-codes-delete) cmd_backup_codes_delete "$@" ;;
		# `web` and `web-mode` are kept forever: they are in users' shell
		# history, scripts and process managers. `dashboard` is the name the
		# interface now goes by, not a replacement verb.
		web|web-mode|dashboard) start_web_mode "$@" ;;
		help|-h|--help)   cmd_help ;;
		*)
			printf "Unknown command: %s\n\n" "$cmd" >&2
			cmd_help
			exit 1
			;;
	esac
}

# Run main only when this file is executed, never when it is sourced.
#
# Without this, `source spm.sh` fell straight into the interactive menu, and a
# menu blocked on `read` holds whatever it had already acquired -- including an
# exclusive flock on ${VAULT_FILE}.lock, which for a caller that had not set
# PASSWORD_VAULT is the operator's real vault. A sourced helper that silently
# locks a live vault until it is killed is not a footgun anyone should have to
# know about; the guard removes it rather than documenting it.
#
# The `:-$0` default matters: piped to a shell (`curl ... | bash`) there is no
# BASH_SOURCE at all, and under `set -o nounset` a bare reference aborts with
# "unbound variable" instead of running. Defaulting to $0 makes that case
# compare equal, so a piped script still runs.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
	main "$@"
fi

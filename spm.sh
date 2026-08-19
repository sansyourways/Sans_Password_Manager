#!/usr/bin/env bash
# Sans Password Manager (SPM)
# Portable Bash + GPG password manager with encrypted vault.
# Dependencies: bash, gpg, openssl, base64, curl (for update)

set -o errexit
set -o nounset
set -o pipefail

VERSION="2.9.3"

# ----- Repo info for update check --------------------------------------------

# Adjust these to match your GitHub repo
REPO_OWNER="sansyourways"
REPO_NAME="Sans_Password_Manager"
REPO_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

# Global master password (in-memory only, per process)
MASTER_PW=""
# Registry of temp files holding decrypted vault material.
# A file (not an array) because make_tmp is called via $(...) subshells,
# whose variable writes would be discarded. Wiped by cleanup() on any exit.
SPM_TMP_REGISTRY="${TMPDIR:-/tmp}/.spm_tmpreg.$$"
# Language: en / id (can be pre-set via env SPM_LANG)
SPM_LANG="${SPM_LANG:-}"

# Environment detection / package manager
ENV_FLAVOR=""   # termux / linux / macos / other
PKG_TYPE=""     # apt / pacman / dnf / apk / brew / none

# ----- Script + vault path detection -----------------------------------------

# Try to resolve the script path for copying into portable/save bundles.
SCRIPT_SRC="$0"
if [ ! -f "$SCRIPT_SRC" ]; then
	if command -v "$0" >/dev/null 2>&1; then
		SCRIPT_SRC="$(command -v "$0")"
	fi
fi

DEFAULT_VAULT_PATH="$HOME/.spm_vault.gpg"

# Vault resolution logic:
# 1) If PASSWORD_VAULT is set → use it
# 2) Else if ./spm_vault.gpg exists → use it (portable bundle case)
# 3) Else → use ~/.spm_vault.gpg
if [ -n "${PASSWORD_VAULT:-}" ]; then
	VAULT_FILE="$PASSWORD_VAULT"
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
	printf '%s' "$1" | tr '\t\r\n' '   '
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
	tmp="$(mktemp "${TMPDIR:-/tmp}/spm.XXXXXX")"
	chmod 600 "$tmp" 2>/dev/null || true
	printf '%s\n' "$tmp" >>"$SPM_TMP_REGISTRY" 2>/dev/null || true
	chmod 600 "$SPM_TMP_REGISTRY" 2>/dev/null || true
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
	printf "Sans Password Manager (SPM)  v%s  \u00a9 %s Sansyourways. All rights reserved.\n\n" "$VERSION" "$year"
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
		PKG_TYPE="apt"
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
	if [ "$SPM_LANG" = "id" ]; then
		printf 'Kata sandi utama: '
	else
		printf 'Master password: '
	fi
	stty -echo
	IFS= read -r MASTER_PW
	stty echo
	printf '\n'
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

decrypt_vault_to_file() {
	local out_file="$1"
	[ -f "$VAULT_FILE" ] || die "Vault does not exist. Run '$0 init' first."

	ensure_master_password_loaded

	if ! printf '%s' "$MASTER_PW" | gpg --batch --quiet \
		--decrypt --cipher-algo AES256 \
		--pinentry-mode loopback --passphrase-fd 0 \
		"$VAULT_FILE" >"$out_file" 2>/dev/null; then
		secure_wipe "$out_file"
		MASTER_PW=""
		if [ "$SPM_LANG" = "id" ]; then
			die "Gagal mendekripsi vault. Kata sandi utama salah?"
		else
			die "Failed to decrypt vault. Wrong master password?"
		fi
	fi
}

encrypt_file_to_vault() {
	local in_file="$1"
	[ "${MASTER_PW:-}" ] || die "MASTER_PW is empty in encrypt_file_to_vault"

	if [ -f "$VAULT_FILE" ]; then
		cp "$VAULT_FILE" "${VAULT_FILE}.bak" 2>/dev/null || true
		# cp creates the copy under the current umask, so the backup would
		# otherwise land as 0644 while the vault itself is 0600.
		chmod 600 "${VAULT_FILE}.bak" 2>/dev/null || true
	fi

	if ! printf '%s' "$MASTER_PW" | gpg --batch --yes \
		--symmetric --cipher-algo AES256 \
		--pinentry-mode loopback --passphrase-fd 0 \
		-o "$VAULT_FILE" "$in_file" 2>/dev/null; then
		die "Failed to re-encrypt vault. Your data is still in '$in_file' and '${VAULT_FILE}.bak'."
	fi

	chmod 600 "$VAULT_FILE" 2>/dev/null || true
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
		printf '%-5s  %-20s  %-20s  %-20s\n' "ID" "Layanan" "Username" "Dibuat"
	else
		printf '%-5s  %-20s  %-20s  %-20s\n' "ID" "Service" "Username" "Created"
	fi
	printf '%.0s-' $(seq 1 70); printf '\n'

	awk -F '\t' '
		NF >= 6 && $1 ~ /^[0-9]+$/ {
			printf "%-5s  %-20s  %-20s  %-20s\n", $1, $2, $3, $6
		}
	' "$file"
}

search_vault() {
	local file="$1"
	local pattern="$2"

	awk -F '\t' -v p="$pattern" '
		$1 ~ /^[0-9]+$/ && (tolower($2) ~ tolower(p) || tolower($3) ~ tolower(p)) {
			printf "%-5s  %-20s  %-20s  %-20s\n", $1, $2, $3, $6
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

	require_cmd openssl
	local pub_b64 tmp_pub

	pub_b64="$(get_recovery_pub_b64_from_vault "$vault_plain")"
	if [ -z "$pub_b64" ]; then
		die "Recovery public key metadata not found in vault. Cannot update recovery file."
	fi

	tmp_pub="$(make_tmp)"
	if ! printf '%s' "$pub_b64" | base64 -d >"$tmp_pub" 2>/dev/null; then
		secure_wipe "$tmp_pub"
		die "Failed to decode embedded recovery public key."
	fi

	if ! printf '%s' "$MASTER_PW" | openssl rsautl -encrypt -pubin -inkey "$tmp_pub" -out "$RECOVERY_FILE" 2>/dev/null; then
		secure_wipe "$tmp_pub"
		die "Failed to create/update recovery file '$RECOVERY_FILE'."
	fi

	secure_wipe "$tmp_pub"
	chmod 600 "$RECOVERY_FILE" 2>/dev/null || true
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
			SPM_RAND_BELOW=$(( RANDOM % bound ))
			return 0
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
	[ "$include_upper" = "1" ] && charset="${charset}ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	[ "$include_lower" = "1" ] && charset="${charset}abcdefghijklmnopqrstuvwxyz"
	[ "$include_digits" = "1" ] && charset="${charset}0123456789"
	[ "$include_symbols" = "1" ] && charset="${charset}!@#$%^&*()_-+=[]{}:;,.?/|~"

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
				length="${2:-16}"
				shift 2
				;;
			-m|--mode)
				mode="${2:-secure}"
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
				break
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

	if ! printf '%s' "$MASTER_PW" | openssl rsautl -encrypt -pubin -inkey "$tmp_pub" -out "$RECOVERY_FILE" 2>/dev/null; then
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
		printf 'Username: '
	else
		printf 'Username: '
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

	local id created
	id="$(next_id_from_vault "$tmp")"
	created="$(now_iso)"

	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" \
		"$(sanitize_field "$service")" \
		"$(sanitize_field "$username")" \
		"$(sanitize_field "$pw")" \
		"$(sanitize_field "$notes")" \
		"$created" >>"$tmp"

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

		IFS=$'\t' read -r id service username password notes created <<EOF
$line
EOF

		# Backward-compat: old rows might have created_at in notes field
		if [ -z "${created:-}" ] && printf '%s\n' "${notes:-}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
			created="$notes"
			notes=""
		fi

		if [ "$SPM_LANG" = "id" ]; then
			printf "ID:       %s\n" "$id"
			printf "Layanan:  %s\n" "$service"
			printf "Username: %s\n" "$username"
			printf "Password: %s\n" "$password"
			printf "Catatan:  %s\n" "$notes"
			printf "Dibuat:   %s\n" "$created"
		else
			printf "ID:       %s\n" "$id"
			printf "Service:  %s\n" "$service"
			printf "Username: %s\n" "$username"
			printf "Password: %s\n" "$password"
			printf "Notes:    %s\n" "$notes"
			printf "Created:  %s\n" "$created"
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
		printf "# Format password: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at\n" >&2
		printf "# Format note    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-\n" >&2
		printf "# Format passphrase: PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-\n" >&2
		printf "# Format backup code: BACKUP_CODE<TAB>id<TAB>label<TAB>base64_codes<TAB>created_at<TAB>-\n" >&2
		printf "# Format authenticator: AUTH<TAB>id<TAB>label<TAB>base32_secret<TAB>period<TAB>created_at<TAB>algorithm\n" >&2
		printf "# Baris meta     : META_RECOVERY_PUBKEY...\n" >&2
	else
		printf "Opening vault in editor: %s\n" "$EDITOR_CMD"
		printf "# Password rows: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at\n" >&2
		printf "# Note rows    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-\n" >&2
		printf "# Passphrase rows: PASSPHRASE<TAB>id<TAB>label<TAB>base64_passphrase<TAB>created_at<TAB>-\n" >&2
		printf "# Backup code rows: BACKUP_CODE<TAB>id<TAB>label<TAB>base64_codes<TAB>created_at<TAB>-\n" >&2
		printf "# Authenticator rows: AUTH<TAB>id<TAB>label<TAB>base32_secret<TAB>period<TAB>created_at<TAB>algorithm\n" >&2
		printf "# Meta row     : META_RECOVERY_PUBKEY...\n" >&2
	fi

	"$EDITOR_CMD" "$tmp"

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

	if [ "$SPM_LANG" = "id" ]; then
		printf "Masukkan kata sandi utama BARU.\n"
	else
		printf "Enter NEW master password.\n"
	fi
	prompt_master_password

	write_recovery_file "$tmp"

	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "Kata sandi utama berhasil diubah.\n"
		printf "File pemulihan diperbarui di: %s\n" "$RECOVERY_FILE"
	else
		printf "Master password changed successfully.\n"
		printf "Recovery file updated at: %s\n" "$RECOVERY_FILE"
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
	local workdir="./$bundle_name"
	local has_recovery="no"
	local has_priv="no"

	if [ -e "$workdir" ]; then
		die "Target directory '$workdir' already exists. Choose another name."
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

	# Copy private key if present
	if [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
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
  - spm_recovery_private.pem (optional)
                          : RSA private key (if found beside the script)
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
  - If the private key (spm_recovery_private.pem) exists beside your script, it is included here—protect this archive carefully.
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
  - spm_recovery_private.pem (opsional)
                          : private key RSA bila ditemukan
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
  - Jika spm_recovery_private.pem tersedia di samping script, file tersebut disertakan—lindungi bundle ini baik-baik.
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

	local workdir="./$bundle_name"
	local has_recovery="no"
	local has_priv="no"
	local archive_path=""

	if [ -e "$workdir" ]; then
		die "Target directory '$workdir' already exists. Choose another name."
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

	# Copy private key if present so backup contains full recovery material
	if [ -f "$RECOVERY_PRIV_DEFAULT" ]; then
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
  - spm_recovery_private.pem : (optional) RSA private key if found beside the script
  - README.txt             : instructions

How to restore:
  1. Move this archive to the target device.
  2. Extract it into a folder.
  3. Run:
       ./spm.sh
  4. Enter your master password to access your vault.

Security notes:
  - Keep this backup offline (USB, encrypted disk, cloud with 2FA).
  - If spm_recovery_private.pem was found, it is included in this archive—protect it carefully.
  - Anyone with both this bundle and your private key could reset the vault password.

------------------------------------------------------------
[ID]

File yang disertakan:
  - spm.sh                   : script SPM
  - spm_vault.gpg            : vault terenkripsi
  - spm_vault.gpg.recovery   : (opsional) file pemulihan
  - spm_recovery_private.pem : (opsional) private key RSA bila ditemukan
  - README.txt               : petunjuk

Cara mengembalikan:
  1. Pindahkan arsip ini ke perangkat tujuan.
  2. Ekstrak ke sebuah folder.
  3. Jalankan:
       ./spm.sh
  4. Masukkan master password.

Catatan keamanan:
  - Simpan backup di tempat aman (USB, disk terenkripsi, cloud dengan 2FA).
  - Jika spm_recovery_private.pem tersedia, file tersebut disertakan—lindungi arsip ini baik-baik.
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

	if ! mv "$bundle_vault" "$dest_vault" 2>/dev/null; then
		cp "$bundle_vault" "$dest_vault" || die "Failed to copy vault."
		rm -f "$bundle_vault"
	fi
	chmod 600 "$dest_vault" 2>/dev/null || true

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
			if ! mv "./spm_vault.gpg.recovery" "$dest_recovery" 2>/dev/null; then
				cp "./spm_vault.gpg.recovery" "$dest_recovery" || die "Failed to copy recovery file."
				rm -f "./spm_vault.gpg.recovery"
			fi
			chmod 600 "$dest_recovery" 2>/dev/null || true
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
	latest_tag="$(printf '%s\n' "$json" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || true
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

	local sha_url
	sha_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -E 'spm\.sh\.sha256"' | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true

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
	read -r conf || conf="no"
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
	if ! tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/spm_update.XXXXXX" 2>/dev/null)"; then
		tmpdir="${TMPDIR:-/tmp}/spm_update.$$"
		mkdir -p "$tmpdir"
	fi
	local zip_path="$tmpdir/spm_latest.zip"
	local sha_path="$tmpdir/spm.sh.sha256"

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

	local target="/usr/local/bin/spm"
	if [ "$SPM_LANG" = "id" ]; then
		printf "Menginstal ke %s (mungkin butuh sudo)...\n" "$target"
	else
		printf "Installing to %s (sudo may be required)...\n" "$target"
	fi

	if command -v sudo >/dev/null 2>&1; then
		if ! sudo cp "$new_spm" "$target"; then
			rm -rf "$tmpdir"
			return 1
		fi
		sudo chmod +x "$target" >/dev/null 2>&1 || true
	else
		cp "$new_spm" "$target"
		chmod +x "$target" >/dev/null 2>&1 || true
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

	local old_master
	if ! old_master="$(openssl rsautl -decrypt -inkey "$pk_path" -in "$RECOVERY_FILE" 2>/dev/null)"; then
		die "Failed to decrypt recovery file with the provided private key."
	fi

	MASTER_PW="$old_master"

	local tmp
	tmp="$(make_tmp)"
	if ! printf '%s' "$MASTER_PW" | gpg --batch --quiet \
		--decrypt --cipher-algo AES256 \
		--pinentry-mode loopback --passphrase-fd 0 \
		"$VAULT_FILE" >"$tmp" 2>/dev/null; then
		secure_wipe "$tmp"
		MASTER_PW=""
		die "Recovered master password could not decrypt the vault. Recovery aborted."
	fi

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nVault berhasil didekripsi menggunakan kata sandi utama lama.\n"
		printf "Sekarang set kata sandi utama BARU.\n\n"
	else
		printf "\nVault successfully decrypted using recovered master password.\n"
		printf "Now set a NEW master password for this vault.\n\n"
	fi

	prompt_master_password
	write_recovery_file "$tmp"
	encrypt_file_to_vault "$tmp"
	secure_wipe "$tmp"

	if [ "$SPM_LANG" = "id" ]; then
		printf "\nKata sandi utama berhasil DI-RESET.\n"
		printf "File pemulihan diperbarui di: %s\n" "$RECOVERY_FILE"
		printf "Simpan baik-baik private key dan file recovery.\n"
	else
		printf "\nMaster password has been RESET.\n"
		printf "Recovery file updated at: %s\n" "$RECOVERY_FILE"
		printf "Keep your private key and this recovery file safe.\n"
	fi
}

cmd_doctor() {
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

	if [ "$SPM_LANG" = "id" ]; then
		printf "[✔] Jumlah entry password : %s\n" "$pw_total"
		printf "[ ] Duplikasi ID          : "
	else
		printf "[✔] Password entries count: %s\n" "$pw_total"
		printf "[ ] Duplicate IDs         : "
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
			if openssl rsautl -decrypt -inkey "$RECOVERY_PRIV_DEFAULT" -in "$RECOVERY_FILE" >/dev/null 2>&1; then
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✔] Private key dan file recovery cocok.\n"
				else
					printf "[✔] Private key and recovery file match.\n"
				fi
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
                "extra": ""
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
                "extra": ""
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
                "extra": ""
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
                "extra": ""
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
                )
            })

fieldnames = ["type","id","label","username","secret","notes","created","extra"]

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
            f.write("| " + " | ".join((r.get(k,"") or "").replace("\n"," ") for k in fieldnames) + " |\n")
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
                val = (r.get(k, "") or "").replace("\n", "\\n").replace('"', '\\"')
                f.write(f'{k} = "{val}"\n')
            f.write("\n")
elif fmt == "org":
    header = "| " + " | ".join(fieldnames) + " |\n"
    sep = "|" + "+".join("-" * (len(k)+2) for k in fieldnames) + "|\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(sep)
        for r in rows:
            f.write("| " + " | ".join((r.get(k,"") or "").replace("\n"," ") for k in fieldnames) + " |\n")
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
                val = val.replace("\n", "\\n")
                f.write(f"  {k}: \"{val}\"\n")
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
                f.write(f"{k}={r.get(k,'') or ''}\n")
            f.write("\n")
elif fmt == "psv":
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="|")
        writer.writeheader()
        writer.writerows(rows)
elif fmt == "rst":
    widths = {k: max(len(k), max(len((r.get(k,"") or "")) for r in rows) if rows else 0) for k in fieldnames}
    def sep(char="+"):
        return char + char.join("-" * (widths[k]+2) for k in fieldnames) + char + "\n"
    def row(vals):
        return "|" + "|".join(" " + v.ljust(widths[k]) + " " for k,v in vals) + "|\n"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(sep())
        f.write(row([(k,k) for k in fieldnames]))
        f.write(sep("+"))
        for r in rows:
            f.write(row([(k, (r.get(k,"") or "").replace("\n"," ")) for k in fieldnames]))
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
import sys, json, csv, base64
fmt, src_path, vault_path = sys.argv[1:]

def load_vault_lines(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.rstrip("\n") for ln in f]

lines = load_vault_lines(vault_path)

def _vf(value):
    # Vault records are TAB-delimited and line-based, so a field holding a raw
    # TAB or newline splits the record. Quoted multi-line notes are ordinary in
    # CSV exports from other managers, and used to land as extra broken rows.
    return str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")

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

def add_password(r):
    pid = str(next_id("PASS"))
    lines.append("\t".join([
        pid,
        _vf(r.get("label","")),
        _vf(r.get("username","")),
        _vf(r.get("secret","")),
        _vf(r.get("notes","")),
        _vf(r.get("created",""))
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
    with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)

def parse_rows():
    if fmt in ("json","jsonc"):
        return parse_structured()
    if fmt in ("ndjson","jsonl"):
        out = []
        with open(src_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line: continue
                out.append(json.loads(line))
        return out
    delim = "," if fmt in ("csv","csv-noheader","jsonc") else ";" if fmt=="scsv" else "\t" if fmt=="tsv" else "|"
    rows=[]
    with open(src_path,"r",encoding="utf-8",errors="ignore",newline="") as f:
        reader = csv.DictReader(f, delimiter=delim) if fmt!="csv-noheader" else csv.reader(f, delimiter=delim)
        if fmt=="csv-noheader":
            for row in reader:
                rows.append({
                    "type": row[0] if len(row)>0 else "",
                    "label": row[1] if len(row)>1 else "",
                    "username": row[2] if len(row)>2 else "",
                    "secret": row[3] if len(row)>3 else "",
                    "notes": row[4] if len(row)>4 else "",
                    "created": row[5] if len(row)>5 else "",
                    "extra": row[6] if len(row)>6 else "",
                })
        else:
            rows = list(reader)
    return rows

def parse_plain_table():
    rows = []
    with open(src_path,"r",encoding="utf-8",errors="ignore") as f:
        for ln in f:
            ln=ln.strip()
            if not ln or ln.startswith("#") or ln.startswith("| ---"): continue
            if "|" in ln:
                parts=[p.strip() for p in ln.strip("|").split("|")]
            else:
                parts=[p.strip() for p in ln.split()]
            if len(parts) < 2:
                continue
            rows.append({
                "type": parts[0],
                "label": parts[1] if len(parts)>1 else "",
                "username": parts[2] if len(parts)>2 else "",
                "secret": parts[3] if len(parts)>3 else "",
                "notes": parts[4] if len(parts)>4 else "",
                "created": parts[5] if len(parts)>5 else "",
                "extra": parts[6] if len(parts)>6 else "",
            })
    return rows

def load_rows():
    if fmt in ("json","jsonc","ndjson","jsonl","csv","csv-noheader","tsv","scsv"):
        return parse_rows()
    else:
        return parse_plain_table()

for row in load_rows():
    t = (row.get("type","") or "").lower()
    if t in ("password","pass"):
        add_password(row)
    elif t in ("note","notes"):
        add_note(row)
    elif t in ("passphrase","phrase","secret"):
        add_passphrase(row)
    elif t in ("backup_code","backup","codes","backupcode"):
        add_backup(row)
    elif t in ("authenticator","auth"):
        add_auth(row)

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
  ./spm.sh forgot          → Reset kata sandi utama dengan private key
  ./spm.sh doctor          → Health / integrity check vault
  ./spm.sh generate        → Generator kata sandi (panjang, mode mudah/aman/angka, simbol opsional)
  ./spm.sh web             → Mode web (pilih sementara / background via pm2)
  ./spm.sh help            → Tampilkan bantuan ini

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
  ./spm.sh generate        → Password generator (length, easy/secure/numeric, optional symbols/upper/lower/digits)
  ./spm.sh web             → Web mode (foreground or pm2 background)
  ./spm.sh help            → Show this help

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

Web Mode:
  - Runs a lightweight HTTP server so you can inspect your vault from a browser.
  - Protected by your master password.
  - Modes:
      • temporary (foreground, stop with Ctrl + C)
      • background (managed by pm2; installed automatically when possible)
  - UI:
      • Password entries table (ID, service, username – passwords are not shown)
      • Secure notes section (view / add / edit / delete)
  - Web session auto-locks after ~30 seconds of inactivity.

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

	# Termux environment: usually behind NAT, no ufw/firewalld
	# Use ${VAR-} so set -u doesn't explode if VAR is undefined
	if [ -n "${TERMUX_VERSION-}" ] || printf '%s\n' "${PREFIX-}" | grep -qi 'termux'; then
		if [ "$SPM_LANG" = "id" ]; then
			echo
			echo ">> Termux terdeteksi. Melewati konfigurasi firewall otomatis."
			echo "   Pastikan jaringan kamu aman jika membuka port ${bind_port}/tcp."
		else
			echo
			echo ">> Termux detected. Skipping automatic firewall configuration."
			echo "   Ensure your network is safe if you expose port ${bind_port}/tcp."
		fi
		return 0
	fi

	if [ "$SPM_LANG" = "id" ]; then
		echo
		echo ">> Mengatur firewall untuk port ${bind_port}/tcp (jika memungkinkan)..."
	else
		echo
		echo ">> Configuring firewall for port ${bind_port}/tcp (if possible)..."
	fi

	_spm_try_install_pkg() {
		local pkg="$1"

		if command -v apt-get >/dev/null 2>&1; then
			sudo apt-get update -y >/dev/null 2>&1 && sudo apt-get install -y "$pkg" >/dev/null 2>&1
			return $?
		fi
		if command -v dnf >/dev/null 2>&1; then
			sudo dnf install -y "$pkg" >/dev/null 2>&1
			return $?
		fi
		if command -v yum >/dev/null 2>&1; then
			sudo yum install -y "$pkg" >/dev/null 2>&1
			return $?
		fi
		if command -v pacman >/dev/null 2>&1; then
			sudo pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1
			return $?
		fi
		if command -v zypper >/dev/null 2>&1; then
			sudo zypper install -y "$pkg" >/dev/null 2>&1
			return $?
		fi
		if command -v apk >/dev/null 2>&1; then
			sudo apk add "$pkg" >/dev/null 2>&1
			return $?
		fi
		return 1
	}

	# 1) ufw path
	local ufw_cmd=""
	if command -v ufw >/dev/null 2>&1; then
		ufw_cmd="$(command -v ufw)"
	elif [ -x /usr/sbin/ufw ]; then
		ufw_cmd="/usr/sbin/ufw"
	fi

	if [ -z "$ufw_cmd" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			echo "   - ufw tidak ditemukan. Mencoba menginstal ufw..."
		else
			echo "   - ufw not found. Trying to install ufw..."
		fi
		if _spm_try_install_pkg ufw; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ✓ ufw berhasil diinstal."
			else
				echo "   ✓ ufw installed successfully."
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ⚠ Gagal menginstal ufw (mungkin butuh sudo / distro tidak mendukung)."
			else
				echo "   ⚠ Failed to install ufw (maybe needs sudo / unsupported distro)."
			fi
		fi
	fi

	if [ -n "$ufw_cmd" ]; then
		if sudo "$ufw_cmd" status 2>/dev/null | grep -qi "Status: inactive"; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   - Mengaktifkan ufw..."
			else
				echo "   - Enabling ufw..."
			fi
			sudo "$ufw_cmd" enable >/dev/null 2>&1
		fi

		if [ "$SPM_LANG" = "id" ]; then
			echo "   - Menambahkan rule ufw: allow ${bind_port}/tcp"
		else
			echo "   - Adding ufw rule: allow ${bind_port}/tcp"
		fi
		if sudo "$ufw_cmd" allow "${bind_port}"/tcp >/dev/null 2>&1; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ✓ Rule ufw ditambahkan (port ${bind_port}/tcp)."
			else
				echo "   ✓ ufw rule added (port ${bind_port}/tcp)."
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ⚠ Gagal menambahkan rule ufw. Cek 'sudo ufw status' secara manual."
			else
				echo "   ⚠ Failed to add ufw rule. Check 'sudo ufw status' manually."
			fi
		fi
		return 0
	fi

	# 2) firewalld path (configure only if already installed)
	if command -v firewall-cmd >/dev/null 2>&1; then
		if [ "$SPM_LANG" = "id" ]; then
			echo "   - Menambahkan port permanen ${bind_port}/tcp pada firewalld."
		else
			echo "   - Adding permanent port ${bind_port}/tcp to firewalld."
		fi
		if sudo firewall-cmd --add-port="${bind_port}"/tcp --permanent >/dev/null 2>&1 && \
		   sudo firewall-cmd --reload >/dev/null 2>&1; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ✓ Rule firewalld ditambahkan dan direload."
			else
				echo "   ✓ firewalld rule added and reloaded."
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ⚠ Gagal mengatur firewalld. Cek 'sudo firewall-cmd --list-ports'."
			else
				echo "   ⚠ Failed to configure firewalld. Check 'sudo firewall-cmd --list-ports'."
			fi
		fi
		return 0
	fi

	# 3) Fallback: iptables
	if command -v iptables >/dev/null 2>&1; then
		if [ "$SPM_LANG" = "id" ]; then
			echo "   - Menggunakan iptables. Menambahkan rule sementara (non-persisten)."
		else
			echo "   - Using iptables. Adding temporary (non-persistent) rule."
		fi
		if sudo iptables -I INPUT -p tcp --dport "${bind_port}" -j ACCEPT >/dev/null 2>&1; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ✓ Rule iptables ditambahkan (tidak persisten setelah reboot)."
			else
				echo "   ✓ iptables rule added (not persistent after reboot)."
			fi
		else
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ⚠ Gagal menambahkan rule iptables. Atur firewall secara manual."
			else
				echo "   ⚠ Failed to add iptables rule. Configure firewall manually."
			fi
		fi
		return 0
	fi

	if [ "$SPM_LANG" = "id" ]; then
		echo "   ⚠ Tidak ada tool firewall yang dikenali (ufw / firewalld / iptables)."
		echo "     Pastikan port ${bind_port}/tcp dibuka atau diamankan secara manual."
	else
		echo "   ⚠ No known firewall tool detected (ufw / firewalld / iptables)."
		echo "     Please ensure port ${bind_port}/tcp is opened/secured manually."
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
	if [ -n "${TERMUX_VERSION-}" ] && command -v pkg >/dev/null 2>&1; then
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


start_web_mode() {
	clear
	echo "==========================================="
	echo "  SPM Web Mode"
	echo "==========================================="
	echo
	if [ "$SPM_LANG" = "id" ]; then
		printf "\n\033[0;31mPERINGATAN: Menjalankan mode web akan mengekspos vault Anda melalui server HTTP. Lanjutkan hanya jika Anda berada di jaringan yang terpercaya.\033[0m\n\n"
	else
		printf "\n\033[0;31mWARNING: Running the web mode will expose your vault over an HTTP server. Only proceed if you are on a trusted network.\033[0m\n\n"
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
			echo "❌ python3 is required for web mode but not found."
			echo "   Install python3 and retry."
			read -r -p "Press Enter to return to menu..." _
		fi
		return
	fi

	# Ask bind address & port
	echo
	local bind_addr bind_port
	if [ "${SPM_LANG:-en}" = "id" ]; then
		echo "Pilih alamat bind:"
		echo "  1) Lokal (127.0.0.1)"
		echo "  2) Global (0.0.0.0)"
		echo "  3) Masukkan IP sendiri"
		read -r -p "Pilihan [1]: " bind_addr
	else
		echo "Choose bind address:"
		echo "  1) Localhost (127.0.0.1)"
		echo "  2) Global (0.0.0.0)"
		echo "  3) Enter custom IP"
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

	# Try to configure firewall automatically if binding to non-local
	configure_firewall_for_web "$bind_addr" "$bind_port"

	# Ensure Python web script exists (and updated)
	local spm_web_script
	spm_web_script="$(write_spm_web_script)" || {
		if [ "${SPM_LANG:-en}" = "id" ]; then
			echo "❌ Gagal menulis script web Python."
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
			echo "  → http://${display_host}:${bind_port}/"
			echo
			echo "Gunakan menu ini lagi (opsi 3) untuk menghentikan proses background."
		else
			echo
			echo "Starting SPM web server in background (PM2, process name: spm-web)..."
			echo "Access it from your browser:"
			echo "  → http://${display_host}:${bind_port}/"
			echo
			echo "Use this menu again (option 3) to stop the background process."
		fi

		# Use env wrapper so PM2 runs with correct variables
		SPM_VAULT_PATH="$VAULT_FILE" \
		SPM_WEB_BIND="$bind_addr" \
		SPM_WEB_PORT="$bind_port" \
		SPM_VERSION="$VERSION" \
		pm2 start "$spm_web_script" \
			--name "spm-web" \
			--interpreter python3 >/dev/null 2>&1 || true

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
		echo "  → http://${display_host}:${bind_port}/"
		echo
		echo "Tekan Ctrl + C di sini untuk menghentikan server."
	else
		echo "Starting SPM web server on ${bind_addr}:${bind_port}..."
		echo "Open this in your browser:"
		echo "  → http://${display_host}:${bind_port}/"
		echo
		echo "Press Ctrl + C here to stop the server."
	fi
	echo

	SPM_VAULT_PATH="$VAULT_FILE" \
	SPM_WEB_BIND="$bind_addr" \
	SPM_WEB_PORT="$bind_port" \
	SPM_VERSION="$VERSION" \
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

	local script_path="${base_dir}/spm_web_server.py"

	cat >"$script_path" <<'PY'
import http.server
import socketserver
import urllib.parse
import subprocess
import os
import secrets
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

VAULT_PATH = os.environ.get("SPM_VAULT_PATH")
BIND_ADDR  = os.environ.get("SPM_WEB_BIND", "127.0.0.1")
PORT       = int(os.environ.get("SPM_WEB_PORT", "8080"))
VERSION    = os.environ.get("SPM_VERSION", "")

if not VAULT_PATH or not os.path.isfile(VAULT_PATH):
    raise SystemExit(f"Vault file not found: {VAULT_PATH!r}")

LATEST_CACHE = {"value": "", "ts": 0}

SUPPORTED_WEB_LANGS = {"en", "id", "ja"}
DEFAULT_WEB_LANG = "en"

def sanitize_lang(value):
    value = (value or "").strip().lower()
    if value in SUPPORTED_WEB_LANGS:
        return value
    return DEFAULT_WEB_LANG

def _vf(value):
    # Vault records are TAB-delimited and line-based. Tabs were already being
    # stripped here, but a newline slipped through and split one entry into two
    # broken records, so collapse both.
    return str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ")

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
      "header.title": "Sans Password Manager",
      "header.subtitle": "Liquid-glass web interface · GPG encrypted",
      "header.check_update": "Check update",
      "header.logout": "Logout",
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
      "section.session_desc": "Protected by your master password. The interface auto-locks after 30 seconds of inactivity and logs you out.",
      "form.vault": "Vault:",
      "form.back_list": "\u2190 Back to list",
      "form.save": "Save",
      "link.back": "\u2190 Back",
      "entry.field.service": "Service / Name",
      "entry.field.username": "Username",
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
      "view.label.username": "Username",
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
      "header.title": "Sans Password Manager",
      "header.subtitle": "Antarmuka web liquid-glass · terenkripsi GPG",
      "header.check_update": "Periksa pembaruan",
      "header.logout": "Keluar",
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
      "section.session_desc": "Dilindungi kata sandi master. Terkunci otomatis setelah 30 detik tidak aktif.",
      "form.vault": "Brankas:",
      "form.back_list": "\u2190 Kembali ke daftar",
      "form.save": "Simpan",
      "link.back": "\u2190 Kembali",
      "entry.field.service": "Layanan / Nama",
      "entry.field.username": "Pengguna",
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
      "view.label.username": "Pengguna",
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
      "header.title": "Sans Password Manager",
      "header.subtitle": "リキッドガラス風Webインターフェース · GPG暗号化",
      "header.check_update": "アップデートを確認",
      "header.logout": "ログアウト",
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
      "section.session_desc": "マスターパスワードで保護。30秒間操作がないと自動ロックされます。",
      "form.vault": "ボールト:",
      "form.back_list": "\u2190 一覧に戻る",
      "form.save": "保存",
      "link.back": "\u2190 戻る",
      "entry.field.service": "サービス / 名称",
      "entry.field.username": "ユーザー名",
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
      "view.label.username": "ユーザー名",
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
.vault-chip .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: 10px; }

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

.menu-btn { display: none; }

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
.lockbar .fill { height: 100%; width: 100%; background: var(--ok); transition: width .95s linear, background .3s var(--ease); }
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
.totp-ring i { display: block; height: 100%; width: calc(var(--pct) * 1%); background: var(--accent); transition: width .95s linear; }

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
.meter i { display: block; height: 100%; width: 0; transition: width .3s var(--ease), background .3s var(--ease); }
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
  body.nav-open .scrim {
    display: block; position: fixed; inset: 0; z-index: 35;
    background: rgba(0,0,0,.5);
  }
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
  .lockbar .track, .vault-chip .path { display: none; }
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
#toast.show { transform:none; }
.overlay { border-radius:0; backdrop-filter:none; -webkit-backdrop-filter:none; background:var(--surface); border-left:2px solid var(--accent); }
.spinner { border-radius:0; }

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
@media (prefers-reduced-motion:reduce) { .console-hero .lede::after { animation:none; } }

@media print { .sidebar, .topbar, .page-actions, #toast { display: none !important; } .app { grid-template-columns: 1fr; } }
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

  /* ---- mobile nav ----------------------------------------------------- */
  window.SPM_toggleNav = function () { document.body.classList.toggle("nav-open"); };

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
      document.body.classList.remove("nav-open");
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    wireSearch();
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
  var deadline = Date.now() + IDLE_MS, paused = false, ticker;
  function reset() { if (!paused) deadline = Date.now() + IDLE_MS; }
  function render() {
    var left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    var bar = document.getElementById("lockbar");
    if (bar) {
      var fill = bar.querySelector(".fill");
      if (fill) fill.style.width = (left / (IDLE_MS / 1000) * 100) + "%";
      bar.classList.toggle("warn", left <= WARN_AT);
      var lbl = bar.querySelector(".lbl");
      if (lbl) {
        var t = (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.in", "Locks in") : "Locks in";
        lbl.textContent = paused ? ((window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.paused", "Lock paused") : "Lock paused") : (t + " " + left + "s");
      }
    }
    if (!paused && left <= 0) { window.location.href = "/logout"; }
  }
  window.SPM_AutoLock = {
    pause: function () { paused = true; render(); },
    resume: function () { paused = false; reset(); render(); },
    restart: reset
  };
  ["click", "keydown", "mousemove", "touchstart", "scroll"].forEach(function (ev) {
    window.addEventListener(ev, reset, { passive: true });
  });
  ticker = setInterval(render, 1000);
  document.addEventListener("DOMContentLoaded", render);
})();
</script>
"""

# nav key -> (href, icon, i18n key, fallback label, counter name)
NAV_SECTIONS = [
    ("nav.group.vault", [
        ("overview",       "/",               "◈", "nav.overview",       "Overview",       None),
        ("passwords",      "/passwords",      "\U0001F511", "nav.passwords",      "Passwords",      "passwords"),
        ("notes",          "/notes",          "\U0001F5D2", "nav.notes",          "Secure Notes",   "notes"),
        ("passphrases",    "/passphrases",    "\U0001F4DD", "nav.passphrases",    "Passphrases",    "passphrases"),
        ("authenticators", "/authenticators", "⏱",  "nav.authenticators", "Authenticators", "authenticators"),
        ("backup-codes",   "/backup-codes",   "\U0001F9EF", "nav.backup_codes",   "Backup Codes",   "backups"),
    ]),
    ("nav.group.tools", [
        ("generator", "/generator", "✨", "nav.generator", "Generator",       None),
        ("transfer",  "/transfer",  "⇅", "nav.transfer",  "Export / Import", None),
    ]),
]


def _nav_html(active, counts):
    out = []
    for group_key, items in NAV_SECTIONS:
        label = {"nav.group.vault": "Vault", "nav.group.tools": "Tools"}[group_key]
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
                f'<a class="{cls}" href="{href}">'
                f'<span class="nav-ico" aria-hidden="true">{ico}</span>'
                f'<span data-i18n="{i18n}">{fallback}</span>{badge}</a>'
            )
        out.append("</div>")
    return "".join(out)


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
        search_html = (
            '<div class="search">'
            '<span class="search-ico" aria-hidden="true">⌕</span>'
            '<input id="q" type="search" autocomplete="off" spellcheck="false" '
            'data-i18n-placeholder="search.placeholder" placeholder="Search this vault...">'
            '<kbd>/</kbd></div>'
        )
    else:
        search_html = '<div class="search" aria-hidden="true"></div>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)} · SPM</title>
{DESIGN_CSS}
</head>
<body class="theme-dark">
<a class="skip-link" href="#main-content">Skip to vault content</a>
<div class="scrim" onclick="SPM_toggleNav()"></div>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">S</div>
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
      <a class="btn btn-ghost btn-sm btn-block" href="/logout">
        <span aria-hidden="true">⏻</span>
        <span data-i18n="header.logout">Logout</span>
      </a>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <button class="icon-btn menu-btn" onclick="SPM_toggleNav()" aria-label="Menu">☰</button>
      {search_html}
      <div class="topbar-right">
        <div class="lockbar" id="lockbar" title="Idle auto-lock">
          <span class="lbl">Locks in 30s</span>
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
{LOCKBAR_SCRIPT}
</body>
</html>"""


def _esc(v):
    return html.escape(v if v is not None else "")


def _empty(icon, title_key, title, desc_key, desc, cta_html="", colspan=4):
    return (
        f'<tr class="empty-row"><td colspan="{colspan}">'
        f'<div class="empty"><div class="empty-ico" aria-hidden="true">{icon}</div>'
        f'<div class="empty-t" data-i18n="{title_key}">{title}</div>'
        f'<div class="empty-d" data-i18n="{desc_key}">{desc}</div>{cta_html}</div>'
        f'</td></tr>'
    )


def _actions(view_href, edit_href, delete_action, item_id, confirm_key, confirm_text):
    bits = ['<div class="icon-row">']
    if view_href:
        bits.append(f'<a class="icon-btn" href="{view_href}" title="View" aria-label="View">\U0001F441</a>')
    if edit_href:
        bits.append(f'<a class="icon-btn" href="{edit_href}" title="Edit" aria-label="Edit">✏</a>')
    if delete_action:
        bits.append(
            f'<form class="inline" method="post" action="{delete_action}" '
            f'onsubmit="return confirm(SPM_I18N.t(\'{confirm_key}\',\'{confirm_text}\'));">'
            f'<input type="hidden" name="id" value="{item_id}">'
            f'<button type="submit" class="icon-btn danger" title="Delete" aria-label="Delete">\U0001F5D1</button>'
            f'</form>'
        )
    bits.append("</div>")
    return "".join(bits)


# --------------------------------------------------------------------------
# Row builders  (each row carries data-row for the instant client-side filter)
# --------------------------------------------------------------------------
def build_rows_html(entries):
    if not entries:
        return _empty("\U0001F511", "empty.passwords.t", "No passwords yet",
                      "empty.passwords.d", "Entries you add will appear here.",
                      '<a class="btn btn-primary btn-sm" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>', 4)
    rows = []
    for _, parts in entries:
        eid, name, user = _esc(parts[0]), _esc(parts[1]), _esc(parts[2])
        key = f"{name} {user} {eid}".lower()
        rows.append(
            f'<tr data-row="{key}">'
            f'<td class="num">{eid}</td>'
            f'<td class="strong">{name}</td>'
            f'<td class="muted">{user or "&mdash;"}</td>'
            f'<td class="actions">{_actions(f"/view?id={eid}", f"/edit?id={eid}", "/delete", eid, "confirm.delete_entry", "Delete this entry?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_notes_rows_html(notes):
    if not notes:
        return _empty("\U0001F5D2", "empty.notes.t", "No secure notes",
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
        return _empty("\U0001F4DD", "empty.passphrases.t", "No passphrases",
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
        return _empty("\U0001F9EF", "empty.backups.t", "No backup codes",
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
        return _empty("⏱", "empty.auth.t", "No authenticators",
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
          <td colspan="{ncols}"><div class="empty"><div class="empty-ico">⌕</div>
          <div class="empty-t" data-i18n="search.no_results">Nothing matches your search</div></div></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>"""


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
def overview_page(counts, recent):
    tiles = [
        ("\U0001F511", counts.get("passwords", 0), "nav.passwords", "Passwords", "/passwords"),
        ("\U0001F5D2", counts.get("notes", 0), "nav.notes", "Secure Notes", "/notes"),
        ("\U0001F4DD", counts.get("passphrases", 0), "nav.passphrases", "Passphrases", "/passphrases"),
        ("⏱", counts.get("authenticators", 0), "nav.authenticators", "Authenticators", "/authenticators"),
        ("\U0001F9EF", counts.get("backups", 0), "nav.backup_codes", "Backup Codes", "/backup-codes"),
    ]
    stats = "".join(
        f'<a class="stat" href="{href}">'
        f'<span class="stat-ico" aria-hidden="true">{ico}</span>'
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
  <div class="empty-ico" aria-hidden="true">\U0001F510</div>
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
        _field("user", "entry.field.username", "Username", v.get("user", "")) +
        _field("password", "entry.field.password", "Password", v.get("password", "")) +
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
    <button class="icon-btn" type="button" onclick="SPM_reveal('{elem_id}', this)" data-title-show="Show" aria-label="Show">\U0001F441</button>
    <button class="icon-btn" type="button" onclick="SPM_copy(document.getElementById('{elem_id}').dataset.val)" aria-label="Copy">\U0001F4CB</button>
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
    btn.textContent = "\\uD83D\\uDE48";
    if (window.SPM_AutoLock) window.SPM_AutoLock.restart();
  } else {
    var v = el.dataset.val || "";
    el.textContent = "\\u2022".repeat(Math.min(v.length, 24));
    el.classList.add("masked");
    btn.textContent = "\\uD83D\\uDC41";
  }
};
</script>
"""


def view_entry_page(parts):
    """Full page for a single password entry."""
    eid, name, user, pw = _esc(parts[0]), _esc(parts[1]), _esc(parts[2]), parts[3] if len(parts) > 3 else ""
    notes = parts[4] if len(parts) > 4 else ""
    created = _esc(parts[5] if len(parts) > 5 else "")
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
  <div class="field"><label data-i18n="view.label.username">Username</label>
    <div class="secret"><span class="secret-val">{user or "&mdash;"}</span>
    <button class="icon-btn" type="button" onclick="SPM_copy({jsonlib.dumps(parts[2] if len(parts)>2 else '')})" aria-label="Copy">\U0001F4CB</button></div>
  </div>
  {_secret_block(pw, "view.label.password", "Password", "pw")}
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Unlock Vault · SPM</title>
{DESIGN_CSS}
</head>
<body class="theme-dark">
<a class="skip-link" href="#main-content">Skip to unlock form</a>
<div class="login-wrap">
  <main class="login-card" id="main-content">
    <div class="login-brand">
      <div class="brand-mark" aria-hidden="true">S</div>
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
    if (meter) { meter.style.width = pct + "%"; meter.style.background = col; }
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
      <button class="btn btn-primary" type="button" onclick="SPM_regen()" data-i18n="generator.btn.regen">Regenerate</button>
      <button class="btn" type="button" onclick="SPM_copyPw()" data-i18n="generator.btn.copy">Copy</button>
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
          <select class="input" name="fmt">{opts}</select>
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
    <button class="btn btn-primary" type="button" onclick="SPM_copy(document.getElementById('code').textContent)"
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
    if (cd) cd.textContent = t("auth.countdown.refresh_in", "Refreshes in") + " " + Math.max(0, left) + "s";
  }}
  function fetchCode() {{
    fetch("/authenticator-code?id=" + encodeURIComponent(id), {{ credentials: "same-origin" }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        document.getElementById("code").textContent = d.code || "------";
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


def _passphrase_fd(master: str) -> int:
    # Never hand the master password to gpg on the command line: argv is world
    # readable through `ps` and /proc/<pid>/cmdline, so every local user could
    # read it. Write it into a pipe instead and let gpg read that fd, mirroring
    # the --passphrase-fd approach the shell side already uses.
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, master.encode("utf-8"))
    finally:
        os.close(write_fd)
    return read_fd

def decrypt_vault(master: str) -> str:
    pw_fd = _passphrase_fd(master)
    try:
        return subprocess.check_output(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(pw_fd), "-d", VAULT_PATH],
            stderr=subprocess.DEVNULL,
            timeout=15,
            pass_fds=(pw_fd,),
        ).decode("utf-8", errors="ignore")
    finally:
        os.close(pw_fd)

def encrypt_vault(master: str, plaintext: str) -> None:
    tmp_path = VAULT_PATH + ".webtmp"
    pw_fd = _passphrase_fd(master)
    p = subprocess.Popen(
        ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
         "--passphrase-fd", str(pw_fd), "--cipher-algo", "AES256",
         "-c", "-o", tmp_path],
        stdin=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        pass_fds=(pw_fd,),
    )
    try:
        stdout, stderr = p.communicate(input=plaintext.encode("utf-8"), timeout=30)
        if p.returncode != 0:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise RuntimeError("Failed to encrypt vault")
        # os.replace swaps the inode, so the vault would otherwise inherit this
        # temp file's umask-derived mode and silently drop from 0600 to 0644.
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, VAULT_PATH)
    except subprocess.TimeoutExpired:
        p.kill()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise RuntimeError("Vault encryption timed out")
    finally:
        os.close(pw_fd)

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

SUPPORTED_FORMATS = ("csv","json","tsv","ndjson","jsonl","md","markdown","html","txt","yaml","yml","xml","sql","ini","psv","rst","toml","org","scsv","csv-noheader","jsonc")

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
                "extra": ""
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
                "extra": ""
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
                "extra": ""
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
                "extra": ""
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
                "extra": f"period={parts[4] if len(parts)>4 else ''};algo={parts[6] if len(parts)>6 else 'sha1'}"
            })
    return rows

def export_content(fmt: str, plaintext: str):
    import csv, json, html as htmlmod, io
    rows = _export_rows(plaintext)
    fieldnames = ["type","id","label","username","secret","notes","created","extra"]
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
            out.append("| " + " | ".join((r.get(k,"") or "").replace("\n"," ") for k in fieldnames) + " |")
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
                val = str(r.get(k, "") or "").replace("\n","\\n").replace('"','\\"')
                out.append(f'{k} = "{val}"')
            out.append("")
        return "\n".join(out)
    if fmt == "org":
        header = "| " + " | ".join(fieldnames) + " |"
        sep = "|" + "+".join("-" * (len(k)+2) for k in fieldnames) + "|"
        out = [header, sep]
        for r in rows:
            out.append("| " + " | ".join((str(r.get(k,"") or "")).replace("\n"," ") for k in fieldnames) + " |")
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
                val = str(r.get(k, "") or "").replace("\n","\\n")
                out.append(f"  {k}: \"{val}\"")
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
                out.append(f"{k}={r.get(k,'') or ''}")
            out.append("")
        return "\n".join(out)
    if fmt == "psv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter="|")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt == "rst":
        widths={k:max(len(k), max(len(str((r.get(k,"") or ""))) for r in rows) if rows else 0) for k in fieldnames}
        def sep(char="+"):
            return char + char.join("-" * (widths[k]+2) for k in fieldnames) + char
        def row(vals):
            return "|" + "|".join(" " + v.ljust(widths[k]) + " " for k,v in vals) + "|"
        out=[sep(), row([(k,k) for k in fieldnames]), sep("+")]
        for r in rows:
            out.append(row([(k, str(r.get(k,"") or "")).replace("\n"," ") for k in fieldnames]))
            out.append(sep())
        return "\n".join(out) + "\n"
    # default csv/txt
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=",")
    writer.writeheader(); writer.writerows(rows)
    return buf.getvalue()

def _parse_import_rows(fmt: str, content: str):
    import csv, json
    fmt = fmt.lower()
    if fmt in ("json","jsonc"):
        return json.loads(content)
    if fmt in ("ndjson","jsonl"):
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    delim = "," if fmt in ("csv","csv-noheader","jsonc") else ";" if fmt=="scsv" else "\t" if fmt=="tsv" else "|"
    rows=[]
    if fmt=="csv-noheader":
        # StringIO, not splitlines(): csv needs the embedded newlines intact
        # to reassemble quoted multi-line fields into a single row.
        reader = csv.reader(io.StringIO(content), delimiter=delim)
        for row in reader:
            rows.append({
                "type": row[0] if len(row)>0 else "",
                "label": row[1] if len(row)>1 else "",
                "username": row[2] if len(row)>2 else "",
                "secret": row[3] if len(row)>3 else "",
                "notes": row[4] if len(row)>4 else "",
                "created": row[5] if len(row)>5 else "",
                "extra": row[6] if len(row)>6 else "",
            })
        return rows
    reader = csv.DictReader(io.StringIO(content), delimiter=delim)
    return list(reader)

def _apply_import(fmt: str, content: str, plaintext: str):
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

    def add_password(r):
        pid = str(next_id("PASS", lines))
        lines.append(tab.join([
            pid,
            _vf(r.get("label","")),
            _vf(r.get("username","")),
            _vf(r.get("secret","")),
            _vf(r.get("notes","")),
            _vf(r.get("created",""))
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
        rows=[]
        for ln in text.splitlines():
            ln=ln.strip()
            if not ln or ln.startswith("#") or ln.startswith("| ---"):
                continue
            if "|" in ln:
                parts=[p.strip() for p in ln.strip("|").split("|")]
            else:
                parts=[p.strip() for p in ln.split()]
            if len(parts) < 2:
                continue
            rows.append({
                "type": parts[0],
                "label": parts[1] if len(parts)>1 else "",
                "username": parts[2] if len(parts)>2 else "",
                "secret": parts[3] if len(parts)>3 else "",
                "notes": parts[4] if len(parts)>4 else "",
                "created": parts[5] if len(parts)>5 else "",
                "extra": parts[6] if len(parts)>6 else "",
            })
        return rows

    if fmt in ("json","jsonc","ndjson","jsonl","csv","csv-noheader","tsv","scsv"):
        rows = _parse_import_rows(fmt, content)
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
    """Password entries."""
    lines = plaintext.splitlines()
    entries = []
    for idx, line in enumerate(lines):
        if not line or line.startswith("#") or line.startswith("META_") or line.startswith("NOTE\t"):
            continue
        if line.startswith("PASSPHRASE\t") or line.startswith("BACKUP_CODE\t") or line.startswith("AUTH\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
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

class SPMServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}  # token -> {"master": str, "created": float, "last_seen": float}
        self.login_failures = {}  # client ip -> {"count": int, "until": float}

SESSION_TTL = 1800
# Absolute lifetime: the idle TTL above slides on every request, so without
# this a session (and the plaintext master password it holds) could live for
# as long as the browser kept poking it.
SESSION_MAX_AGE = 12 * 3600
# Web mode can bind beyond loopback, so an unauthenticated master-password
# guess has to cost something. Lock a client out briefly once it burns through
# this many attempts.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
MAX_POST_BYTES = 2 * 1024 * 1024
MAX_IMPORT_BYTES = 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[SPM Web] " + fmt % args + "\n")

    def _send_html(self, code, body):
        lang = html.escape(self._get_lang())
        if "__LANG__" in body:
            body = body.replace("__LANG__", lang)
        self.send_response(code)
        self._add_cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

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

    def _add_cors(self):
        origin = self.headers.get("Origin", "")
        allowed = {"http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT}
        if origin in allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

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
            if (now - sess.get("last_seen", 0) > SESSION_TTL
                    or now - sess.get("created", 0) > SESSION_MAX_AGE):
                self.server.sessions.pop(tok, None)

    def _login_client(self):
        try:
            return self.client_address[0]
        except (AttributeError, IndexError):
            return "unknown"

    def _login_lockout_remaining(self):
        entry = self.server.login_failures.get(self._login_client())
        if not entry:
            return 0
        return max(0, int(entry.get("until", 0) - time.time()))

    def _record_login_failure(self):
        client = self._login_client()
        now = time.time()
        entry = self.server.login_failures.get(client) or {"count": 0, "until": 0}
        if entry.get("until", 0) <= now and entry.get("count", 0) >= LOGIN_MAX_FAILURES:
            entry = {"count": 0, "until": 0}
        entry["count"] = entry.get("count", 0) + 1
        if entry["count"] >= LOGIN_MAX_FAILURES:
            entry["until"] = now + LOGIN_LOCKOUT_SECONDS
        self.server.login_failures[client] = entry
        self.log_message("failed login from %s (%d/%d)", client, entry["count"], LOGIN_MAX_FAILURES)

    def _clear_login_failures(self):
        self.server.login_failures.pop(self._login_client(), None)

    def _get_cookie_session(self):
        now = time.time()
        self._sweep_sessions(now)
        token = self._parse_cookies().get("spm_session")
        if not token:
            return None
        session = self.server.sessions.get(token)
        if not session:
            return None
        session["last_seen"] = now
        return session.get("master", "")

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

    def _require_login(self):
        master = self._get_cookie_session()
        if not master:
            page = login_page(VERSION)
            self._send_html(200, page)
            return None
        return master

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
                plaintext = decrypt_vault(master)
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
            recent = list(reversed(entries))[:5]
            body = render_shell(overview_page(counts, recent), "overview",
                                VERSION, VAULT_PATH, title="Overview",
                                counts=counts, flash=flash)
            self._send_html(200, body)
            return

        if path == "/transfer":
            self._send_html(200, transfer_page())
            return

        if path in ("/passwords", "/notes", "/passphrases", "/authenticators", "/backup-codes"):
            try:
                plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
            plaintext = decrypt_vault(master)
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
                decrypt_vault(password)
            except subprocess.CalledProcessError:
                self._record_login_failure()
                page = login_page(VERSION, "<div class='msg'>Invalid master password.</div>")
                self._send_html(200, page)
                return

            self._clear_login_failures()
            token = secrets.token_hex(32)
            self.server.sessions[token] = {"master": password, "created": time.time(), "last_seen": time.time()}
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session={token}; {self._session_cookie_attrs()}")
            self.send_header("Location", "/")
            self.end_headers()
            return

        master = self._get_cookie_session()
        if not master:
            page = login_page(VERSION)
            self._send_html(200, page)
            return

        raw_body_bytes = self._read_body()
        if raw_body_bytes is None:
            return
        raw_body = raw_body_bytes.decode("utf-8", errors="ignore")
        data = urllib.parse.parse_qs(raw_body)

        if path == "/add":
            name = (data.get("name") or [""])[0].strip()
            user = (data.get("user") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            notes = (data.get("notes") or [""])[0]

            if not name:
                page = build_entry_form(
                    title="Add Entry",
                    vault_path=VAULT_PATH,
                    action="/add",
                    values={"name": name, "user": user, "password": password, "notes": notes},
                    message="<div class='msg'>Name / service is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = decrypt_vault(master)
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
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
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

            if not name:
                values = {
                    "name": name,
                    "user": user,
                    "password": password,
                    "notes": notes,
                }
                page = build_entry_form(
                    title=f"Edit Entry #{entry_id}",
                    vault_path=VAULT_PATH,
                    action="/edit?id=" + urllib.parse.quote(entry_id),
                    values=values,
                    message="<div class='msg'>Name / service is required.</div>",
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
            ])
            lines[idx_to_update] = new_line
            new_plain = "\n".join(lines) + "\n"
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/delete":
            entry_id = (data.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
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

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/notes-delete":
            note_id = (data.get("id") or [""])[0]
            if not note_id:
                self.send_error(400, "Missing id")
                return

            plaintext = decrypt_vault(master)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("NOTE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == note_id:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            encrypt_vault(master, new_plain)

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
                    self.send_response(200)
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

            if body_len > 10 * 1024 * 1024:
                respond_error("Payload too large (max 10MB).", status=413)
                return

            sys.stderr.write(f'[import] Reading {body_len} bytes from request body...\n')

            fmt = "csv"
            content = ""

            if "multipart/form-data" in content_type.lower():
                try:
                    fields = parse_multipart(body_bytes, content_type)
                    fmt_raw = fields.get("fmt") or b"csv"
                    fmt = fmt_raw.decode("utf-8", "ignore").lower()
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
                plaintext = decrypt_vault(master)
                new_plain, stats = _apply_import(fmt, content, plaintext)
                encrypt_vault(master, new_plain)
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

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
            lines, passphrases = parse_passphrases(plaintext)
            idx_to_update = None
            created = ""
            for idx, parts in passphrases:
                if parts[1] == pid:
                    idx_to_update = idx
                    if len(parts) >= 5:
                        created = parts[4]
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
                    secret = base64.b64decode(passphrases[idx_to_update][1][3].encode("ascii")).decode("utf-8", errors="replace")
                except Exception:
                    secret = secrets.token_urlsafe(32)
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
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/passphrase-delete":
            pid = (data.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = decrypt_vault(master)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("PASSPHRASE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == pid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-delete":
            aid = (data.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
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
            encrypt_vault(master, new_plain)

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

            plaintext = decrypt_vault(master)
            lines, backups = parse_backup_codes(plaintext)
            idx_to_update = None
            created = ""
            for idx, parts in backups:
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
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-delete":
            bid = (data.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = decrypt_vault(master)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("BACKUP_CODE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == bid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            encrypt_vault(master, new_plain)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        self.send_error(404, "Not found")

def run():
    with SPMServer((BIND_ADDR, PORT), Handler) as httpd:
        print(f"[SPM Web] Serving on http://{BIND_ADDR}:{PORT}/")
        print("[SPM Web] Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SPM Web] Shutting down...")

if __name__ == "__main__":
    run()
PY

	echo "$script_path"
}

get_external_ip() {
    curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "UNKNOWN_IP"
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
			printf " 20) Mode web\n"
			printf " 21) Restore vault dari bundle portable/save\n"
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
			printf " 20) Web mode\n"
			printf " 21) Restore vault from bundle\n"
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
			20) clear; start_web_mode || true ;;  # ← Web Mode (experimental)
			21) clear; cmd_restore || true; pause_menu ;;
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
	ensure_requirements
	choose_language
	ensure_policy_consent

	if [ $# -eq 0 ]; then
		interactive_menu
		return
	fi

	local cmd="$1"
	shift || true

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
		forgot|forgotten) cmd_forgot "$@" ;;
		doctor)           cmd_doctor "$@" ;;
		export)           cmd_export "$@" ;;
		import)           cmd_import "$@" ;;
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
		web|web-mode)     start_web_mode "$@" ;;  # ← CLI access for Web Mode
		help|-h|--help)   cmd_help ;;
		*)
			printf "Unknown command: %s\n\n" "$cmd" >&2
			cmd_help
			exit 1
			;;
	esac
}

main "$@"

#!/usr/bin/env bash
# Sans Password Manager (SPM)
# Portable Bash + GPG password manager with encrypted vault.
# Dependencies: bash, gpg, openssl, base64, curl (for update)

set -o errexit
set -o nounset
set -o pipefail

VERSION="2.7.9"

# ----- Repo info for update check --------------------------------------------

# Adjust these to match your GitHub repo
REPO_OWNER="sansyourways"
REPO_NAME="Sans_Password_Manager"
REPO_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

# Global master password (in-memory only, per process)
MASTER_PW=""
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

make_tmp() {
	require_cmd mktemp
	local tmp
	tmp="$(mktemp "${TMPDIR:-/tmp}/spm.XXXXXX")"
	chmod 600 "$tmp" 2>/dev/null || true
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
}

trap cleanup EXIT INT

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
	ans_lc=$(printf '%s' "$ans" | tr 'A-Z' 'a-z')

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
			idx=$(( RANDOM % ${#WORDS[@]} ))
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
			pw="${pw}-$(printf '%02d' $((RANDOM % 100)))"
		fi
		if [ "$include_symbols" = "1" ]; then
			local syms="!@#$%^&*"
			local s="${syms:$((RANDOM % ${#syms})):1}"
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
		idx="$(( RANDOM % set_len ))"
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

	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$service" "$username" "$pw" "$notes" "$created" >>"$tmp"

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

	printf 'NOTE\t%s\t%s\t%s\t%s\t-\n' "$note_id" "$title" "$body_b64" "$created" >>"$tmp"

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

	printf 'PASSPHRASE\t%s\t%s\t%s\t%s\t-\n' "$pass_id" "$label" "$secret_b64" "$created" >>"$tmp"

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
	printf '%s' "$secret" | python3 - "$period" "$algo" <<'PY'
import base64, hashlib, hmac, struct, time, sys
secret = sys.stdin.read().replace(" ", "").upper()
period = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() and int(sys.argv[1]) > 0 else 30
algo = sys.argv[2].lower() if len(sys.argv) > 2 else "sha1"
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
	secret_b32="$(printf '%s' "$secret" | tr -d '\n' | tr 'a-z' 'A-Z')"

	printf 'AUTH\t%s\t%s\t%s\t%s\t%s\t%s\n' "$auth_id" "$label" "$secret_b32" "$period" "$created" "$algo" >>"$tmp"

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

	printf 'BACKUP_CODE\t%s\t%s\t%s\t%s\t-\n' "$bc_id" "$label" "$codes_b64" "$created" >>"$tmp"

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

	local tag bc_id label codes_b64 created dummy
	IFS=$'\t' read -r tag bc_id label codes_b64 created dummy <<EOF
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
  - This portable bundle does NOT include your RSA private key
    (spm_recovery_private.pem). Keep that file stored safely in your own
    secure location (offline or separate backup).
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
  - Bundle portabel INI TIDAK berisi private key RSA
    (spm_recovery_private.pem). Simpan file private key tersebut
    di lokasi yang aman (offline atau backup terpisah).
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
	local dest_vault="$DEFAULT_VAULT_PATH"
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

	if [ "$SPM_LANG" = "id" ]; then
		printf "Vault dipindahkan ke %s.\n" "$dest_vault"
		if [ -f "$dest_recovery" ]; then
			printf "File pemulihan dipindahkan ke %s.\n" "$dest_recovery"
		fi
		printf "Jalankan SPM dari lokasi biasa (mis. ~/.spm_vault.gpg) untuk melanjutkan.\n"
	else
		printf "Vault moved to %s.\n" "$dest_vault"
		if [ -f "$dest_recovery" ]; then
			printf "Recovery file moved to %s.\n" "$dest_recovery"
		fi
		printf "You can now run SPM normally (using the home vault path).\n"
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
	asset_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -E '\\.zip"' | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true

	if [ -z "$asset_url" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "Tidak menemukan asset ZIP di rilis. Update manual diperlukan.\n"
		else
			printf "Could not find ZIP asset in release. Manual update required.\n"
		fi
		return 1
	fi

	local sha_url
	sha_url="$(printf '%s\n' "$json" | grep -E '"browser_download_url"' | grep -E 'spm\\.sh\\.sha256"' | head -n1 | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')" || true

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
	local pw_count dup_ids empty_pw_count
	pw_count="$(awk -F '\t' '
		$1 ~ /^[0-9]+$/ { c++; if (length($4)==0) ep++; ids[$1]++ }
		END {
			for (i in ids) if (ids[i]>1) {dup=1}
			if (dup) print c "|" ep "|dup";
			else print c "|" ep "|ok";
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
		printf "ADA\n"
	else
		printf "tidak ada\n"
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
			local test_pw
			if test_pw="$(openssl rsautl -decrypt -inkey "$RECOVERY_PRIV_DEFAULT" -in "$RECOVERY_FILE" 2>/dev/null)"; then
				if [ "$SPM_LANG" = "id" ]; then
					printf "[✔] Private key dan file recovery cocok.\n"
				else
					printf "[✔] Private key and recovery file match.\n"
				fi
				test_pw=""
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
	format="$(printf '%s' "$format" | tr 'A-Z' 'a-z')"
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
	format="$(printf '%s' "$format" | tr 'A-Z' 'a-z')"
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
        r.get("label","").replace("\t"," "),
        r.get("username","").replace("\t"," "),
        r.get("secret",""),
        r.get("notes","").replace("\t"," "),
        r.get("created","")
    ]))

def add_note(r):
    nid = str(next_id("NOTE"))
    body_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "NOTE",
        nid,
        r.get("label","").replace("\t"," "),
        body_b64,
        r.get("created",""),
        "-"
    ]))

def add_passphrase(r):
    pid = str(next_id("PASSPHRASE"))
    secret_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "PASSPHRASE",
        pid,
        r.get("label","").replace("\t"," "),
        secret_b64,
        r.get("created",""),
        "-"
    ]))

def add_backup(r):
    bid = str(next_id("BACKUP_CODE"))
    codes_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
    lines.append("\t".join([
        "BACKUP_CODE",
        bid,
        r.get("label","").replace("\t"," "),
        codes_b64,
        r.get("created",""),
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
        r.get("label","").replace("\t"," "),
        r.get("secret",""),
        period,
        r.get("created",""),
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
	if ! command -v ufw >/dev/null 2>&1; then
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

	if command -v ufw >/dev/null 2>&1; then
		if sudo ufw status >/dev/null 2>&1 | grep -qi "Status: inactive"; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   - Mengaktifkan ufw..."
			else
				echo "   - Enabling ufw..."
			fi
			sudo ufw enable >/dev/null 2>&1
		fi

		if [ "$SPM_LANG" = "id" ]; then
			echo "   - Menambahkan rule ufw: allow ${bind_port}/tcp"
		else
			echo "   - Adding ufw rule: allow ${bind_port}/tcp"
		fi
		if sudo ufw allow "${bind_port}"/tcp >/dev/null 2>&1; then
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

	# 2) firewalld path
	if ! command -v firewall-cmd >/dev/null 2>&1; then
		if [ "$SPM_LANG" = "id" ]; then
			echo "   - firewalld tidak ditemukan. Mencoba menginstal firewalld..."
		else
			echo "   - firewalld not found. Trying to install firewalld..."
		fi
		if _spm_try_install_pkg firewalld; then
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ✓ firewalld berhasil diinstal."
			else
				echo "   ✓ firewalld installed successfully."
			fi
			sudo systemctl enable firewalld >/dev/null 2>&1
			sudo systemctl start firewalld >/dev/null 2>&1
		else
			if [ "$SPM_LANG" = "id" ]; then
				echo "   ⚠ Gagal menginstal firewalld."
			else
				echo "   ⚠ Failed to install firewalld."
			fi
		fi
	fi

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
					echo "ℹ️ Tidak ada proses spm-web di PM2."
					read -r -p "Tekan Enter untuk kembali ke menu..." _
				else
					echo "ℹ️ No spm-web process found in PM2."
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
		read -r -p "Bind address [127.0.0.1 lokal, 0.0.0.0 VPS]: " bind_addr
	else
		read -r -p "Bind address [127.0.0.1 for local, 0.0.0.0 for VPS]: " bind_addr
	fi
	[ -z "$bind_addr" ] && bind_addr="127.0.0.1"

	if [ "${SPM_LANG:-en}" = "id" ]; then
		read -r -p "Port [8080]: " bind_port
	else
		read -r -p "Port [8080]: " bind_port
	fi
	[ -z "$bind_port" ] && bind_port="8080"

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

AUTOLOCK_SCRIPT = """
<script>
  (function() {
    let autoTimer;
    let paused = false;
    function start() {
      if (paused) return;
      stop();
      autoTimer = setTimeout(function() {
        window.location.href = "/logout";
      }, 30000);
    }
    function stop() {
      if (autoTimer) {
        clearTimeout(autoTimer);
        autoTimer = null;
      }
    }
    window.SPM_AutoLock = {
      pause: function() { paused = true; stop(); },
      resume: function() { paused = false; start(); },
      restart: function() { start(); }
    };
    ["click","keydown","mousemove","touchstart","scroll"].forEach(function(ev) {
      window.addEventListener(ev, function() {
        if (!paused) start();
      }, { passive: true });
    });
    start();
  })();
</script>
"""

LOGIN_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: dark;
      --bg-image: radial-gradient(circle at top, #202438 0, #05060a 40%, #020308 100%);
      --bg: #05060a;
      --panel: rgba(10,10,14,0.9);
      --card: rgba(10,10,14,0.9);
      --text: #f5f5f7;
      --muted: #888ea6;
      --accent: #5f5fff;
    }
    body.theme-amoled {
      --bg-image: #000;
      --bg: #000;
      --panel: rgba(0,0,0,0.92);
      --card: rgba(0,0,0,0.92);
      --text: #e9e9f0;
      --muted: #7d8199;
      --accent: #00d2ff;
    }
    body.theme-cyberpunk {
      --bg-image: linear-gradient(135deg,#11001f 0%,#0a0014 100%);
      --bg: #0a0014;
      --panel: rgba(12,0,28,0.92);
      --card: rgba(20,0,36,0.9);
      --text: #f8e9ff;
      --muted: #9b7fff;
      --accent: #ff2fd1;
    }
    body.theme-light {
      color-scheme: light;
      --bg-image: linear-gradient(135deg,#f7f9fc 0%,#edf1f9 100%);
      --bg: #f6f7fb;
      --panel: #ffffff;
      --card: #f5f7fc;
      --text: #0f172a;
      --muted: #5b6475;
      --accent: #2563eb;
    }
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: var(--bg-image);
      color: var(--text);
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      margin:0;
      padding:16px;
      animation: bgShift 18s ease-in-out infinite alternate;
    }
    @keyframes bgShift {
      0% { background-position: 0% 0%; }
      50% { background-position: 50% 50%; }
      100% { background-position: 100% 0%; }
    }
    .glass {
      position: relative;
      padding: 24px 22px 20px;
      width: min(380px, 100%);
      border-radius: 20px;
      background: linear-gradient(145deg, rgba(255,255,255,0.16), rgba(5,5,9,0.9));
      box-shadow:
        0 22px 50px rgba(0,0,0,0.9),
        0 0 0 1px rgba(255,255,255,0.04);
      backdrop-filter: blur(26px) saturate(180%);
      -webkit-backdrop-filter: blur(26px) saturate(180%);
      border: 1px solid rgba(255,255,255,0.18);
      animation: floatIn 0.5s ease-out, floatLoop 8s ease-in-out infinite alternate;
      transform-origin: center;
    }
    @keyframes floatIn {
      from { opacity:0; transform: translateY(18px) scale(0.98); }
      to   { opacity:1; transform: translateY(0) scale(1); }
    }
    @keyframes floatLoop {
      0% { transform: translateY(0) scale(1); }
      100% { transform: translateY(-4px) scale(1.01); }
    }
    h1 {
      margin: 0 0 4px 0;
      font-size: 20px;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-align:center;
    }
    .subtitle {
      text-align:center;
      font-size: 12px;
      color:#aaa;
      margin-bottom: 18px;
    }
    label {
      font-size: 13px;
      color:#ccc;
      display:block;
      margin-bottom:6px;
    }
    input[type=password] {
      width:100%;
      padding:11px 12px;
      margin-bottom:14px;
      border-radius:12px;
      border:1px solid rgba(255,255,255,0.18);
      background:rgba(5,5,7,0.9);
      color:#f5f5f5;
      outline:none;
      font-size:13px;
      transition: border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    }
    input[type=password]:focus {
      border-color:rgba(140,190,255,0.9);
      box-shadow:0 0 0 1px rgba(120,180,255,0.5);
      background:rgba(2,2,5,1);
    }
    input[type=submit] {
      width:100%;
      padding:10px;
      border:none;
      border-radius:999px;
      background:linear-gradient(135deg,#0f9bff,#5f5fff);
      color:#fff;
      cursor:pointer;
      font-size:13px;
      font-weight:500;
      letter-spacing:0.09em;
      text-transform:uppercase;
      transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
    }
    input[type=submit]:hover {
      filter:brightness(1.08);
      box-shadow:0 10px 24px rgba(15,155,255,0.35);
      transform: translateY(-1px);
    }
    input[type=submit]:active {
      transform: translateY(0);
      box-shadow:none;
    }
    .msg {
      margin-top:10px;
      font-size:12px;
      color:#ff7b7b;
      text-align:center;
      animation: fadeIn 0.25s ease-out;
    }
    @keyframes fadeIn {
      from { opacity:0; transform: translateY(4px); }
      to   { opacity:1; transform: translateY(0); }
    }
  </style>
  <style>
    body.theme-dark {
      --bg:#05060a; --panel:rgba(10,10,14,0.9); --card:rgba(10,10,14,0.9); --text:#f5f5f7; --muted:#888ea6; --accent:#5f5fff;
      background:var(--bg); color:var(--text);
    }
    body.theme-amoled {
      --bg:#000; --panel:rgba(0,0,0,0.9); --card:rgba(0,0,0,0.9); --text:#e9e9f0; --muted:#7d8199; --accent:#00d2ff;
      background:var(--bg); color:var(--text);
    }
    body.theme-cyberpunk {
      --bg:#0a0014; --panel:rgba(12,0,28,0.9); --card:rgba(20,0,36,0.9); --text:#f8e9ff; --muted:#9b7fff; --accent:#ff2fd1;
      background:var(--bg); color:var(--text);
    }
    body.theme-light {
      --bg:#f6f7fb; --panel:#ffffff; --card:#f1f3f9; --text:#12131a; --muted:#5a5d70; --accent:#2563eb;
      background:var(--bg); color:var(--text);
    }
    body[class*="theme-"] .panel,
    body[class*="theme-"] .card,
    body[class*="theme-"] .glass,
    body[class*="theme-"] .vault-badge {
      background:var(--panel) !important;
      color:var(--text);
    }
    body[class*="theme-"] .sub,
    body[class*="theme-"] .muted,
    body[class*="theme-"] .vault-badge span,
    body[class*="theme-"] th,
    body[class*="theme-"] td {
      color:var(--muted);
    }
    body[class*="theme-"] .btn-primary { background:linear-gradient(135deg,var(--accent),#9a7bff); }
    body.theme-light a, body.theme-light .link { color:#2563eb; }
  </style>
</head>
<body>
  <div class="glass">
    <h1>Sans Password Manager</h1>
    <div class="subtitle">Web access · encrypted with GnuPG</div>
    <form method="post" action="/login">
      <label>Master Password</label>
      <input type="password" name="password" autocomplete="current-password" autofocus>
      <input type="submit" value="Unlock">
    </form>
    __MESSAGE__
  </div>
</body>
</html>
"""

MAIN_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sans Password Manager – Web</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      color-scheme: dark;
      --bg-image: radial-gradient(circle at top left, #1a1a27 0, #050509 45%, #000 100%);
      --bg: #05060a;
      --panel: rgba(12,12,18,0.94);
      --card: rgba(16,16,24,0.9);
      --text: #f7f8fb;
      --muted: #a3a7be;
      --accent: #5f5fff;
      --accent-2: #8d8dff;
      --danger: #ff4d6a;
      --danger-soft: rgba(255,77,106,0.14);
      --table-alt: rgba(255,255,255,0.03);
      --border: rgba(255,255,255,0.1);
    }
    body.theme-amoled {
      --bg-image: #000;
      --bg: #000;
      --panel: #0b0b0b;
      --card: #111;
      --text: #ededf2;
      --muted: #90909c;
      --accent: #00c2ff;
      --accent-2: #2ee1ff;
      --table-alt: rgba(255,255,255,0.05);
      --border: rgba(255,255,255,0.08);
    }
    body.theme-cyberpunk {
      --bg-image: linear-gradient(135deg,#1a0030 0%,#0a0014 50%,#180020 100%);
      --bg: #0a0014;
      --panel: rgba(22,0,40,0.96);
      --card: rgba(28,0,48,0.9);
      --text: #fce9ff;
      --muted: #caa8ff;
      --accent: #ff2fd1;
      --accent-2: #5cf4ff;
      --table-alt: rgba(255,47,209,0.08);
      --border: rgba(255,255,255,0.12);
    }
    body.theme-light {
      color-scheme: light;
      --bg-image: linear-gradient(135deg,#f8fafc 0%,#eef2f9 100%);
      --bg: #f7f9fc;
      --panel: #ffffffea;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #4b5563;
      --accent: #2563eb;
      --accent-2: #5f8dff;
      --table-alt: #f3f4f7;
      --border: rgba(17,24,39,0.08);
    }
    * { box-sizing:border-box; }
    body {
      margin:0;
      padding:0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: var(--bg-image);
      color: var(--text);
      min-height:100vh;
      display:flex;
      flex-direction:column;
      animation:bgShift 24s ease-in-out infinite alternate;
    }
    @keyframes bgShift {
      0% { background-position: 0% 0%; }
      50% { background-position: 60% 40%; }
      100% { background-position: 100% 0%; }
    }
    header {
      position:sticky;
      top:0;
      z-index:10;
      padding:10px 16px;
      background:linear-gradient(to bottom, rgba(0,0,0,0.35), transparent);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border-bottom:1px solid var(--border);
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:12px;
    }
    .title {
      display:flex;
      flex-direction:column;
      gap:2px;
    }
    .title h1 {
      margin:0;
      font-size:17px;
      letter-spacing:0.12em;
      text-transform:uppercase;
    }
    .title .sub {
      font-size:11px;
      color:var(--muted);
    }
    .right-header {
      display:flex;
      align-items:center;
      gap:8px;
      min-width:0;
    }
    .vault-badge {
      font-size:11px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,0.12);
      background:var(--panel);
      color:var(--text);
      max-width:220px;
      text-overflow:ellipsis;
      overflow:hidden;
      white-space:nowrap;
      display:flex;
      align-items:center;
      gap:4px;
      animation: floatHeader 9s ease-in-out infinite alternate;
    }
    @keyframes floatHeader {
      0% { transform: translateY(0); }
      100% { transform: translateY(-2px); }
    }
    .vault-badge span.label {
      opacity:0.7;
    }
    .logout {
      font-size:11px;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,0.18);
      background:linear-gradient(to bottom right, rgba(255,255,255,0.05), rgba(0,0,0,0.9));
      color:#ff9b9b;
      text-decoration:none;
      transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease;
      white-space:nowrap;
    }
    .logout:hover {
      background:linear-gradient(to bottom right, rgba(255,120,120,0.18), rgba(0,0,0,0.9));
      box-shadow:0 8px 24px rgba(255,120,120,0.4);
      transform: translateY(-1px);
    }
    .layout {
      flex:1;
      display:flex;
      padding:16px;
      gap:16px;
      flex-wrap:wrap;
    }
    .panel {
      flex: 3 1 280px;
      border-radius:22px;
      background:var(--panel);
      backdrop-filter: blur(26px) saturate(180%);
      -webkit-backdrop-filter: blur(26px) saturate(180%);
      border:1px solid var(--border);
      box-shadow:0 18px 40px rgba(0,0,0,0.28);
      padding:14px 16px 10px;
      display:flex;
      flex-direction:column;
      overflow:hidden;
      animation: fadeUp 0.4s ease-out;
    }
    .panel-header {
      display:flex;
      justify-content:space-between;
      align-items:center;
      padding:4px 4px 6px;
      gap:8px;
      flex-wrap:wrap;
    }
    .panel-header h2 {
      margin:0;
      font-size:13px;
      text-transform:uppercase;
      letter-spacing:0.18em;
      color:#d4d7e5;
    }
    .chip {
      display:inline-flex;
      align-items:center;
      padding:3px 9px;
      border-radius:999px;
      font-size:10px;
      border:1px solid rgba(255,255,255,0.18);
      background:radial-gradient(circle at top, rgba(255,255,255,0.08), rgba(0,0,0,0.9));
      color:#cfd3e8;
      gap:6px;
      margin-left:8px;
    }
    .chip-dot {
      width:7px;
      height:7px;
      border-radius:999px;
      background:radial-gradient(circle, #54e37d, #1d9c55);
      box-shadow:0 0 9px rgba(84,227,125,0.9);
      animation: pulse 1.6s ease-in-out infinite;
    }
    @keyframes pulse {
      0% { transform: scale(0.9); opacity:0.9; }
      50% { transform: scale(1.15); opacity:1; }
      100% { transform: scale(0.9); opacity:0.9; }
    }
.btn-primary {
      border-radius:999px;
      border:none;
      padding:7px 13px;
      font-size:11px;
      font-weight:500;
      letter-spacing:0.08em;
      text-transform:uppercase;
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      gap:6px;
      text-decoration:none;
      background:linear-gradient(135deg, rgba(95,95,255,0.18), rgba(95,95,255,0.32));
      color:var(--text);
      border:1px solid var(--border);
      box-shadow:0 6px 14px rgba(0,0,0,0.12);
      transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
    }
    .btn-primary.small {
      padding:6px 11px;
      font-size:10px;
    }
    .btn-primary:hover {
      filter:brightness(1.08);
      box-shadow:0 8px 22px rgba(0,0,0,0.18);
      transform: translateY(-1px);
    }
    .table-wrapper {
      margin-top:8px;
      border-radius:18px;
      border:1px solid var(--border);
      background:var(--card);
      overflow:auto;
      max-height:60vh;
      scrollbar-width: thin;
      scrollbar-color: rgba(120,120,140,0.7) transparent;
    }
    .table-wrapper::-webkit-scrollbar {
      height:6px;
      width:6px;
    }
    .table-wrapper::-webkit-scrollbar-thumb {
      background:rgba(140,140,170,0.7);
      border-radius:999px;
    }
    table {
      width:100%;
      border-collapse:collapse;
      min-width:380px;
      background:var(--card);
      border:1px solid var(--border);
      border-radius:12px;
      overflow:hidden;
    }
    th, td {
      padding:8px 10px;
      font-size:12px;
      border-bottom:1px solid var(--border);
      color:var(--text);
    }
    th {
      text-align:left;
      background:linear-gradient(to right, rgba(255,255,255,0.04), transparent);
      font-weight:600;
      color:var(--text);
      position:sticky;
      top:0;
      z-index:1;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }
    tr:nth-child(even) td {
      background:var(--table-alt);
    }
    tr:last-child td {
      border-bottom:none;
    }
    tr:hover td {
      background:linear-gradient(to right, rgba(255,255,255,0.07), transparent);
    }
    td.actions {
      text-align:right;
      white-space:nowrap;
      min-width:90px;
    }
    .icon-row {
      display:inline-flex;
      gap:4px;
    }
    .icon-btn {
      width:26px;
      height:26px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,0.25);
      background:rgba(5,5,8,0.96);
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-size:14px;
      color:#e5e7f5;
      text-decoration:none;
      cursor:pointer;
      padding:0;
      transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.15s ease, border-color 0.15s ease;
    }
    .icon-btn:hover {
      background:rgba(15,15,22,1);
      box-shadow:0 6px 18px rgba(0,0,0,0.7);
      transform: translateY(-1px);
    }
    .icon-btn.danger {
      border-color:rgba(255,77,106,0.7);
      color:#ffd0d8;
      background:rgba(60,10,20,0.98);
    }
    .icon-btn.danger:hover {
      box-shadow:0 8px 22px rgba(255,77,106,0.6);
    }
    .badge-empty {
      padding:16px;
      text-align:center;
      font-size:12px;
      color:#9fa3b4;
    }
    .side {
      flex: 2 1 260px;
      display:flex;
      flex-direction:column;
      gap:16px;
    }
    .card {
      border-radius:20px;
      padding:14px 14px 12px;
      background:var(--card);
      border:1px solid var(--border);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      box-shadow:0 12px 26px rgba(0,0,0,0.16);
      animation: fadeUp 0.5s ease-out;
    }
    .import-card {
      position:relative;
      overflow:hidden;
    }
    .import-card[data-loading] > *:not(.import-overlay) {
      filter:blur(1px);
      pointer-events:none;
      user-select:none;
    }
    .import-overlay {
      position:absolute;
      inset:0;
      display:none;
      align-items:center;
      justify-content:center;
      background:rgba(3,5,18,0.85);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      z-index:5;
      text-align:center;
      padding:18px;
    }
    .import-overlay.visible {
      display:flex;
    }
    .import-card[data-loading] .import-overlay {
      display:flex;
    }
    .import-overlay-inner {
      display:flex;
      flex-direction:column;
      gap:10px;
      align-items:center;
    }
    .import-spinner {
      width:30px;
      height:30px;
      border-radius:50%;
      border:3px solid rgba(255,255,255,0.2);
      border-top-color:#9fa3f0;
      animation:spin 1s linear infinite;
    }
    .import-overlay.success {
      background:rgba(16,48,30,0.9);
    }
    .import-overlay.error {
      background:rgba(70,16,24,0.92);
    }
    .import-overlay.success .import-spinner,
    .import-overlay.error .import-spinner {
      display:none;
    }
    .import-overlay-text {
      font-size:12px;
      color:#f5f5f7;
      letter-spacing:0.04em;
      text-transform:uppercase;
    }
    .card h3 {
      margin:0 0 6px;
      font-size:13px;
      letter-spacing:0.12em;
      text-transform:uppercase;
      color:var(--text);
    }
    .card p {
      margin:0 0 8px;
      font-size:11px;
      color:var(--muted);
    }
    .notes-table-wrapper {
      margin-top:6px;
      border-radius:14px;
      border:1px solid var(--border);
      background:var(--card);
      overflow:auto;
      max-height:220px;
      scrollbar-width: thin;
      scrollbar-color: rgba(120,120,140,0.5) transparent;
    }
    .notes-table-wrapper::-webkit-scrollbar {
      height:6px;
      width:6px;
    }
    .notes-table-wrapper::-webkit-scrollbar-thumb {
      background:rgba(140,140,170,0.7);
      border-radius:999px;
    }
    table.notes-table {
      width:100%;
      border-collapse:collapse;
      min-width:260px;
      background:var(--card);
      border:1px solid var(--border);
      border-radius:12px;
      overflow:hidden;
    }
    table.notes-table th,
    table.notes-table td {
      padding:6px 8px;
      font-size:11px;
      border-bottom:1px solid var(--border);
      color:var(--text);
    }
    table.notes-table th {
      background:linear-gradient(to right, rgba(255,255,255,0.04), transparent);
      font-weight:600;
    }
    table.notes-table tr:nth-child(even) td { background:var(--table-alt); }
    table.notes-table tr:last-child td {
      border-bottom:none;
    }
    table.notes-table td.actions {
      min-width:70px;
    }
    form.inline {
      display:inline;
      margin:0;
      padding:0;
    }
    @keyframes fadeUp {
      from { opacity:0; transform: translateY(10px); }
      to   { opacity:1; transform: translateY(0); }
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to   { transform: rotate(360deg); }
    }

    @media (max-width: 720px) {
      header {
        flex-direction:column;
        align-items:flex-start;
      }
      .right-header {
        width:100%;
        justify-content:space-between;
      }
      .layout {
        padding:12px;
      }
      table {
        min-width:100%;
      }
    }

    /* Theme overrides */
    body { background: var(--bg-image) !important; color: var(--text) !important; }
    header { background: linear-gradient(to bottom, var(--panel), rgba(0,0,0,0.4), transparent) !important; }
    .panel, .card, .glass, .vault-badge { background: var(--panel) !important; color: var(--text) !important; }
    .panel, .card { border:1px solid rgba(255,255,255,0.08); }
    .title .sub, .muted, .panel-header h2, .chip, th, td { color: var(--muted) !important; }
.btn-primary { background: linear-gradient(135deg, rgba(95,95,255,0.18), rgba(95,95,255,0.32)) !important; color: var(--text) !important; border:1px solid var(--border) !important; }
    a, .link { color: var(--accent); }
    body.theme-light a, body.theme-light .link { color: #2563eb; }
    .flash {
      margin: 12px 16px 0;
      padding: 10px 12px;
      border-radius: 10px;
      font-size: 12px;
      background: rgba(46, 204, 113, 0.14);
      color: #b3f5c6;
      border: 1px solid rgba(46, 204, 113, 0.25);
    }
    .flash.error {
      background: rgba(255, 77, 106, 0.16);
      color: #ffd0d8;
      border-color: rgba(255,77,106,0.3);
    }
  </style>
</head>
<body>
  <header>
    <div class="title">
      <h1>Sans Password Manager</h1>
      <div class="sub">Liquid-glass web interface · GPG encrypted</div>
    </div>
    <div class="right-header">
      <div class="vault-badge">
        <span class="label">Vault</span> <span>__VAULT_PATH__</span>
      </div>
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <div style="font-size:11px; color:#888ea6;">v__VERSION__</div>
        <button class="logout" style="padding:6px 10px; border-radius:10px;" onclick="checkUpdate(true)">Check update</button>
        <select id="theme-picker" style="background:rgba(255,255,255,0.08); color:#f5f5f7; border:1px solid rgba(255,255,255,0.18); border-radius:10px; padding:6px; font-size:12px;">
          <option value="dark">Dark</option>
          <option value="amoled">AMOLED</option>
          <option value="cyberpunk">Cyberpunk</option>
          <option value="light">Light</option>
        </select>
        <a href="/logout" class="logout">Logout</a>
      </div>
    </div>
  </header>
  __FLASH__
  <div class="layout">
    <section class="panel">
      <div class="panel-header">
        <div style="display:flex; align-items:center; flex-wrap:wrap; gap:6px;">
          <h2>Passwords</h2>
          <div class="chip"><span class="chip-dot"></span><span>Online · read / write</span></div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <a href="/add" class="btn-primary">+ Add Entry</a>
        </div>
      </div>
      <div class="table-wrapper">
        <table>
          <tr><th style="width:52px;">ID</th><th>Name</th><th>Username</th><th style="width:110px; text-align:right;">Actions</th></tr>
          __ROWS__
        </table>
      </div>
      <div style="padding:8px 10px 4px; font-size:11px; color:#888ea6;">
        Passwords are never sent anywhere else – all crypto stays on this host with GnuPG.
      </div>
    </section>
    <section class="side">
      <div class="card">
        <h3>Secure Notes</h3>
        <p>Encrypted notes stored inside the same vault.</p>
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <a href="/notes-add" class="btn-primary small">+ Add Note</a>
        </div>
        <div class="notes-table-wrapper">
          <table class="notes-table">
            <tr><th style="width:40px;">ID</th><th>Title</th><th style="width:70px; text-align:right;">Actions</th></tr>
            __NOTES_ROWS__
          </table>
        </div>
      </div>
      <div class="card">
        <h3>Password Generator</h3>
        <p>Create strong passwords with length, mode, and symbol toggles.</p>
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <a href="/generator" class="btn-primary small">Open Generator</a>
        </div>
      </div>
      <div class="card import-card" id="import-card">
        <div class="import-overlay" id="import-overlay" aria-live="polite" aria-busy="true">
          <div class="import-overlay-inner">
            <div class="import-spinner" id="import-overlay-spinner"></div>
            <div class="import-overlay-text" id="import-overlay-text">Uploading...</div>
          </div>
        </div>
        <h3>Export / Import</h3>
        <p>Download or paste data (csv/json + extended formats).</p>
        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:8px;">
          <form method="get" action="/export" style="display:flex; gap:6px; flex-wrap:wrap; align-items:center; width:100%;">
            <label style="font-size:12px;">Format</label>
            <select name="fmt" style="flex:1; min-width:140px; padding:6px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
              <option value="csv">csv (default)</option>
              <option value="json">json</option>
              <option value="tsv">tsv</option>
              <option value="ndjson">ndjson</option>
              <option value="md">md</option>
              <option value="html">html</option>
              <option value="txt">txt</option>
              <option value="yaml">yaml</option>
              <option value="xml">xml</option>
              <option value="sql">sql</option>
              <option value="ini">ini</option>
              <option value="psv">psv</option>
              <option value="rst">rst</option>
              <option value="toml">toml</option>
              <option value="org">org</option>
              <option value="scsv">scsv</option>
              <option value="csv-noheader">csv-noheader</option>
              <option value="jsonc">jsonc</option>
            </select>
            <button class="btn-primary small" type="submit">Download</button>
          </form>
        </div>
        <form id="import-form" method="post" action="/import" enctype="multipart/form-data" onsubmit="return window.SPM_handleImportSubmit ? window.SPM_handleImportSubmit(event, this) : true;" style="display:flex; flex-direction:column; gap:8px;">
          <label style="font-size:12px;">Import format</label>
          <select name="fmt" style="padding:6px; border-radius:10px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text);">
            <option value="csv">csv</option>
            <option value="json">json</option>
            <option value="tsv">tsv</option>
            <option value="ndjson">ndjson/jsonl</option>
            <option value="md">md/markdown</option>
            <option value="html">html</option>
            <option value="txt">txt</option>
            <option value="yaml">yaml/yml</option>
            <option value="xml">xml</option>
            <option value="sql">sql</option>
            <option value="ini">ini</option>
            <option value="psv">psv</option>
            <option value="rst">rst</option>
            <option value="toml">toml</option>
            <option value="org">org</option>
            <option value="scsv">scsv</option>
            <option value="csv-noheader">csv-noheader</option>
            <option value="jsonc">jsonc</option>
          </select>
          <label style="font-size:12px;">Upload export file</label>
          <input type="file" name="file" accept=".csv,.json,.tsv,.ndjson,.jsonl,.md,.markdown,.html,.txt,.yaml,.yml,.xml,.sql,.ini,.psv,.rst,.toml,.org,.scsv" style="color:var(--text);">
          <label style="font-size:12px;">Or paste file contents</label>
          <textarea name="data" rows="5" placeholder="Paste exported data here" style="width:100%; border-radius:12px; border:1px solid var(--border); background:rgba(255,255,255,0.04); color:var(--text); padding:8px;"></textarea>
          <button class="btn-primary small" type="submit" id="import-submit">Import</button>
          <div id="import-status" style="font-size:11px; min-height:14px; color:var(--muted);"></div>
          <div style="font-size:11px; color:var(--muted);">Supports passwords, notes, passphrases, authenticators, backup codes.</div>
        </form>
      </div>
      <div class="card">
        <h3>Passphrases</h3>
        <p>Store API tokens or recovery phrases. View prompts master re-check.</p>
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <a href="/passphrase-add" class="btn-primary small">+ Add Passphrase</a>
        </div>
        <div class="notes-table-wrapper">
          <table class="notes-table">
            <tr><th style="width:40px;">ID</th><th>Label</th><th style="width:70px; text-align:right;">Actions</th></tr>
            __PASSPHRASE_ROWS__
          </table>
        </div>
      </div>
      <div class="card">
        <h3>Authenticators (TOTP)</h3>
        <p>Store 2FA secrets and view live codes.</p>
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <a href="/authenticator-add" class="btn-primary small">+ Add Authenticator</a>
        </div>
        <div class="notes-table-wrapper">
          <table class="notes-table">
            <tr><th style="width:40px;">ID</th><th>Label</th><th style="width:70px;">Every</th><th style="width:70px;">Algo</th><th style="width:90px; text-align:right;">Actions</th></tr>
            __AUTH_ROWS__
          </table>
        </div>
      </div>
      <div class="card">
        <h3>Backup Codes</h3>
        <p>Store recovery codes (view shows full codes).</p>
        <div style="display:flex; justify-content:flex-end; margin-bottom:6px;">
          <a href="/backup-codes-add" class="btn-primary small">+ Add Backup Codes</a>
        </div>
        <div class="notes-table-wrapper">
          <table class="notes-table">
            <tr><th style="width:40px;">ID</th><th>Label</th><th style="width:70px; text-align:right;">Actions</th></tr>
            __BACKUP_ROWS__
          </table>
        </div>
      </div>
      <div class="card">
        <h3>Web Session</h3>
        <p>Protected by your master password. The interface auto-locks after 30 seconds of inactivity and logs you out.</p>
      </div>
    </section>
  </div>
  <div style="position:fixed; bottom:10px; right:12px; font-size:11px; color:#888ea6;">
    © 2025 Sansyourways · v__VERSION__
  </div>
  <script>
    const currentVersion = "__VERSION__";
    async function fetchLatestVersion() {
      try {
        const resp = await fetch("https://api.github.com/repos/sansyourways/Sans_Password_Manager/releases/latest", { headers: { "Accept": "application/vnd.github+json" } });
        const data = await resp.json();
        const tag = (data.tag_name || "").replace(/^v/i, "");
        return tag;
      } catch (e) {
        return "";
      }
    }
    async function checkUpdate(showPopup) {
      const latest = await fetchLatestVersion();
      if (latest && latest !== currentVersion) {
        if (showPopup) alert(`Update available: v${latest} (current v${currentVersion}).`);
        const btn = document.querySelector(".right-header .logout");
        if (btn) btn.textContent = `Update · v${latest}`;
      } else if (showPopup) {
        alert(`You are on the latest version (v${currentVersion}) or cannot reach update server.`);
      }
    }
    function setTheme(theme) {
      document.body.classList.remove("theme-dark","theme-amoled","theme-cyberpunk","theme-light");
      document.body.classList.add("theme-" + theme);
      localStorage.setItem("spm_theme", theme);
    }
    function initTheme() {
      const saved = localStorage.getItem("spm_theme") || "dark";
      setTheme(saved);
      const picker = document.getElementById("theme-picker");
      if (picker) {
        picker.value = saved;
        picker.addEventListener("change", () => setTheme(picker.value));
      }
    }
    window.SPM_handleImportSubmit = function(ev, form) {
      if (ev) ev.preventDefault();
      form = form || document.getElementById("import-form");
      if (!form) return false;
      const statusEl = document.getElementById("import-status");
      const submitBtn = document.getElementById("import-submit") || form.querySelector("button[type=submit]");
      const card = document.getElementById("import-card");
      const overlay = document.getElementById("import-overlay");
      const overlayText = document.getElementById("import-overlay-text");
      const overlaySpinner = document.getElementById("import-overlay-spinner");
      const defaultLabel = submitBtn ? submitBtn.textContent : "";
      let overlayClearTimer = null;
      const setStatus = (msg, ok=true) => {
        if (!statusEl) return;
        statusEl.textContent = msg || "";
        statusEl.style.color = ok ? "#9fa3f0" : "#ff9b9b";
      };
      const setOverlay = (state, msg) => {
        if (!card) return;
        if (!overlay) {
          if (state) {
            card.dataset.loading = "1";
            card.setAttribute("aria-busy", "true");
          } else {
            delete card.dataset.loading;
            card.removeAttribute("aria-busy");
          }
          return;
        }
        if (!state) {
          delete card.dataset.loading;
          card.removeAttribute("aria-busy");
          overlay.style.display = "none";
          overlay.classList.remove("success","error");
          if (overlaySpinner) overlaySpinner.style.display = "";
          if (overlayText) overlayText.textContent = "";
          return;
        }
        card.dataset.loading = "1";
        card.setAttribute("aria-busy", "true");
        overlay.style.display = "flex";
        overlay.classList.remove("success","error");
        if (state === "success") overlay.classList.add("success");
        if (state === "error") overlay.classList.add("error");
        if (overlaySpinner) overlaySpinner.style.display = state === "loading" ? "" : "none";
        if (overlayText) overlayText.textContent = msg || "";
      };
      const clearOverlayLater = (delay) => {
        if (overlayClearTimer) {
          clearTimeout(overlayClearTimer);
        }
        overlayClearTimer = setTimeout(() => setOverlay(null), delay);
      };
      if (window.SPM_AutoLock) window.SPM_AutoLock.pause();
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Importing...";
      }
      setOverlay("loading", "Uploading...");
      setStatus("Uploading...", true);
      const fd = new FormData(form);
      fetch("/import", {
        method: "POST",
        body: fd,
        headers: { "X-Requested-With": "fetch" },
      })
        .then(async (resp) => {
          let payload = {};
          try { payload = await resp.json(); } catch (e) {}
          if (!payload.ok) {
            throw new Error((payload && payload.message) || "Import failed.");
          }
          return payload;
        })
        .then((payload) => {
          const msg = payload.message || "Import complete.";
          setStatus(msg, true);
          form.reset();
          setOverlay("success", msg);
          setTimeout(() => { window.location.reload(); }, 800);
        })
        .catch((err) => {
          const msg = err.message || "Import failed.";
          setStatus(msg, false);
          setOverlay("error", msg);
          clearOverlayLater(2400);
        })
        .finally(() => {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = defaultLabel || "Import";
          }
          if (!overlay) {
            if (card) delete card.dataset.loading;
          }
          if (window.SPM_AutoLock) window.SPM_AutoLock.resume();
        });
      return false;
    };
    document.addEventListener("DOMContentLoaded", () => {
      initTheme();
      checkUpdate(false);
    });

  </script>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

ENTRY_FORM_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – __TITLE__</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      animation:bgShift 20s ease-in-out infinite alternate;
    }
    @keyframes bgShift {
      0% { background-position: 0% 0%; }
      100% { background-position: 80% 40%; }
    }
    .glass {
      width:min(480px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:
        0 22px 42px rgba(0,0,0,0.9),
        0 0 0 1px rgba(255,255,255,0.04);
      animation: fadeUp 0.4s ease-out;
    }
    @keyframes fadeUp {
      from { opacity:0; transform: translateY(10px); }
      to   { opacity:1; transform: translateY(0); }
    }
    h1 {
      margin:0 0 4px;
      font-size:18px;
      letter-spacing:0.1em;
      text-transform:uppercase;
    }
    .sub {
      margin:0 0 16px;
      font-size:11px;
      color:#a4a9c0;
    }
    label {
      display:block;
      font-size:12px;
      margin-bottom:4px;
      color:#d0d4e0;
    }
    input[type=text], input[type=password], textarea {
      width:100%;
      padding:9px 10px;
      border-radius:12px;
      border:1px solid rgba(255,255,255,0.18);
      background:rgba(3,3,5,0.94);
      color:#f5f5f7;
      font-size:13px;
      margin-bottom:10px;
      outline:none;
      transition:border-color 0.2s ease, box-shadow 0.2s ease;
    }
    input[type=text]:focus, input[type=password]:focus, textarea:focus {
      border-color:rgba(120,180,255,0.85);
      box-shadow:0 0 0 1px rgba(120,180,255,0.5);
    }
    textarea {
      resize:vertical;
      min-height:80px;
    }
    .actions {
      margin-top:10px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      flex-wrap:wrap;
    }
    .btn-primary {
      border-radius:999px;
      border:none;
      padding:8px 16px;
      font-size:12px;
      font-weight:500;
      letter-spacing:0.08em;
      text-transform:uppercase;
      cursor:pointer;
      background:linear-gradient(135deg,#0f9bff,#5f5fff);
      color:#fff;
      transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
    }
    .btn-primary:hover {
      filter:brightness(1.08);
      box-shadow:0 10px 25px rgba(15,155,255,0.5);
      transform: translateY(-1px);
    }
    .link {
      font-size:12px;
      color:#9fa3f0;
      text-decoration:none;
    }
    .link:hover {
      text-decoration:underline;
    }
    .msg {
      margin-top:6px;
      font-size:11px;
      color:#ff9f9f;
      animation: fadeUp 0.2s ease-out;
    }
  </style>
</head>
<body>
  <div class="glass">
    <h1>__TITLE__</h1>
    <p class="sub">Vault: __VAULT_PATH__</p>
    <form method="post" action="__ACTION__">
      __BODY__
      <div class="actions">
        <a href="/" class="link">← Back to list</a>
        <button type="submit" class="btn-primary">Save</button>
      </div>
    </form>
    __MESSAGE__
  </div>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

VIEW_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – View Entry</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      animation:bgShift 20s ease-in-out infinite alternate;
    }
    @keyframes bgShift {
      0% { background-position: 0% 0%; }
      100% { background-position: 80% 40%; }
    }
    .glass {
      width:min(460px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:
        0 22px 42px rgba(0,0,0,0.9),
        0 0 0 1px rgba(255,255,255,0.04);
      animation: fadeUp 0.35s ease-out;
    }
    @keyframes fadeUp {
      from { opacity:0; transform: translateY(10px); }
      to   { opacity:1; transform: translateY(0); }
    }
    h1 {
      margin:0 0 4px;
      font-size:18px;
      letter-spacing:0.1em;
      text-transform:uppercase;
    }
    .sub {
      margin:0 0 16px;
      font-size:11px;
      color:#a4a9c0;
    }
    .field {
      margin-bottom:10px;
      font-size:13px;
    }
    .label {
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:0.12em;
      color:#a4a9c0;
      margin-bottom:2px;
    }
    .value {
      font-size:13px;
    }
    .mono {
      font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    .actions {
      margin-top:12px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      font-size:12px;
      flex-wrap:wrap;
    }
    .btn-soft, .btn-danger {
      border-radius:999px;
      border:none;
      padding:7px 13px;
      font-size:11px;
      font-weight:500;
      letter-spacing:0.08em;
      text-transform:uppercase;
      cursor:pointer;
      background:rgba(255,255,255,0.06);
      color:#e1e3f0;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .btn-soft:hover {
      box-shadow:0 8px 20px rgba(255,255,255,0.18);
      transform: translateY(-1px);
    }
    .btn-danger {
      background:rgba(255,77,106,0.16);
      color:#ffd0d8;
    }
    .btn-danger:hover {
      box-shadow:0 8px 20px rgba(255,77,106,0.4);
      transform: translateY(-1px);
    }
    .link {
      font-size:12px;
      color:#9fa3f0;
      text-decoration:none;
    }
    .link:hover {
      text-decoration:underline;
    }
    .btn-secondary {
      border-radius:10px;
      border:1px solid rgba(255,255,255,0.15);
      background:rgba(255,255,255,0.08);
      color:#f5f5f7;
      padding:6px 10px;
      font-size:12px;
      cursor:pointer;
      margin-right:6px;
    }
    .toast {
      position:fixed;
      top:18px;
      right:18px;
      background:rgba(7,9,20,0.92);
      border:1px solid rgba(159,163,240,0.45);
      border-radius:12px;
      padding:10px 14px;
      font-size:12px;
      letter-spacing:0.04em;
      color:#f5f5f7;
      opacity:0;
      transform:translateY(-6px);
      transition:opacity 0.25s ease, transform 0.25s ease;
      pointer-events:none;
      box-shadow:0 12px 30px rgba(0,0,0,0.55);
      z-index:99;
    }
    .toast.show {
      opacity:1;
      transform:translateY(0);
    }
    .toast.error {
      border-color:rgba(255,155,155,0.6);
      color:#ffd0d8;
    }
  </style>
  <script>
    let toastTimer = null;
    function ensureToast() {
      let toast = document.getElementById('spm-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'spm-toast';
        toast.className = 'toast';
        toast.setAttribute('role','status');
        toast.setAttribute('aria-live','polite');
        toast.setAttribute('aria-atomic','true');
        document.body.appendChild(toast);
      }
      return toast;
    }
    function showToast(message, ok=true) {
      const toast = ensureToast();
      toast.textContent = message || (ok ? 'Copied to clipboard.' : 'Copy failed.');
      toast.classList.remove('error');
      if (!ok) toast.classList.add('error'); else toast.classList.remove('error');
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => { toast.classList.remove('show'); }, 2000);
    }
    function copyToClipboard(text) {
      if (!text) return Promise.resolve();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function(resolve, reject) {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.top = '-1000px';
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    }
    function handleCopy(textPromise, label) {
      textPromise
        .then(() => showToast(label ? `${label} copied.` : 'Copied.'))
        .catch(() => showToast('Copy failed.', false));
    }
    function togglePassword() {
      const el = document.getElementById('pw');
      const btn = document.getElementById('pwbtn');
      if (!el) return;
      const hidden = el.getAttribute('data-hidden') === '1';
      if (hidden) {
        el.textContent = el.getAttribute('data-real');
        el.setAttribute('data-hidden', '0');
        btn.textContent = 'Hide';
      } else {
        el.textContent = '••••••••';
        el.setAttribute('data-hidden', '1');
        btn.textContent = 'Show';
      }
    }
    function copyText(id, label) {
      const el = document.getElementById(id);
      if (!el) return;
      const text = el.getAttribute('data-real') || el.textContent || '';
      handleCopy(copyToClipboard(text), label);
    }
  </script>
</head>
<body>
  <div class="glass">
    <h1>View Entry</h1>
    <p class="sub">Vault: __VAULT_PATH__ · ID __ID__</p>

    <div class="field">
      <div class="label">Name</div>
      <div class="value mono">__NAME__</div>
    </div>
    <div class="field">
      <div class="label">Username</div>
      <div class="value mono" id="user-val">__USER__</div>
      <button class="btn-secondary" type="button" onclick="copyText('user-val','Username')">Copy Username</button>
    </div>
    <div class="field">
      <div class="label">Password</div>
      <div class="value mono" id="pw" data-hidden="1" data-real="__PASS__">••••••••</div>
      <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:6px;">
        <button id="pwbtn" class="btn-soft" type="button" onclick="togglePassword()">Show</button>
        <button class="btn-secondary" type="button" onclick="copyText('pw','Password')">Copy Password</button>
      </div>
    </div>
    <div class="field">
      <div class="label">Notes</div>
      <div class="value mono" id="notes-val">__NOTES__</div>
      <button class="btn-secondary" type="button" onclick="copyText('notes-val','Notes')">Copy Notes</button>
    </div>
    <div class="field">
      <div class="label">Created at</div>
      <div class="value mono">__CREATED__</div>
    </div>

    <div class="actions">
      <a href="/" class="link">← Back to list</a>
      <div style="display:flex; gap:6px; flex-wrap:wrap;">
        <form method="get" action="/edit" style="display:inline;">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-soft">Edit</button>
        </form>
        <form method="post" action="/delete" style="display:inline;" onsubmit="return confirm('Delete this entry?');">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </div>
    </div>
  </div>
  <div id="spm-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

NOTES_VIEW_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – View Note</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      animation:bgShift 20s ease-in-out infinite alternate;
    }
    @keyframes bgShift {
      0% { background-position: 0% 0%; }
      100% { background-position: 80% 40%; }
    }
    .glass {
      width:min(460px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:
        0 22px 42px rgba(0,0,0,0.9),
        0 0 0 1px rgba(255,255,255,0.04);
      animation: fadeUp 0.35s ease-out;
    }
    @keyframes fadeUp {
      from { opacity:0; transform: translateY(10px); }
      to   { opacity:1; transform: translateY(0); }
    }
    h1 {
      margin:0 0 4px;
      font-size:18px;
      letter-spacing:0.1em;
      text-transform:uppercase;
    }
    .sub {
      margin:0 0 16px;
      font-size:11px;
      color:#a4a9c0;
    }
    .field {
      margin-bottom:10px;
      font-size:13px;
    }
    .label {
      font-size:11px;
      text-transform:uppercase;
      letter-spacing:0.12em;
      color:#a4a9c0;
      margin-bottom:2px;
    }
    .value {
      font-size:13px;
    }
    .mono {
      font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      white-space:pre-wrap;
    }
    .actions {
      margin-top:12px;
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:10px;
      font-size:12px;
      flex-wrap:wrap;
    }
    .btn-danger {
      border-radius:999px;
      border:none;
      padding:7px 13px;
      font-size:11px;
      font-weight:500;
      letter-spacing:0.08em;
      text-transform:uppercase;
      cursor:pointer;
      background:rgba(255,77,106,0.16);
      color:#ffd0d8;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .btn-danger:hover {
      box-shadow:0 8px 20px rgba(255,77,106,0.4);
      transform: translateY(-1px);
    }
    .link {
      font-size:12px;
      color:#9fa3f0;
      text-decoration:none;
    }
    .link:hover {
      text-decoration:underline;
    }
    .btn-secondary { border-radius:10px; border:1px solid rgba(255,255,255,0.15); background:rgba(255,255,255,0.08); color:#f5f5f7; padding:6px 10px; font-size:12px; cursor:pointer; margin-right:6px; }
    .toast {
      position:fixed;
      top:18px;
      right:18px;
      background:rgba(7,9,20,0.92);
      border:1px solid rgba(159,163,240,0.45);
      border-radius:12px;
      padding:10px 14px;
      font-size:12px;
      letter-spacing:0.04em;
      color:#f5f5f7;
      opacity:0;
      transform:translateY(-6px);
      transition:opacity 0.25s ease, transform 0.25s ease;
      pointer-events:none;
      box-shadow:0 12px 30px rgba(0,0,0,0.55);
      z-index:99;
    }
    .toast.show { opacity:1; transform:translateY(0); }
    .toast.error { border-color:rgba(255,155,155,0.6); color:#ffd0d8; }
  </style>
  <script>
    let toastTimer = null;
    function ensureToast() {
      let toast = document.getElementById('spm-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'spm-toast';
        toast.className = 'toast';
        toast.setAttribute('role','status');
        toast.setAttribute('aria-live','polite');
        toast.setAttribute('aria-atomic','true');
        document.body.appendChild(toast);
      }
      return toast;
    }
    function showToast(message, ok=true) {
      const toast = ensureToast();
      toast.textContent = message || (ok ? 'Copied to clipboard.' : 'Copy failed.');
      toast.classList.toggle('error', !ok);
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 2000);
    }
    function copyToClipboard(text) {
      if (!text) return Promise.resolve();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function(resolve, reject) {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.top = '-1000px';
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    }
    function copyText() {
      const text = document.getElementById('note-content').textContent || '';
      copyToClipboard(text)
        .then(() => showToast('Note copied.'))
        .catch(() => showToast('Copy failed.', false));
    }
  </script>
</head>
<body>
  <div class="glass">
    <h1>Secure Note</h1>
    <p class="sub">Vault: __VAULT_PATH__ · Note ID __ID__</p>

    <div class="field">
      <div class="label">Title</div>
      <div class="value mono">__TITLE__</div>
    </div>
    <div class="field">
      <div class="label">Content</div>
      <div class="value mono" id="note-content">__CONTENT__</div>
      <button type="button" class="btn-secondary" onclick="copyText()">Copy Content</button>
    </div>
    <div class="field">
      <div class="label">Created at</div>
      <div class="value mono">__CREATED__</div>
    </div>

    <div class="actions">
      <a href="/" class="link">← Back to list</a>
      <form method="post" action="/notes-delete" onsubmit="return confirm('Delete this note?');">
        <input type="hidden" name="id" value="__ID__">
        <button type="submit" class="btn-danger">Delete</button>
      </form>
    </div>
  </div>
  <div id="spm-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

PASSPHRASE_VIEW_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – View Passphrase</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
    }
    .glass {
      width:min(460px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:0 22px 42px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.04);
    }
    h1 { margin:0 0 4px; font-size:18px; letter-spacing:0.1em; text-transform:uppercase; }
    .sub { margin:0 0 16px; font-size:11px; color:#a4a9c0; }
    .field { margin-bottom:10px; font-size:13px; }
    .label { font-size:11px; text-transform:uppercase; letter-spacing:0.12em; color:#a4a9c0; margin-bottom:2px; }
    .mono { font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .actions { margin-top:12px; display:flex; justify-content:space-between; align-items:center; gap:10px; font-size:12px; flex-wrap:wrap; }
    .btn-soft, .btn-danger { border-radius:999px; border:none; padding:7px 13px; font-size:11px; font-weight:500; letter-spacing:0.08em; text-transform:uppercase; cursor:pointer; background:rgba(255,255,255,0.06); color:#e1e3f0; }
    .btn-danger { background:rgba(255,77,106,0.16); color:#ffd0d8; }
    .link { font-size:12px; color:#9fa3f0; text-decoration:none; }
    .link:hover { text-decoration:underline; }
    .btn-secondary { border-radius:10px; border:1px solid rgba(255,255,255,0.15); background:rgba(255,255,255,0.08); color:#f5f5f7; padding:6px 10px; font-size:12px; cursor:pointer; margin-right:6px; }
    .toast {
      position:fixed;
      top:18px;
      right:18px;
      background:rgba(7,9,20,0.92);
      border:1px solid rgba(159,163,240,0.45);
      border-radius:12px;
      padding:10px 14px;
      font-size:12px;
      letter-spacing:0.04em;
      color:#f5f5f7;
      opacity:0;
      transform:translateY(-6px);
      transition:opacity 0.25s ease, transform 0.25s ease;
      pointer-events:none;
      box-shadow:0 12px 30px rgba(0,0,0,0.55);
      z-index:99;
    }
    .toast.show { opacity:1; transform:translateY(0); }
    .toast.error { border-color:rgba(255,155,155,0.6); color:#ffd0d8; }
  </style>
  <script>
    let toastTimer = null;
    function ensureToast() {
      let toast = document.getElementById('spm-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'spm-toast';
        toast.className = 'toast';
        toast.setAttribute('role','status');
        toast.setAttribute('aria-live','polite');
        toast.setAttribute('aria-atomic','true');
        document.body.appendChild(toast);
      }
      return toast;
    }
    function showToast(message, ok=true) {
      const toast = ensureToast();
      toast.textContent = message || (ok ? 'Copied to clipboard.' : 'Copy failed.');
      toast.classList.toggle('error', !ok);
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 2000);
    }
    function copyToClipboard(text) {
      if (!text) return Promise.resolve();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function(resolve, reject) {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.top = '-1000px';
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    }
    function copySecret() {
      const text = document.getElementById('pass-secret').textContent || '';
      copyToClipboard(text)
        .then(() => showToast('Passphrase copied.'))
        .catch(() => showToast('Copy failed.', false));
    }
  </script>
</head>
<body>
  <div class="glass">
    <h1>Passphrase</h1>
    <p class="sub">Vault: __VAULT_PATH__ · ID __ID__</p>
    <div class="field"><div class="label">Label</div><div class="mono">__LABEL__</div></div>
    <div class="field"><div class="label">Created</div><div class="mono">__CREATED__</div></div>
    <div class="field"><div class="label">Passphrase</div><div class="mono" id="pass-secret">__SECRET__</div><button class="btn-secondary" type="button" onclick="copySecret()">Copy</button></div>
    <div class="actions">
      <a href="/" class="link">← Back</a>
      <div style="display:flex; gap:6px; flex-wrap:wrap;">
        <form method="get" action="/passphrase-edit" style="display:inline;">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-soft">Edit</button>
        </form>
        <form method="post" action="/passphrase-delete" style="display:inline;" onsubmit="return confirm('Delete this passphrase?');">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </div>
    </div>
  </div>
  <div id="spm-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

BACKUP_VIEW_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – Backup Codes</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
    }
    .glass {
      width:min(520px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:0 22px 42px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.04);
    }
    h1 { margin:0 0 4px; font-size:18px; letter-spacing:0.1em; text-transform:uppercase; }
    .sub { margin:0 0 16px; font-size:11px; color:#a4a9c0; }
    pre {
      background:rgba(255,255,255,0.05);
      padding:12px;
      border-radius:10px;
      font-size:12px;
      overflow:auto;
    }
    .actions { margin-top:12px; display:flex; justify-content:space-between; align-items:center; gap:10px; font-size:12px; flex-wrap:wrap; }
    .btn-soft, .btn-danger { border-radius:999px; border:none; padding:7px 13px; font-size:11px; font-weight:500; letter-spacing:0.08em; text-transform:uppercase; cursor:pointer; background:rgba(255,255,255,0.06); color:#e1e3f0; }
    .btn-danger { background:rgba(255,77,106,0.16); color:#ffd0d8; }
    .link { font-size:12px; color:#9fa3f0; text-decoration:none; }
    .link:hover { text-decoration:underline; }
    .btn-secondary { border-radius:10px; border:1px solid rgba(255,255,255,0.15); background:rgba(255,255,255,0.08); color:#f5f5f7; padding:6px 10px; font-size:12px; cursor:pointer; margin-right:6px; }
    .toast {
      position:fixed;
      top:18px;
      right:18px;
      background:rgba(7,9,20,0.92);
      border:1px solid rgba(159,163,240,0.45);
      border-radius:12px;
      padding:10px 14px;
      font-size:12px;
      letter-spacing:0.04em;
      color:#f5f5f7;
      opacity:0;
      transform:translateY(-6px);
      transition:opacity 0.25s ease, transform 0.25s ease;
      pointer-events:none;
      box-shadow:0 12px 30px rgba(0,0,0,0.55);
      z-index:99;
    }
    .toast.show { opacity:1; transform:translateY(0); }
    .toast.error { border-color:rgba(255,155,155,0.6); color:#ffd0d8; }
  </style>
  <script>
    let toastTimer = null;
    function ensureToast() {
      let toast = document.getElementById('spm-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'spm-toast';
        toast.className = 'toast';
        toast.setAttribute('role','status');
        toast.setAttribute('aria-live','polite');
        toast.setAttribute('aria-atomic','true');
        document.body.appendChild(toast);
      }
      return toast;
    }
    function showToast(message, ok=true) {
      const toast = ensureToast();
      toast.textContent = message || (ok ? 'Copied to clipboard.' : 'Copy failed.');
      toast.classList.toggle('error', !ok);
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 2000);
    }
    function copyToClipboard(text) {
      if (!text) return Promise.resolve();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function(resolve, reject) {
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.style.position = 'fixed';
          ta.style.top = '-1000px';
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    }
    function copyCodes() {
      const text = document.getElementById('backup-codes').textContent || '';
      copyToClipboard(text)
        .then(() => showToast('Backup codes copied.'))
        .catch(() => showToast('Copy failed.', false));
    }
  </script>
</head>
<body>
  <div class="glass">
    <h1>Backup Codes</h1>
    <p class="sub">Vault: __VAULT_PATH__ · ID __ID__</p>
    <div style="font-size:13px; margin-bottom:8px;">Label: <span class="mono">__LABEL__</span></div>
    <div style="font-size:13px; margin-bottom:8px;">Created: <span class="mono">__CREATED__</span></div>
    <pre id="backup-codes">__CODES__</pre>
    <button class="btn-secondary" type="button" onclick="copyCodes()">Copy Codes</button>
    <div class="actions">
      <a href="/" class="link">← Back</a>
      <div style="display:flex; gap:6px; flex-wrap:wrap;">
        <form method="get" action="/backup-codes-edit" style="display:inline;">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-soft">Edit</button>
        </form>
        <form method="post" action="/backup-codes-delete" style="display:inline;" onsubmit="return confirm('Delete these backup codes?');">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </div>
    </div>
  </div>
  <div id="spm-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

GENERATOR_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – Password Generator</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
    }
    .glass {
      width:min(520px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:0 22px 42px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.04);
    }
    h1 { margin:0 0 4px; font-size:18px; letter-spacing:0.1em; text-transform:uppercase; }
    .sub { margin:0 0 16px; font-size:11px; color:#a4a9c0; }
    .row { display:flex; gap:12px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }
    label { font-size:12px; color:#d0d4e0; }
    input[type=range] { width:100%; }
    .mono { font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .output { font-size:16px; padding:10px 12px; border-radius:12px; background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.16); word-break:break-all; }
    .pill { border:1px solid rgba(255,255,255,0.14); padding:6px 10px; border-radius:12px; background:rgba(255,255,255,0.06); cursor:pointer; user-select:none; }
    .pill.active { background:linear-gradient(135deg,#0f9bff,#5f5fff); border-color:transparent; }
    .btn { border:none; padding:9px 14px; border-radius:14px; background:linear-gradient(135deg,#14c38e,#2f7cff); color:#fff; font-weight:600; letter-spacing:0.04em; cursor:pointer; }
    .btn-secondary { border:1px solid rgba(255,255,255,0.14); padding:8px 12px; border-radius:12px; background:rgba(255,255,255,0.08); color:#f5f5f7; font-weight:500; }
    .stats { font-size:12px; color:#c8cbe4; }
  </style>
</head>
<body>
  <div class="glass">
    <h1>Password Generator</h1>
    <p class="sub">Vault: __VAULT_PATH__</p>
    <div class="row">
      <label for="len">Length: <span id="len-label">16</span></label>
      <input type="range" id="len" min="4" max="64" value="16">
    </div>
    <div class="row">
      <span id="mode-secure" class="pill active" onclick="setMode('secure')">Secure</span>
      <span id="mode-easy" class="pill" onclick="setMode('easy')">Easy / Memorable</span>
    </div>
    <div class="row" style="flex-wrap:wrap; gap:10px;">
      <label><input type="checkbox" id="upper" checked> Uppercase</label>
      <label><input type="checkbox" id="lower" checked> Lowercase</label>
      <label><input type="checkbox" id="digits" checked> Numbers</label>
      <label><input type="checkbox" id="symbols" checked> Symbols</label>
    </div>
    <div class="row" style="flex-direction:column; align-items:flex-start;">
      <div class="output mono" id="pw-out">••••••</div>
      <div class="stats" id="pw-stats">–</div>
    </div>
    <div class="row">
      <button class="btn" onclick="regen()">Regenerate</button>
      <button class="btn-secondary" onclick="copyPw()">Copy</button>
      <a href="/" class="btn-secondary" style="text-decoration:none;">Back</a>
    </div>
  </div>
  <script>
    const WORDS = ["sun","moon","star","river","ocean","cloud","stone","tree","leaf","fern","fire","ember","storm","wind","breeze","shadow","light","silver","gold","amber","flame","nova","comet","aurora","pulse","echo","vapor","wave","mist","dawn","dusk","zen","sage","whale","lynx","orca","hawk","raven"];
    function activeMode() {
      if (document.getElementById('mode-easy').classList.contains('active')) return 'easy';
      return 'secure';
    }
    function setMode(m) {
      ['mode-secure','mode-easy'].forEach(id => document.getElementById(id).classList.remove('active'));
      document.getElementById('mode-' + m).classList.add('active');
      regen();
    }
    function charset(includeSymbols, includeUpper, includeLower, includeDigits) {
      let base = "";
      if (includeUpper) base += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (includeLower) base += "abcdefghijklmnopqrstuvwxyz";
      if (includeDigits) base += "0123456789";
      if (includeSymbols) base += "!@#$%^&*()_-+=[]{}:;,.?/|~";
      if (!base) base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      return base;
    }
    function genSecure(len, opts) {
      const chars = charset(opts.symbols, opts.upper, opts.lower, opts.digits);
      let out = "";
      for (let i = 0; i < len; i++) {
        const idx = Math.floor(Math.random() * chars.length);
        out += chars[idx];
      }
      return { pw: out, charsetSize: chars.length };
    }
    function genEasy(wordsCount, opts) {
      let count = Math.min(8, Math.max(2, wordsCount));
      const parts = [];
      for (let i = 0; i < count; i++) {
        const idx = Math.floor(Math.random() * WORDS.length);
        let w = WORDS[idx];
        if (opts.upper && !opts.lower) {
          w = w.toUpperCase();
        } else if (opts.upper) {
          w = w.charAt(0).toUpperCase() + w.slice(1);
        } else if (!opts.lower) {
          w = w.toUpperCase();
        }
        parts.push(w);
      }
      let pw = parts.join("-");
      if (opts.digits) {
        pw += "-" + String(Math.floor(Math.random() * 100)).padStart(2, "0");
      }
      if (opts.symbols) {
        const syms = "!@#$%^&*";
        pw += syms[Math.floor(Math.random() * syms.length)];
      }
      // Rough charset size estimate for entropy
      let charsetSize = 0;
      if (opts.upper) charsetSize += 26;
      if (opts.lower) charsetSize += 26;
      if (opts.digits) charsetSize += 10;
      if (opts.symbols) charsetSize += 10;
      if (charsetSize === 0) charsetSize = 26;
      return { pw, charsetSize };
    }
    function entropy(pw, chars) {
      if (!pw || chars <= 1) return 0;
      const L = pw.length;
      return L * Math.log(chars) / Math.log(2);
    }
    function crackTime(bits) {
      const guessesPerSec = 1e10; // offline fast attacker
      const seconds = Math.pow(2, bits) / guessesPerSec;
      const units = [
        ["sec", 60],
        ["min", 60],
        ["hr", 24],
        ["day", 365],
        ["yr", 100],
        ["century", 10]
      ];
      let t = seconds;
      let label = "sec";
      for (const [name, base] of units) {
        if (t >= base) {
          t /= base;
          label = name;
        } else {
          break;
        }
      }
      return t.toFixed(1) + " " + label;
    }
    function updateStats(pw, chars) {
      const bits = entropy(pw, chars);
      let strength = "Weak";
      if (bits >= 100) strength = "Excellent";
      else if (bits >= 80) strength = "Strong";
      else if (bits >= 60) strength = "Moderate";
      else if (bits >= 40) strength = "Weak";
      else strength = "Very weak";
      const time = crackTime(bits);
      document.getElementById('pw-stats').textContent = `${strength} · ~${bits.toFixed(1)} bits · ~${time} to brute-force (est.)`;
    }
    function regen() {
      let lenVal = parseInt(document.getElementById('len').value, 10) || 16;
      const mode = activeMode();
      const opts = {
        symbols: document.getElementById('symbols').checked,
        upper: document.getElementById('upper').checked,
        lower: document.getElementById('lower').checked,
        digits: document.getElementById('digits').checked
      };
      let result;
      if (mode === 'easy') {
        const wordsCount = Math.min(8, Math.max(2, Math.round(lenVal / 6)));
        document.getElementById('len-label').textContent = `Words: ${wordsCount}`;
        result = genEasy(wordsCount, opts);
      } else {
        if (lenVal < 4) lenVal = 4;
        document.getElementById('len-label').textContent = lenVal;
        result = genSecure(lenVal, opts);
      }
      document.getElementById('pw-out').textContent = result.pw;
      updateStats(result.pw, result.charsetSize);
    }
    function copyPw() {
      const pw = document.getElementById('pw-out').textContent || '';
      navigator.clipboard.writeText(pw).catch(()=>{});
    }
    document.getElementById('len').addEventListener('input', regen);
    regen();
  </script>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

AUTH_VIEW_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>SPM Web – Authenticator</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing:border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #202438, #050507 55%, #000 100%);
      color:#f5f5f7;
      margin:0;
      padding:16px;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
    }
    .glass {
      width:min(520px, 100%);
      padding:22px 22px 18px;
      border-radius:24px;
      background:linear-gradient(135deg, rgba(255,255,255,0.14), rgba(10,10,14,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(26px);
      -webkit-backdrop-filter: blur(26px);
      box-shadow:0 22px 42px rgba(0,0,0,0.9), 0 0 0 1px rgba(255,255,255,0.04);
    }
    h1 { margin:0 0 4px; font-size:18px; letter-spacing:0.1em; text-transform:uppercase; }
    .sub { margin:0 0 16px; font-size:11px; color:#a4a9c0; }
    .field { margin-bottom:10px; font-size:13px; }
    .label { font-size:11px; text-transform:uppercase; letter-spacing:0.12em; color:#a4a9c0; margin-bottom:2px; }
    .mono { font-family: "SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .code {
      font-size:28px;
      letter-spacing:6px;
      font-weight:700;
      margin:12px 0 6px;
      display:block;
    }
    .countdown { font-size:12px; color:#9fa3f0; }
    .actions { margin-top:12px; display:flex; justify-content:space-between; align-items:center; gap:10px; font-size:12px; flex-wrap:wrap; }
    .btn-soft, .btn-danger { border-radius:999px; border:none; padding:7px 13px; font-size:11px; font-weight:500; letter-spacing:0.08em; text-transform:uppercase; cursor:pointer; background:rgba(255,255,255,0.06); color:#e1e3f0; }
    .btn-danger { background:rgba(255,77,106,0.16); color:#ffd0d8; }
    .link { font-size:12px; color:#9fa3f0; text-decoration:none; }
    .link:hover { text-decoration:underline; }
    .toast {
      position:fixed;
      top:18px;
      right:18px;
      background:rgba(7,9,20,0.92);
      border:1px solid rgba(159,163,240,0.45);
      border-radius:12px;
      padding:10px 14px;
      font-size:12px;
      letter-spacing:0.04em;
      color:#f5f5f7;
      opacity:0;
      transform:translateY(-6px);
      transition:opacity 0.25s ease, transform 0.25s ease;
      pointer-events:none;
      box-shadow:0 12px 30px rgba(0,0,0,0.55);
      z-index:99;
    }
    .toast.show { opacity:1; transform:translateY(0); }
    .toast.error { border-color:rgba(255,155,155,0.6); color:#ffd0d8; }
  </style>
</head>
<body>
  <div class="glass">
    <h1>Authenticator</h1>
    <p class="sub">Vault: __VAULT_PATH__ · ID __ID__</p>
    <div class="field"><div class="label">Label</div><div class="mono">__LABEL__</div></div>
    <div class="field"><div class="label">Interval</div><div class="mono">__PERIOD__ seconds</div></div>
    <div class="field"><div class="label">Algorithm</div><div class="mono">__ALGO__</div></div>
    <div class="field"><div class="label">Created</div><div class="mono">__CREATED__</div></div>
    <div class="field"><div class="label">Base32 Secret</div><div class="mono">__SECRET__</div></div>
    <div class="field">
      <div class="label">Live Code</div>
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <span id="code" class="code" style="margin:0;">••••••</span>
        <button type="button" class="btn-soft" id="copy-btn" title="Copy code">📋 Copy</button>
      </div>
      <div class="countdown" id="countdown"></div>
      <div id="copy-status" style="font-size:11px; color:#9fa3f0; min-height:14px;"></div>
    </div>
    <div class="actions">
      <a href="/" class="link">← Back</a>
      <div style="display:flex; gap:6px; flex-wrap:wrap;">
        <form method="get" action="/authenticator-edit" style="display:inline;">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-soft">Edit</button>
        </form>
        <form method="post" action="/authenticator-delete" style="display:inline;" onsubmit="return confirm('Delete this authenticator?');">
          <input type="hidden" name="id" value="__ID__">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </div>
    </div>
  </div>
  <div id="spm-toast" class="toast" role="status" aria-live="polite" aria-atomic="true"></div>
  <script>
    let toastTimer = null;
    function showToast(message, ok=true) {
      const toast = document.getElementById('spm-toast');
      if (!toast) return;
      toast.textContent = message || (ok ? 'Copied to clipboard.' : 'Copy failed.');
      toast.classList.toggle('error', !ok);
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 2000);
    }
    (function() {
      const period = Number("__PERIOD__") || 30;
      const id = "__ID__";
      const codeEl = document.getElementById('code');
      const cdEl = document.getElementById('countdown');
      const copyBtn = document.getElementById('copy-btn');
      const copyStatus = document.getElementById('copy-status');
      let countdownTimer, nextTimer, currentCode = "";
      function showStatus(msg, ok=true) {
        if (!copyStatus) return;
        copyStatus.textContent = msg || "";
        copyStatus.style.color = ok ? "#9fa3f0" : "#ff9b9b";
        if (msg) {
          setTimeout(() => { copyStatus.textContent = ""; }, 2000);
        }
      }
      function copyCode() {
        if (!currentCode) {
          showStatus("No code yet", false);
          return;
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(currentCode)
            .then(() => { showStatus("Copied!"); showToast("Code copied."); })
            .catch(() => fallbackCopy());
        } else {
          fallbackCopy();
        }
      }
      function fallbackCopy() {
        try {
          const ta = document.createElement("textarea");
          ta.value = currentCode;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          ta.remove();
          showStatus("Copied!");
          showToast("Code copied.");
        } catch (e) {
          showStatus("Copy failed", false);
          showToast("Copy failed.", false);
        }
      }
      if (copyBtn) {
        copyBtn.addEventListener("click", copyCode);
      }
      function scheduleTick(ms) {
        if (nextTimer) clearTimeout(nextTimer);
        nextTimer = setTimeout(tick, ms);
      }
      function tick() {
        if (nextTimer) {
          clearTimeout(nextTimer);
          nextTimer = null;
        }
        fetch('/authenticator-code?id=' + encodeURIComponent(id))
          .then(r => r.json())
          .then(d => {
            currentCode = d.code || '';
            codeEl.textContent = currentCode || '------';
            let remaining = d.expires_in || period;
            cdEl.textContent = 'Refreshes in ' + remaining + 's';
            if (countdownTimer) clearInterval(countdownTimer);
            countdownTimer = setInterval(() => {
              remaining -= 1;
              if (remaining <= 0) {
                cdEl.textContent = 'Refreshing...';
                clearInterval(countdownTimer);
                tick();
              } else {
                cdEl.textContent = 'Refreshes in ' + remaining + 's';
              }
            }, 1000);
            const wait = Math.max(800, (remaining * 1000) - 250);
            scheduleTick(wait);
          })
          .catch(() => scheduleTick(period * 1000));
      }
      tick();
    })();
  </script>
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

# ---------- Helpers ----------------------------------------------------------

def decrypt_vault(master: str) -> str:
    return subprocess.check_output(
        ["gpg", "--batch", "--yes", "--passphrase", master, "-d", VAULT_PATH],
        stderr=subprocess.DEVNULL,
        timeout=15,
    ).decode("utf-8", errors="ignore")

def encrypt_vault(master: str, plaintext: str) -> None:
    tmp_path = VAULT_PATH + ".webtmp"
    p = subprocess.Popen(
        ["gpg", "--batch", "--yes", "--passphrase", master, "-c", "-o", tmp_path],
        stdin=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        stdout, stderr = p.communicate(input=plaintext.encode("utf-8"), timeout=30)
        if p.returncode != 0:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise RuntimeError("Failed to encrypt vault")
        os.replace(tmp_path, VAULT_PATH)
    except subprocess.TimeoutExpired:
        p.kill()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise RuntimeError("Vault encryption timed out")

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
    delim = "," if fmt in ("csv","csv-noheader","jsonc") else ";" if fmt=="scsv" else "\\t" if fmt=="tsv" else "|"
    rows=[]
    if fmt=="csv-noheader":
        reader = csv.reader(content.splitlines(), delimiter=delim)
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
    reader = csv.DictReader(content.splitlines(), delimiter=delim)
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
            (r.get("label","") or "").replace(tab," "),
            (r.get("username","") or "").replace(tab," "),
            r.get("secret","") or "",
            (r.get("notes","") or "").replace(tab," "),
            r.get("created","") or ""
        ]))
        stats["passwords"] += 1

    def add_note(r):
        nid = str(next_id("NOTE", lines))
        body_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "NOTE",
            nid,
            (r.get("label","") or "").replace(tab," "),
            body_b64,
            r.get("created","") or "",
            "-"
        ]))
        stats["notes"] += 1

    def add_passphrase(r):
        pid = str(next_id("PASSPHRASE", lines))
        secret_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "PASSPHRASE",
            pid,
            (r.get("label","") or "").replace(tab," "),
            secret_b64,
            r.get("created","") or "",
            "-"
        ]))
        stats["passphrases"] += 1

    def add_backup(r):
        bid = str(next_id("BACKUP_CODE", lines))
        codes_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "BACKUP_CODE",
            bid,
            (r.get("label","") or "").replace(tab," "),
            codes_b64,
            r.get("created","") or "",
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
            (r.get("label","") or "").replace(tab," "),
            r.get("secret","") or "",
            period_val or "30",
            r.get("created","") or "",
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

def build_rows_html(entries):
    if not entries:
        return "<tr><td colspan='4' class='badge-empty'><i>No entries yet. Use “Add Entry” to create one.</i></td></tr>"
    rows = []
    for _, parts in entries:
        entry_id = html.escape(parts[0])
        name     = html.escape(parts[1])
        user     = html.escape(parts[2])
        row = (
            "<tr>"
            f"<td>{entry_id}</td>"
            f"<td>{name}</td>"
            f"<td>{user}</td>"
            "<td class='actions'><div class='icon-row'>"
            f"<a class='icon-btn' href='/view?id={entry_id}' title='View'><span>👁</span></a>"
            f"<a class='icon-btn' href='/edit?id={entry_id}' title='Edit'><span>✏</span></a>"
            "<form class='inline' method='post' action='/delete' "
            "onsubmit=\"return confirm('Delete this entry?');\">"
            f"<input type='hidden' name='id' value='{entry_id}'>"
            "<button type='submit' class='icon-btn danger' title='Delete'><span>🗑</span></button>"
            "</form>"
            "</div></td>"
            "</tr>"
        )
        rows.append(row)
    return "".join(rows)

def build_notes_rows_html(notes):
    if not notes:
        return "<tr><td colspan='3' class='badge-empty'><i>No secure notes yet.</i></td></tr>"
    rows = []
    for _, parts in notes:
        note_id = html.escape(parts[1])
        title   = html.escape(parts[2])
        row = (
            "<tr>"
            f"<td>{note_id}</td>"
            f"<td>{title}</td>"
            "<td class='actions'><div class='icon-row'>"
            f"<a class='icon-btn' href='/notes-view?id={note_id}' title='View'><span>👁</span></a>"
            "<form class='inline' method='post' action='/notes-delete' "
            "onsubmit=\"return confirm('Delete this note?');\">"
            f"<input type='hidden' name='id' value='{note_id}'>"
            "<button type='submit' class='icon-btn danger' title='Delete'><span>🗑</span></button>"
            "</form>"
            "</div></td>"
            "</tr>"
        )
        rows.append(row)
    return "".join(rows)

def build_passphrase_rows_html(passphrases):
    if not passphrases:
        return "<tr><td colspan='3' class='badge-empty'><i>No passphrases stored.</i></td></tr>"
    rows = []
    for _, parts in passphrases:
        pid = html.escape(parts[1])
        label = html.escape(parts[2])
        row = (
            "<tr>"
            f"<td>{pid}</td>"
            f"<td>{label}</td>"
            "<td class='actions'><div class='icon-row'>"
            f"<a class='icon-btn' href='/passphrase-view?id={pid}' title='View'><span>👁</span></a>"
            f"<a class='icon-btn' href='/passphrase-edit?id={pid}' title='Edit'><span>✏</span></a>"
            "<form class='inline' method='post' action='/passphrase-delete' "
            "onsubmit=\"return confirm('Delete this passphrase?');\">"
            f"<input type='hidden' name='id' value='{pid}'>"
            "<button type='submit' class='icon-btn danger' title='Delete'><span>🗑</span></button>"
            "</form>"
            "</div></td>"
            "</tr>"
        )
        rows.append(row)
    return "".join(rows)

def build_backup_rows_html(backups):
    if not backups:
        return "<tr><td colspan='3' class='badge-empty'><i>No backup codes stored.</i></td></tr>"
    rows = []
    for _, parts in backups:
        bid = html.escape(parts[1])
        label = html.escape(parts[2])
        row = (
            "<tr>"
            f"<td>{bid}</td>"
            f"<td>{label}</td>"
            "<td class='actions'><div class='icon-row'>"
            f"<a class='icon-btn' href='/backup-codes-view?id={bid}' title='View'><span>👁</span></a>"
            f"<a class='icon-btn' href='/backup-codes-edit?id={bid}' title='Edit'><span>✏</span></a>"
            "<form class='inline' method='post' action='/backup-codes-delete' "
            "onsubmit=\"return confirm('Delete these backup codes?');\">"
            f"<input type='hidden' name='id' value='{bid}'>"
            "<button type='submit' class='icon-btn danger' title='Delete'><span>🗑</span></button>"
            "</form>"
            "</div></td>"
            "</tr>"
        )
        rows.append(row)
    return "".join(rows)

def build_auth_rows_html(auths):
    if not auths:
        return "<tr><td colspan='5' class='badge-empty'><i>No authenticators stored.</i></td></tr>"
    rows = []
    for _, parts in auths:
        aid = html.escape(parts[1])
        label = html.escape(parts[2])
        interval = html.escape(parts[4] if len(parts) > 4 else "30")
        algo = html.escape(parts[6] if len(parts) > 6 else "sha1")
        row = (
            "<tr>"
            f"<td>{aid}</td>"
            f"<td>{label}</td>"
            f"<td>{interval}s</td>"
            f"<td>{algo.upper()}</td>"
            "<td class='actions'><div class='icon-row'>"
            f"<a class='icon-btn' href='/authenticator-view?id={aid}' title='View live'><span>👁</span></a>"
            f"<a class='icon-btn' href='/authenticator-edit?id={aid}' title='Edit'><span>✏</span></a>"
            "<form class='inline' method='post' action='/authenticator-delete' "
            "onsubmit=\"return confirm('Delete this authenticator?');\">"
            f"<input type='hidden' name='id' value='{aid}'>"
            "<button type='submit' class='icon-btn danger' title='Delete'><span>🗑</span></button>"
            "</form>"
            "</div></td>"
            "</tr>"
        )
        rows.append(row)
    return "".join(rows)

def build_entry_form(title, vault_path, action, values=None, message=""):
    values = values or {}
    def v(k): return html.escape(values.get(k, "") or "")
    body = (
        "<label>Service / Name</label>"
        f"<input type='text' name='name' value='{v('name')}' required>"
        "<label>Username</label>"
        f"<input type='text' name='user' value='{v('user')}'>"
        "<label>Password</label>"
        f"<input type='password' name='password' value='{v('password')}'>"
        "<label>Notes</label>"
        f"<textarea name='notes'>{v('notes')}</textarea>"
    )
    page = ENTRY_FORM_HTML.replace("__TITLE__", html.escape(title))
    page = page.replace("__VAULT_PATH__", html.escape(vault_path))
    page = page.replace("__ACTION__", action)
    page = page.replace("__BODY__", body)
    page = page.replace("__MESSAGE__", message)
    return page

def build_note_form(title, vault_path, action, values=None, message=""):
    values = values or {}
    def v(k): return html.escape(values.get(k, "") or "")
    body = (
        "<label>Title</label>"
        f"<input type='text' name='title' value='{v('title')}' required>"
        "<label>Content</label>"
        f"<textarea name='content'>{v('content')}</textarea>"
    )
    page = ENTRY_FORM_HTML.replace("__TITLE__", html.escape(title))
    page = page.replace("__VAULT_PATH__", html.escape(vault_path))
    page = page.replace("__ACTION__", action)
    page = page.replace("__BODY__", body)
    page = page.replace("__MESSAGE__", message)
    return page

def build_passphrase_form(title, vault_path, action, values=None, message=""):
    values = values or {}
    def v(k): return html.escape(values.get(k, "") or "")
    body = (
        "<label>Label</label>"
        f"<input type='text' name='label' value='{v('label')}' required>"
        "<label>Passphrase (leave blank to auto-generate)</label>"
        f"<input type='text' name='secret' value='{v('secret')}'>"
    )
    page = ENTRY_FORM_HTML.replace("__TITLE__", html.escape(title))
    page = page.replace("__VAULT_PATH__", html.escape(vault_path))
    page = page.replace("__ACTION__", action)
    page = page.replace("__BODY__", body)
    page = page.replace("__MESSAGE__", message)
    return page

def build_backup_form(title, vault_path, action, values=None, message=""):
    values = values or {}
    def v(k): return html.escape(values.get(k, "") or "")
    body = (
        "<label>Label</label>"
        f"<input type='text' name='label' value='{v('label')}' required>"
        "<label>Backup codes (one per line)</label>"
        f"<textarea name='codes'>{v('codes')}</textarea>"
    )
    page = ENTRY_FORM_HTML.replace("__TITLE__", html.escape(title))
    page = page.replace("__VAULT_PATH__", html.escape(vault_path))
    page = page.replace("__ACTION__", action)
    page = page.replace("__BODY__", body)
    page = page.replace("__MESSAGE__", message)
    return page

def build_auth_form(title, vault_path, action, values=None, message=""):
    values = values or {}
    def v(k): return html.escape(values.get(k, "") or "")
    algo = (values.get("algo") or "sha1").lower()
    if algo not in ("sha1","sha256","sha512"):
        algo = "sha1"
    body = (
        "<label>Label</label>"
        f"<input type='text' name='label' value='{v('label')}' required>"
        "<label>Base32 Secret</label>"
        f"<input type='text' name='secret' value='{v('secret')}' placeholder='JBSWY3DPEHPK3PXP' required>"
        "<label>Refresh interval (seconds)</label>"
        f"<input type='number' name='period' min='5' max='120' value='{v('period') or '30'}'>"
        "<label>Algorithm</label>"
        "<select name='algo'>"
        f"<option value='sha1'{' selected' if algo=='sha1' else ''}>SHA1 (default)</option>"
        f"<option value='sha256'{' selected' if algo=='sha256' else ''}>SHA256</option>"
        f"<option value='sha512'{' selected' if algo=='sha512' else ''}>SHA512</option>"
        "</select>"
    )
    page = ENTRY_FORM_HTML.replace("__TITLE__", html.escape(title))
    page = page.replace("__VAULT_PATH__", html.escape(vault_path))
    page = page.replace("__ACTION__", action)
    page = page.replace("__BODY__", body)
    page = page.replace("__MESSAGE__", message)
    return page

# ---------- HTTP server ------------------------------------------------------

class SPMServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}  # token -> master password

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[SPM Web] " + fmt % args + "\n")

    def _send_html(self, code, body):
        self.send_response(code)
        self._add_cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _add_cors(self):
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

    def _get_cookie_session(self):
        cookie = self.headers.get("Cookie", "")
        token = None
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("spm_session="):
                token = part.split("=", 1)[1].strip()
                break
        if not token:
            return None
        return self.server.sessions.get(token)

    def _require_login(self):
        master = self._get_cookie_session()
        if not master:
            page = LOGIN_HTML.replace("__MESSAGE__", "")
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

        if path.startswith("/logout"):
            self.send_response(302)
            self.send_header("Set-Cookie", "spm_session=deleted; Max-Age=0; HttpOnly; Path=/")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path == "/login":
            page = LOGIN_HTML.replace("__MESSAGE__", "")
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
                self.send_header("Set-Cookie", "spm_session=deleted; Max-Age=0; HttpOnly; Path=/")
                self.send_header("Location", "/login")
                self.end_headers()
                return

            _, entries = parse_entries(plaintext)
            _, notes = parse_notes(plaintext)
            _, passphrases = parse_passphrases(plaintext)
            _, backups = parse_backup_codes(plaintext)
            _, auths = parse_authenticators(plaintext)
            rows_html = build_rows_html(entries)
            notes_html = build_notes_rows_html(notes)
            pass_rows_html = build_passphrase_rows_html(passphrases)
            backup_rows_html = build_backup_rows_html(backups)
            auth_rows_html = build_auth_rows_html(auths)
            body = MAIN_HTML.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            body = body.replace("__FLASH__", flash)
            body = body.replace("__ROWS__", rows_html)
            body = body.replace("__NOTES_ROWS__", notes_html)
            body = body.replace("__PASSPHRASE_ROWS__", pass_rows_html)
            body = body.replace("__BACKUP_ROWS__", backup_rows_html)
            body = body.replace("__AUTH_ROWS__", auth_rows_html)
            body = body.replace("__VERSION__", html.escape(VERSION))
            self._send_html(200, body)
            return

        if path == "/generator":
            page = GENERATOR_HTML.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
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

            page = VIEW_HTML
            page = page.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            page = page.replace("__ID__", html.escape(found[0]))
            page = page.replace("__NAME__", html.escape(found[1]))
            page = page.replace("__USER__", html.escape(found[2]))
            page = page.replace("__PASS__", html.escape(found[3]))
            page = page.replace("__NOTES__", html.escape(found[4]))
            page = page.replace("__CREATED__", html.escape(found[5]))
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

            page = NOTES_VIEW_HTML
            page = page.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            page = page.replace("__ID__", html.escape(note_id))
            page = page.replace("__TITLE__", html.escape(title))
            page = page.replace("__CONTENT__", html.escape(content))
            page = page.replace("__CREATED__", html.escape(created))
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
            page = PASSPHRASE_VIEW_HTML
            page = page.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            page = page.replace("__ID__", html.escape(pid))
            page = page.replace("__LABEL__", html.escape(found[2]))
            page = page.replace("__CREATED__", html.escape(created))
            page = page.replace("__SECRET__", html.escape(secret))
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
            page = AUTH_VIEW_HTML
            page = page.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            page = page.replace("__ID__", html.escape(aid))
            page = page.replace("__LABEL__", html.escape(found[2]))
            page = page.replace("__SECRET__", html.escape(found[3]))
            page = page.replace("__PERIOD__", html.escape(found[4] or "30"))
            page = page.replace("__CREATED__", html.escape(created))
            page = page.replace("__ALGO__", html.escape(algo.upper()))
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
            page = BACKUP_VIEW_HTML
            page = page.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            page = page.replace("__ID__", html.escape(bid))
            page = page.replace("__LABEL__", html.escape(found[2]))
            page = page.replace("__CREATED__", html.escape(created))
            page = page.replace("__CODES__", html.escape(codes))
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
            code = totp_code(found[3], period, algo) or "------"
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

        if path == "/login":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", errors="ignore")
            data = urllib.parse.parse_qs(body)
            password = data.get("password", [""])[0]

            if not password:
                page = LOGIN_HTML.replace("__MESSAGE__", "<div class='msg'>Password required.</div>")
                self._send_html(200, page)
                return

            try:
                decrypt_vault(password)
            except subprocess.CalledProcessError:
                page = LOGIN_HTML.replace("__MESSAGE__", "<div class='msg'>Invalid master password.</div>")
                self._send_html(200, page)
                return

            token = secrets.token_hex(32)
            self.server.sessions[token] = password
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session={token}; HttpOnly; Path=/; SameSite=Lax")
            self.send_header("Location", "/")
            self.end_headers()
            return

        master = self._get_cookie_session()
        if not master:
            page = LOGIN_HTML.replace("__MESSAGE__", "")
            self._send_html(200, page)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (ValueError, TypeError):
            length = 0
        raw_body_bytes = self.rfile.read(length)
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
                name.replace("\t", " "),
                user.replace("\t", " "),
                password.replace("\t", " "),
                notes.replace("\t", " "),
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
                name.replace("\t", " "),
                user.replace("\t", " "),
                password.replace("\t", " "),
                notes.replace("\t", " "),
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
                title.replace("\t", " "),
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
                label.replace("\t", " "),
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
                label.replace("\t", " "),
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
                label.replace("\t", " "),
                secret.replace("\t", ""),
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
                label.replace("\t", " "),
                secret.replace("\t", ""),
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
                label.replace("\t", " "),
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
                label.replace("\t", " "),
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

#!/usr/bin/env bash
# Sans Password Manager (SPM)
# Portable Bash + GPG password manager with encrypted vault.
# Dependencies: bash, gpg, openssl, base64, curl (for update)

set -o errexit
set -o nounset
set -o pipefail

VERSION="2.1.0"

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
	local tmp
	if command -v mktemp >/dev/null 2>&1; then
		tmp="$(mktemp "${TMPDIR:-/tmp}/spm.XXXXXX")"
	else
		tmp="${TMPDIR:-/tmp}/spm.$RANDOM.$RANDOM.$$"
		: >"$tmp"
	fi
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
		printf "# Baris meta     : META_RECOVERY_PUBKEY...\n" >&2
	else
		printf "Opening vault in editor: %s\n" "$EDITOR_CMD"
		printf "# Password rows: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at\n" >&2
		printf "# Note rows    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-\n" >&2
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
  - README.txt             : instructions

How to restore:
  1. Move this archive to the target device.
  2. Extract it into a folder.
  3. Run:
       ./spm.sh
  4. Enter your master password to access your vault.

Security notes:
  - Keep this backup offline (USB, encrypted disk, cloud with 2FA).
  - Private key (spm_recovery_private.pem) is NOT in this archive.
  - Without your private key, the recovery file cannot be used.

------------------------------------------------------------
[ID]

File yang disertakan:
  - spm.sh                 : script SPM
  - spm_vault.gpg          : vault terenkripsi
  - spm_vault.gpg.recovery : (opsional) file pemulihan
  - README.txt             : petunjuk

Cara mengembalikan:
  1. Pindahkan arsip ini ke perangkat tujuan.
  2. Ekstrak ke sebuah folder.
  3. Jalankan:
       ./spm.sh
  4. Masukkan master password.

Catatan keamanan:
  - Simpan backup di tempat aman (USB, disk terenkripsi, cloud dengan 2FA).
  - Private key (spm_recovery_private.pem) TIDAK disertakan.
  - Tanpa private key, file pemulihan tidak dapat digunakan.

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
	printf "  - README.txt\n"
	printf "Final archive: %s\n" "$archive_path"
}

# ----- Update / Forgot / Doctor ----------------------------------------------

cmd_update() {
	require_cmd curl

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

	if [ "$latest_tag" = "$VERSION" ]; then
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nSudah memakai versi terbaru.\n"
		else
			printf "\nYou are already on the latest version.\n"
		fi
	else
		if [ "$SPM_LANG" = "id" ]; then
			printf "\nAda versi baru tersedia.\n"
			printf "Contoh cara update script ini:\n\n"
		else
			printf "\nA newer version is available.\n"
			printf "To update this script (example):\n\n"
		fi
		printf "  curl -L -o spm.sh \"https://raw.githubusercontent.com/%s/%s/%s/spm.sh\"\n" "$REPO_OWNER" "$REPO_NAME" "$latest_tag"
		printf "  chmod +x spm.sh\n\n"
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

VAULT_PATH = os.environ.get("SPM_VAULT_PATH")
BIND_ADDR  = os.environ.get("SPM_WEB_BIND", "127.0.0.1")
PORT       = int(os.environ.get("SPM_WEB_PORT", "8080"))

if not VAULT_PATH or not os.path.isfile(VAULT_PATH):
    raise SystemExit(f"Vault file not found: {VAULT_PATH!r}")

# ---------- HTML templates (liquid glass, icons, auto-lock) ------------------

AUTOLOCK_SCRIPT = """
<script>
  (function() {
    let t;
    function reset() {
      if (t) clearTimeout(t);
      t = setTimeout(function() {
        window.location.href = "/logout";
      }, 30000);
    }
    ["click","keydown","mousemove","touchstart","scroll"].forEach(function(ev) {
      window.addEventListener(ev, reset, { passive: true });
    });
    reset();
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
    }
    * { box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background:
        radial-gradient(circle at top, #202438 0, #05060a 40%, #020308 100%);
      color: #eee;
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
      --accent: #0f9bff;
      --accent-soft: rgba(15,155,255,0.24);
      --danger: #ff4d6a;
      --danger-soft: rgba(255,77,106,0.14);
    }
    * { box-sizing:border-box; }
    body {
      margin:0;
      padding:0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background:
        radial-gradient(circle at top left, #2a2a36 0, #050509 45%, #000 100%);
      color:#f5f5f7;
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
      background:linear-gradient(to bottom, rgba(5,5,8,0.96), rgba(5,5,8,0.7), transparent);
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
      border-bottom:1px solid rgba(255,255,255,0.06);
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
      color:#9fa3b4;
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
      border:1px solid rgba(255,255,255,0.16);
      background:radial-gradient(circle at top left, rgba(255,255,255,0.14), rgba(0,0,0,0.9));
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      color:#d0d4e0;
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
      background:radial-gradient(circle at top left, rgba(255,255,255,0.1), rgba(5,5,10,0.95));
      backdrop-filter: blur(26px) saturate(180%);
      -webkit-backdrop-filter: blur(26px) saturate(180%);
      border:1px solid rgba(255,255,255,0.15);
      box-shadow:
        0 24px 45px rgba(0,0,0,0.85),
        0 0 0 1px rgba(255,255,255,0.03);
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
      background:linear-gradient(135deg,#0f9bff,#5f5fff);
      color:#fff;
      transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
    }
    .btn-primary.small {
      padding:6px 11px;
      font-size:10px;
    }
    .btn-primary:hover {
      filter:brightness(1.08);
      box-shadow:0 10px 25px rgba(15,155,255,0.5);
      transform: translateY(-1px);
    }
    .table-wrapper {
      margin-top:8px;
      border-radius:18px;
      border:1px solid rgba(255,255,255,0.12);
      background:linear-gradient(145deg, rgba(2,2,5,0.98), rgba(12,12,20,0.95));
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
    }
    th, td {
      padding:8px 10px;
      font-size:12px;
      border-bottom:1px solid rgba(255,255,255,0.06);
    }
    th {
      text-align:left;
      background:linear-gradient(to right, rgba(255,255,255,0.06), transparent);
      font-weight:500;
      color:#cfd3e8;
      position:sticky;
      top:0;
      z-index:1;
      backdrop-filter: blur(18px);
      -webkit-backdrop-filter: blur(18px);
    }
    tr:last-child td {
      border-bottom:none;
    }
    tr:hover td {
      background:radial-gradient(circle at left, rgba(255,255,255,0.05), transparent);
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
      background:radial-gradient(circle at top left, rgba(255,255,255,0.1), rgba(10,10,18,0.96));
      border:1px solid rgba(255,255,255,0.16);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      box-shadow:0 18px 35px rgba(0,0,0,0.85);
      animation: fadeUp 0.5s ease-out;
    }
    .card h3 {
      margin:0 0 6px;
      font-size:13px;
      letter-spacing:0.12em;
      text-transform:uppercase;
      color:#d4d7e5;
    }
    .card p {
      margin:0 0 8px;
      font-size:11px;
      color:#a4a9c0;
    }
    .notes-table-wrapper {
      margin-top:6px;
      border-radius:14px;
      border:1px solid rgba(255,255,255,0.12);
      background:linear-gradient(145deg, rgba(2,2,5,0.98), rgba(12,12,20,0.95));
      overflow:auto;
      max-height:220px;
      scrollbar-width: thin;
      scrollbar-color: rgba(120,120,140,0.7) transparent;
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
    }
    table.notes-table th,
    table.notes-table td {
      padding:6px 8px;
      font-size:11px;
      border-bottom:1px solid rgba(255,255,255,0.06);
    }
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
      <a href="/logout" class="logout">Logout</a>
    </div>
  </header>
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
        <h3>Web Session</h3>
        <p>Protected by your master password. The interface auto-locks after 30 seconds of inactivity and logs you out.</p>
      </div>
    </section>
  </div>
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
  </style>
  <script>
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
      <div class="value mono">__USER__</div>
    </div>
    <div class="field">
      <div class="label">Password</div>
      <div class="value mono" id="pw" data-hidden="1" data-real="__PASS__">••••••••</div>
      <button id="pwbtn" class="btn-soft" type="button" onclick="togglePassword()">Show</button>
    </div>
    <div class="field">
      <div class="label">Notes</div>
      <div class="value mono">__NOTES__</div>
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
  </style>
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
      <div class="value mono">__CONTENT__</div>
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
  """ + AUTOLOCK_SCRIPT + """
</body>
</html>
"""

# ---------- Helpers ----------------------------------------------------------

def decrypt_vault(master: str) -> str:
    return subprocess.check_output(
        ["gpg", "--batch", "--yes", "--passphrase", master, "-d", VAULT_PATH],
        stderr=subprocess.DEVNULL,
    ).decode("utf-8", errors="ignore")

def encrypt_vault(master: str, plaintext: str) -> None:
    tmp_path = VAULT_PATH + ".webtmp"
    p = subprocess.Popen(
        ["gpg", "--batch", "--yes", "--passphrase", master, "-c", "-o", tmp_path],
        stdin=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    p.communicate(input=plaintext.encode("utf-8"))
    if p.returncode != 0:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise RuntimeError("Failed to encrypt vault")
    os.replace(tmp_path, VAULT_PATH)

def parse_entries(plaintext: str):
    """Password entries."""
    lines = plaintext.splitlines()
    entries = []
    for idx, line in enumerate(lines):
        if not line or line.startswith("#") or line.startswith("META_") or line.startswith("NOTE\t"):
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
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

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
            rows_html = build_rows_html(entries)
            notes_html = build_notes_rows_html(notes)
            body = MAIN_HTML.replace("__VAULT_PATH__", html.escape(VAULT_PATH))
            body = body.replace("__ROWS__", rows_html)
            body = body.replace("__NOTES_ROWS__", notes_html)
            self._send_html(200, body)
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
            self.send_header("Set-Cookie", f"spm_session={token}; HttpOnly; Path=/")
            self.send_header("Location", "/")
            self.end_headers()
            return

        master = self._get_cookie_session()
        if not master:
            page = LOGIN_HTML.replace("__MESSAGE__", "")
            self._send_html(200, page)
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8", errors="ignore")
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
			printf "  9) Help\n"
			printf " 10) Cek update\n"
			printf " 11) Lupa / Reset kata sandi utama (pemulihan)\n"
			printf " 12) Catatan aman (secure notes)\n"
			printf " 13) Doctor / Health check\n"
			printf " 14) Mode web\n"
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
			printf "  9) Help\n"
			printf " 10) Check for updates\n"
			printf " 11) Forgot / Reset master (use private key)\n"
			printf " 12) Secure notes\n"
			printf " 13) Doctor / Health check\n"
			printf " 14) Web mode\n"
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
			9)  clear; cmd_help; pause_menu ;;
			10) clear; cmd_update || true; pause_menu ;;
			11) clear; cmd_forgot || true; pause_menu ;;
			12) interactive_menu_notes ;;
			13) clear; cmd_doctor || true; pause_menu ;;
			14) clear; start_web_mode || true ;;  # ← Web Mode (experimental)
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
		update)           cmd_update "$@" ;;
		forgot|forgotten) cmd_forgot "$@" ;;
		doctor)           cmd_doctor "$@" ;;
		notes-add)        cmd_notes_add "$@" ;;
		notes-list)       cmd_notes_list "$@" ;;
		notes-view)       cmd_notes_view "$@" ;;
		notes-delete)     cmd_notes_delete "$@" ;;
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

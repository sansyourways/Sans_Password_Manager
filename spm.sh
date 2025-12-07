#!/usr/bin/env bash
# Sans Password Manager (SPM)
# Portable Bash + GPG password manager with encrypted vault.
# Dependencies: bash, gpg, openssl, base64, curl (for update)

set -o errexit
set -o nounset
set -o pipefail

VERSION="2.0.0"

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
	printf "Sans Password Manager (SPM)  v%s  \u00a9 %s SansYourWays. All rights reserved.\n\n" "$VERSION" "$year"
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

# ----- Help ------------------------------------------------------------------

cmd_help() {
	print_banner

	if [ "$SPM_LANG" = "id" ]; then
		cat <<EOF
[ID] Panduan Singkat
====================

Sans Password Manager (SPM) v$VERSION

Perintah utama:
  ./spm.sh                 → Menu interaktif
  ./spm.sh init            → Inisialisasi vault baru
  ./spm.sh add             → Tambah entry password
  ./spm.sh list            → List entry password
  ./spm.sh get <id|pola>   → Lihat entry atau cari
  ./spm.sh edit            → Edit vault mentah
  ./spm.sh delete <id>     → Hapus entry password
  ./spm.sh change-master   → Ganti kata sandi utama
  ./spm.sh portable [nama] → Buat bundle portable
  ./spm.sh save [nama]     → Buat SAVE bundle + hapus vault lokal
  ./spm.sh update          → Cek update GitHub
  ./spm.sh forgot          → Lupa kata sandi utama (pakai private key)
  ./spm.sh doctor          → Health / integrity check
  ./spm.sh help            → Bantuan

Catatan Aman (Secure Notes):
  ./spm.sh notes-add       → Tambah catatan aman
  ./spm.sh notes-list      → List catatan aman
  ./spm.sh notes-view <id> → Lihat isi catatan
  ./spm.sh notes-delete <id>
                           → Hapus catatan

Format:
  - Baris password: id<TAB>service<TAB>username<TAB>password<TAB>notes<TAB>created_at
  - Baris note    : NOTE<TAB>note_id<TAB>title<TAB>base64_note<TAB>created_at<TAB>-
  - Baris meta    : META_RECOVERY_PUBKEY...

EOF
	fi

	cat <<EOF
[EN] Quick Guide
================

Main commands:
  ./spm.sh                 → Interactive menu
  ./spm.sh init            → Initialize a new vault
  ./spm.sh add             → Add password entry
  ./spm.sh list            → List password entries
  ./spm.sh get <id|pattern>→ View entry or search
  ./spm.sh edit            → Edit raw vault
  ./spm.sh delete <id>     → Delete password entry
  ./spm.sh change-master   → Change master password
  ./spm.sh portable [name] → Create portable bundle
  ./spm.sh save [name]     → Create SAVE bundle + wipe local vault
  ./spm.sh update          → Check GitHub release
  ./spm.sh forgot          → Forgot master password (use private key)
  ./spm.sh doctor          → Health / integrity check
  ./spm.sh help            → This help

Secure Notes:
  ./spm.sh notes-add       → Add secure note
  ./spm.sh notes-list      → List secure notes
  ./spm.sh notes-view <id> → View note content
  ./spm.sh notes-delete <id>
                           → Delete secure note

Clipboard:
  - Auto-copy passwords and auto-clear clipboard (~15s).
  - Shows "No clipboard helper available" / "Tidak ada helper clipboard tersedia"
    when helper is missing (including from interactive menu).

EOF
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
		help|-h|--help)   cmd_help ;;
		*)
			printf "Unknown command: %s\n\n" "$cmd" >&2
			cmd_help
			exit 1
			;;
	esac
}

main "$@"

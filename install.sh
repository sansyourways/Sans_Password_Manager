#!/usr/bin/env bash
set -euo pipefail

REPO="sansyourways/Sans_Password_Manager"
VERSION="latest"
PREFIX="${SPM_INSTALL_PREFIX:-/usr/local}"
DRY_RUN=0
MODIFY_PATH=1
[ -n "${SPM_NO_MODIFY_PATH:-}" ] && MODIFY_PATH=0

usage() {
	cat <<'EOF'
Usage: ./install.sh [--version X.Y.Z] [--prefix DIRECTORY] [--dry-run]
                    [--no-modify-path]

Downloads an official SPM release ZIP and its matching SHA-256 file, verifies
the archive, validates spm.sh syntax, and installs the CLI as PREFIX/bin/spm.

If PREFIX/bin is not on your PATH, the installer appends it to your shell
profile so `spm` works from any directory. Pass --no-modify-path (or set
SPM_NO_MODIFY_PATH=1) to be told what to add instead of having it done for you.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--version)
			[ "$#" -ge 2 ] || { printf 'Missing value for --version.\n' >&2; exit 2; }
			VERSION="$2"; shift 2 ;;
		--prefix)
			[ "$#" -ge 2 ] || { printf 'Missing value for --prefix.\n' >&2; exit 2; }
			PREFIX="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--no-modify-path) MODIFY_PATH=0; shift ;;
		-h|--help) usage; exit 0 ;;
		*) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

# Does $1 appear in PATH as its own entry? Wrapping both sides in colons keeps
# a prefix like /usr/local/bin from matching /usr/local/bin-other.
dir_on_path() {
	case ":${PATH}:" in
		*":$1:"*) return 0 ;;
	esac
	return 1
}

# Where a login shell would read an exported PATH from.
profile_for_shell() {
	case "$(basename "${SHELL:-sh}")" in
		zsh) printf '%s\n' "${ZDOTDIR:-$HOME}/.zshrc" ;;
		fish) printf '%s\n' "$HOME/.config/fish/conf.d/spm.fish" ;;
		bash)
			# macOS terminals start login shells, which read .bash_profile and
			# never .bashrc; most Linux terminals do the opposite.
			if [ "$(uname -s)" = "Darwin" ]; then
				printf '%s\n' "$HOME/.bash_profile"
			else
				printf '%s\n' "$HOME/.bashrc"
			fi ;;
		*) printf '%s\n' "$HOME/.profile" ;;
	esac
}

shell_quote() {
	# POSIX and Fish both accept single-quoted path literals. Replace every
	# embedded quote with: close quote, escaped quote, reopen quote.
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

ensure_on_path() {
	local dir="$1" profile marker line
	if dir_on_path "$dir"; then
		printf 'PATH        : already contains %s\n' "$dir"
		return 0
	fi
	if [ "$MODIFY_PATH" -eq 0 ]; then
		printf 'PATH        : %s is missing. Add this line to your shell profile:\n' "$dir"
		printf '                export PATH="%s:$PATH"\n' "$dir"
		return 0
	fi
	if [ "$(id -u)" -eq 0 ]; then
		# Under sudo, HOME may belong to root rather than the person installing,
		# so editing a profile here would write to the wrong account.
		printf 'PATH        : %s is missing, but running as root; no profile was edited.\n' "$dir"
		printf '                Add this to your own shell profile:\n'
		printf '                export PATH="%s:$PATH"\n' "$dir"
		return 0
	fi
	profile="$(profile_for_shell)"
	case "$profile" in
		*.fish) line="fish_add_path -- $(shell_quote "$dir")" ;;
		*) line="export PATH=$(shell_quote "$dir"):\$PATH" ;;
	esac
	marker="# added by the Sans Password Manager installer: $dir"
	if [ -f "$profile" ] && grep -Fqx "$line" "$profile"; then
		printf 'PATH        : %s already configured in %s; restart your shell\n' "$dir" "$profile"
		return 0
	fi
	mkdir -p "$(dirname "$profile")" || {
		printf 'PATH        : could not create %s; add %s to PATH yourself\n' "$(dirname "$profile")" "$dir" >&2
		return 0
	}
	printf '\n%s\n%s\n' "$marker" "$line" >>"$profile" || {
		printf 'PATH        : could not write %s; add %s to PATH yourself\n' "$profile" "$dir" >&2
		return 0
	}
	printf 'PATH        : added %s to %s\n' "$dir" "$profile"
	printf '                run "exec %s" or open a new terminal to pick it up\n' "${SHELL:-sh}"
}

for command_name in curl sha256sum unzip bash mktemp; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf "Required command '%s' is not installed.\n" "$command_name" >&2
		exit 1
	}
done

if printf '%s' "$PREFIX" | LC_ALL=C grep -q '[[:cntrl:]]'; then
	printf 'Invalid prefix: control characters are not allowed.\n' >&2
	exit 2
fi

if [ "$VERSION" = "latest" ]; then
	api_url="https://api.github.com/repos/$REPO/releases/latest"
	VERSION="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
	[ -n "$VERSION" ] || { printf 'Could not resolve the latest release.\n' >&2; exit 1; }
fi
VERSION="${VERSION#v}"
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
	printf 'Invalid version: %s\n' "$VERSION" >&2
	exit 2
}

archive="Sans_Password_Manager_v${VERSION}.zip"
base_url="https://github.com/$REPO/releases/download/$VERSION"
target_dir="${PREFIX%/}/bin"
target="$target_dir/spm"

printf 'SPM version : %s\n' "$VERSION"
printf 'Source      : %s/%s\n' "$base_url" "$archive"
printf 'Destination : %s\n' "$target"
if dir_on_path "$target_dir"; then
	printf 'PATH        : already contains %s\n' "$target_dir"
elif [ "$MODIFY_PATH" -eq 1 ]; then
	printf 'PATH        : does not contain %s (will be added)\n' "$target_dir"
else
	printf 'PATH        : does not contain %s (left alone; --no-modify-path)\n' "$target_dir"
fi
if [ "$DRY_RUN" -eq 1 ]; then
	printf 'Dry run complete; no files were downloaded, installed, or added to PATH.\n'
	exit 0
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/spm-install.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT INT TERM

curl -fL "$base_url/$archive" -o "$workdir/$archive"
curl -fL "$base_url/$archive.sha256" -o "$workdir/$archive.sha256"
expected="$(awk 'NR==1{print $1}' "$workdir/$archive.sha256")"
printf '%s' "$expected" | grep -Eq '^[a-fA-F0-9]{64}$' || {
	printf 'Release checksum file is invalid.\n' >&2
	exit 1
}
actual="$(sha256sum "$workdir/$archive" | awk '{print $1}')"
[ "$expected" = "$actual" ] || {
	printf 'SHA-256 verification failed. Installation aborted.\n' >&2
	exit 1
}

mkdir -p "$workdir/extract"
unzip -q "$workdir/$archive" -d "$workdir/extract"
candidate="$workdir/extract/spm.sh"
[ -f "$candidate" ] || { printf 'Verified archive does not contain spm.sh.\n' >&2; exit 1; }
bash -n "$candidate"

if [ -w "$PREFIX" ] || { [ -d "$target_dir" ] && [ -w "$target_dir" ]; }; then
	install -d -m 0755 "$target_dir"
	install -m 0755 "$candidate" "$target"
elif command -v sudo >/dev/null 2>&1; then
	sudo install -d -m 0755 "$target_dir"
	sudo install -m 0755 "$candidate" "$target"
else
	printf 'Cannot write to %s and sudo is unavailable. Use --prefix with a writable directory.\n' "$target_dir" >&2
	exit 1
fi

installed="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' "$target")"
[ "$installed" = "$VERSION" ] || { printf 'Installed version verification failed.\n' >&2; exit 1; }
printf 'Installed SPM %s at %s\n' "$installed" "$target"
ensure_on_path "$target_dir"

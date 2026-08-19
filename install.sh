#!/usr/bin/env bash
set -euo pipefail

REPO="sansyourways/Sans_Password_Manager"
VERSION="latest"
PREFIX="${SPM_INSTALL_PREFIX:-/usr/local}"
DRY_RUN=0

usage() {
	cat <<'EOF'
Usage: ./install.sh [--version X.Y.Z] [--prefix DIRECTORY] [--dry-run]

Downloads an official SPM release ZIP and its matching SHA-256 file, verifies
the archive, validates spm.sh syntax, and installs the CLI as PREFIX/bin/spm.
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
		-h|--help) usage; exit 0 ;;
		*) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

for command_name in curl sha256sum unzip bash mktemp; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf "Required command '%s' is not installed.\n" "$command_name" >&2
		exit 1
	}
done

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
if [ "$DRY_RUN" -eq 1 ]; then
	printf 'Dry run complete; no files were downloaded or installed.\n'
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

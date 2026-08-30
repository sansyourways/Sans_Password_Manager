#!/usr/bin/env bash
# Build an installable Termux package.
#
# Termux uses apt, so the unit of distribution is a .deb. This builds one with
# ar and tar rather than dpkg-deb, because the machine that cuts a release is
# not a Debian machine and adding dpkg to the release job to produce a file
# whose format is three tar archives in an ar container is not a trade worth
# making.
#
# Reproducible for the same reason release-archive.sh is: same commit, same
# bytes, so the published checksum is one a third party can arrive at.
#
# Usage: build-deb.sh [version] [output-directory]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

# The output directory is resolved to an absolute path here, before anything
# changes directory, so a relative one means what the caller meant: relative to
# where they ran this. Two directory changes happen below -- into ROOT_DIR to
# read the tree, and into the staging area to assemble the archives -- and a
# relative path silently meant something different in each. That is why
# `build-deb.sh 3.12.0 dist` failed in CI while every local run, which passed
# an absolute path, worked.
out_dir="${2:-$ROOT_DIR}"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"

cd "$ROOT_DIR"

version="${1:-}"
[ -n "$version" ] || version="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' spm.sh)"
[ -n "$version" ] || { printf 'build-deb: no version\n' >&2; exit 1; }

# Termux installs under a prefix that is not /usr. Hard-coding /data/data/...
# would break on a device with a different install root, so it is read from the
# environment when present and defaulted otherwise.
prefix="${TERMUX_PREFIX:-/data/data/com.termux/files/usr}"

# GNU tar, explicitly. The reproducibility here rests on --mtime, --owner,
# --group, --numeric-owner and --no-recursion, and bsdtar -- which is what
# macOS ships as `tar` -- either spells those differently or lacks them. It
# would still produce a .deb, just not the same one twice, which is the whole
# point. Refusing beats emitting a package that looks fine and is not.
tar_cmd="tar"
if ! tar --version 2>/dev/null | head -1 | grep -q 'GNU tar'; then
	if command -v gtar >/dev/null 2>&1 && gtar --version 2>/dev/null | head -1 | grep -q 'GNU tar'; then
		tar_cmd="gtar"
	else
		printf 'build-deb: GNU tar is required (install gnu-tar, or build on Linux).\n' >&2
		exit 3
	fi
fi
# GNU ar, for the same reason as GNU tar. The `D` in `ar rD` is a GNU flag
# that zeroes the member timestamps, uid and gid; BSD ar -- which is what macOS
# ships -- rejects it outright and prints its usage. Presence was not enough to
# check: the macOS runner has both `gtar` and an `ar`, so a check for "is there
# an ar" passed and the build then failed on the flag.
ar_cmd=""
for candidate in ar gar; do
	if command -v "$candidate" >/dev/null 2>&1 \
		&& "$candidate" --version 2>/dev/null | head -1 | grep -q 'GNU ar'; then
		ar_cmd="$candidate"
		break
	fi
done
[ -n "$ar_cmd" ] || {
	printf 'build-deb: GNU ar is required (it is in binutils; build on Linux).\n' >&2
	exit 3
}

stage="$(mktemp -d "${TMPDIR:-/tmp}/spm-deb.XXXXXX")"
trap 'rm -rf "$stage"' EXIT INT TERM

# Every timestamp comes from the commit, not the clock.
stamp="$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd \
	2>/dev/null || true)"
[ -n "$stamp" ] || stamp="2020-01-01T00:00:00Z"
epoch="$(TZ=UTC date -u -d "$stamp" +%s 2>/dev/null \
	|| TZ=UTC date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$stamp" +%s)"

install -d -m 0755 "$stage/data${prefix}/bin"
install -m 0755 spm.sh "$stage/data${prefix}/bin/spm"
install -d -m 0755 "$stage/data${prefix}/share/doc/spm"
install -m 0644 README.md CHANGELOG.md ROADMAP.md LICENSE \
	"$stage/data${prefix}/share/doc/spm/"

installed_kb="$(du -sk "$stage/data" | awk '{print $1}')"

mkdir -p "$stage/control"
cat > "$stage/control/control" <<CONTROL
Package: spm
Version: $version
Architecture: all
Maintainer: Sans Password Manager <team@silentprotocol.top>
Installed-Size: $installed_kb
Depends: bash, gnupg, python
Recommends: termux-api
Section: utils
Priority: optional
Homepage: https://github.com/sansyourways/Sans_Password_Manager
Description: Single-file encrypted password manager
 SPM keeps passwords, notes, passphrases, backup codes and TOTP
 authenticators in a GnuPG-encrypted vault, with a command line
 interface and an optional local web dashboard.
CONTROL

# Architecture: all is honest here -- spm is a shell script and a Python
# module, with nothing compiled. A per-arch package would be three identical
# files under different names.

( cd "$stage/data" && find . -type f -o -type d | LC_ALL=C sort \
	| "$tar_cmd" --format=gnu --mtime="@$epoch" --owner=0 --group=0 \
	      --numeric-owner --no-recursion -T - -czf "$stage/data.tar.gz" 2>/dev/null )
( cd "$stage/control" && "$tar_cmd" --format=gnu --mtime="@$epoch" \
	--owner=0 --group=0 --numeric-owner -czf "$stage/control.tar.gz" . )
printf '2.0\n' > "$stage/debian-binary"

deb="$out_dir/spm_${version}_all.deb"
rm -f "$deb"
( cd "$stage" && "$ar_cmd" rD "$deb" debian-binary control.tar.gz data.tar.gz )
printf '%s\n' "$deb"

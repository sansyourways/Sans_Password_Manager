#!/usr/bin/env bash
# Build the release archive, deterministically.
#
# Two runs of this script over the same commit must produce the same bytes.
# That is what lets a third party rebuild a release and compare its checksum
# against the published one, rather than trusting that the checksum beside a
# download came from the source it claims to.
#
# zip stores a modification time and a directory order for every entry, and
# both vary between checkouts. The order is pinned by sorting the file list,
# and the times by stamping every file with the commit date -- so the archive
# is a function of the commit, not of when the machine happened to unpack it.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT_DIR"

# macOS has shasum, not sha256sum. The suite runs on both, and a release
# script that only works on the runner it happened to be written on is the
# kind of thing that fails once, publicly, at tag time.
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1"
	else
		shasum -a 256 "$1"
	fi
}

sha256_check() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c "$1"
	else
		shasum -a 256 -c "$1"
	fi
}

version="${1:-}"
if [ -z "$version" ]; then
	version="$(sed -n 's/^VERSION="\([^"]*\)"/\1/p' spm.sh)"
fi
[ -n "$version" ] || { printf 'release-archive: no version to build\n' >&2; exit 1; }

archive="Sans_Password_Manager_v${version}.zip"
rm -f -- "$archive" "$archive.sha256"

# src/ and build.sh ship with the archive so anyone holding a release can run
# `./build.sh --check` and confirm the spm.sh they were given is exactly what
# these sources produce.
paths=(
	spm.sh install.sh build.sh
	README.md ROADMAP.md CHANGELOG.md CONTRIBUTING.md LICENSE NOTICE DCO
	src docs browser-extension browser-extension-universal tests
	.github/PULL_REQUEST_TEMPLATE.md .github/ISSUE_TEMPLATE
)

# A template, not a bare mktemp: BSD mktemp requires one.
listing="$(mktemp "${TMPDIR:-/tmp}/spm-archive.XXXXXX")"
stage=""
trap 'rm -f "$listing"; [ -n "$stage" ] && rm -rf "$stage"' EXIT INT TERM
find "${paths[@]}" -type f \
	! -name '*.bak' ! -path '*/dist/*' ! -path '*/__pycache__/*' \
	| LC_ALL=C sort > "$listing"
[ -s "$listing" ] || { printf 'release-archive: nothing to archive\n' >&2; exit 1; }

# The stamp every entry gets, in order of authority: an explicit
# SOURCE_DATE_EPOCH (the reproducible-builds convention, and what lets a
# rebuild outside a git checkout still match), then the commit date, then a
# fixed epoch so the script still produces the same bytes twice from a bare
# tarball. Written as UTC with a trailing Z rather than an offset: BSD touch,
# which is what the macOS runner has, rejects the +hh:mm form GNU accepts.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	printf '%s' "$SOURCE_DATE_EPOCH" | grep -Eq '^[0-9]+$' || {
		printf 'release-archive: SOURCE_DATE_EPOCH is not a number\n' >&2
		exit 2
	}
	# GNU date takes -d @SECONDS; BSD date takes -r SECONDS.
	stamp="$(TZ=UTC date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
		|| TZ=UTC date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
else
	stamp="$(TZ=UTC git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd \
		2>/dev/null || true)"
fi
[ -n "$stamp" ] || stamp="2020-01-01T00:00:00Z"
# Staged into a copy rather than stamped in place. Rewriting every mtime in the
# working tree would be a surprising thing for a build to do to someone's
# checkout, and it is self-defeating besides: once the sources carry the commit
# time, dropping the stamping step stops changing the output and a test can no
# longer tell whether it happens at all.
stage="$(mktemp -d "${TMPDIR:-/tmp}/spm-stage.XXXXXX")"
trap 'rm -f "$listing"; rm -rf "$stage"' EXIT INT TERM
tar -cf - -T "$listing" | tar -xf - -C "$stage"

# -0 rather than -d: BSD xargs has no -d. No path here contains a newline, and
# the listing is built by find, so NUL separation is exact either way.
(cd "$stage" && tr '\n' '\0' < "$listing" | TZ=UTC xargs -0 touch -h -d "$stamp")

# -X drops uid, gid and the extended timestamp field, which differ per machine.
(cd "$stage" && TZ=UTC zip -q -X -9 "$archive" -@ < "$listing")
mv "$stage/$archive" "$archive"
sha256_of "$archive" > "$archive.sha256"
unzip -t "$archive" >/dev/null
sha256_check "$archive.sha256" >/dev/null
printf '%s\n' "$archive"

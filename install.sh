#!/usr/bin/env bash
set -euo pipefail

REPO="sansyourways/Sans_Password_Manager"
VERSION="latest"
# The first release whose archive carries a build attestation. Anything older
# genuinely has nothing to verify, and treating that as a failure would make
# the installer refuse releases that were fine when they were made.
FIRST_ATTESTED_VERSION="3.9.0"
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

Where the GitHub CLI is installed and signed in, the archive's build
attestation is also checked, which is what proves the file came from this
repository's release workflow rather than only that it arrived intact.

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

# Numeric, component-by-component. sort -V is not portable and a string
# compare puts 3.10.0 before 3.9.0, which would silently skip verification on
# every release after this one.
version_at_least() {
	awk -v a="$1" -v b="$2" '
	BEGIN {
		na = split(a, x, "."); nb = split(b, y, ".")
		n = (na > nb) ? na : nb
		for (i = 1; i <= n; i++) {
			p = (i <= na) ? x[i] + 0 : 0
			q = (i <= nb) ? y[i] + 0 : 0
			if (p > q) { print 1; exit }
			if (p < q) { print 0; exit }
		}
		print 1
	}'
}

# A checksum published next to a download proves the transfer was intact and
# nothing more: whoever can write one file can write the other. The
# attestation is a signed statement from GitHub that this exact archive was
# built by this repository's release workflow.
#
# It is checked when it can be, and the reason is stated when it cannot, so
# nobody reads "installed" as "verified" when no verification happened. A
# release that should carry an attestation and fails the check aborts.
verify_provenance() {
	local archive_path="$1" version="$2"
	if [ "$(version_at_least "$version" "$FIRST_ATTESTED_VERSION")" != "1" ]; then
		printf 'Provenance  : %s predates build attestations; checksum only\n' "$version"
		return 0
	fi
	if ! command -v gh >/dev/null 2>&1; then
		printf 'Provenance  : not checked (the GitHub CLI is not installed)\n'
		return 0
	fi
	# `gh attestation` arrived in gh 2.49. Older builds are still perfectly
	# good GitHub CLIs -- Debian stable ships 2.23 -- and treating "this
	# command does not exist" as "this archive is forged" would refuse an
	# install for a reason that has nothing to do with the archive.
	if ! gh attestation verify --help >/dev/null 2>&1; then
		printf 'Provenance  : not checked (this GitHub CLI is too old; needs 2.49+)\n'
		return 0
	fi
	if ! gh auth status >/dev/null 2>&1; then
		printf 'Provenance  : not checked (the GitHub CLI is not signed in)\n'
		return 0
	fi
	# --repo alone says "some workflow in this repository attested these bytes".
	# Only release.yml is supposed to mint one -- it is the sole workflow with
	# attestations: write -- but that is a one-line change away from being
	# untrue, and the installer should not depend on a permission staying where
	# it is. Pin the workflow where gh can.
	# `case`, not grep: the installer declares curl, sha256sum, unzip, bash and
	# mktemp as its dependencies and should not quietly grow a sixth for a
	# capability probe. Pattern matching is a shell builtin and works on the
	# minimal PATH the tests deliberately run this under.
	gh_help="$(gh attestation verify --help 2>&1 || true)"
	case "$gh_help" in
	*--signer-workflow*)
		if gh attestation verify "$archive_path" --repo "$REPO" \
			--signer-workflow "$REPO/.github/workflows/release.yml" >/dev/null 2>&1; then
			printf 'Provenance  : attestation verified against %s (release.yml)\n' "$REPO"
			return 0
		fi
		;;
	*)
		if gh attestation verify "$archive_path" --repo "$REPO" >/dev/null 2>&1; then
			# Said out loud rather than skipped quietly: a weaker check that
			# reads like the stronger one is worse than no check, because it
			# is trusted.
			printf 'Provenance  : attestation verified against %s; this gh cannot pin\n' "$REPO"
			printf '              the signing workflow (needs a newer GitHub CLI)\n'
			return 0
		fi
		;;
	esac
	printf 'Provenance verification failed: %s does not carry a valid build\n' "$archive" >&2
	printf 'attestation from %s. Installation aborted.\n' "$REPO" >&2
	return 1
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

# The tag and the version are not the same string, and assuming they were made
# every download 404. Releases through 2.9.6 were tagged bare ("2.9.6");
# everything from 2.10.11 onward is tagged with a leading "v". The archive
# inside a release is always Sans_Password_Manager_v<version>.zip, so the "v"
# has to be stripped for the filename and the version check above -- but the
# stripped value was then reused as the tag, so "--version 2.11.2" asked for a
# tag named 2.11.2 that does not exist, and the default "latest" path resolved
# tag_name to "v2.11.2" only to strip it back off again.
#
# Ask which tag actually exists instead of guessing.
release_tag() {
	local candidate
	for candidate in "v$1" "$1"; do
		if curl -fsSL -o /dev/null --head \
			"https://github.com/$REPO/releases/download/$candidate/$archive" 2>/dev/null; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	return 1
}

RELEASE_TAG="$(release_tag "$VERSION" || true)"
if [ -z "$RELEASE_TAG" ]; then
	if [ "$DRY_RUN" -eq 1 ]; then
		# A dry run must still describe the plan when the network is
		# unavailable; it downloads nothing either way.
		RELEASE_TAG="v$VERSION"
	else
		printf 'No release asset found for %s (tried tags v%s and %s).\n' \
			"$VERSION" "$VERSION" "$VERSION" >&2
		exit 1
	fi
fi
base_url="https://github.com/$REPO/releases/download/$RELEASE_TAG"
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

verify_provenance "$workdir/$archive" "$VERSION" || exit 1

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

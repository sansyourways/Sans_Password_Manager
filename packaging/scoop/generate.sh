#!/usr/bin/env bash
# Generate the Scoop manifest for a published release.
#
# Generated rather than checked in, for the same reason as the Homebrew formula:
# the manifest carries the sha256 of an archive that does not exist until the
# release is published.
#
# Usage: generate.sh <version> [sha256]
# With no sha256 the published checksum file is fetched.
set -euo pipefail

REPO="sansyourways/Sans_Password_Manager"
version="${1:-}"
[ -n "$version" ] || { printf 'usage: generate.sh <version> [sha256]\n' >&2; exit 2; }
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
	printf 'generate.sh: %s is not a version\n' "$version" >&2; exit 2; }

archive="Sans_Password_Manager_v${version}.zip"
url="https://github.com/$REPO/releases/download/v${version}/${archive}"

sha="${2:-}"
if [ -z "$sha" ]; then
	sha="$(curl -fsSL "$url.sha256" | awk 'NR==1{print $1}')"
fi
printf '%s' "$sha" | grep -Eq '^[a-f0-9]{64}$' || {
	printf 'generate.sh: %s is not a sha256\n' "$sha" >&2; exit 1; }

# Scoop hashes are upper- or lower-case hex; keep the published lower-case form.
cat <<MANIFEST
{
  "version": "$version",
  "description": "Single-file encrypted password manager with a CLI and a local dashboard",
  "homepage": "https://github.com/$REPO",
  "license": "MIT",
  "url": "$url",
  "hash": "$sha",
  "bin": [["spm.sh", "spm"]],
  "suggest": {
    "Git (provides the bash SPM runs under)": "git",
    "Python (local dashboard and record engine)": "python"
  },
  "notes": [
    "SPM is a bash program: run it under Git Bash or WSL.",
    "The release ships spm.sh together with the src/ it was built from."
  ],
  "checkver": {
    "github": "https://github.com/$REPO"
  },
  "autoupdate": {
    "url": "https://github.com/$REPO/releases/download/v\$version/Sans_Password_Manager_v\$version.zip",
    "hash": {
      "url": "\$url.sha256"
    }
  }
}
MANIFEST

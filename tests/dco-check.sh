#!/usr/bin/env bash
set -euo pipefail

base_sha="${1:-}"
head_sha="${2:-HEAD}"

if [ -z "$base_sha" ] || ! git cat-file -e "$base_sha^{commit}" 2>/dev/null; then
	printf 'A valid base commit is required for the DCO check.\n' >&2
	exit 2
fi
if ! git cat-file -e "$head_sha^{commit}" 2>/dev/null; then
	printf 'The requested head commit is not available.\n' >&2
	exit 2
fi

failed=0
count=0
while IFS= read -r commit_sha; do
	[ -n "$commit_sha" ] || continue
	count=$((count + 1))
	if ! git show -s --format=%B "$commit_sha" |
		grep -Eiq '^Signed-off-by: .+ <[^>]+>[[:space:]]*$'; then
		printf 'Missing DCO sign-off: %s %s\n' \
			"${commit_sha:0:12}" "$(git show -s --format=%s "$commit_sha")" >&2
		failed=1
	fi
done < <(git rev-list --reverse "$base_sha..$head_sha")

if [ "$count" -eq 0 ]; then
	printf 'No commits were found in the requested range.\n' >&2
	exit 2
fi
if [ "$failed" -ne 0 ]; then
	printf 'Add a sign-off with: git commit --signoff\n' >&2
	exit 1
fi

printf 'DCO sign-offs verified for %s commit(s).\n' "$count"

#!/usr/bin/env bash
# Assemble spm.sh from the sources in src/.
#
# SPM ships as one file, because a password manager you install by copying a
# single script is a password manager people actually install. It is not
# *written* as one file: the trusted core and the dashboard are real Python
# modules that a linter, a type checker and an editor can all understand, and
# this script pastes them into the shell script that carries them.
#
#   build.sh          regenerate spm.sh
#   build.sh --check  fail if spm.sh is not what src/ would produce
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${root_dir}/src/spm.sh.in"
target="${root_dir}/spm.sh"

check_only=0
case "${1:-}" in
	--check) check_only=1 ;;
	"") ;;
	*) echo "usage: build.sh [--check]" >&2; exit 2 ;;
esac

[ -f "$template" ] || { echo "build: missing $template" >&2; exit 1; }

staged="$(mktemp "${TMPDIR:-/tmp}/spm-build.XXXXXX")"
trap 'rm -f "$staged"' EXIT

# Substitute every `@@INCLUDE <path>@@` line with that file's contents.
#
# The included files land inside quoted heredocs, so the shell never expands
# them -- but a line in the payload identical to the heredoc terminator would
# end the heredoc early and produce a broken script that still parses. Refuse
# that outright rather than ship it.
python3 - "$template" "$root_dir" >"$staged" <<'PY'
import re
import sys

template, root = sys.argv[1], sys.argv[2]
include = re.compile(r"^@@INCLUDE (.+)@@$")
terminator = re.compile(r"<<-?'([A-Za-z_][A-Za-z0-9_]*)'")

out = []
pending = None  # heredoc terminator we are currently inside
for lineno, line in enumerate(open(template, encoding="utf-8").read().split("\n"), 1):
    if pending is not None and line == pending:
        pending = None
    elif pending is None:
        found = terminator.search(line)
        if found:
            pending = found.group(1)

    match = include.match(line)
    if not match:
        out.append(line)
        continue
    path = f"{root}/{match.group(1)}"
    try:
        body = open(path, encoding="utf-8").read()
    except OSError as exc:
        sys.exit(f"build: {template}:{lineno}: {exc}")
    body = body[:-1] if body.endswith("\n") else body
    rows = body.split("\n")
    if pending is not None and pending in rows:
        sys.exit(
            f"build: {match.group(1)} contains a line equal to the heredoc "
            f"terminator {pending!r}, which would truncate the generated script"
        )
    out.extend(rows)

sys.stdout.write("\n".join(out))
PY

if [ "$check_only" -eq 1 ]; then
	if cmp -s "$staged" "$target"; then
		echo "spm.sh is current with src/."
		exit 0
	fi
	echo "spm.sh is stale: it does not match what src/ produces." >&2
	echo "Run ./build.sh and commit the result." >&2
	diff -u "$target" "$staged" | head -40 >&2 || true
	exit 1
fi

cat "$staged" >"$target"
chmod +x "$target"
echo "Wrote $target ($(wc -l <"$target") lines)."

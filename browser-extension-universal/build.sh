#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
TARGET="${1:-chromium}"
case "$TARGET" in chromium|firefox) ;; *) printf 'Usage: %s chromium|firefox\n' "$0" >&2; exit 2 ;; esac
OUT="$ROOT_DIR/dist/$TARGET"
mkdir -p "$OUT"
cp "$ROOT_DIR/manifest.$TARGET.json" "$OUT/manifest.json"
cp "$ROOT_DIR/background.js" "$ROOT_DIR/popup.html" "$ROOT_DIR/popup.js" "$ROOT_DIR/fill.js" "$OUT/"
printf '%s\n' "$OUT"

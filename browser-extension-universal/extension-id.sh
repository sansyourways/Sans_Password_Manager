#!/usr/bin/env bash
# Print the Chromium extension ID the browser will assign to the unpacked build.
#
# Chrome derives an unpacked extension's ID from the manifest's public key: the
# first 16 bytes of its SHA-256, hex-mapped onto a-p. Deriving it here the same
# way means the native-host registration is computed from the identity the
# browser actually uses, so the two cannot drift. A hardcoded copy in each
# script could.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

python3 - "$ROOT_DIR/manifest.chromium.json" <<'PY'
import base64
import hashlib
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    key = json.load(handle)["key"]
digest = hashlib.sha256(base64.b64decode(key, validate=True)).hexdigest()[:32]
sys.stdout.write("".join(chr(ord("a") + int(c, 16)) for c in digest))
PY

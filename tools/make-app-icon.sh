#!/usr/bin/env bash
# Render the SPM Dashboard app icon (apple-touch-icon / PWA) and print it as base64.
#
# The artwork is the login page brand mark, reproduced from the CSS rather than
# redrawn by eye:
#
#   .login-brand .brand-mark  52x52, border-radius 14px      (spm.sh DESIGN_CSS)
#   Console .brand-mark       1px solid #5fd095, transparent (spm.sh DESIGN_CSS)
#   .brand-mark .icon         24x24, stroke-width 1.75       (spm.sh DESIGN_CSS)
#   #i-brand                  M4 6l5 6-5 6M12 18h8M12 6h8    (spm.sh ICON_SPRITE)
#
# The mark is drawn at 70% of the canvas on the page background (#0a0e0c). The
# padding is not decoration: iOS masks home screen icons with a superellipse, so
# a mark drawn edge to edge loses its green border at the corners. The same
# padding satisfies the Android maskable safe zone, so one asset serves both.
#
# Paste the output into APP_ICON_PNG_B64 in spm.sh.
#
# Usage: tools/make-app-icon.sh [output.png]
set -o errexit -o nounset -o pipefail

readonly SIDE=512      # canvas
readonly TILE=360      # brand mark box, 70% of the canvas
readonly BG="#0a0e0c"  # --bg
readonly FG="#5fd095"  # --accent

# Ratios taken straight from the CSS above, scaled by TILE/52. SVG centres
# strokes on the path, so the tile rect is inset by half its stroke width.
SCALE="$(awk -v t="$TILE" 'BEGIN{printf "%.6f", t/52}')"
STROKE="$(awk -v s="$SCALE" 'BEGIN{printf "%.4f", 1*s}')"    # 1px border
RADIUS="$(awk -v s="$SCALE" 'BEGIN{printf "%.4f", 14*s}')"   # 14px radius
INSET="$(awk -v n="$SIDE" -v t="$TILE" -v w="$STROKE" 'BEGIN{printf "%.4f", (n-t)/2 + w/2}')"
BOX="$(awk -v t="$TILE" -v w="$STROKE" 'BEGIN{printf "%.4f", t-w}')"
GLYPH="$(awk -v n="$SIDE" -v s="$SCALE" 'BEGIN{printf "%.4f", (n - 24*s)/2}')"
readonly SCALE STROKE RADIUS INSET BOX GLYPH

out="${1:-app-icon.png}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/icon.svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="$SIDE" height="$SIDE" viewBox="0 0 $SIDE $SIDE">
  <rect width="$SIDE" height="$SIDE" fill="$BG"/>
  <rect x="$INSET" y="$INSET" width="$BOX" height="$BOX" rx="$RADIUS"
        fill="none" stroke="$FG" stroke-width="$STROKE"/>
  <g transform="translate($GLYPH $GLYPH) scale($SCALE)"
     fill="none" stroke="$FG" stroke-width="1.75"
     stroke-linecap="butt" stroke-linejoin="miter">
    <path d="M4 6l5 6-5 6M12 18h8M12 6h8"/>
  </g>
</svg>
SVG

# Chromium is the only trustworthy SVG rasteriser present here; rsvg-convert and
# inkscape are absent and ImageMagick's internal MSVG renderer mangles strokes.
chromium --headless --disable-gpu --hide-scrollbars \
	--force-device-scale-factor=1 --window-size="$SIDE,$SIDE" \
	--user-data-dir="$tmp/chrome" \
	--screenshot="$tmp/raw.png" "file://$tmp/icon.svg" >/dev/null 2>&1

# Flat art, so palette quantisation is lossless in practice; -strip drops
# metadata so the embedded blob stays small and reproducible.
convert "$tmp/raw.png" -strip -colors 16 "$out"

printf 'wrote %s (%s bytes)\n' "$out" "$(stat -c%s "$out")" >&2
base64 -w0 "$out"
printf '\n'

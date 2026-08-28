#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
CHROMIUM_ID="infdncbkefpjncplegccokcfpiicadlo"
BROWSER="auto"
OPEN_BROWSER=1

usage() {
	cat <<'EOF'
Usage: ./browser-extension-universal/setup.sh [options]

Builds the extension, registers its native host, detects a browser, and opens
the final browser installation page.

Options:
  --browser NAME  auto, chrome, chromium, edge, brave, vivaldi, opera, firefox
  --no-open       prepare everything without opening browser or file-manager windows
  -h, --help      show this help
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--browser) [ $# -ge 2 ] || { printf 'Missing browser name.\n' >&2; exit 2; }; BROWSER="$2"; shift 2 ;;
		--no-open) OPEN_BROWSER=0; shift ;;
		-h|--help) usage; exit 0 ;;
		*) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

case "$BROWSER" in auto|chrome|chromium|edge|brave|vivaldi|opera|firefox) ;; *) printf 'Unsupported browser: %s\n' "$BROWSER" >&2; exit 2 ;; esac
case "$(uname -s)" in Linux|Darwin) ;; *) printf 'Guided setup currently supports Linux and macOS.\n' >&2; exit 1 ;; esac

detect_linux_browser() {
	for candidate in google-chrome google-chrome-stable chromium microsoft-edge microsoft-edge-stable brave-browser vivaldi opera firefox; do
		if command -v "$candidate" >/dev/null 2>&1; then
			case "$candidate" in google-chrome|google-chrome-stable) printf chrome ;; microsoft-edge|microsoft-edge-stable) printf edge ;; brave-browser) printf brave ;; *) printf '%s' "$candidate" ;; esac
			return
		fi
	done
}

detect_macos_browser() {
	for entry in 'chrome:Google Chrome' 'chromium:Chromium' 'edge:Microsoft Edge' 'brave:Brave Browser' 'vivaldi:Vivaldi' 'opera:Opera' 'firefox:Firefox'; do
		name="${entry%%:*}"; app="${entry#*:}"
		if [ -d "/Applications/$app.app" ] || [ -d "$HOME/Applications/$app.app" ]; then printf '%s' "$name"; return; fi
	done
}

if [ "$BROWSER" = auto ]; then
	case "$(uname -s)" in Linux) BROWSER="$(detect_linux_browser)" ;; Darwin) BROWSER="$(detect_macos_browser)" ;; esac
	[ -n "$BROWSER" ] || { printf 'No supported browser was detected. Use --browser NAME after installing one.\n' >&2; exit 1; }
fi

case "$BROWSER" in firefox) TARGET=firefox ;; *) TARGET=chromium ;; esac
DIST_DIR="$ROOT_DIR/dist/$TARGET"
printf 'Preparing Sans Password Manager for %s…\n' "$BROWSER"
bash "$ROOT_DIR/build.sh" "$TARGET" >/dev/null
bash "$ROOT_DIR/install-host.sh" "$CHROMIUM_ID" >/dev/null

printf '\nPrepared extension: %s\n' "$DIST_DIR"
printf 'Native host       : registered\n'
printf 'Stable extension ID: %s\n\n' "$CHROMIUM_ID"

if [ "$TARGET" = firefox ]; then
	printf 'Finish in Firefox:\n'
	printf '  1. Click Load Temporary Add-on.\n'
	printf '  2. Select: %s/manifest.json\n' "$DIST_DIR"
	printf '  3. Open a login page and pin the SPM toolbar button.\n'
else
	printf 'Finish in %s:\n' "$BROWSER"
	printf '  1. Enable Developer mode.\n'
	printf '  2. Click Load unpacked.\n'
	printf '  3. Select: %s\n' "$DIST_DIR"
fi

[ "$OPEN_BROWSER" -eq 1 ] || exit 0
linux_browser_command() {
	case "$1" in
		chrome) command -v google-chrome 2>/dev/null || command -v google-chrome-stable ;;
		chromium) command -v chromium ;;
		edge) command -v microsoft-edge 2>/dev/null || command -v microsoft-edge-stable ;;
		brave) command -v brave-browser ;;
		vivaldi|opera|firefox) command -v "$1" ;;
	esac
}
if [ "$(uname -s)" = Linux ]; then
	browser_bin="$(linux_browser_command "$BROWSER" || true)"
	[ -n "$browser_bin" ] || { printf '\n%s is prepared but its browser executable was not found.\n' "$BROWSER" >&2; exit 1; }
fi
case "$(uname -s):$BROWSER" in
	Linux:chrome|Linux:chromium) "$browser_bin" chrome://extensions >/dev/null 2>&1 & ;;
	Linux:edge) "$browser_bin" edge://extensions >/dev/null 2>&1 & ;;
	Linux:brave) "$browser_bin" brave://extensions >/dev/null 2>&1 & ;;
	Linux:vivaldi) "$browser_bin" vivaldi://extensions >/dev/null 2>&1 & ;;
	Linux:opera) "$browser_bin" opera://extensions >/dev/null 2>&1 & ;;
	Linux:firefox) "$browser_bin" 'about:debugging#/runtime/this-firefox' >/dev/null 2>&1 & ;;
	Darwin:chrome) open -a 'Google Chrome' 'chrome://extensions'; open "$DIST_DIR" ;;
	Darwin:chromium) open -a Chromium 'chrome://extensions'; open "$DIST_DIR" ;;
	Darwin:edge) open -a 'Microsoft Edge' 'edge://extensions'; open "$DIST_DIR" ;;
	Darwin:brave) open -a 'Brave Browser' 'brave://extensions'; open "$DIST_DIR" ;;
	Darwin:vivaldi) open -a Vivaldi 'vivaldi://extensions'; open "$DIST_DIR" ;;
	Darwin:opera) open -a Opera 'opera://extensions'; open "$DIST_DIR" ;;
	Darwin:firefox) open -a Firefox 'about:debugging#/runtime/this-firefox'; open "$DIST_DIR" ;;
	*) printf '\nCould not open %s automatically; use the path printed above.\n' "$BROWSER" >&2 ;;
esac
if [ "$(uname -s)" = Linux ] && command -v xdg-open >/dev/null 2>&1; then xdg-open "$DIST_DIR" >/dev/null 2>&1 & fi

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
HOST_NAME="xyz.sansyourways.spm"
HOST_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/spm/browser-extension"
HOST_PATH="$HOST_DIR/native_host.py"
CHROMIUM_ID="${1:-}"

if [ -n "$CHROMIUM_ID" ]; then
	printf '%s' "$CHROMIUM_ID" | grep -Eq '^[a-p]{32}$' || { printf 'Invalid Chromium extension ID.\n' >&2; exit 2; }
fi
mkdir -p "$HOST_DIR"
install -m 700 "$ROOT_DIR/native_host.py" "$HOST_PATH"

write_chromium_manifest() {
	local directory="$1"
	[ -n "$CHROMIUM_ID" ] || return 0
	mkdir -p "$directory"
	printf '{\n  "name": "%s",\n  "description": "Sans Password Manager native bridge",\n  "path": "%s",\n  "type": "stdio",\n  "allowed_origins": ["chrome-extension://%s/"]\n}\n' \
		"$HOST_NAME" "$HOST_PATH" "$CHROMIUM_ID" > "$directory/$HOST_NAME.json"
}
write_firefox_manifest() {
	local directory="$1"
	mkdir -p "$directory"
	printf '{\n  "name": "%s",\n  "description": "Sans Password Manager native bridge",\n  "path": "%s",\n  "type": "stdio",\n  "allowed_extensions": ["browser-extension@sansyourways.xyz"]\n}\n' \
		"$HOST_NAME" "$HOST_PATH" > "$directory/$HOST_NAME.json"
}

case "$(uname -s)" in
	Linux)
		for directory in \
			"$HOME/.config/google-chrome/NativeMessagingHosts" \
			"$HOME/.config/chromium/NativeMessagingHosts" \
			"$HOME/.config/microsoft-edge/NativeMessagingHosts" \
			"$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
			"$HOME/.config/vivaldi/NativeMessagingHosts" \
			"$HOME/.config/opera/NativeMessagingHosts"; do write_chromium_manifest "$directory"; done
		write_firefox_manifest "$HOME/.mozilla/native-messaging-hosts"
		;;
	Darwin)
		for directory in \
			"$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" \
			"$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts" \
			"$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts" \
			"$HOME/Library/Application Support/Vivaldi/NativeMessagingHosts" \
			"$HOME/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts"; do write_chromium_manifest "$directory"; done
		write_firefox_manifest "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
		;;
	*) printf 'Automatic native-host installation supports Linux and macOS.\n' >&2; exit 1 ;;
esac
printf 'Installed %s. Fully restart the browser before testing.\n' "$HOST_NAME"
[ -n "$CHROMIUM_ID" ] || printf 'Firefox registered. Pass a Chromium extension ID to register Chromium-family browsers too.\n'

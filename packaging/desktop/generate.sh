#!/usr/bin/env bash
# Generate the desktop-integration launchers for `spm desktop` (roadmap 41).
#
# No packaged runtime: these just launch `spm desktop`, which brings up the local
# dashboard and opens it in the OS browser. Emitted per release so the version in
# them is the one shipping. Usage: generate.sh <version> [outdir] (default: .)
set -euo pipefail

version="${1:-}"
outdir="${2:-.}"
[ -n "$version" ] || { printf 'usage: generate.sh <version> [outdir]\n' >&2; exit 2; }
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || {
	printf 'generate.sh: %s is not a version\n' "$version" >&2; exit 2; }
mkdir -p "$outdir"

# Linux: a freedesktop .desktop entry. Installed to ~/.local/share/applications
# (by install.sh) so SPM appears in the application menu.
cat > "$outdir/spm.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Sans Password Manager
GenericName=Password Manager
Comment=Open the local SPM Dashboard
Exec=spm desktop
Icon=spm
Terminal=true
Categories=Utility;Security;
Keywords=password;vault;spm;
X-SPM-Version=$version
DESKTOP

# macOS: a double-clickable .command that runs the launcher in Terminal.
cat > "$outdir/spm-desktop.command" <<'COMMAND'
#!/bin/sh
# Sans Password Manager desktop launcher (macOS). Double-click to open the
# dashboard; close the Terminal window or press Ctrl-C to stop it.
exec spm desktop
COMMAND
chmod +x "$outdir/spm-desktop.command"

# Windows: a .cmd that runs the launcher under the available bash (Git-Bash or
# WSL), matching the packaging/windows shim.
cat > "$outdir/spm-desktop.cmd" <<'CMD'
@echo off
REM Sans Password Manager desktop launcher (Windows). Runs `spm desktop` under
REM Git-Bash or WSL, whichever is present.
where bash >nul 2>nul && ( bash -lc "spm desktop" & goto :eof )
where wsl  >nul 2>nul && ( wsl spm desktop & goto :eof )
echo Could not find bash or wsl. Install Git for Windows or WSL, then run: spm desktop
pause
CMD

printf 'wrote spm.desktop, spm-desktop.command, spm-desktop.cmd to %s (v%s)\n' "$outdir" "$version"

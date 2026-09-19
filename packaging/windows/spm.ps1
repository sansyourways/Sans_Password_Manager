# Sans Password Manager launcher shim for PowerShell (roadmap 42).
# SPM is a bash program; this runs it under Git-Bash or WSL, forwarding args.
# Put this on your PATH (or dot-source a function) as `spm`.
$ErrorActionPreference = "Stop"
if (Get-Command bash -ErrorAction SilentlyContinue) {
    & bash -lc "spm $($args -join ' ')"
} elseif (Get-Command wsl -ErrorAction SilentlyContinue) {
    & wsl spm @args
} else {
    Write-Error "Sans Password Manager needs bash. Install Git for Windows (Git-Bash) or WSL, then re-run."
    exit 1
}

@echo off
REM Sans Password Manager launcher shim for Windows (roadmap 42).
REM SPM is a bash program; this runs it under Git-Bash or WSL, whichever is
REM present, forwarding all arguments. Put this on your PATH as `spm`.
setlocal
where bash >nul 2>nul && (
  bash -lc "spm \"$@\"" -- %*
  goto :eof
)
where wsl >nul 2>nul && (
  wsl spm %*
  goto :eof
)
echo Sans Password Manager needs bash. Install Git for Windows (Git-Bash) or WSL,
echo then re-run this command.
exit /b 1

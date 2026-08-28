# Sans Password Manager 2.10.5

This patch finishes the Console Web Mode refinement pass and hardens idle locking.

- Replaced the mixed emoji and text-glyph Web Mode icons with a deterministic
  inline SVG sprite on the Console 24-unit grid, using `currentColor`, square
  stroke terminals, accessible control names, and no external asset requests
- Added restrained, reduced-motion-aware motion for toast feedback, the mobile
  navigation scrim, import progress, and changed authenticator codes
- Fixed the web auto-lock refresh/navigation loop: one logout transition, the
  interval stopped before leaving, and teardown on `pagehide`
- Fixed a back/forward-cache idle-lock bypass. Timers are frozen while a page is
  cached, so the restored interval could not observe the elapsed idle time and
  the page was granted a fresh 30-second window. The surviving deadline is now
  honoured and an expired page locks immediately on restore.
- Made the `pagehide` teardown repeatable so the timer is still stopped on a
  second navigation away after a back/forward-cache round trip
- Cleared the remaining ShellCheck warning in the regression suite and added
  coverage for the icon sprite, motion tokens, and auto-lock restore path

There are no vault-format, encryption, or CLI behavior changes.

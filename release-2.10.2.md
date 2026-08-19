# Sans Password Manager 2.10.2

This patch repairs Global background Web Mode without weakening its secure
default.

- Explicit confirmation for non-loopback plain-HTTP binds
- Verified PM2 startup with visible failure diagnostics
- Correct propagation of the remote-bind approval into the web process
- Offline LAN-address discovery with no public IP lookup
- No automatic package installation or firewall mutation during web startup
- Revalidated CLI/Web import and export behavior using disposable vault data

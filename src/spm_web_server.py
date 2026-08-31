import http.server
import socketserver
import urllib.parse
import subprocess
import os
import secrets
import hmac
import html
import sys
import time
import base64
import json as jsonlib
import urllib.request
import re
import io
import email.parser
import email.policy
import warnings
import threading
import tempfile
import shutil
import fcntl
import ipaddress
import hashlib

VAULT_PATH = os.environ.get("SPM_VAULT_PATH")
BIND_ADDR  = os.environ.get("SPM_WEB_BIND", "127.0.0.1")
PORT       = int(os.environ.get("SPM_WEB_PORT", "8080"))
VERSION    = os.environ.get("SPM_VERSION", "")

def _is_loopback_bind(value):
    value = (value or "").strip().strip("[]")
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False

if not _is_loopback_bind(BIND_ADDR) and os.environ.get("SPM_WEB_ALLOW_INSECURE_REMOTE") != "1":
    raise SystemExit(
        "Refusing non-loopback plain HTTP. Bind localhost behind TLS, or explicitly "
        "set SPM_WEB_ALLOW_INSECURE_REMOTE=1 for an isolated trusted network."
    )

if not VAULT_PATH or not os.path.isfile(VAULT_PATH):
    raise SystemExit(f"Vault file not found: {VAULT_PATH!r}")

# WebAuthn relying-party id for biometric unlock. Deliberately NOT derived from
# the Host header: a header rewrite would otherwise move the relying party, and
# every credential is bound to whatever value was in force at registration. No
# id configured means the whole unlock feature stays off rather than guessing.
def _webauthn_config():
    rp = (os.environ.get("SPM_WEB_RP_ID") or "").strip().lower()
    if not rp:
        # No default is inferred, not even on loopback. The obvious guess there
        # is the bind address, but "127.0.0.1" is not a valid relying-party id
        # -- browsers require a domain -- so guessing would enable a feature
        # whose ceremony can only ever fail. Local development sets
        # SPM_WEB_RP_ID=localhost and browses to http://localhost:PORT.
        return "", ""
    # A relying-party id is a bare domain: no scheme, no port, no path.
    if not re.match(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", rp):
        return "", ""
    # An explicit origin wins, for a deployment whose public URL this cannot be
    # derived from -- a proxy on a non-default port, say.
    override = (os.environ.get("SPM_WEB_ORIGIN") or "").strip()
    if override:
        if not re.match(r"^https?://[A-Za-z0-9.\-\[\]]+(:[0-9]{1,5})?$", override):
            return "", ""
        return rp, override.rstrip("/")
    # The scheme follows the RELYING PARTY, never the bind address. SPM's
    # documented deployment binds loopback behind a TLS reverse proxy, so the
    # bind says nothing about what the browser connected to: it is 127.0.0.1
    # while the origin the browser reports is https://<public name>. Deriving
    # the scheme from the bind produced http://<public name>:<port> there and
    # every assertion failed on an origin mismatch.
    #
    # localhost is the one host a browser treats as a secure context over plain
    # HTTP, which is what makes local development and the regression suite work
    # without TLS. Everything else is https by definition -- WebAuthn will not
    # run in an insecure context, so no other answer could ever verify.
    if rp == "localhost":
        origin = "http://%s:%d" % (rp, PORT)
    else:
        origin = "https://%s" % rp
    return rp, origin

WEBAUTHN_RP_ID, WEBAUTHN_ORIGIN = _webauthn_config()
WEBAUTHN_ENABLED = bool(WEBAUTHN_RP_ID)
# How long a server-issued ceremony challenge stays usable. Long enough for a
# Face ID prompt the user has to notice, short enough to be worthless later.
WEBAUTHN_CHALLENGE_TTL = 120

LATEST_CACHE = {"value": "", "ts": 0}

SUPPORTED_WEB_LANGS = {"en", "id", "ja"}
DEFAULT_WEB_LANG = "en"

def sanitize_lang(value):
    value = (value or "").strip().lower()
    if value in SUPPORTED_WEB_LANGS:
        return value
    return DEFAULT_WEB_LANG

# str.splitlines() breaks on eleven characters; collapsing only \t \r \n let the
# other eight split a record when it was read back, dropping the entry.
_VAULT_BREAKS = "\t\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029"

def _vf(value):
    # Vault records are TAB-delimited and line-based, so any character that
    # splitlines() honours has to be collapsed before the record is written.
    text = str(value or "")
    for ch in _VAULT_BREAKS:
        text = text.replace(ch, " ")
    return text


_URL_RE = re.compile(r"^https?://[^\s/]+", re.IGNORECASE)


def _vurl(value):
    """Sanitise a URL field; None means "present but unusable".

    The scheme is an allowlist, not a denylist. This value is rendered as an
    href on the entry page and will be handed to the browser extension as a
    match target, so "javascript:" or "data:" here is code execution and an
    exfiltration path rather than merely a bad link. Empty is always valid --
    the field is optional. None is distinct from "" so the form can say why it
    rejected the input instead of silently blanking it.
    """
    text = _vf(value).strip()
    if not text:
        return ""
    return text if _URL_RE.match(text) else None

def fetch_latest_version():
    now = time.time()
    if now - LATEST_CACHE.get("ts", 0) < 300 and LATEST_CACHE.get("value"):
        return LATEST_CACHE["value"]
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/sansyourways/Sans_Password_Manager/releases/latest",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "SPM"},
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = resp.read().decode("utf-8", "ignore")
        m = re.search(r'"tag_name"\\s*:\\s*"v?([^"]+)"', data)
        if m:
            LATEST_CACHE["value"] = m.group(1)
            LATEST_CACHE["ts"] = now
            return LATEST_CACHE["value"]
    except Exception:
        pass
    return ""

# ---------- HTML templates (liquid glass, icons, auto-lock) ------------------


I18N_SCRIPT = """
<script>
(function() {
  const DICT = {
    "en": {
      "nav.security": "Security",
      "nav.history": "History",
      "nav.events": "Security Events",
      "entry.field.folder": "Folder",
      "entry.hint.folder": "Optional. Type a new name to create one.",
      "entry.field.custom": "Custom fields",
      "entry.field.custom_name": "Field name",
      "entry.field.custom_value": "Value",
      "entry.field.custom_add": "Add another field",
      "entry.hint.custom": "Anything this record needs that has no box of its own. Stored in the vault, encrypted like the password.",
      "view.label.folder": "Folder",
      "search.folder": "Folder",
      "page.events.desc": "Operations on this vault. Recorded outside the vault and holding no record names, usernames or secrets.",
      "events.when": "When (UTC)",
      "events.kind": "Event",
      "events.outcome": "Outcome",
      "events.detail": "Detail",
      "events.empty": "Nothing recorded yet.",
      "events.empty_sub": "Unlocks, writes and master-password changes will appear here as they happen.",
      "nav.unlock": "Biometric Unlock",
      "page.unlock.desc": "Resume the idle lock with this device instead of your master password.",
      "unlock.registered": "Registered",
      "unlock.empty": "No device registered yet",
      "unlock.empty_sub": "Register one below, or keep using your master password",
      "unlock.field.label": "Label for this device",
      "unlock.register": "Register this device",
      "unlock.note": "The master password is still required for the first sign-in, once the session reaches its maximum age, and whenever a locked session goes unresumed for too long.",
      "unlock.title": "Vault locked",
      "unlock.sub": "Confirm with your device to continue where you left off.",
      "unlock.btn": "Unlock with biometrics",
      "unlock.fallback": "Use master password instead",
      "unlock.waiting": "Waiting for biometric confirmation...",
      "unlock.failed": "Unlock failed.",
      "unlock.nosupport": "This browser has no biometric support.",
      "register.waiting": "Waiting for the authenticator...",
      "register.failed": "Registration failed.",
      "security.sub": "What is pulling your vault score down.",
      "security.scope": "Only password entries are scored. IDs are shown; secrets never are.",
      "security.none": "Nothing to fix here.",
      "security.weak": "Weak passwords",
      "security.weak_d": "Shorter than 12 characters, or using fewer than three character classes.",
      "security.reused": "Reused passwords",
      "security.reused_d": "Each row below is one group of entries sharing a password.",
      "security.aging": "Due for rotation",
      "security.aging_d": "Older than the rotation threshold:",
      "security.incomplete": "Missing details",
      "security.incomplete_d": "No service name or no username.",
      "security.malformed": "Malformed authenticators",
      "security.malformed_d": "Missing a secret, or an algorithm SPM cannot generate codes for.",
      "security.breached": "Known breaches",
      "security.breached_d": "Matches in Pwned Passwords. Only five SHA-1 prefix characters leave this device.",
      "security.breach_check": "Check known breaches",
      "security.breach_optin": "Opt-in online check. Passwords and full hashes are never sent.",
      "security.breach_unavailable": "The breach service is unavailable. No clean result is assumed.",
      "page.history.desc": "Encrypted vault snapshots kept before each change.",
      "history.when": "When",
      "history.size": "Size",
      "history.name": "Snapshot",
      "history.newest": "newest",
      "btn.restore": "Restore",
      "confirm.restore_snapshot": "Restore this snapshot? The current vault is archived first.",
      "empty.history.t": "No snapshots yet",
      "empty.history.d": "SPM archives the vault before each change.",
      "search.title": "Search",
      "search.desc": "Look across every record type.",
      "search.kind": "Type",
      "empty.search.t": "Nothing found",
      "empty.search.d": "No label, name or username matches that text.",
      "badge.aging": "rotate",
      "tags.all": "All",
      "header.title": "Sans Password Manager",
      "header.subtitle": "Liquid-glass web interface · GPG encrypted",
      "header.check_update": "Check update",
      "header.logout": "Logout",
      "nav.collapse": "Collapse sidebar",
      "nav.expand": "Expand sidebar",
      "nav.open": "Menu",
      "nav.close": "Close menu",
      "header.vault": "Vault",
      "section.passwords": "Passwords",
      "chip.online": "Online · read / write",
      "btn.add_entry": "+ Add Entry",
      "table.id": "ID",
      "import.export_password": "Export password",
      "import.export_password_hint": "The password you set when exporting from Bitwarden",
      "import.export_password_note": "Only needed for a password-protected Bitwarden export. It is used to read the file and is never stored.",
      "overview.security_score": "Security score",
      "table.service": "Service",
      "table.name": "Name",
      "table.username": "Username",
      "table.actions": "Actions",
      "table.title": "Title",
      "table.label": "Label",
      "table.every": "Every",
      "table.algo": "Algo",
      "passwords.footer": "Passwords are never sent anywhere else – all crypto stays on this host with GnuPG.",
      "section.secure_notes": "Secure Notes",
      "section.secure_notes_desc": "Encrypted notes stored inside the same vault.",
      "btn.add_note": "+ Add Note",
      "section.generator": "Password Generator",
      "section.generator_desc": "Create strong passwords with length, mode, and symbol toggles.",
      "btn.open_generator": "Open Generator",
      "import.title": "Export / Import",
      "import.subtitle": "Download or paste data (csv/json + extended formats).",
      "import.format_label": "Format",
      "import.download": "Download",
      "import.import_label": "Import format",
      "import.upload_label": "Upload export file",
      "import.paste_label": "Or paste file contents",
      "import.placeholder": "Paste exported data here",
      "import.submit": "Import",
      "import.supports": "Supports passwords, notes, passphrases, authenticators, backup codes.",
      "import.overlay_upload": "Uploading...",
      "import.overlay_success": "Import complete.",
      "import.overlay_error": "Import failed.",
      "import.importing": "Importing...",
      "import.status_uploading": "Uploading...",
      "import.success_default": "Import complete.",
      "import.error_default": "Import failed.",
      "import.preview.title": "Review this import",
      "import.preview.sub": "Nothing has been written yet.",
      "import.preview.kind": "Type",
      "import.preview.confirm": "Import these records",
      "import.preview.cancel": "Cancel",
      "import.preview.back": "Back to Export / Import",
      "import.preview.secret": "Secret",
      "section.passphrases": "Passphrases",
      "section.passphrases_desc": "Store API tokens or recovery phrases. View prompts master re-check.",
      "btn.add_passphrase": "+ Add Passphrase",
      "section.authenticators": "Authenticators (TOTP)",
      "section.authenticators_desc": "Store 2FA secrets and view live codes.",
      "btn.add_authenticator": "+ Add Authenticator",
      "section.backups": "Backup Codes",
      "section.backups_desc": "Store recovery codes (view shows full codes).",
      "btn.add_backups": "+ Add Backup Codes",
      "section.session": "Web Session",
      "section.session_desc": "Protected by your master password. The interface auto-locks after 30 seconds of inactivity; the server expires an idle session after 5 minutes and any session after 12 hours.",
      "form.vault": "Vault:",
      "form.back_list": "\u2190 Back to list",
      "form.save": "Save",
      "link.back": "\u2190 Back",
      "entry.field.service": "Service / Name",
      "entry.field.username": "Username / Email",
      "entry.field.url": "URL",
      "entry.hint.url": "Used to match this entry to a site. http:// or https:// only.",
      "entry.field.password": "Password",
      "entry.field.notes": "Notes",
      "note.field.title": "Title",
      "note.field.content": "Content",
      "pass.field.label": "Label",
      "pass.field.secret_hint": "Passphrase (leave blank to auto-generate)",
      "backup.field.label": "Label",
      "backup.field.codes": "Backup codes (one per line)",
      "auth.field.label": "Label",
      "auth.field.secret": "Base32 Secret",
      "auth.field.period": "Refresh interval (seconds)",
      "auth.field.algorithm": "Algorithm",
      "auth.option.sha1": "SHA1 (default)",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "View Entry",
      "view.label.name": "Name",
      "view.label.username": "Username / Email",
      "view.label.url": "URL",
      "view.label.password": "Password",
      "view.label.notes": "Notes",
      "view.label.previous": "Previous passwords",
      "view.previous.hint": "Newest first. Recorded when the password changed; deleting this entry deletes them with it.",
      "view.label.created": "Created at",
      "view.sub_prefix": "Vault:",
      "btn.copy_username": "Copy Username",
      "btn.copy_password": "Copy Password",
      "btn.copy_notes": "Copy Notes",
      "btn.copy_passphrase": "Copy",
      "btn.copy_codes": "Copy Codes",
      "btn.copy_code": "Copy Code",
      "btn.show": "Show",
      "btn.hide": "Hide",
      "btn.edit": "Edit",
      "btn.delete": "Delete",
      "pass.view.title": "Passphrase",
      "pass.view.label_field": "Label",
      "pass.view.created": "Created",
      "pass.view.secret": "Passphrase",
      "backup.view.title": "Backup Codes",
      "backup.view.label": "Label:",
      "backup.view.created": "Created:",
      "auth.view.title": "Authenticator",
      "auth.view.label": "Label",
      "auth.view.interval": "Interval",
      "auth.view.algo": "Algorithm",
      "auth.view.created": "Created",
      "auth.view.secret": "Base32 Secret",
      "auth.view.code": "Live Code",
      "auth.view.seconds_label": "seconds",
      "generator.title": "Password Generator",
      "generator.length": "Length",
      "generator.mode_secure": "Secure",
      "generator.mode_easy": "Easy / Memorable",
      "generator.opt.upper": "Uppercase",
      "generator.opt.lower": "Lowercase",
      "generator.opt.digits": "Numbers",
      "generator.opt.symbols": "Symbols",
      "generator.btn.regen": "Regenerate",
      "generator.btn.copy": "Copy",
      "generator.btn.back": "Back",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "bits",
      "generator.stats.suffix": "to brute-force (est.)",
      "generator.words_prefix": "Words",
      "generator.strength.very_weak": "Very weak",
      "generator.strength.weak": "Weak",
      "generator.strength.moderate": "Moderate",
      "generator.strength.strong": "Strong",
      "generator.strength.excellent": "Excellent",
      "generator.unit.sec": "sec",
      "generator.unit.min": "min",
      "generator.unit.hr": "hr",
      "generator.unit.day": "day",
      "generator.unit.yr": "yr",
      "generator.unit.century": "century",
      "import.placeholder": "Paste exported data here",
      "toast.copy_success": "Copied to clipboard.",
      "toast.copy_fail": "Copy failed.",
      "auth.countdown.refresh_in": "Refreshes in {n}s",
      "auth.countdown.refreshing": "Refreshing...",
      "auth.status.no_code": "No code yet",
      "auth.status.copy_ok": "Copied!",
      "auth.status.copy_fail": "Copy failed",
      "confirm.delete_entry": "Delete this entry?",
      "confirm.delete_passphrase": "Delete this passphrase?",
      "confirm.delete_backup": "Delete these backup codes?",
      "confirm.delete_authenticator": "Delete this authenticator?",
      "nav.group.vault": "Vault",
      "nav.group.tools": "Tools",
      "nav.group.settings": "Settings",
      "nav.master_password": "Master Password",
      "page.settings.title": "Master Password",
      "page.settings.desc": "Change the password that encrypts this vault.",
      "settings.current": "Current master password",
      "settings.new": "New master password",
      "settings.confirm": "Confirm new master password",
      "settings.submit": "Change master password",
      "settings.hint": "At least 12 characters. There is no way to recover a master password you forget \u2014 only the recovery file and its private key can reset it.",
      "settings.mismatch": "The two new passwords do not match.",
      "settings.effect": "What this does",
      "settings.effect_vault": "Re-encrypts the whole vault under the new password.",
      "settings.effect_recovery": "Rewrites the recovery file so \\"spm forgot\\" keeps working.",
      "settings.effect_sessions": "Signs out every other browser session.",
      "settings.effect_backup": "Keeps the previous vault as a .bak and a history snapshot.",
      "nav.overview": "Overview",
      "nav.passwords": "Passwords",
      "nav.notes": "Secure Notes",
      "nav.passphrases": "Passphrases",
      "nav.authenticators": "Authenticators",
      "nav.backup_codes": "Backup Codes",
      "nav.generator": "Generator",
      "nav.transfer": "Export / Import",
      "search.label": "Search this vault",
      "search.placeholder": "Search this vault...",
      "search.no_results": "Nothing matches your search",
      "lock.in": "Locks in",
      "lock.paused": "Lock paused",
      "overview.sub": "Everything in your encrypted vault at a glance.",
      "overview.recent": "Recently added",
      "overview.view_all": "View all",
      "overview.console_eyebrow": "session / local vault / authenticated",
      "overview.console_records": "encrypted records indexed",
      "overview.console_gpg": "GnuPG boundary active on this host",
      "overview.console_lock": "idle lock armed for 30 seconds",
      "overview.console_lede": "Inspect, generate, and maintain credentials from one auditable session.",
      "btn.view": "View",
      "generator.mode": "Mode",
      "login.sub": "Unlock your encrypted vault to continue.",
      "login.master": "Master password",
      "login.unlock": "Unlock",
      "login.note": "All decryption happens locally with GnuPG. Nothing leaves this host.",
      "empty.vault.t": "Your vault is empty",
      "empty.vault.d": "Add your first password to get started.",
      "empty.passwords.t": "No passwords yet",
      "empty.passwords.d": "Entries you add will appear here.",
      "empty.notes.t": "No secure notes",
      "empty.notes.d": "Encrypted notes live inside the same vault.",
      "empty.passphrases.t": "No passphrases",
      "empty.passphrases.d": "Store API tokens or recovery phrases here.",
      "empty.backups.t": "No backup codes",
      "empty.backups.d": "Keep one-time recovery codes safe here.",
      "empty.auth.t": "No authenticators",
      "empty.auth.d": "Add a TOTP secret to generate 2FA codes.",
      "page.passwords.desc": "Login credentials stored in your vault.",
      "page.notes.desc": "Encrypted notes stored inside the same vault.",
      "page.passphrases.desc": "API tokens and recovery phrases.",
      "page.authenticators.desc": "Time-based one-time password codes.",
      "page.backups.desc": "One-time recovery codes for your accounts.",
    },
    "id": {
      "nav.security": "Keamanan",
      "nav.history": "Riwayat",
      "nav.events": "Peristiwa Keamanan",
      "entry.field.folder": "Folder",
      "entry.hint.folder": "Opsional. Ketik nama baru untuk membuatnya.",
      "entry.field.custom": "Bidang khusus",
      "entry.field.custom_name": "Nama bidang",
      "entry.field.custom_value": "Nilai",
      "entry.field.custom_add": "Tambah bidang lain",
      "entry.hint.custom": "Apa pun yang dibutuhkan catatan ini dan belum punya kolom sendiri. Disimpan terenkripsi seperti kata sandi.",
      "view.label.folder": "Folder",
      "search.folder": "Folder",
      "page.events.desc": "Operasi pada brankas ini. Dicatat di luar brankas dan tidak memuat nama catatan, nama pengguna, atau rahasia.",
      "events.when": "Waktu (UTC)",
      "events.kind": "Peristiwa",
      "events.outcome": "Hasil",
      "events.detail": "Rincian",
      "events.empty": "Belum ada yang tercatat.",
      "events.empty_sub": "Pembukaan, penulisan, dan perubahan kata sandi utama akan muncul di sini.",
      "nav.unlock": "Buka Biometrik",
      "page.unlock.desc": "Lanjutkan sesi terkunci dengan perangkat ini, bukan kata sandi master.",
      "unlock.registered": "Terdaftar",
      "unlock.empty": "Belum ada perangkat terdaftar",
      "unlock.empty_sub": "Daftarkan di bawah, atau tetap pakai kata sandi master",
      "unlock.field.label": "Label untuk perangkat ini",
      "unlock.register": "Daftarkan perangkat ini",
      "unlock.note": "Kata sandi master tetap diperlukan untuk masuk pertama kali, saat sesi mencapai usia maksimum, dan bila sesi terkunci terlalu lama tidak dilanjutkan.",
      "unlock.title": "Brankas terkunci",
      "unlock.sub": "Konfirmasi dengan perangkat Anda untuk melanjutkan.",
      "unlock.btn": "Buka dengan biometrik",
      "unlock.fallback": "Pakai kata sandi master saja",
      "unlock.waiting": "Menunggu konfirmasi biometrik...",
      "unlock.failed": "Gagal membuka.",
      "unlock.nosupport": "Peramban ini tidak mendukung biometrik.",
      "register.waiting": "Menunggu autentikator...",
      "register.failed": "Pendaftaran gagal.",
      "security.sub": "Hal yang menurunkan skor brankas Anda.",
      "security.scope": "Hanya entry password yang dinilai. ID ditampilkan; rahasia tidak pernah.",
      "security.none": "Tidak ada yang perlu diperbaiki.",
      "security.weak": "Password lemah",
      "security.weak_d": "Kurang dari 12 karakter, atau kurang dari tiga jenis karakter.",
      "security.reused": "Password dipakai ulang",
      "security.reused_d": "Tiap baris di bawah adalah satu grup entry dengan password sama.",
      "security.aging": "Saatnya diganti",
      "security.aging_d": "Lebih tua dari ambang rotasi:",
      "security.incomplete": "Detail belum lengkap",
      "security.incomplete_d": "Tidak ada nama layanan atau username.",
      "security.malformed": "Authenticator rusak",
      "security.malformed_d": "Secret hilang, atau algoritma tidak didukung SPM.",
      "security.breached": "Pelanggaran yang diketahui",
      "security.breached_d": "Cocok di Pwned Passwords. Hanya lima karakter awalan SHA-1 yang meninggalkan perangkat ini.",
      "security.breach_check": "Periksa pelanggaran yang diketahui",
      "security.breach_optin": "Pemeriksaan daring opsional. Password dan hash lengkap tidak pernah dikirim.",
      "security.breach_unavailable": "Layanan pemeriksaan tidak tersedia. Hasil bersih tidak diasumsikan.",
      "page.history.desc": "Snapshot brankas terenkripsi sebelum tiap perubahan.",
      "history.when": "Waktu",
      "history.size": "Ukuran",
      "history.name": "Snapshot",
      "history.newest": "terbaru",
      "btn.restore": "Pulihkan",
      "confirm.restore_snapshot": "Pulihkan snapshot ini? Brankas saat ini diarsipkan dulu.",
      "empty.history.t": "Belum ada snapshot",
      "empty.history.d": "SPM mengarsipkan brankas sebelum tiap perubahan.",
      "search.title": "Cari",
      "search.desc": "Cari di semua jenis record.",
      "search.kind": "Jenis",
      "empty.search.t": "Tidak ditemukan",
      "empty.search.d": "Tidak ada label, nama, atau username yang cocok.",
      "badge.aging": "ganti",
      "tags.all": "Semua",
      "header.title": "Sans Password Manager",
      "header.subtitle": "Antarmuka web liquid-glass · terenkripsi GPG",
      "header.check_update": "Periksa pembaruan",
      "header.logout": "Keluar",
      "nav.collapse": "Ciutkan bilah sisi",
      "nav.expand": "Bentangkan bilah sisi",
      "nav.open": "Menu",
      "nav.close": "Tutup menu",
      "header.vault": "Brankas",
      "section.passwords": "Kata Sandi",
      "chip.online": "Online · baca / tulis",
      "btn.add_entry": "+ Tambah Entri",
      "table.id": "ID",
      "import.export_password": "Kata sandi ekspor",
      "import.export_password_hint": "Kata sandi yang Anda atur saat mengekspor dari Bitwarden",
      "import.export_password_note": "Hanya diperlukan untuk ekspor Bitwarden yang dilindungi kata sandi. Dipakai untuk membaca berkas dan tidak pernah disimpan.",
      "overview.security_score": "Skor keamanan",
      "table.service": "Layanan",
      "table.name": "Nama",
      "table.username": "Pengguna",
      "table.actions": "Aksi",
      "table.title": "Judul",
      "table.label": "Label",
      "table.every": "Interval",
      "table.algo": "Algo",
      "passwords.footer": "Kata sandi tidak pernah dikirim ke mana pun — seluruh kripto tetap di host ini dengan GnuPG.",
      "section.secure_notes": "Catatan Aman",
      "section.secure_notes_desc": "Catatan terenkripsi di dalam brankas yang sama.",
      "btn.add_note": "+ Tambah Catatan",
      "section.generator": "Pembuat Kata Sandi",
      "section.generator_desc": "Buat kata sandi kuat dengan panjang, mode, dan simbol.",
      "btn.open_generator": "Buka Generator",
      "import.title": "Ekspor / Impor",
      "import.subtitle": "Unduh atau tempel data (csv/json + format lainnya).",
      "import.format_label": "Format",
      "import.download": "Unduh",
      "import.import_label": "Format impor",
      "import.upload_label": "Unggah berkas ekspor",
      "import.paste_label": "Atau tempel isi berkas",
      "import.placeholder": "Tempel data hasil ekspor di sini",
      "import.submit": "Impor",
      "import.supports": "Mendukung kata sandi, catatan, frasa sandi, autentikator, kode cadangan.",
      "import.overlay_upload": "Mengunggah...",
      "import.overlay_success": "Impor selesai.",
      "import.overlay_error": "Impor gagal.",
      "import.importing": "Sedang mengimpor...",
      "import.status_uploading": "Mengunggah...",
      "import.success_default": "Impor selesai.",
      "import.error_default": "Impor gagal.",
      "import.preview.title": "Tinjau impor ini",
      "import.preview.sub": "Belum ada yang ditulis.",
      "import.preview.kind": "Jenis",
      "import.preview.confirm": "Impor catatan ini",
      "import.preview.cancel": "Batal",
      "import.preview.back": "Kembali ke Ekspor / Impor",
      "import.preview.secret": "Rahasia",
      "section.passphrases": "Frasa Sandi",
      "section.passphrases_desc": "Simpan token API atau frasa pemulihan. Tampilan meminta master lagi.",
      "btn.add_passphrase": "+ Tambah Frasa Sandi",
      "section.authenticators": "Autentikator (TOTP)",
      "section.authenticators_desc": "Simpan rahasia 2FA dan lihat kode langsung.",
      "btn.add_authenticator": "+ Tambah Autentikator",
      "section.backups": "Kode Cadangan",
      "section.backups_desc": "Simpan kode pemulihan (tampilan memperlihatkan penuh).",
      "btn.add_backups": "+ Tambah Kode Cadangan",
      "section.session": "Sesi Web",
      "section.session_desc": "Dilindungi kata sandi master. Terkunci otomatis setelah 30 detik tidak aktif; server menutup sesi menganggur setelah 5 menit dan sesi apa pun setelah 12 jam.",
      "form.vault": "Brankas:",
      "form.back_list": "\u2190 Kembali ke daftar",
      "form.save": "Simpan",
      "link.back": "\u2190 Kembali",
      "entry.field.service": "Layanan / Nama",
      "entry.field.username": "Pengguna / Email",
      "entry.field.url": "URL",
      "entry.hint.url": "Dipakai untuk mencocokkan entry ini dengan situs. Hanya http:// atau https://.",
      "entry.field.password": "Kata sandi",
      "entry.field.notes": "Catatan",
      "note.field.title": "Judul",
      "note.field.content": "Konten",
      "pass.field.label": "Label",
      "pass.field.secret_hint": "Frasa sandi (kosongkan untuk membuat otomatis)",
      "backup.field.label": "Label",
      "backup.field.codes": "Kode cadangan (satu per baris)",
      "auth.field.label": "Label",
      "auth.field.secret": "Rahasia Base32",
      "auth.field.period": "Interval penyegaran (detik)",
      "auth.field.algorithm": "Algoritma",
      "auth.option.sha1": "SHA1 (default)",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "Lihat Entri",
      "view.label.name": "Nama",
      "view.label.username": "Pengguna / Email",
      "view.label.url": "URL",
      "view.label.password": "Kata sandi",
      "view.label.notes": "Catatan",
      "view.label.previous": "Kata sandi sebelumnya",
      "view.previous.hint": "Terbaru dulu. Dicatat saat kata sandi diubah; menghapus entri ini menghapusnya juga.",
      "view.label.created": "Dibuat",
      "view.sub_prefix": "Brankas:",
      "btn.copy_username": "Salin pengguna",
      "btn.copy_password": "Salin kata sandi",
      "btn.copy_notes": "Salin catatan",
      "btn.copy_passphrase": "Salin",
      "btn.copy_codes": "Salin kode",
      "btn.copy_code": "Salin kode",
      "btn.show": "Tampilkan",
      "btn.hide": "Sembunyikan",
      "btn.edit": "Ubah",
      "btn.delete": "Hapus",
      "pass.view.title": "Frasa sandi",
      "pass.view.label_field": "Label",
      "pass.view.created": "Dibuat",
      "pass.view.secret": "Frasa sandi",
      "backup.view.title": "Kode Cadangan",
      "backup.view.label": "Label:",
      "backup.view.created": "Dibuat:",
      "auth.view.title": "Autentikator",
      "auth.view.label": "Label",
      "auth.view.interval": "Interval",
      "auth.view.algo": "Algoritma",
      "auth.view.created": "Dibuat",
      "auth.view.secret": "Rahasia Base32",
      "auth.view.code": "Kode langsung",
      "auth.view.seconds_label": "detik",
      "generator.title": "Pembuat Kata Sandi",
      "generator.length": "Panjang",
      "generator.mode_secure": "Aman",
      "generator.mode_easy": "Mudah / Mudah diingat",
      "generator.opt.upper": "Huruf besar",
      "generator.opt.lower": "Huruf kecil",
      "generator.opt.digits": "Angka",
      "generator.opt.symbols": "Simbol",
      "generator.btn.regen": "Buat ulang",
      "generator.btn.copy": "Salin",
      "generator.btn.back": "Kembali",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "bit",
      "generator.stats.suffix": "untuk brute-force (perk.)",
      "generator.words_prefix": "Kata",
      "generator.strength.very_weak": "Sangat lemah",
      "generator.strength.weak": "Lemah",
      "generator.strength.moderate": "Sedang",
      "generator.strength.strong": "Kuat",
      "generator.strength.excellent": "Sangat kuat",
      "generator.unit.sec": "detik",
      "generator.unit.min": "menit",
      "generator.unit.hr": "jam",
      "generator.unit.day": "hari",
      "generator.unit.yr": "tahun",
      "generator.unit.century": "abad",
      "import.placeholder": "Tempel data hasil ekspor di sini",
      "toast.copy_success": "Disalin ke clipboard.",
      "toast.copy_fail": "Gagal menyalin.",
      "auth.countdown.refresh_in": "Segar ulang dalam {n}dtk",
      "auth.countdown.refreshing": "Sedang menyegarkan...",
      "auth.status.no_code": "Belum ada kode",
      "auth.status.copy_ok": "Disalin!",
      "auth.status.copy_fail": "Gagal menyalin",
      "confirm.delete_entry": "Hapus entri ini?",
      "confirm.delete_passphrase": "Hapus frasa sandi ini?",
      "confirm.delete_backup": "Hapus kode cadangan ini?",
      "confirm.delete_authenticator": "Hapus autentikator ini?",
      "nav.group.vault": "Brankas",
      "nav.group.tools": "Alat",
      "nav.group.settings": "Pengaturan",
      "nav.master_password": "Kata Sandi Utama",
      "page.settings.title": "Kata Sandi Utama",
      "page.settings.desc": "Ubah kata sandi yang mengenkripsi brankas ini.",
      "settings.current": "Kata sandi utama saat ini",
      "settings.new": "Kata sandi utama baru",
      "settings.confirm": "Konfirmasi kata sandi utama baru",
      "settings.submit": "Ubah kata sandi utama",
      "settings.hint": "Minimal 12 karakter. Kata sandi utama yang lupa tidak bisa dipulihkan \u2014 hanya file pemulihan dan kunci privatnya yang bisa meresetnya.",
      "settings.mismatch": "Kedua kata sandi baru tidak sama.",
      "settings.effect": "Yang akan terjadi",
      "settings.effect_vault": "Mengenkripsi ulang seluruh brankas dengan kata sandi baru.",
      "settings.effect_recovery": "Menulis ulang file pemulihan agar \\"spm forgot\\" tetap berfungsi.",
      "settings.effect_sessions": "Mengeluarkan semua sesi browser lain.",
      "settings.effect_backup": "Menyimpan brankas lama sebagai .bak dan snapshot riwayat.",
      "nav.overview": "Ringkasan",
      "nav.passwords": "Kata Sandi",
      "nav.notes": "Catatan Aman",
      "nav.passphrases": "Frasa Sandi",
      "nav.authenticators": "Autentikator",
      "nav.backup_codes": "Kode Cadangan",
      "nav.generator": "Generator",
      "nav.transfer": "Ekspor / Impor",
      "search.label": "Cari di brankas ini",
      "search.placeholder": "Cari di brankas ini...",
      "search.no_results": "Tidak ada yang cocok dengan pencarian",
      "lock.in": "Terkunci dalam",
      "lock.paused": "Kunci dijeda",
      "overview.sub": "Semua isi brankas terenkripsi Anda sekilas.",
      "overview.recent": "Baru ditambahkan",
      "overview.view_all": "Lihat semua",
      "overview.console_eyebrow": "sesi / brankas lokal / terautentikasi",
      "overview.console_records": "rekaman terenkripsi terindeks",
      "overview.console_gpg": "Batas GnuPG aktif pada host ini",
      "overview.console_lock": "kunci diam disiapkan selama 30 detik",
      "overview.console_lede": "Periksa, buat, dan kelola kredensial dari satu sesi yang dapat diaudit.",
      "btn.view": "Lihat",
      "generator.mode": "Mode",
      "login.sub": "Buka brankas terenkripsi Anda untuk melanjutkan.",
      "login.master": "Kata sandi utama",
      "login.unlock": "Buka",
      "login.note": "Semua dekripsi dilakukan lokal dengan GnuPG. Tidak ada data yang keluar dari host ini.",
      "empty.vault.t": "Brankas Anda kosong",
      "empty.vault.d": "Tambahkan kata sandi pertama untuk memulai.",
      "empty.passwords.t": "Belum ada kata sandi",
      "empty.passwords.d": "Entri yang Anda tambahkan akan muncul di sini.",
      "empty.notes.t": "Belum ada catatan aman",
      "empty.notes.d": "Catatan terenkripsi tersimpan di brankas yang sama.",
      "empty.passphrases.t": "Belum ada frasa sandi",
      "empty.passphrases.d": "Simpan token API atau frasa pemulihan di sini.",
      "empty.backups.t": "Belum ada kode cadangan",
      "empty.backups.d": "Simpan kode pemulihan sekali pakai dengan aman di sini.",
      "empty.auth.t": "Belum ada autentikator",
      "empty.auth.d": "Tambahkan secret TOTP untuk membuat kode 2FA.",
      "page.passwords.desc": "Kredensial login yang tersimpan di brankas Anda.",
      "page.notes.desc": "Catatan terenkripsi di dalam brankas yang sama.",
      "page.passphrases.desc": "Token API dan frasa pemulihan.",
      "page.authenticators.desc": "Kode sekali pakai berbasis waktu.",
      "page.backups.desc": "Kode pemulihan sekali pakai untuk akun Anda.",
    },
    "ja": {
      "nav.security": "セキュリティ",
      "nav.history": "履歴",
      "nav.events": "セキュリティイベント",
      "entry.field.folder": "フォルダ",
      "entry.hint.folder": "任意。新しい名前を入力すると作成されます。",
      "entry.field.custom": "カスタムフィールド",
      "entry.field.custom_name": "フィールド名",
      "entry.field.custom_value": "値",
      "entry.field.custom_add": "フィールドを追加",
      "entry.hint.custom": "専用の入力欄がない情報のためのフィールド。パスワードと同様に暗号化して保存されます。",
      "view.label.folder": "フォルダ",
      "search.folder": "フォルダ",
      "page.events.desc": "この保管庫での操作。保管庫の外に記録され、レコード名・ユーザー名・秘密情報は含みません。",
      "events.when": "日時 (UTC)",
      "events.kind": "イベント",
      "events.outcome": "結果",
      "events.detail": "詳細",
      "events.empty": "まだ記録はありません。",
      "events.empty_sub": "アンロック、書き込み、マスターパスワードの変更がここに表示されます。",
      "nav.unlock": "生体認証ロック解除",
      "page.unlock.desc": "マスターパスワードの代わりに、この端末でロックを解除します。",
      "unlock.registered": "登録日時",
      "unlock.empty": "登録済みの端末はありません",
      "unlock.empty_sub": "下から登録するか、マスターパスワードを使い続けてください",
      "unlock.field.label": "この端末のラベル",
      "unlock.register": "この端末を登録",
      "unlock.note": "初回サインイン時、セッションが最大有効期間に達したとき、およびロックされたセッションが長時間再開されなかった場合は、引き続きマスターパスワードが必要です。",
      "unlock.title": "保管庫はロック中",
      "unlock.sub": "端末で確認して、続きから再開します。",
      "unlock.btn": "生体認証で解除",
      "unlock.fallback": "マスターパスワードを使う",
      "unlock.waiting": "生体認証の確認を待っています...",
      "unlock.failed": "ロック解除に失敗しました。",
      "unlock.nosupport": "このブラウザは生体認証に対応していません。",
      "register.waiting": "認証器を待っています...",
      "register.failed": "登録に失敗しました。",
      "security.sub": "ボールトのスコアを下げている項目。",
      "security.scope": "評価対象はパスワードのみ。IDのみ表示し、シークレットは表示しません。",
      "security.none": "修正すべき項目はありません。",
      "security.weak": "弱いパスワード",
      "security.weak_d": "12文字未満、または文字種が3種類未満。",
      "security.reused": "使い回しパスワード",
      "security.reused_d": "以下の各行は同じパスワードを共有するグループです。",
      "security.aging": "更新が必要",
      "security.aging_d": "ローテーション期限を超過:",
      "security.incomplete": "情報が不足",
      "security.incomplete_d": "サービス名またはユーザー名がありません。",
      "security.malformed": "不正な認証アプリ",
      "security.malformed_d": "シークレットが無いか、SPMが対応しないアルゴリズムです。",
      "security.breached": "既知の漏えい",
      "security.breached_d": "Pwned Passwords との一致。端末外へ送るのは SHA-1 の先頭5文字だけです。",
      "security.breach_check": "既知の漏えいを確認",
      "security.breach_optin": "任意のオンライン確認です。パスワードと完全なハッシュは送信されません。",
      "security.breach_unavailable": "漏えい確認サービスを利用できません。安全とは判定しません。",
      "page.history.desc": "変更前に保存される暗号化スナップショット。",
      "history.when": "日時",
      "history.size": "サイズ",
      "history.name": "スナップショット",
      "history.newest": "最新",
      "btn.restore": "復元",
      "confirm.restore_snapshot": "このスナップショットを復元しますか？現在のボールトは先に保存されます。",
      "empty.history.t": "スナップショットなし",
      "empty.history.d": "SPMは変更前にボールトを保存します。",
      "search.title": "検索",
      "search.desc": "すべての種類のレコードを検索します。",
      "search.kind": "種類",
      "empty.search.t": "見つかりません",
      "empty.search.d": "一致するラベル・名前・ユーザー名がありません。",
      "badge.aging": "更新",
      "tags.all": "すべて",
      "header.title": "Sans Password Manager",
      "header.subtitle": "リキッドガラス風Webインターフェース · GPG暗号化",
      "header.check_update": "アップデートを確認",
      "header.logout": "ログアウト",
      "nav.collapse": "サイドバーを折りたたむ",
      "nav.expand": "サイドバーを展開",
      "nav.open": "メニュー",
      "nav.close": "メニューを閉じる",
      "header.vault": "ボールト",
      "section.passwords": "パスワード",
      "chip.online": "オンライン · 読み/書き",
      "btn.add_entry": "+ エントリ追加",
      "table.id": "ID",
      "import.export_password": "\u30a8\u30af\u30b9\u30dd\u30fc\u30c8\u30d1\u30b9\u30ef\u30fc\u30c9",
      "import.export_password_hint": "Bitwarden \u304b\u3089\u30a8\u30af\u30b9\u30dd\u30fc\u30c8\u3059\u308b\u3068\u304d\u306b\u8a2d\u5b9a\u3057\u305f\u30d1\u30b9\u30ef\u30fc\u30c9",
      "import.export_password_note": "\u30d1\u30b9\u30ef\u30fc\u30c9\u4fdd\u8b77\u3055\u308c\u305f Bitwarden \u30a8\u30af\u30b9\u30dd\u30fc\u30c8\u306b\u306e\u307f\u5fc5\u8981\u3067\u3059\u3002\u30d5\u30a1\u30a4\u30eb\u306e\u8aad\u307f\u53d6\u308a\u306b\u4f7f\u308f\u308c\u3001\u4fdd\u5b58\u3055\u308c\u307e\u305b\u3093\u3002",
      "overview.security_score": "\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3\u30b9\u30b3\u30a2",
      "table.service": "\u30b5\u30fc\u30d3\u30b9",
      "table.name": "名前",
      "table.username": "ユーザー名",
      "table.actions": "操作",
      "table.title": "タイトル",
      "table.label": "ラベル",
      "table.every": "周期",
      "table.algo": "方式",
      "passwords.footer": "パスワードはどこにも送信されません。暗号化はすべてこのホスト上で完結します。",
      "section.secure_notes": "セキュアノート",
      "section.secure_notes_desc": "同じボールト内に暗号化して保存されます。",
      "btn.add_note": "+ ノート追加",
      "section.generator": "パスワード生成",
      "section.generator_desc": "長さ・モード・記号を調整して強力なパスワードを生成。",
      "btn.open_generator": "ジェネレーターを開く",
      "import.title": "エクスポート / インポート",
      "import.subtitle": "データをダウンロードまたは貼り付け（csv/json + 拡張フォーマット）。",
      "import.format_label": "フォーマット",
      "import.download": "ダウンロード",
      "import.import_label": "インポート形式",
      "import.upload_label": "エクスポートファイルをアップロード",
      "import.paste_label": "または内容を貼り付け",
      "import.placeholder": "ここにエクスポートデータを貼り付け",
      "import.submit": "インポート",
      "import.supports": "パスワード、ノート、パスフレーズ、認証器、バックアップコードに対応。",
      "import.overlay_upload": "アップロード中...",
      "import.overlay_success": "インポート完了。",
      "import.overlay_error": "インポート失敗。",
      "import.importing": "インポート中...",
      "import.status_uploading": "アップロード中...",
      "import.success_default": "インポート完了。",
      "import.error_default": "インポート失敗。",
      "import.preview.title": "このインポートを確認",
      "import.preview.sub": "まだ何も書き込まれていません。",
      "import.preview.kind": "種類",
      "import.preview.confirm": "これらのレコードをインポート",
      "import.preview.cancel": "キャンセル",
      "import.preview.back": "エクスポート / インポートに戻る",
      "import.preview.secret": "シークレット",
      "section.passphrases": "パスフレーズ",
      "section.passphrases_desc": "APIトークンや復旧フレーズを保存。閲覧時に再確認します。",
      "btn.add_passphrase": "+ パスフレーズ追加",
      "section.authenticators": "認証アプリ (TOTP)",
      "section.authenticators_desc": "2FAシークレットを保存しライブコードを表示。",
      "btn.add_authenticator": "+ 認証を追加",
      "section.backups": "バックアップコード",
      "section.backups_desc": "復旧コードを保存（表示時は全文表示）。",
      "btn.add_backups": "+ コード追加",
      "section.session": "Webセッション",
      "section.session_desc": "マスターパスワードで保護。30秒間操作がないと自動ロックされ、サーバーも5分でアイドルセッションを、12時間で全セッションを失効させます。",
      "form.vault": "ボールト:",
      "form.back_list": "\u2190 一覧に戻る",
      "form.save": "保存",
      "link.back": "\u2190 戻る",
      "entry.field.service": "サービス / 名称",
      "entry.field.username": "ユーザー名 / メール",
      "entry.field.url": "URL",
      "entry.hint.url": "このエントリをサイトに紐づけるために使用します。http:// または https:// のみ。",
      "entry.field.password": "パスワード",
      "entry.field.notes": "メモ",
      "note.field.title": "タイトル",
      "note.field.content": "内容",
      "pass.field.label": "ラベル",
      "pass.field.secret_hint": "パスフレーズ（空欄で自動生成）",
      "backup.field.label": "ラベル",
      "backup.field.codes": "バックアップコード（1行1コード）",
      "auth.field.label": "ラベル",
      "auth.field.secret": "Base32シークレット",
      "auth.field.period": "更新間隔（秒）",
      "auth.field.algorithm": "アルゴリズム",
      "auth.option.sha1": "SHA1（標準）",
      "auth.option.sha256": "SHA256",
      "auth.option.sha512": "SHA512",
      "view.title": "エントリ表示",
      "view.label.name": "名前",
      "view.label.username": "ユーザー名 / メール",
      "view.label.url": "URL",
      "view.label.password": "パスワード",
      "view.label.notes": "メモ",
      "view.label.previous": "\u4ee5\u524d\u306e\u30d1\u30b9\u30ef\u30fc\u30c9",
      "view.previous.hint": "\u65b0\u3057\u3044\u9806\u3002\u30d1\u30b9\u30ef\u30fc\u30c9\u5909\u66f4\u6642\u306b\u8a18\u9332\u3055\u308c\u3001\u3053\u306e\u30a8\u30f3\u30c8\u30ea\u3092\u524a\u9664\u3059\u308b\u3068\u4e00\u7dd2\u306b\u524a\u9664\u3055\u308c\u307e\u3059\u3002",
      "view.label.created": "作成日時",
      "view.sub_prefix": "ボールト:",
      "btn.copy_username": "ユーザー名をコピー",
      "btn.copy_password": "パスワードをコピー",
      "btn.copy_notes": "ノートをコピー",
      "btn.copy_passphrase": "コピー",
      "btn.copy_codes": "コードをコピー",
      "btn.copy_code": "コードをコピー",
      "btn.show": "表示",
      "btn.hide": "非表示",
      "btn.edit": "編集",
      "btn.delete": "削除",
      "pass.view.title": "パスフレーズ",
      "pass.view.label_field": "ラベル",
      "pass.view.created": "作成日",
      "pass.view.secret": "パスフレーズ",
      "backup.view.title": "バックアップコード",
      "backup.view.label": "ラベル:",
      "backup.view.created": "作成:",
      "auth.view.title": "認証アプリ",
      "auth.view.label": "ラベル",
      "auth.view.interval": "間隔",
      "auth.view.algo": "アルゴリズム",
      "auth.view.created": "作成日",
      "auth.view.secret": "Base32シークレット",
      "auth.view.code": "ライブコード",
      "auth.view.seconds_label": "秒",
      "generator.title": "パスワード生成",
      "generator.length": "長さ",
      "generator.mode_secure": "強力",
      "generator.mode_easy": "簡単 / 覚えやすい",
      "generator.opt.upper": "大文字",
      "generator.opt.lower": "小文字",
      "generator.opt.digits": "数字",
      "generator.opt.symbols": "記号",
      "generator.btn.regen": "再生成",
      "generator.btn.copy": "コピー",
      "generator.btn.back": "戻る",
      "generator.stats.placeholder": "\u2013",
      "generator.stats.bits": "ビット",
      "generator.stats.suffix": "推定総当たり時間",
      "generator.words_prefix": "単語",
      "generator.strength.very_weak": "とても弱い",
      "generator.strength.weak": "弱い",
      "generator.strength.moderate": "普通",
      "generator.strength.strong": "強い",
      "generator.strength.excellent": "最強",
      "generator.unit.sec": "秒",
      "generator.unit.min": "分",
      "generator.unit.hr": "時間",
      "generator.unit.day": "日",
      "generator.unit.yr": "年",
      "generator.unit.century": "世紀",
      "import.placeholder": "ここにエクスポートデータを貼り付け",
      "toast.copy_success": "クリップボードにコピーしました。",
      "toast.copy_fail": "コピーに失敗しました。",
      "auth.countdown.refresh_in": "{n}秒で更新",
      "auth.countdown.refreshing": "更新中...",
      "auth.status.no_code": "まだコードがありません",
      "auth.status.copy_ok": "コピーしました",
      "auth.status.copy_fail": "コピー失敗",
      "confirm.delete_entry": "このエントリを削除しますか？",
      "confirm.delete_passphrase": "このパスフレーズを削除しますか？",
      "confirm.delete_backup": "これらのバックアップコードを削除しますか？",
      "confirm.delete_authenticator": "この認証情報を削除しますか？",
      "nav.group.vault": "\u4fdd\u7ba1\u5eab",
      "nav.group.tools": "\u30c4\u30fc\u30eb",
      "nav.group.settings": "\u8a2d\u5b9a",
      "nav.master_password": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "page.settings.title": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "page.settings.desc": "\u3053\u306e\u4fdd\u7ba1\u5eab\u3092\u6697\u53f7\u5316\u3057\u3066\u3044\u308b\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5909\u66f4\u3057\u307e\u3059\u3002",
      "settings.current": "\u73fe\u5728\u306e\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "settings.new": "\u65b0\u3057\u3044\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "settings.confirm": "\u65b0\u3057\u3044\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\uff08\u78ba\u8a8d\uff09",
      "settings.submit": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5909\u66f4",
      "settings.hint": "12\u6587\u5b57\u4ee5\u4e0a\u3002\u5fd8\u308c\u305f\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u5fa9\u5143\u3059\u308b\u65b9\u6cd5\u306f\u3042\u308a\u307e\u305b\u3093\u3002\u30ea\u30ab\u30d0\u30ea\u30d5\u30a1\u30a4\u30eb\u3068\u79d8\u5bc6\u9375\u3060\u3051\u304c\u30ea\u30bb\u30c3\u30c8\u3067\u304d\u307e\u3059\u3002",
      "settings.mismatch": "\u65b0\u3057\u3044\u30d1\u30b9\u30ef\u30fc\u30c9\u304c\u4e00\u81f4\u3057\u307e\u305b\u3093\u3002",
      "settings.effect": "\u5b9f\u884c\u3055\u308c\u308b\u5185\u5bb9",
      "settings.effect_vault": "\u4fdd\u7ba1\u5eab\u5168\u4f53\u3092\u65b0\u3057\u3044\u30d1\u30b9\u30ef\u30fc\u30c9\u3067\u518d\u6697\u53f7\u5316\u3057\u307e\u3059\u3002",
      "settings.effect_recovery": "\\"spm forgot\\" \u304c\u5f15\u304d\u7d9a\u304d\u4f7f\u3048\u308b\u3088\u3046\u30ea\u30ab\u30d0\u30ea\u30d5\u30a1\u30a4\u30eb\u3092\u66f8\u304d\u63db\u3048\u307e\u3059\u3002",
      "settings.effect_sessions": "\u4ed6\u306e\u3059\u3079\u3066\u306e\u30d6\u30e9\u30a6\u30b6\u30bb\u30c3\u30b7\u30e7\u30f3\u3092\u30b5\u30a4\u30f3\u30a2\u30a6\u30c8\u3057\u307e\u3059\u3002",
      "settings.effect_backup": "\u4ee5\u524d\u306e\u4fdd\u7ba1\u5eab\u3092 .bak \u3068\u5c65\u6b74\u30b9\u30ca\u30c3\u30d7\u30b7\u30e7\u30c3\u30c8\u3068\u3057\u3066\u4fdd\u6301\u3057\u307e\u3059\u3002",
      "nav.overview": "\u6982\u8981",
      "nav.passwords": "\u30d1\u30b9\u30ef\u30fc\u30c9",
      "nav.notes": "\u30bb\u30ad\u30e5\u30a2\u30e1\u30e2",
      "nav.passphrases": "\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba",
      "nav.authenticators": "\u8a8d\u8a3c\u30a2\u30d7\u30ea",
      "nav.backup_codes": "\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u30b3\u30fc\u30c9",
      "nav.generator": "\u30b8\u30a7\u30cd\u30ec\u30fc\u30bf\u30fc",
      "nav.transfer": "\u30a8\u30af\u30b9\u30dd\u30fc\u30c8 / \u30a4\u30f3\u30dd\u30fc\u30c8",
      "search.label": "\u3053\u306e\u4fdd\u7ba1\u5eab\u3092\u691c\u7d22",
      "search.placeholder": "\u3053\u306e\u4fdd\u7ba1\u5eab\u3092\u691c\u7d22...",
      "search.no_results": "\u691c\u7d22\u6761\u4ef6\u306b\u4e00\u81f4\u3059\u308b\u9805\u76ee\u306f\u3042\u308a\u307e\u305b\u3093",
      "lock.in": "\u30ed\u30c3\u30af\u307e\u3067",
      "lock.paused": "\u30ed\u30c3\u30af\u4e00\u6642\u505c\u6b62\u4e2d",
      "overview.sub": "\u6697\u53f7\u5316\u3055\u308c\u305f\u4fdd\u7ba1\u5eab\u306e\u5185\u5bb9\u3092\u4e00\u89a7\u3067\u304d\u307e\u3059\u3002",
      "overview.recent": "\u6700\u8fd1\u8ffd\u52a0\u3057\u305f\u9805\u76ee",
      "overview.view_all": "\u3059\u3079\u3066\u8868\u793a",
      "overview.console_eyebrow": "\u30bb\u30c3\u30b7\u30e7\u30f3 / \u30ed\u30fc\u30ab\u30eb\u4fdd\u7ba1\u5eab / \u8a8d\u8a3c\u6e08\u307f",
      "overview.console_records": "\u4ef6\u306e\u6697\u53f7\u5316\u30ec\u30b3\u30fc\u30c9\u3092\u7d22\u5f15\u6e08\u307f",
      "overview.console_gpg": "\u3053\u306e\u30db\u30b9\u30c8\u3067 GnuPG \u5883\u754c\u304c\u6709\u52b9",
      "overview.console_lock": "30 \u79d2\u306e\u30a2\u30a4\u30c9\u30eb\u30ed\u30c3\u30af\u3092\u6709\u52b9\u5316",
      "overview.console_lede": "\u76e3\u67fb\u53ef\u80fd\u306a1\u3064\u306e\u30bb\u30c3\u30b7\u30e7\u30f3\u3067\u8a8d\u8a3c\u60c5\u5831\u3092\u78ba\u8a8d\u3001\u751f\u6210\u3001\u7ba1\u7406\u3057\u307e\u3059\u3002",
      "btn.view": "\u8868\u793a",
      "generator.mode": "\u30e2\u30fc\u30c9",
      "login.sub": "\u7d9a\u884c\u3059\u308b\u306b\u306f\u4fdd\u7ba1\u5eab\u306e\u30ed\u30c3\u30af\u3092\u89e3\u9664\u3057\u3066\u304f\u3060\u3055\u3044\u3002",
      "login.master": "\u30de\u30b9\u30bf\u30fc\u30d1\u30b9\u30ef\u30fc\u30c9",
      "login.unlock": "\u30ed\u30c3\u30af\u89e3\u9664",
      "login.note": "\u5fa9\u53f7\u306f\u3059\u3079\u3066 GnuPG \u306b\u3088\u308a\u30ed\u30fc\u30ab\u30eb\u3067\u884c\u308f\u308c\u3001\u30c7\u30fc\u30bf\u304c\u30db\u30b9\u30c8\u5916\u3078\u51fa\u308b\u3053\u3068\u306f\u3042\u308a\u307e\u305b\u3093\u3002",
      "empty.vault.t": "\u4fdd\u7ba1\u5eab\u306f\u7a7a\u3067\u3059",
      "empty.vault.d": "\u6700\u521d\u306e\u30d1\u30b9\u30ef\u30fc\u30c9\u3092\u8ffd\u52a0\u3057\u3066\u59cb\u3081\u307e\u3057\u3087\u3046\u3002",
      "empty.passwords.t": "\u30d1\u30b9\u30ef\u30fc\u30c9\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.passwords.d": "\u8ffd\u52a0\u3057\u305f\u9805\u76ee\u304c\u3053\u3053\u306b\u8868\u793a\u3055\u308c\u307e\u3059\u3002",
      "empty.notes.t": "\u30bb\u30ad\u30e5\u30a2\u30e1\u30e2\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.notes.d": "\u6697\u53f7\u5316\u3055\u308c\u305f\u30e1\u30e2\u306f\u540c\u3058\u4fdd\u7ba1\u5eab\u306b\u4fdd\u5b58\u3055\u308c\u307e\u3059\u3002",
      "empty.passphrases.t": "\u30d1\u30b9\u30d5\u30ec\u30fc\u30ba\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.passphrases.d": "API \u30c8\u30fc\u30af\u30f3\u3084\u5fa9\u65e7\u30d5\u30ec\u30fc\u30ba\u3092\u3053\u3053\u306b\u4fdd\u5b58\u3067\u304d\u307e\u3059\u3002",
      "empty.backups.t": "\u30d0\u30c3\u30af\u30a2\u30c3\u30d7\u30b3\u30fc\u30c9\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.backups.d": "\u4f7f\u3044\u6368\u3066\u306e\u5fa9\u65e7\u30b3\u30fc\u30c9\u3092\u3053\u3053\u306b\u5b89\u5168\u306b\u4fdd\u7ba1\u3057\u307e\u3059\u3002",
      "empty.auth.t": "\u8a8d\u8a3c\u30a2\u30d7\u30ea\u304c\u3042\u308a\u307e\u305b\u3093",
      "empty.auth.d": "TOTP \u30b7\u30fc\u30af\u30ec\u30c3\u30c8\u3092\u8ffd\u52a0\u3057\u3066 2FA \u30b3\u30fc\u30c9\u3092\u751f\u6210\u3057\u307e\u3059\u3002",
      "page.passwords.desc": "\u4fdd\u7ba1\u5eab\u306b\u4fdd\u5b58\u3055\u308c\u3066\u3044\u308b\u30ed\u30b0\u30a4\u30f3\u60c5\u5831\u3002",
      "page.notes.desc": "\u540c\u3058\u4fdd\u7ba1\u5eab\u5185\u306b\u4fdd\u5b58\u3055\u308c\u305f\u6697\u53f7\u5316\u30e1\u30e2\u3002",
      "page.passphrases.desc": "API \u30c8\u30fc\u30af\u30f3\u3068\u5fa9\u65e7\u30d5\u30ec\u30fc\u30ba\u3002",
      "page.authenticators.desc": "\u6642\u523b\u30d9\u30fc\u30b9\u306e\u30ef\u30f3\u30bf\u30a4\u30e0\u30d1\u30b9\u30ef\u30fc\u30c9\u30b3\u30fc\u30c9\u3002",
      "page.backups.desc": "\u30a2\u30ab\u30a6\u30f3\u30c8\u7528\u306e\u4f7f\u3044\u6368\u3066\u5fa9\u65e7\u30b3\u30fc\u30c9\u3002",
    }
  };
  const FALLBACK = "en";
  const SUPPORTED = Object.keys(DICT);
  function normalize(lang) {
    lang = (lang || "").toLowerCase();
    if (SUPPORTED.includes(lang)) return lang;
    return FALLBACK;
  }
  function lookup(key, lang) {
    const dict = DICT[normalize(lang)] || {};
    if (Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    const fb = DICT[FALLBACK] || {};
    if (Object.prototype.hasOwnProperty.call(fb, key)) return fb[key];
    return null;
  }
  let current = normalize(window.SPM_LANG);
  function applyTranslations(lang) {
    current = normalize(lang);
    if (document.documentElement) document.documentElement.setAttribute("lang", current);
    if (document.body) document.body.setAttribute("data-lang", current);
    document.querySelectorAll("[data-i18n]").forEach((node) => {
      const key = node.getAttribute("data-i18n");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.textContent = text;
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
      const key = node.getAttribute("data-i18n-placeholder");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.setAttribute("placeholder", text);
    });
    /* Collapsed to a rail, a nav item's only remaining label is its tooltip.
       Leaving that untranslated would make the icon-only sidebar English-only. */
    document.querySelectorAll("[data-i18n-title]").forEach((node) => {
      const key = node.getAttribute("data-i18n-title");
      const text = lookup(key, current);
      if (text !== null && text !== undefined) node.setAttribute("title", text);
    });
    const picker = document.getElementById("lang-picker");
    if (picker) picker.value = current;
  }
  function persist(lang) {
    try {
      fetch("/lang", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Requested-With": "fetch"
        },
        body: "lang=" + encodeURIComponent(lang),
        credentials: "same-origin"
      }).catch(() => {});
    } catch (e) {}
  }
  function setLang(lang) {
    const normalized = normalize(lang);
    applyTranslations(normalized);
    persist(normalized);
  }
  document.addEventListener("DOMContentLoaded", () => {
    applyTranslations(current);
    const picker = document.getElementById("lang-picker");
    if (picker) {
      picker.value = current;
      picker.addEventListener("change", () => setLang(picker.value));
    }
  });
  window.SPM_I18N = {
    dict: DICT,
    t: function(key, fallback) {
      const text = lookup(key, current);
      if (text !== null && text !== undefined) return text;
      return fallback !== undefined ? fallback : key;
    },
    setLang: setLang,
    getLang: function() { return current; },
    apply: applyTranslations
  };
})();

// Inline handlers were removed so the CSP no longer needs 'unsafe-inline'.
// One delegated listener covers every control, including markup added later.
(function () {
  document.addEventListener("click", function (ev) {
    // WebKit can report an SVG <use> (and older builds occasionally a text
    // node) as the tap target. Those targets do not reliably implement
    // Element.closest(), so walk to an Element before delegating actions.
    var target = ev.target;
    if (target && target.nodeType !== 1) target = target.parentElement;
    const el = target && target.closest ? target.closest("[data-act]") : null;
    if (!el) return;
    const act = el.getAttribute("data-act");
    const id = el.getAttribute("data-target");
    const node = id ? document.getElementById(id) : null;
    if (act === "reveal") { if (window.SPM_reveal) SPM_reveal(id, el); }
    else if (act === "copy-val") { if (node && window.SPM_copy) SPM_copy(node.dataset.val); }
    else if (act === "copy-text") { if (node && window.SPM_copy) SPM_copy(node.textContent); }
    else if (act === "regen") { if (window.SPM_regen) SPM_regen(); }
    else if (act === "copy-pw") { if (window.SPM_copyPw) SPM_copyPw(); }
    else if (act === "tag") {
      // A tag chip drives the search box that already filters this table,
      // rather than adding a second filtering path that could disagree with it.
      var box = document.getElementById("q");
      if (box) {
        box.value = el.getAttribute("data-tag") || "";
        box.dispatchEvent(new Event("input", { bubbles: true }));
      }
      document.querySelectorAll("[data-act='tag']").forEach(function (c) {
        c.classList.toggle("chip-on", c === el);
      });
    }
    else return;
    ev.preventDefault();
  });
  document.addEventListener("submit", function (ev) {
    const form = ev.target.closest("form[data-confirm-key]");
    if (!form) return;
    const key = form.getAttribute("data-confirm-key");
    const fallback = form.getAttribute("data-confirm-text") || "";
    const text = window.SPM_I18N ? SPM_I18N.t(key, fallback) : fallback;
    if (!confirm(text)) ev.preventDefault();
  });
})();
</script>
"""

DESIGN_CSS = """
<style>
/* ============================================================
   SPM design system - one stylesheet for every page.
   Tokens first, then primitives, then components, then layout.
   Console is intentionally dark-only. Components consume semantic
   action, emitted-value, state, surface, and text roles.
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; }

:root {
  --sp-1: 4px;  --sp-2: 8px;  --sp-3: 12px; --sp-4: 16px;
  --sp-5: 24px; --sp-6: 32px; --sp-7: 48px;
  --r-sm: 8px; --r-md: 12px; --r-lg: 16px; --r-full: 999px;
  --fs-xs: 11px; --fs-sm: 12px; --fs-md: 13px; --fs-base: 14px;
  --fs-lg: 16px; --fs-xl: 20px; --fs-2xl: 26px; --fs-3xl: 34px;
  --sidebar-w: 260px;
  --topbar-h: 60px;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --ease: cubic-bezier(.4, 0, .2, 1);
  --motion-instant: 80ms;
  --motion-fast: 140ms;
  --motion-base: 200ms;
  --motion-live: 320ms;
  /* A07 durations. Exits are faster than entrances on purpose: a departing
     surface has already been decided about, and equal timings make dismissal
     feel sticky. --motion-reveal fires once per element, ever; --motion-ambient
     is reserved for state that is genuinely live. */
  --motion-slow: 320ms;
  --motion-reveal: 500ms;
  --motion-ambient: 8s;
  --motion-tick: 950ms;
  --stagger: 40ms;
  --ease-entrance: cubic-bezier(.2, .7, .3, 1);
  --ease-exit: cubic-bezier(.4, 0, 1, 1);
  --rail-w: 68px;
}

/* ---- Theme: dark (default) ---- */
body, body.theme-dark {
  --bg:        #0d1017;
  --bg-grad:   radial-gradient(1200px 600px at 15% -10%, #1b2540 0%, transparent 60%), #0d1017;
  --surface:   #151a24;
  --surface-2: #1c2230;
  --surface-3: #232b3b;
  --border:    #262e3d;
  --border-hi: #364157;
  --text:      #e8ecf5;
  --text-dim:  #98a3b8;
  --text-faint:#6b7688;
  --accent:    #5b8cff;
  --accent-hi: #7aa2ff;
  --accent-fg: #ffffff;
  --accent-soft:rgba(91,140,255,.14);
  --ok:        #3ecf8e;
  --ok-soft:   rgba(62,207,142,.14);
  --warn:      #f5b544;
  --warn-soft: rgba(245,181,68,.14);
  --danger:    #f2555a;
  --danger-soft:rgba(242,85,90,.14);
  --shadow:    0 1px 2px rgba(0,0,0,.4), 0 4px 16px rgba(0,0,0,.28);
  --shadow-lg: 0 12px 40px rgba(0,0,0,.5);
}

/* ---- Theme: AMOLED ---- */
body.theme-amoled {
  --bg:        #000000;
  --bg-grad:   radial-gradient(900px 500px at 20% -15%, #0d1424 0%, transparent 62%), #000000;
  --surface:   #08090c;
  --surface-2: #101319;
  --surface-3: #171b23;
  --border:    #1b1f28;
  --border-hi: #2b3140;
  --text:      #f2f5fa;
  --text-dim:  #94a0b4;
  --text-faint:#636d7e;
  --accent:    #4f8bff;
  --accent-hi: #74a6ff;
  --accent-soft:rgba(79,139,255,.16);
  --shadow:    0 1px 2px rgba(0,0,0,.9), 0 4px 18px rgba(0,0,0,.7);
  --shadow-lg: 0 14px 44px rgba(0,0,0,.85);
}

/* ---- Theme: cyberpunk ---- */
body.theme-cyberpunk {
  --bg:        #0a0713;
  --bg-grad:   radial-gradient(1000px 520px at 12% -10%, #2a0f47 0%, transparent 58%), radial-gradient(800px 400px at 95% 8%, #06303a 0%, transparent 55%), #0a0713;
  --surface:   #140d22;
  --surface-2: #1c1230;
  --surface-3: #26193f;
  --border:    #33204f;
  --border-hi: #4b2f70;
  --text:      #f6ecff;
  --text-dim:  #b19ad0;
  --text-faint:#8875a3;
  --accent:    #f637d4;
  --accent-hi: #ff6ae0;
  --accent-fg: #ffffff;
  --accent-soft:rgba(246,55,212,.16);
  --ok:        #35f0c0;
  --ok-soft:   rgba(53,240,192,.14);
  --warn:      #ffcc4d;
  --danger:    #ff4d6d;
  --shadow:    0 1px 2px rgba(0,0,0,.6), 0 4px 20px rgba(120,20,140,.3);
  --shadow-lg: 0 14px 46px rgba(140,20,160,.42);
}

/* ---- Theme: light ---- */
body.theme-light {
  --bg:        #f4f6fa;
  --bg-grad:   radial-gradient(1100px 560px at 12% -12%, #e2eaff 0%, transparent 60%), #f4f6fa;
  --surface:   #ffffff;
  --surface-2: #f7f9fc;
  --surface-3: #eef2f8;
  --border:    #dfe5ee;
  --border-hi: #c4cede;
  --text:      #131822;
  --text-dim:  #5a6577;
  --text-faint:#8b95a6;
  --accent:    #2f6bf0;
  --accent-hi: #1d55d4;
  --accent-fg: #ffffff;
  --accent-soft:rgba(47,107,240,.10);
  --ok:        #14915c;
  --ok-soft:   rgba(20,145,92,.12);
  --warn:      #b57611;
  --warn-soft: rgba(181,118,17,.12);
  --danger:    #d3323b;
  --danger-soft:rgba(211,50,59,.10);
  --shadow:    0 1px 2px rgba(16,24,40,.06), 0 4px 14px rgba(16,24,40,.07);
  --shadow-lg: 0 14px 40px rgba(16,24,40,.16);
}

/* ---- Base ---- */
html, body { height: 100%; }
body {
  margin: 0;
  font-family: var(--font);
  font-size: var(--fs-base);
  line-height: 1.55;
  color: var(--text);
  background: var(--bg-grad, var(--bg));
  background-attachment: fixed;
  -webkit-font-smoothing: antialiased;
  transition: background-color .25s var(--ease), color .25s var(--ease);
}
a { color: inherit; text-decoration: none; }
h1, h2, h3, h4 { margin: 0; font-weight: 650; letter-spacing: -.01em; }
p  { margin: 0; }
::selection { background: var(--accent-soft); }

:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: var(--r-sm);
}

/* Scrollbars */
* { scrollbar-width: thin; scrollbar-color: var(--border-hi) transparent; }
*::-webkit-scrollbar { width: 10px; height: 10px; }
*::-webkit-scrollbar-track { background: transparent; }
*::-webkit-scrollbar-thumb { background: var(--border-hi); border-radius: var(--r-full); border: 3px solid transparent; background-clip: content-box; }
*::-webkit-scrollbar-thumb:hover { background: var(--text-faint); background-clip: content-box; }

/* ============================ Layout ============================ */
.app { display: grid; grid-template-columns: var(--sidebar-w) 1fr; min-height: 100vh; }

.sidebar {
  position: sticky; top: 0; height: 100vh;
  display: flex; flex-direction: column;
  background: var(--surface);
  border-right: 1px solid var(--border);
  padding: var(--sp-4) var(--sp-3);
  gap: var(--sp-4);
  overflow-y: auto;
  z-index: 40;
}
.brand { display: flex; align-items: center; gap: var(--sp-3); padding: var(--sp-2); }
.brand-mark {
  width: 36px; height: 36px; flex: none; border-radius: 10px;
  display: grid; place-items: center;
  background: linear-gradient(135deg, var(--accent), var(--accent-hi));
  color: var(--accent-fg); font-size: 17px; font-weight: 700;
  box-shadow: var(--shadow);
}
.brand-text { min-width: 0; }
.brand-name { font-size: var(--fs-base); font-weight: 650; line-height: 1.25; }
.brand-meta { font-size: var(--fs-xs); color: var(--text-faint); }

.nav { display: flex; flex-direction: column; gap: 2px; }
.nav-label {
  font-size: var(--fs-xs); text-transform: uppercase; letter-spacing: .07em;
  color: var(--text-faint); padding: var(--sp-3) var(--sp-2) var(--sp-1);
  font-weight: 600;
}
.nav-item {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: 9px var(--sp-3); border-radius: var(--r-md);
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 500;
  transition: background .16s var(--ease), color .16s var(--ease);
  position: relative;
}
.nav-item:hover { background: var(--surface-2); color: var(--text); }
.nav-item.active { background: var(--accent-soft); color: var(--accent-hi); font-weight: 600; }
.nav-item.active::before {
  content: ""; position: absolute; left: -12px;
  top: 50%; transform: translateY(-50%);
  width: 3px; height: 18px; border-radius: 0 3px 3px 0; background: var(--accent);
}
.nav-ico { width: 18px; text-align: center; font-size: 15px; flex: none; }
.nav-count {
  margin-left: auto; font-size: var(--fs-xs); font-variant-numeric: tabular-nums;
  background: var(--surface-3); color: var(--text-dim);
  padding: 1px 7px; border-radius: var(--r-full); font-weight: 600;
}
.nav-item.active .nav-count { background: var(--accent); color: var(--accent-fg); }

.sidebar-foot { margin-top: auto; display: flex; flex-direction: column; gap: var(--sp-2); }
.vault-chip {
  display: flex; align-items: center; gap: var(--sp-2);
  padding: var(--sp-2) var(--sp-3); border-radius: var(--r-md);
  background: var(--surface-2); border: 1px solid var(--border);
  font-size: var(--fs-xs); color: var(--text-dim); min-width: 0;
}
.vault-chip .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); flex: none; box-shadow: 0 0 0 3px var(--ok-soft); }
.vault-chip .path { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: 10px; }

.main { display: flex; flex-direction: column; min-width: 0; }

.topbar {
  position: sticky; top: 0; z-index: 30;
  height: var(--topbar-h); flex: none;
  display: flex; align-items: center; gap: var(--sp-3);
  padding: 0 var(--sp-5);
  background: var(--surface);
  background: color-mix(in srgb, var(--bg) 86%, transparent);
  backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  border-bottom: 1px solid var(--border);
}
@supports not (backdrop-filter: blur(4px)) { .topbar { background: var(--bg); } }

/* Shown at every width. Under 900px it opens the drawer; above, it collapses
   the sidebar to an icon rail. It used to be display:none until 900px, which
   left the desktop button in the markup but invisible and inert. */
.menu-btn { display: inline-grid; }

.search {
  position: relative; flex: 1; max-width: 460px;
}
.search input {
  width: 100%; height: 38px;
  padding: 0 var(--sp-3) 0 36px;
  border-radius: var(--r-md);
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text); font-size: var(--fs-md); font-family: inherit;
  transition: border-color .16s var(--ease), box-shadow .16s var(--ease);
}
.search input::placeholder { color: var(--text-faint); }
.search input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent); }
.search-ico { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-faint); font-size: 14px; pointer-events: none; }
.search kbd {
  position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
  font-family: var(--font); font-size: 10px; color: var(--text-faint);
  border: 1px solid var(--border); border-radius: 5px; padding: 1px 5px; background: var(--surface-2);
}
.search input:focus ~ kbd { opacity: 0; }

.topbar-right { margin-left: auto; display: flex; align-items: center; gap: var(--sp-2); }

.select {
  height: 34px; padding: 0 26px 0 var(--sp-3);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
  font-size: var(--fs-sm); font-family: inherit; cursor: pointer;
  appearance: none; -webkit-appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, currentColor 50%), linear-gradient(135deg, currentColor 50%, transparent 50%);
  background-position: calc(100% - 14px) 50%, calc(100% - 9px) 50%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
  transition: border-color .16s var(--ease);
}
.select:hover { border-color: var(--border-hi); }
.select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent); }

.content { padding: var(--sp-5); max-width: 1280px; width: 100%; margin: 0 auto; flex: 1; }

.page-head { display: flex; align-items: flex-start; gap: var(--sp-4); margin-bottom: var(--sp-5); flex-wrap: wrap; }
.page-title { font-size: var(--fs-2xl); line-height: 1.2; }
.page-sub { color: var(--text-dim); font-size: var(--fs-md); margin-top: 2px; }
.page-actions { margin-left: auto; display: flex; gap: var(--sp-2); flex-wrap: wrap; }

/* ============================ Components ============================ */
.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 7px;
  height: 36px; padding: 0 var(--sp-4);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
  font-size: var(--fs-md); font-weight: 550; font-family: inherit;
  cursor: pointer; white-space: nowrap;
  transition: background .16s var(--ease), border-color .16s var(--ease), transform .08s var(--ease), box-shadow .16s var(--ease);
}
.btn:hover { background: var(--surface-2); border-color: var(--border-hi); }
.btn:active { transform: translateY(1px); }
.btn-primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); box-shadow: var(--shadow); }
.btn-primary:hover { background: var(--accent-hi); border-color: var(--accent-hi); }
.btn-danger { background: transparent; border-color: var(--danger); color: var(--danger); }
.btn-danger:hover { background: var(--danger-soft); border-color: var(--danger); }
.btn-ghost { background: transparent; border-color: transparent; color: var(--text-dim); }
.btn-ghost:hover { background: var(--surface-2); color: var(--text); }
.btn-sm { height: 30px; padding: 0 var(--sp-3); font-size: var(--fs-sm); }
.btn-block { width: 100%; }
.btn[disabled] { opacity: .5; cursor: not-allowed; }

.icon-btn {
  display: inline-grid; place-items: center;
  width: 30px; height: 30px; flex: none;
  border-radius: var(--r-sm); border: 1px solid transparent;
  background: transparent; color: var(--text-dim);
  cursor: pointer; font-size: 14px; line-height: 1;
  transition: background .14s var(--ease), color .14s var(--ease), border-color .14s var(--ease);
}
.icon-btn:hover { background: var(--surface-3); color: var(--text); border-color: var(--border); }
.icon-btn.danger:hover { background: var(--danger-soft); color: var(--danger); border-color: transparent; }
.icon-row { display: flex; gap: 2px; justify-content: flex-end; align-items: center; }
form.inline { display: inline; margin: 0; }

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--r-lg);
  box-shadow: var(--shadow);
  overflow: hidden;
}
.card-head {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-4) var(--sp-5);
  border-bottom: 1px solid var(--border);
}
.card-head h2, .card-head h3 { font-size: var(--fs-lg); }
.card-head .spacer { margin-left: auto; }
.card-body { padding: var(--sp-5); }
.card-foot {
  padding: var(--sp-3) var(--sp-5);
  border-top: 1px solid var(--border);
  background: var(--surface-2);
  font-size: var(--fs-xs); color: var(--text-faint);
}

/* Stat tiles */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: var(--sp-4); margin-bottom: var(--sp-5); }
.stat {
  display: flex; align-items: center; gap: var(--sp-4);
  padding: var(--sp-4) var(--sp-5);
  background: var(--surface); border: 1px solid var(--border);
  border-radius: var(--r-lg); box-shadow: var(--shadow);
  transition: border-color .16s var(--ease), transform .16s var(--ease);
}
.stat:hover { border-color: var(--border-hi); transform: translateY(-2px); }
.stat-ico {
  width: 42px; height: 42px; flex: none; border-radius: var(--r-md);
  display: grid; place-items: center; font-size: 19px;
  background: var(--accent-soft); color: var(--accent-hi);
}
.stat-n { font-size: var(--fs-2xl); font-weight: 680; line-height: 1.1; font-variant-numeric: tabular-nums; }
.stat-l { font-size: var(--fs-sm); color: var(--text-dim); }

/* Tables */
.table-wrap { overflow-x: auto; }
table.t { width: 100%; border-collapse: collapse; font-size: var(--fs-md); }
table.t th {
  text-align: left; font-weight: 600; font-size: var(--fs-xs);
  text-transform: uppercase; letter-spacing: .05em; color: var(--text-faint);
  padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border);
  white-space: nowrap; background: var(--surface-2);
  position: sticky; top: 0; z-index: 1;
}
table.t td { padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border); vertical-align: middle; }
table.t tbody tr { transition: background .13s var(--ease); }
table.t tbody tr:hover { background: var(--surface-2); }
table.t tbody tr:last-child td { border-bottom: none; }
table.t td.num { font-variant-numeric: tabular-nums; color: var(--text-faint); width: 56px; }
table.t td.actions { text-align: right; width: 1%; white-space: nowrap; }
table.t td.strong { font-weight: 550; }
.mono { font-family: var(--mono); font-size: var(--fs-sm); }

.empty { padding: var(--sp-7) var(--sp-5); text-align: center; color: var(--text-dim); }
.empty-ico { font-size: 34px; opacity: .5; margin-bottom: var(--sp-3); }
.empty-t { font-weight: 600; color: var(--text); margin-bottom: var(--sp-1); }
.empty-d { font-size: var(--fs-md); margin-bottom: var(--sp-4); }

/* Forms */
.field { margin-bottom: var(--sp-4); }
.field > label { display: block; font-size: var(--fs-sm); font-weight: 550; color: var(--text-dim); margin-bottom: 6px; }
.input, textarea.input, select.input {
  width: 100%; min-height: 38px; padding: 8px var(--sp-3);
  border-radius: var(--r-md); border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text);
  font-size: var(--fs-base); font-family: inherit; line-height: 1.5;
  transition: border-color .16s var(--ease), box-shadow .16s var(--ease), background .16s var(--ease);
}
.input::placeholder { color: var(--text-faint); }
/* The ring is --accent, not --accent-soft. Measured on the Console palette,
   an --accent-soft ring is 1.15:1 against the field it surrounds -- invisible,
   on every form in the dashboard, for anyone navigating by keyboard. WCAG
   1.4.11 wants 3.0:1 for a non-text indicator; --accent gives 9.4:1.
   outline:none is only acceptable because this replaces it in the same rule. */
.input:focus { outline: none; border-color: var(--accent); background: var(--surface); box-shadow: 0 0 0 2px var(--accent); }
textarea.input { min-height: 120px; resize: vertical; font-family: var(--mono); font-size: var(--fs-md); }
.hint { font-size: var(--fs-xs); color: var(--text-faint); margin-top: 5px; }
.form-actions { display: flex; gap: var(--sp-2); margin-top: var(--sp-5); flex-wrap: wrap; }
.row2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); }

/* Chips / badges */
.chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 10px; border-radius: var(--r-full);
  font-size: var(--fs-xs); font-weight: 600;
  background: var(--surface-3); color: var(--text-dim); border: 1px solid var(--border);
}
.chip.ok { background: var(--ok-soft); color: var(--ok); border-color: transparent; }
.chip.warn { background: var(--warn-soft); color: var(--warn); border-color: transparent; }
.chip-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

/* Flash / alerts */
.flash {
  display: flex; align-items: center; gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4); margin-bottom: var(--sp-4);
  border-radius: var(--r-md); font-size: var(--fs-md);
  background: var(--ok-soft); color: var(--ok);
  border: 1px solid transparent;
}
.flash.error { background: var(--danger-soft); color: var(--danger); }
.msg {
  padding: var(--sp-3) var(--sp-4); margin-bottom: var(--sp-4);
  border-radius: var(--r-md); font-size: var(--fs-md);
  background: var(--danger-soft); color: var(--danger);
}

/* Secret reveal field */
.secret {
  display: flex; align-items: center; gap: var(--sp-2);
  padding: var(--sp-3) var(--sp-4);
  background: var(--surface-2); border: 1px solid var(--border);
  border-radius: var(--r-md);
}
.secret-val { font-family: var(--mono); font-size: var(--fs-base); word-break: break-all; flex: 1; min-width: 0; }
.secret-val.masked { letter-spacing: .18em; color: var(--text-faint); }

/* Definition list for view pages */
.dl { display: grid; grid-template-columns: 150px 1fr; gap: var(--sp-3) var(--sp-4); align-items: start; }
.dl dt { font-size: var(--fs-sm); color: var(--text-dim); font-weight: 550; }
.dl dd { margin: 0; font-size: var(--fs-base); word-break: break-word; }

/* Toast */
#toast {
  position: fixed; left: 50%; bottom: 26px; transform: translate(-50%, 14px);
  background: var(--surface-3); color: var(--text);
  border: 1px solid var(--border-hi); border-radius: var(--r-md);
  padding: 10px var(--sp-4); font-size: var(--fs-md); font-weight: 550;
  box-shadow: var(--shadow-lg); z-index: 200;
  opacity: 0; pointer-events: none;
  transition: opacity .2s var(--ease), transform .2s var(--ease);
}
#toast.show { opacity: 1; transform: translate(-50%, 0); }
#toast.error { border-color: var(--danger); color: var(--danger); }

/* Auto-lock countdown */
.lockbar { display: flex; align-items: center; gap: 7px; font-size: var(--fs-xs); color: var(--text-faint); }
.lockbar.warn { color: var(--warn); font-weight: 600; }
.lockbar .track { width: 44px; height: 4px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; }
/* scaleX, not width: width relayouts the track on every one of these frames,
   and this one repaints once a second for the life of the session (A07 4.6). */
.lockbar .fill { height: 100%; width: 100%; transform-origin: left center; background: var(--ok); transition: transform var(--motion-tick) linear, background var(--motion-base) var(--ease); }
.lockbar.warn .fill { background: var(--warn); }

/* TOTP */
.totp {
  display: flex; flex-direction: column; align-items: center; gap: var(--sp-3);
  padding: var(--sp-6) var(--sp-5);
}
.totp-code {
  font-family: var(--mono); font-size: 44px; font-weight: 600;
  letter-spacing: .14em; color: var(--accent-hi);
  font-variant-numeric: tabular-nums; line-height: 1;
}
.totp-ring { --pct: 100; width: 100%; max-width: 240px; height: 5px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; }
.totp-ring i { display: block; height: 100%; width: 100%; transform-origin: left center; transform: scaleX(calc(var(--pct) / 100)); background: var(--accent); transition: transform var(--motion-tick) linear; }

/* Login */
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: var(--sp-5); }
.login-card { width: 100%; max-width: 400px; }
.login-brand { text-align: center; margin-bottom: var(--sp-5); }
.login-brand .brand-mark { margin: 0 auto var(--sp-3); width: 52px; height: 52px; font-size: 24px; border-radius: 14px; }
.login-brand h1 { font-size: var(--fs-xl); }
.login-brand p { color: var(--text-dim); font-size: var(--fs-md); margin-top: 4px; }

/* Generator */
.gen-out {
  font-family: var(--mono); font-size: var(--fs-xl); font-weight: 600;
  padding: var(--sp-4); border-radius: var(--r-md);
  background: var(--surface-2); border: 1px dashed var(--border-hi);
  word-break: break-all; text-align: center; min-height: 62px;
  display: grid; place-items: center;
}
.meter { height: 6px; border-radius: var(--r-full); background: var(--surface-3); overflow: hidden; margin-top: var(--sp-3); }
.meter i { display: block; height: 100%; width: 100%; transform-origin: left center; transform: scaleX(0); transition: transform var(--motion-base) var(--ease), background var(--motion-base) var(--ease); }
.switch-row { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid var(--border); }
.switch-row:last-child { border-bottom: none; }
.switch-row span { font-size: var(--fs-md); }
input[type="range"] { width: 100%; accent-color: var(--accent); }
input[type="checkbox"] { accent-color: var(--accent); width: 16px; height: 16px; cursor: pointer; }

/* Overlay (import progress) */
.overlay {
  position: absolute; inset: 0; z-index: 5;
  display: none; place-items: center;
  background: var(--surface);
  background: color-mix(in srgb, var(--surface) 88%, transparent);
  backdrop-filter: blur(3px); -webkit-backdrop-filter: blur(3px);
  border-radius: var(--r-lg);
}
.overlay.on { display: grid; }
.spinner {
  width: 30px; height: 30px; border-radius: 50%;
  border: 3px solid var(--border-hi); border-top-color: var(--accent);
  animation: spin .8s linear infinite; margin: 0 auto var(--sp-3);
}
@keyframes spin { to { transform: rotate(360deg); } }
.overlay-in { text-align: center; font-size: var(--fs-md); color: var(--text-dim); }

/* Utilities */
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: var(--sp-4); }
.stack { display: flex; flex-direction: column; gap: var(--sp-4); }
.muted { color: var(--text-dim); }
.faint { color: var(--text-faint); font-size: var(--fs-sm); }
.hidden { display: none !important; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
.icon { inline-size:20px; block-size:20px; flex:none; fill:none; stroke:currentColor;
  stroke-width:1.5; stroke-linecap:butt; stroke-linejoin:miter; }
.icon-sm { inline-size:16px; block-size:16px; }
.icon-lg { inline-size:32px; block-size:32px; stroke-width:2; }
.brand-mark .icon { inline-size:24px; block-size:24px; stroke-width:1.75; }
.nav-ico .icon, .icon-btn .icon { inline-size:16px; block-size:16px; }
.stat-ico .icon { inline-size:20px; block-size:20px; }
.empty-ico .icon { inline-size:32px; block-size:32px; stroke-width:2; }

/* ============================ Responsive ============================ */
.scrim { display: none; }

@media (max-width: 900px) {
  .app { grid-template-columns: 1fr; }
  .sidebar {
    position: fixed; inset: 0 auto 0 0; width: 272px;
    transform: translateX(-100%);
    transition: transform .24s var(--ease);
    box-shadow: var(--shadow-lg);
  }
  body.nav-open .sidebar { transform: translateX(0); }
  .scrim {
    display: block; position: fixed; inset: 0; z-index: 35;
    background: rgba(0,0,0,.5); opacity: 0; pointer-events: none;
    transition: opacity var(--motion-base) var(--ease);
  }
  body.nav-open .scrim { opacity: 1; pointer-events: auto; }
  .menu-btn { display: inline-grid; }
  .content { padding: var(--sp-4); }
  .search kbd { display: none; }
  .dl { grid-template-columns: 1fr; gap: var(--sp-1); }
  .dl dt { margin-top: var(--sp-3); }
  .row2 { grid-template-columns: 1fr; }
  .page-actions { width: 100%; }
}
@media (max-width: 620px) {
  .topbar { padding: 0 var(--sp-3); gap: var(--sp-2); }
  /* Only the lockbar track is in the narrow main column. The vault chip
     sits in the sidebar drawer, which is a fixed 272px panel, so hiding
     its path here left an empty box holding a lone status dot. The path
     already ellipsises, which is the right degradation. */
  .lockbar .track { display: none; }
  .totp-code { font-size: 34px; }
  .stats { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: var(--sp-3); }
  .stat { padding: var(--sp-3) var(--sp-4); gap: var(--sp-3); }
  .stat-ico { width: 36px; height: 36px; font-size: 16px; }
  .stat-n { font-size: var(--fs-xl); }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
}

/* Console / CNS-18: the interface is a transcript. */
:root {
  --bg:#0a0e0c; --surface:#121815; --surface-2:#0f1412; --surface-3:#18201c;
  --border:#232e28; --border-hi:#3b4a42; --text:#d8e8dc; --text-dim:#9aada1; --text-faint:#84968b;
  --accent:#5fd095; --accent-hi:#7be0aa; --accent-fg:#05120b; --accent-soft:#10251a;
  --ok:#5fd095; --ok-soft:#10251a; --warn:#dda95e; --warn-soft:#1c1610;
  --danger:#ff8b84; --danger-soft:#291311; --shadow:none; --shadow-lg:none;
  --r-sm:0; --r-md:0; --r-lg:0; --r-full:0;
  --font:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;
  --mono:"JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace;
  --ease:cubic-bezier(.2,.7,.3,1); --sidebar-w:248px; color-scheme:dark;
}
body, body.theme-dark, body.theme-amoled, body.theme-cyberpunk, body.theme-light {
  --bg:#0a0e0c; --surface:#121815; --surface-2:#0f1412; --surface-3:#18201c;
  --border:#232e28; --border-hi:#3b4a42; --text:#d8e8dc; --text-dim:#9aada1; --text-faint:#84968b;
  --accent:#5fd095; --accent-hi:#7be0aa; --accent-fg:#05120b; --accent-soft:#10251a;
  --ok:#5fd095; --ok-soft:#10251a; --warn:#dda95e; --warn-soft:#1c1610;
  --danger:#ff8b84; --danger-soft:#291311; --shadow:none; --shadow-lg:none;
  background:var(--bg); color:var(--text);
}
body { font-variant-numeric:tabular-nums; transition:none; }
body::before { content:""; position:fixed; inset:0; pointer-events:none; opacity:.16;
  background-image:repeating-linear-gradient(to bottom,var(--border) 0 1px,transparent 1px 4px); }
.skip-link { position:fixed; top:var(--sp-2); left:var(--sp-2); z-index:300; padding:var(--sp-2) var(--sp-3);
  background:var(--accent); color:var(--accent-fg); transform:translateY(-160%); }
.skip-link:focus { transform:translateY(0); }
.sidebar { background:var(--bg); padding:var(--sp-4); }
.brand { border-bottom:1px solid var(--border); padding:var(--sp-2) 0 var(--sp-4); }
.brand-mark { width:36px; height:36px; border:1px solid var(--accent); background:transparent; color:var(--accent); box-shadow:none; }
.brand-name::before { content:"$ "; color:var(--accent); }
.brand-meta { color:var(--warn); }
.nav { gap:0; }
.nav-label { padding:var(--sp-4) 0 var(--sp-2); color:var(--text-faint); }
.nav-label::before { content:"# "; color:var(--warn); }
.nav-item { border-left:2px solid transparent; padding:var(--sp-2) var(--sp-3); }
.nav-item:hover { background:var(--surface-2); color:var(--accent); }
.nav-item.active { border-left-color:var(--accent); background:var(--accent-soft); color:var(--accent); }
.nav-item.active::before { display:none; }
.nav-count, .nav-item.active .nav-count { background:var(--warn-soft); color:var(--warn); border:1px solid var(--border); }
.vault-chip { border-left:2px solid var(--warn); background:var(--surface-2); }
.vault-chip .dot { background:var(--ok); box-shadow:none; }
.topbar { background:var(--bg); backdrop-filter:none; -webkit-backdrop-filter:none; }
.content { max-width:1180px; padding:var(--sp-6); position:relative; }
.page-head { border-bottom:1px solid var(--border); padding-bottom:var(--sp-4); }
.page-title { font-weight:500; letter-spacing:-.01em; }
.page-title::before { content:"$ "; color:var(--accent); }
.page-sub { color:var(--text-dim); margin-top:var(--sp-2); }
.page-sub::before { content:"> "; color:var(--warn); }
.console-hero { border-left:2px solid var(--accent); padding:var(--sp-5); margin-bottom:var(--sp-5); background:var(--surface-2); }
.console-hero .eyebrow { color:var(--text-dim); font-size:var(--fs-sm); margin-bottom:var(--sp-3); }
.console-hero .eyebrow::before { content:"> "; color:var(--accent); }
.console-hero h1 { font-size:clamp(24px,4vw,42px); font-weight:500; margin-bottom:var(--sp-3); }
.console-hero h1::before { content:"$ "; color:var(--accent); }
.console-output { display:grid; gap:var(--sp-1); color:var(--warn); margin-bottom:var(--sp-3); }
.console-output span::before { content:"[emit] "; color:var(--text-faint); }
.console-output i { font-style:normal; }
.console-hero .lede { max-width:66ch; color:var(--text-dim); }
.console-hero .lede::after { content:""; display:inline-block; width:.55em; height:1em; margin-left:.25em;
  vertical-align:-.14em; background:var(--accent); animation:cnsblink 1.1s steps(2,end) infinite; }
@keyframes cnsblink { 50% { opacity:0; } }
.card, .stat { border-left:2px solid var(--accent); box-shadow:none; background:var(--surface); }
.card-head h2::before, .card-head h3::before { content:"* "; color:var(--warn); }
.stat { display:block; }
.stat:hover { transform:none; border-color:var(--border); border-left-color:var(--accent); background:var(--surface-2); }
.stat-ico { width:auto; height:auto; display:inline; background:none; color:var(--text-faint); margin-right:var(--sp-2); }
.stat-n { display:block; color:var(--warn); margin-top:var(--sp-2); }
.stat-l { display:block; margin-top:var(--sp-1); }
.btn, .icon-btn, .select, .input, textarea.input, select.input, .search input { border-radius:0; }
.btn-primary { box-shadow:none; }
.chip { border-radius:0; background:var(--warn-soft); color:var(--warn); }
.flash, .msg { border-radius:0; border-left:2px solid currentColor; }
.secret-val, .totp-code, .gen-out, .stat-n, .num, .faint.mono { color:var(--warn); }
#toast { left:auto; right:var(--sp-4); bottom:var(--sp-4); transform:none; border-left:2px solid var(--accent); box-shadow:none; }
#toast { transform:translateY(var(--sp-2)); transition:opacity var(--motion-fast) var(--ease), transform var(--motion-base) var(--ease); }
#toast.show { transform:translateY(0); }
.overlay { border-radius:0; backdrop-filter:none; -webkit-backdrop-filter:none; background:var(--surface); border-left:2px solid var(--accent); }
.overlay { display:grid; visibility:hidden; opacity:0; pointer-events:none;
  transition:opacity var(--motion-base) var(--ease), visibility 0s linear var(--motion-base); }
.overlay.on { visibility:visible; opacity:1; pointer-events:auto; transition-delay:0s; }
.spinner { border-radius:0; }
.totp-code.code-updated { animation:code-updated var(--motion-live) var(--ease); }
@keyframes code-updated {
  0% { opacity:.45; transform:translateY(var(--sp-1)); }
  100% { opacity:1; transform:translateY(0); }
}

@media (max-width:620px) {
  .content, .console-hero { padding:var(--sp-4); }
  .stats { grid-template-columns:1fr; }
  table.t thead { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); }
  table.t, table.t tbody, table.t tr, table.t td { display:block; width:100%; }
  table.t tr { border-bottom:1px solid var(--border); padding:var(--sp-2) 0; }
  table.t td { border:0; padding:var(--sp-1) var(--sp-3); white-space:normal; }
  table.t td.actions { width:100%; text-align:left; }
  .icon-row { justify-content:flex-start; }
}
@media (prefers-reduced-motion:reduce) {
  .console-hero .lede::after, .totp-code.code-updated { animation:none; }
  .scrim, #toast, .overlay { transition:none; }
}

@media print { .sidebar, .topbar, .page-actions, #toast { display: none !important; } .app { grid-template-columns: 1fr; } }

/* viewport-fit=cover lets the page paint under the status bar, the notch and
   the home indicator, and a home screen launch has no browser chrome holding
   them off. env() resolves to 0 wherever the browser already reserves that
   space, so these are unconditional rather than scoped to standalone.

   The sidebar needs insets of its own: under 900px it is position:fixed, so
   padding on body does not reach it. It also cannot keep height:100vh, which
   on iOS measures the largest possible viewport rather than the visible one
   and pushed .sidebar-foot -- the vault chip and the logout button -- off the
   bottom of the screen. 100dvh tracks the viewport actually on display, and
   browsers without dvh keep the 100vh above. */
.sidebar {
  height: 100dvh;
  padding-top: calc(var(--sp-4) + env(safe-area-inset-top));
  padding-bottom: calc(var(--sp-4) + env(safe-area-inset-bottom));
  padding-left: calc(var(--sp-4) + env(safe-area-inset-left));
}
/* The topbar sets an explicit height and box-sizing is border-box, so the
   inset has to grow the box or it would eat into the row and squash it. */
.topbar {
  height: calc(var(--topbar-h) + env(safe-area-inset-top));
  padding-top: env(safe-area-inset-top);
}
body { padding-bottom: env(safe-area-inset-bottom); }

/* Tag chips, rotation badges and the security score.
   Declared last on purpose: the console block above restyles every .chip to
   the warn colour, so these variants have to come after it to win. */
.tagbar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: var(--sp-3); }
.chip-btn { cursor: pointer; font-family: inherit; }
.chip-btn:hover { border-color: var(--accent); }
.chip-on { background: var(--accent); color: var(--bg); border-color: transparent; }
.chip-warn { background: var(--warn-soft); color: var(--warn); border-color: transparent; }
tr[data-row] .chip { margin-left: 6px; vertical-align: middle; }
.score-ok { color: var(--ok); }
.score-warn { color: var(--warn); }
.score-bad { color: var(--danger); }

/* ============================================================
   Desktop rail, and the motion layer.
   Declared last for the same reason the chips above are: the console
   block restyles most of these selectors, so anything that has to win
   over it comes after it.
   ============================================================ */

/* ---- Sidebar rail (>= 901px) ----
   Under 900px the sidebar is an off-canvas drawer and the hamburger opens
   it. Above that there is nothing to open, so the same control collapses
   the sidebar to an icon rail instead.

   Labels are clipped, not display:none, so they stay in the accessibility
   tree -- a screen reader still reads "Passwords", and the tooltip is a
   convenience for pointer users rather than the only remaining name.

   The collapse is deliberately instant. The sidebar is a grid column, so
   animating it would animate grid-template-columns and relayout the whole
   page on every frame, which A07 4.6 forbids outright. */
@media (min-width: 901px) {
  body.rail { --sidebar-w: var(--rail-w); }
  body.rail .sidebar { padding-left: var(--sp-2); padding-right: var(--sp-2); }
  body.rail .brand { justify-content: center; }
  body.rail .nav-item { justify-content: center; padding-left: 0; padding-right: 0; }
  body.rail .vault-chip { justify-content: center; padding-left: 0; padding-right: 0; }
  body.rail .sidebar-foot .btn { padding-left: 0; padding-right: 0; }
  body.rail .brand-text,
  body.rail .nav-text,
  body.rail .nav-label,
  body.rail .nav-count,
  body.rail .vault-chip .path,
  body.rail .rail-label {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  /* With the label gone, the left rule and the tinted ground are the only
     things left saying which page you are on, so both have to stay. */
  body.rail .nav-item.active .nav-ico { color: var(--accent); }
}

/* ---- First-sight reveal: the transcript prints ----
   Blocks arrive in reading order, one stagger step apart, once per load.
   A07 4.2 forbids entrance animation that re-fires on scroll, so this is
   bound to load and never to an IntersectionObserver; 4.4 caps the stagger
   at eight items, past which the group arrives as one.

   The static state is the truth. These rules only ever *add* motion: they
   sit behind an explicit no-preference query and behind a class that only
   JS sets. With JS off, motion off, or the query unsupported, every block
   is already at its final position -- which is the failure A07 4.5 calls
   the single most common bug in this area. */
@media (prefers-reduced-motion: no-preference) {
  body.can-reveal .content > [data-reveal] {
    opacity: 0;
    transform: translateY(var(--sp-2));
    transition: opacity var(--motion-reveal) var(--ease-entrance),
                transform var(--motion-reveal) var(--ease-entrance);
    transition-delay: var(--reveal-delay, 0ms);
  }
  body.can-reveal .content > [data-reveal][data-seen] { opacity: 1; transform: none; }
}

/* ---- Live session indicator ----
   A07 4.2 permits a loop only on something genuinely live. This tracks the
   idle countdown and stops the moment it is paused, so it reports session
   state rather than decorating the sidebar. */
@keyframes sessionpulse {
  0%, 92%, 100% { opacity: 1; }
  96%           { opacity: .3; }
}
@media (prefers-reduced-motion: no-preference) {
  body:not(.lock-paused) .vault-chip .dot {
    animation: sessionpulse var(--motion-ambient) var(--ease) infinite;
  }
}

/* ---- Row hover ----
   The border is always present and always the same width, so hovering a row
   repaints a colour instead of reflowing the table. */
table.t tbody tr[data-row] td:first-child {
  border-left: 2px solid transparent;
  transition: border-color var(--motion-base) var(--ease);
}
table.t tbody tr[data-row]:hover td:first-child { border-left-color: var(--accent); }

/* ---- Entrances are slower than exits ----
   A07 4.3. A departing surface has already been decided about; matching the
   two durations is what makes dismissal feel sticky. */
@media (max-width: 900px) {
  .sidebar { transition: transform var(--motion-fast) var(--ease-exit); }
  .scrim { transition: opacity var(--motion-fast) var(--ease-exit); }
  body.nav-open .sidebar { transition: transform var(--motion-slow) var(--ease-entrance); }
  body.nav-open .scrim { transition: opacity var(--motion-slow) var(--ease-entrance); }
}

@media (prefers-reduced-motion: reduce) {
  .vault-chip .dot { animation: none; }
  /* Belt and braces: the reveal rules above cannot strand content because
     they only exist under no-preference, but stating the final state here
     means a future edit that moves them cannot either. */
  .content > [data-reveal] { opacity: 1; transform: none; }
}
</style>
"""


SHELL_SCRIPT = """
<script>
(function () {
  /* ---- toast ---------------------------------------------------------- */
  var toastTimer;
  function toast(msg, isErr) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.toggle("error", !!isErr);
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2000);
  }
  window.SPM_toast = toast;

  /* ---- clipboard ------------------------------------------------------ */
  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }
  window.SPM_copy = function (text, label) {
    function ok() { toast(label || t("toast.copy_success", "Copied to clipboard.")); }
    function bad() { toast(t("toast.copy_fail", "Copy failed."), true); }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(ok).catch(fallback);
    } else { fallback(); }
    function fallback() {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        var done = document.execCommand("copy");
        document.body.removeChild(ta);
        done ? ok() : bad();
      } catch (e) { bad(); }
    }
  };

  /* ---- sidebar: a drawer under 900px, an icon rail above ---------------
     One control, two jobs, because the sidebar has two shapes. Below 900px
     it is off-canvas and the button opens it; above, it is always on screen
     and there is nothing to open, so the button collapses it to icons
     instead. That upper half did not exist -- the button was rendered and
     then hidden by CSS, so on a desktop it was dead markup. */
  var DESKTOP = "(min-width: 901px)";
  function isDesktop() {
    return !!(window.matchMedia && window.matchMedia(DESKTOP).matches);
  }
  function syncTrigger() {
    var trigger = document.querySelector(".menu-btn");
    if (!trigger || !document.body) return;
    var desktop = isDesktop();
    var expanded = desktop
      ? !document.body.classList.contains("rail")
      : document.body.classList.contains("nav-open");
    /* aria-expanded describes the sidebar either way: on desktop "expanded"
       means showing labels, on mobile it means on screen. */
    trigger.setAttribute("aria-expanded", expanded ? "true" : "false");
    var key, fb;
    if (desktop) {
      key = expanded ? "nav.collapse" : "nav.expand";
      fb = expanded ? "Collapse sidebar" : "Expand sidebar";
    } else {
      key = expanded ? "nav.close" : "nav.open";
      fb = expanded ? "Close menu" : "Menu";
    }
    trigger.setAttribute("aria-label", t(key, fb));
    trigger.setAttribute("title", t(key, fb));
    trigger.setAttribute("data-i18n-title", key);
  }
  function setNav(open) {
    document.body.classList.toggle("nav-open", open);
    syncTrigger();
  }
  function setRail(on) {
    document.body.classList.toggle("rail", on);
    /* Storage can throw outright where site data is blocked, and a sidebar
       that refuses to collapse because a preference could not be saved is a
       worse failure than one that forgets. */
    try { localStorage.setItem("spm.rail", on ? "1" : "0"); } catch (e) {}
    syncTrigger();
  }
  window.SPM_toggleNav = function () {
    if (isDesktop()) setRail(!document.body.classList.contains("rail"));
    else setNav(!document.body.classList.contains("nav-open"));
  };
  function wireMobileNav() {
    // Navigation is deliberately wired directly. Delegating through an SVG
    // event target made the installed iOS web app's hamburger a no-op.
    var trigger = document.querySelector(".menu-btn");
    var scrim = document.querySelector(".scrim");
    if (trigger) trigger.addEventListener("click", function (e) {
      e.preventDefault();
      window.SPM_toggleNav();
    });
    if (scrim) scrim.addEventListener("click", function (e) {
      e.preventDefault();
      setNav(false);
    });
    /* Crossing the breakpoint with the drawer open would otherwise leave
       nav-open set on a layout that has no drawer, and the button's label
       would still describe the other mode. */
    if (window.matchMedia) {
      var mq = window.matchMedia(DESKTOP);
      var onChange = function () {
        if (mq.matches) document.body.classList.remove("nav-open");
        syncTrigger();
      };
      if (mq.addEventListener) mq.addEventListener("change", onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
    syncTrigger();
  }

  /* ---- first-sight reveal ---------------------------------------------
     The transcript prints: the page's top-level blocks arrive in reading
     order, once per load. Bound to load and never to scroll position --
     A07 4.2 prohibits entrance animation that re-fires as content scrolls
     into view.

     Everything here only ever adds motion on top of a finished page. The
     hiding rules live behind a no-preference query *and* behind the
     can-reveal class set below, so with JS off, motion off, or the query
     unsupported, the content was never hidden in the first place. */
  function wireReveal() {
    var main = document.querySelector(".content");
    if (!main || !window.matchMedia) return;
    if (!window.matchMedia("(prefers-reduced-motion: no-preference)").matches) return;
    var kids = [];
    for (var i = 0; i < main.children.length; i++) {
      var el = main.children[i];
      /* The import overlay is positioned over the card it belongs to and is
         shown by its own class; giving it an entrance would fight that. */
      if (el.classList && el.classList.contains("overlay")) continue;
      kids.push(el);
    }
    if (!kids.length) return;
    /* A07 4.4 caps the stagger at about eight items. Past that the delay on
       the last item reads as the page being slow rather than as sequence,
       so the group arrives together instead. */
    var stagger = kids.length <= 8;
    kids.forEach(function (el, i) {
      el.setAttribute("data-reveal", "");
      if (stagger) el.style.setProperty("--reveal-delay", "calc(var(--stagger) * " + i + ")");
    });
    document.body.classList.add("can-reveal");
    var shown = false;
    function show() {
      if (shown) return;
      shown = true;
      kids.forEach(function (el) { el.setAttribute("data-seen", ""); });
    }
    /* requestAnimationFrame does not fire in a background tab, so a page
       opened in one would sit at opacity 0 until it was focused. The timer
       is the guarantee; the frames are just the fast path. */
    setTimeout(show, 1000);
    requestAnimationFrame(function () { requestAnimationFrame(show); });
  }

  /* ---- instant table filter ------------------------------------------- */
  function wireSearch() {
    var box = document.getElementById("q");
    if (!box) return;
    function run() {
      var term = box.value.trim().toLowerCase();
      var any = false;
      document.querySelectorAll("[data-searchable] tbody tr[data-row]").forEach(function (tr) {
        var hit = !term || (tr.getAttribute("data-row") || "").indexOf(term) >= 0;
        tr.classList.toggle("hidden", !hit);
        if (hit) any = true;
      });
      document.querySelectorAll("[data-empty-search]").forEach(function (n) {
        n.classList.toggle("hidden", any || !term);
      });
    }
    box.addEventListener("input", run);
    box.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { box.value = ""; run(); box.blur(); }
    });
    run();
  }

  /* ---- keyboard shortcuts --------------------------------------------- */
  document.addEventListener("keydown", function (e) {
    var tag = (e.target && e.target.tagName || "").toLowerCase();
    var typing = tag === "input" || tag === "textarea" || tag === "select";
    if (e.key === "/" && !typing) {
      var box = document.getElementById("q");
      if (box) { e.preventDefault(); box.focus(); box.select(); }
    }
    if (e.key === "Escape" && document.body.classList.contains("nav-open")) {
      setNav(false);
    }
  });

  document.addEventListener("DOMContentLoaded", function () {
    wireMobileNav();
    wireSearch();
    try { wireReveal(); } catch (e) { document.body.classList.remove("can-reveal"); }
  });
})();
</script>
"""

# Auto-lock with a visible countdown. Same 30s idle policy as before, but the
# user can now see it coming instead of being logged out with no warning.
LOCKBAR_SCRIPT = """
<script>
(function () {
  var IDLE_MS = 30000, WARN_AT = 10;
  var deadline = Date.now() + IDLE_MS, paused = false, locking = false, ticker;
  /* The session dot is allowed to pulse only while the session is actually
     counting down (A07 4.2 permits a loop on live state and nothing else),
     so the countdown owns the class and the stylesheet reads it. */
  function syncLive() {
    if (document.body) document.body.classList.toggle("lock-paused", paused || locking);
  }
  function reset() { if (!paused && !locking) deadline = Date.now() + IDLE_MS; }
  function render() {
    var left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    var bar = document.getElementById("lockbar");
    if (bar) {
      var fill = bar.querySelector(".fill");
      if (fill) fill.style.transform = "scaleX(" + (left / (IDLE_MS / 1000)) + ")";
      bar.classList.toggle("warn", left <= WARN_AT);
      var lbl = bar.querySelector(".lbl");
      if (lbl) {
        var t = (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.in", "Locks in") : "Locks in";
        lbl.textContent = paused ? ((window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t("lock.paused", "Lock paused") : "Lock paused") : (t + " " + left + "s");
      }
    }
    if (!paused && !locking && left <= 0) {
      locking = true;
      syncLive();
      clearInterval(ticker);
      lock();
    }
  }
  /* Suspending is a server-side state change, not a redirect. The 2.10.14 bug
     is the reason: a CDN rewrote these scripts out of existence and the lock
     silently stopped existing. If suspension lived in this file, anyone
     holding the phone could disable JavaScript and walk straight past it.
     This function only asks; the server is what enforces. Any failure falls
     through to a full logout, which is the safe direction. */
  function lock() {
    var cfg = window.SPM_UNLOCK;
    if (!cfg || !cfg.available || !window.PublicKeyCredential) {
      window.location.replace("/logout");
      return;
    }
    fetch("/unlock/suspend", {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({csrf: cfg.csrf})
    }).then(function (r) {
      window.location.replace(r.ok ? "/unlock" : "/logout");
    }).catch(function () {
      window.location.replace("/logout");
    });
  }
  window.SPM_AutoLock = {
    pause: function () { paused = true; syncLive(); render(); },
    resume: function () { paused = false; syncLive(); reset(); render(); },
    restart: reset
  };
  ["click", "keydown", "mousemove", "touchstart", "scroll"].forEach(function (ev) {
    window.addEventListener(ev, reset, { passive: true });
  });
  ticker = setInterval(render, 1000);
  document.addEventListener("DOMContentLoaded", render);
  window.addEventListener("pagehide", function () { clearInterval(ticker); });
  window.addEventListener("pageshow", function (event) {
    if (!event.persisted || locking) return;
    /* Timers are frozen in the back/forward cache, so the interval never
       observed the idle time that elapsed while the page was away. The
       deadline is the only surviving evidence: honour it instead of
       resetting, or returning via Back would hand back an unlocked vault. */
    clearInterval(ticker);
    if (Date.now() >= deadline) {
      locking = true;
      lock();
      return;
    }
    ticker = setInterval(render, 1000);
    render();
  });
})();
</script>
"""

ICON_SPRITE = """
<svg class="icon-sprite" aria-hidden="true" width="0" height="0" style="position:absolute;overflow:hidden">
  <symbol id="i-brand" viewBox="0 0 24 24"><path d="M4 6l5 6-5 6M12 18h8M12 6h8"/></symbol>
  <symbol id="i-overview" viewBox="0 0 24 24"><path d="M3.5 3.5h7v7h-7zM13.5 3.5h7v7h-7zM3.5 13.5h7v7h-7zM13.5 13.5h7v7h-7z"/></symbol>
  <symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="12" r="4.5"/><path d="M12.5 12H21M17 12v3M20 12v2"/></symbol>
  <symbol id="i-note" viewBox="0 0 24 24"><path d="M4 3.5h16v17H4zM7 8h10M7 12h10M7 16h6"/></symbol>
  <symbol id="i-phrase" viewBox="0 0 24 24"><path d="M5 5H2.5v14H5M19 5h2.5v14H19M8 9h8M8 15h8"/></symbol>
  <symbol id="i-authenticator" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 6.5V12l4 2M8 3l-2-2M16 3l2-2"/></symbol>
  <symbol id="i-backup" viewBox="0 0 24 24"><path d="M3.5 5.5h17v13h-17zM3.5 12h17M9 5.5v13M15 5.5v13"/></symbol>
  <symbol id="i-generator" viewBox="0 0 24 24"><path d="M12 2.5V8M12 16v5.5M2.5 12H8M16 12h5.5M5.5 5.5l4 4M14.5 14.5l4 4M18.5 5.5l-4 4M9.5 14.5l-4 4"/></symbol>
  <symbol id="i-transfer" viewBox="0 0 24 24"><path d="M7 3v17M3 7l4-4 4 4M17 21V4M13 17l4 4 4-4"/></symbol>
  <symbol id="i-menu" viewBox="0 0 24 24"><path d="M3.5 7h17M3.5 12h17M3.5 17h17"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.1 15.1l5.4 5.4"/></symbol>
  <symbol id="i-view" viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z"/><circle cx="12" cy="12" r="2.5"/></symbol>
  <symbol id="i-hide" viewBox="0 0 24 24"><path d="M3 3l18 18M5.5 7.5C3.5 9 2.5 12 2.5 12s3.5 6 9.5 6c1.5 0 2.8-.4 4-1M9 6.5c.9-.3 1.9-.5 3-.5 6 0 9.5 6 9.5 6s-.8 1.4-2.3 2.9"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="M4 20h4L20 8l-4-4L4 16zM15 5l4 4"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M3.5 6h17M6 6v14a1 1 0 001 1h10a1 1 0 001-1V6M9.5 6V4a1 1 0 011-1h3a1 1 0 011 1v2M10 10v7M14 10v7"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><path d="M8 3h13v13H8zM16 19v1a1 1 0 01-1 1H4a1 1 0 01-1-1V9a1 1 0 011-1h1"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><path d="M4.5 11h15v9.5h-15zM8 11V7.5a4 4 0 018 0V11"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M10 4H4v16h6M14 7l5 5-5 5M8 12h11"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 2.5l8 3v6.5c0 5-3.5 8-8 9.5C7.5 20 4 17 4 12V5.5zM8.5 12l2.5 2.5 4.5-5"/></symbol>
  <symbol id="i-history" viewBox="0 0 24 24"><path d="M12 7v5l3.5 2M3.5 12a8.5 8.5 0 1 0 2.6-6.1M3.5 4.5V10h5.5"/></symbol>
  <symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.25"/><path d="M19.9 15a1.7 1.7 0 00.34 1.87l.06.07a2.05 2.05 0 11-2.9 2.9l-.06-.07a1.7 1.7 0 00-1.88-.34 1.7 1.7 0 00-1.03 1.56v.18a2.05 2.05 0 11-4.1 0v-.1a1.7 1.7 0 00-1.11-1.55 1.7 1.7 0 00-1.88.34l-.06.07a2.05 2.05 0 11-2.9-2.9l.06-.07a1.7 1.7 0 00.34-1.88 1.7 1.7 0 00-1.55-1.03H3a2.05 2.05 0 110-4.1h.1A1.7 1.7 0 004.65 8.7a1.7 1.7 0 00-.34-1.88l-.06-.06a2.05 2.05 0 112.9-2.9l.06.06a1.7 1.7 0 001.88.34h.08A1.7 1.7 0 0010.2 2.7v-.18a2.05 2.05 0 114.1 0v.1a1.7 1.7 0 001.03 1.56 1.7 1.7 0 001.88-.34l.06-.06a2.05 2.05 0 112.9 2.9l-.06.06a1.7 1.7 0 00-.34 1.88v.08a1.7 1.7 0 001.56 1.03h.17a2.05 2.05 0 110 4.1h-.1A1.7 1.7 0 0019.9 15z"/></symbol>
  <symbol id="i-empty" viewBox="0 0 24 24"><path d="M3.5 5.5h17v13h-17zM3.5 12h17M12 5.5v13"/></symbol>
</svg>
"""

# The home screen / tab icon is the login page brand mark, reproduced from the
# CSS above rather than redrawn: a 52x52 box with a 14px radius and a 1px
# #5fd095 border over --bg, holding the 24x24 #i-brand glyph at stroke-width
# 1.75. Regenerate the PNG with tools/make-app-icon.sh.
#
# The sprite symbols cannot be reused here. They carry geometry only and
# inherit stroke:currentColor from DESIGN_CSS, which does not exist once the
# icon is fetched as a standalone file.
FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52" width="52" height="52">
  <rect width="52" height="52" fill="#0a0e0c"/>
  <rect x="0.5" y="0.5" width="51" height="51" rx="14" fill="none" stroke="#5fd095" stroke-width="1"/>
  <g transform="translate(14 14)" fill="none" stroke="#5fd095" stroke-width="1.75"
     stroke-linecap="butt" stroke-linejoin="miter">
    <path d="M4 6l5 6-5 6M12 18h8M12 6h8"/>
  </g>
</svg>
"""

# Same mark at 512x512, drawn at 70% of the canvas on the page background.
# The padding is required, not decoration: iOS masks home screen icons with a
# superellipse, so a mark drawn edge to edge loses its border at the corners.
# The same padding satisfies the Android maskable safe zone, so one asset
# serves both "any" and "maskable".
APP_ICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIABAMAAAAGVsnJAAAAJFBMVEUKDgwTJBsaMyYfQC4kSzc0b1E9hV9ElGpUuYRez5QqWUFNqXlY7PjJAAANFUlEQVR42u2dz28bxxXHuRT1+7JGUMRMLozbg4lehCI9KCc2/QEQvQhBVYnOxZe0IHJxkLoOfWLSJhbdi9o0Nre+KEANlzcWqFGwf101M7vkihYpUpz3Y7TfDyLJjsWZeW9n3q/ZnS2VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJhNdMXfbyRR7nt5SvDpn45bU5+b/gqF9w8/+eLkJPFM/+TJ7+59GEsLdxXll498Sz7WgP32zW9q0jLOYe2ISvo8r7Wq4K1jDvENXzekZb2Mf3GJb3gaS4s7zTsdTvmT5Pn30hJf5BWv+IbH0jLnKLfyIzt5eO/nP4lLeY8ep78YlS7GB/k/vvHbF4OF6Ifvvzy64Fy/i0tKKOem/5N771F29dbLL3LLoCYtuWNtNB7S6wZ9d5WJr+3vSctu2Ollw3lc4+mxfDTu8kxa+vMLkg3m65iv0/KxGg2UU/n7n/P2+8us31hW/qid2qMGd8+V1PI+k9XAIB1Fjb/rzPf8Q1L+H0t65CiNPv4sJ//bqfmT6j81hQ+k+k8NoOAcdAlYvybUvZuC38nJf26De4JDeFdW/U4DbhIOJfqu2K5f7EnKn40iaQh07SKAA1n5zyNx54f5O75tO/5MWv5sJf6bu9tI0vpcpCUSEt+VN4AZ7lr8lbfTsp1396Vld2zawdRY+2yaLv8uLfmF0fyNs0frfF7E0oJnlG1N6oyxx5ZoCP4mm8wWeUONB8ho85qklooQKM866yWpqLKAjianFWhKRd9zWGO8KGvsTmcR6nyxgA0CY2mBp4nMqL5i60ndBCiVqlzXxaaBe9LivoldmV8ydDTS5wIcxja/oO9mnTvqXG5kB+Td1LUFgRPaHMYpUpYF5NnkKIxs8iy069FjuDgD/uLL4lTpt2nKCqPgCRX6UGBbpgS9KCZN7ZL20JbahlmMLerrE6lMA6bGVyPsYFdrFJgxIJ6hTT218MvZIL5CZoZJyzgXswb6dM2va18Bbg0ckLVe1e0DDMZKnZK1PmLfgVoaE6k9p2q8ojsKcrQJyzW7mvOAjCphMNjUWgrJYwz1t0Rtj7Q7QUuPzAiU9TtBQ5PMUm/od4KGLbJotaptR/Ry1slMdTsIE2CjYZKqLVnDvmkRpex0U8szVEt1W3sqnLFBFAo1dReDJlC56zZhluGXDk3KQhhieqZJ4q7WSBNtr2yT7F1shGID3VAfeG91W+dtEZdBM1kHYcSBFpItQiLTSgKJwwrHCbibOHy3GZATcPaq5rnN9XCcgHMDB57b3NR8X8A0FQI/uB1KJmCICNYrhV2ho+f/drFWMKmQoeO/dtMJoiKcQXC5QikHOfwv2HJIYQBFILATUhjgAoEz5S2Ssu49EgoqDnKR0H2vLe6GFAc5kzX02uJ2UHGQdVqnXhusBqaAnm+vXVd8k/xljHzHws2A6kGGtu+iWCuQjVGy8baDSgVsCdevAjoBVQQN+76XbEflw6KzqftOB71b1QAVEFA2TOC2Q1NA1bcCekGVA2zo7vexgbDqIVCA/+QtNAVsESigKy3UMlDMAChAWqhloFgCp9JCSSugKy3UMhR+CcANFn0GFF4BhbcBvmcAxT0npBR+Bni/pSk0BRTeCBY+FC58IFR4BewW3QYU3g1SzIBTaaGWgWIGDKWFklbAqbRQy4AlgCXgPxc4lRZqGbzf1xiaAgofBxTeC8AIYgaEOgOi1ZswBBQIvTw8PPzkcIz549H512/Pvz66fqtb4bjBZDYr3O2rbgmUmRWgbV8gGsW8CtAWCNVn32VIowBlRrAy57bFcGbACgpoJbOfYgtHAcNrf3hznjThKKB73c9GIyvOHrcCYi0KqDtxZpjBMNzgSgroOHFmvP8lnCVwet3PVlN5HjAqQNXmaDmV5/KHeLI84OE4HRj/aYVcQJURdC9oTOY8fR3lvkql2MN4dQVC66kCGJ86UrY5Oko1ELMpQJURdNdjjickQJUbTN9+k3A+f63LCI5jIb5jSJTNAPcSsNU8+3JomwHuXdUJ3xtKlBnBNCFk9ITK3GBp7Am5zKC2muAkIRjyKEDdErgiIQhCAd3VWhhclRDcdAXwJgT6jOC4LsLjCRXOAGuYEw/tLITGW2SyhIDlZE59XqA0qYscMCiAIg7ortrITqoAjgOJVM6AcUKwR68AbdmgI0sIGOoiOmeAfTl6wvCGeG1F0THzdwh8ojEOKE0SAvqD6ZTOgKt3CHzhewb4enR2gyshoFDA0EdDWUIQEytApxs8512mhECpG+TbIaCYAUMvDe3zJASqtscvsMPjCZXGAYY2S11EsQKyjdIvSRWgdwmUoiwhIFWA4hnAkxBQKGDoqal6qAo49dMSzxLQmgyVJlURWiOoNRkqcW2U610CWSBEfKuEXiOYmcADWgWojQMyE0i9O0JhBIc+2tliMYGKbQBXXVirDWDbI9dqAwapAs4KqgC+srhSBdxl3RiJPSug66UVC7n8SmuCmQ8s7Obocdjb4ysrgCkNsKiMA5jSAIvGGcBTCSFUQNfDmDh2xSwajWC6L9qvhaqA4Wot/IArDbAotAFZKazBogCKmmB3pRayNIDpDe76ZsBttjTAoi8X4PSBGhXAeI+kRV0cwLMboFcB7A9OajOCnGkAmQK61//0+FmJmEsByuIArt0AOgWsuATSNIDxAAVd5wkKHKGhqybYvGI3IJ76qVQBp9f97PzdgPTInOP051Hub8qO0bm2ArI0oDur5VnclJOkTuamATQKUPX4/N25JjCMGbDS8wJpNbTBqQBdkaDAgYq64gCBIzVVuUG7JzSzEhKOAoYrfLw+ewGFYQRXrQdEJzVeBShbAvxHa1PMgKHXBokVoG4GzCY9Sv8w9zM7VFNZLtClUUBM0mpAM4AGXZHgDVCAlzNEOKGwAafSQkkroCst1DLACBZ9BsAGFH0GFH4JFF4BsAEENcGutFDLgCVQ9CWAGYAZAAVAAb4V0JUWahmQCxR9CWAGFH0GwAgWfQbABmAGFHwGwAYUfQbABvhWQA8KYHxdpAeqvs9uLrwCRqwPvChUQCcwBdSLroB93w/qt3leD+SNpu8X+7UZn/v1wcD3iW0tjiPgNI93wPauSD90fC/ZOt/hD17o+Tba3kNLYrznLt6zK1o8noSdU0BNWqzFWfP+fIN5Q9KZtFiLY07uu++1RfME/IG0WJLDNaegPJAWa3HMo5oNry2WwyoJbfs3WUlQBYG6f6fVCSoZGPg/tS2sWLjjP3UJKxb2HgkT3HtKif9A0L2y4UxasEXZIXDa695jK0I2CMK2tZACAZLMJQmoLLpPkbsSeBYy2hQ+uxlQRSChqGEThNdUVEjs1UY4boBmqDRqJcFM1j3/zZIsLBKIzFWH7VxsDyOlSNyaoVhBU7z5lqDdrVCs4CaRtVoPpShUJcrbTI4ZRCzYosrcW4HEgglV8aoaxt7ADtlS3QjjdtFtMmNdXu14Ly6adMW7URCF0Z7vG8QmNEMwAutEYZBhK4RIoEp38p9NCNXvjnS874tONR5LSzgfY6mpTIDbc+xKizifXdLi7YZ+RzggNdT2XSHSIs6HeIRN7TeKbBJnbLva18CA0Aka7MsiYmkpZ2PXaI2yh45uP2BeZkFbuLytOxZqk18fuwYa0nLOokK+AlxZSG0+UGWo2hk/ozYnHhH7AEuitzq+yRKn7estDrcISwET7IvDzqRlnTmyA/p+RlqjwQFpJjzBvjlrT1raN7E+kOONhjbcVOgJ62xhOl9Py1Dusd3HZqPBr6QFnqbOuDKbCq2AuZGT7Q6WHc7OFqTJmqS0mDzu4tgYgC8+M8VRXVlxm/mStJRlBJu8EyANOvjeI30V0Yg9Pt9XZQetBaRPg/K4V+keSEvusCaJ+xY+U3xJ+rG07Ab3TlO+95qnvSZqFkFT5lpYw6vBE7iBPODv2LrCfkNa/opdABIFCpt+JS9iWfmdB+zXJPp2c082GojaUgvAMLCdP5VUgBuCVIWubKdf8ic5+W08JrgMbQ6WJP+R6v/XiXQ89rYbwdNYpPdj1/tncvKnQUiSPBHQQGr/pItzLTeK5w3ujisd17P4LlU6juRz3m5/lXb7LJZWgIuHzvmmwdfpWjr9hSKgi1RG6WCSx0yjiV5lPb5oSEtvWMtWAY8K1o7G3fFbnsspTzSQ/PefMWVX0U8/nfT1rCYt+XhYrSTH64/uvHcrjtJ/mvyS+S+vHfNP6d/j8bcL3/O/Ht26c+eDT/P9yNu/3OheJez8QVroi7wzWlmipXj+vbTE0/BOgv/F0vJeQuWYS/zXP5OWdZYKPmYRvyEt5xzKH3zcoxS+/8dfxNIyXsmPDn//6MS7Gvp/efTw8ENp2a5FPPdnnPvKvt964//fCGYpAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDr8H/aXWn+0xtUwwAAAABJRU5ErkJggg=="
)
APP_ICON_PNG = base64.b64decode(APP_ICON_PNG_B64)

MANIFEST_JSON = """{
  "name": "Sans Password Manager",
  "short_name": "SPM",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "background_color": "#0a0e0c",
  "theme_color": "#0a0e0c",
  "icons": [
    {"src": "/apple-touch-icon.png", "sizes": "512x512", "type": "image/png",
     "purpose": "any maskable"}
  ]
}
"""

# render_shell() and login_page() each carry their own <head>; interpolate this
# into both so the two cannot drift apart.
HEAD_ICONS = """<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0a0e0c">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="SPM">"""


def _icon(name, cls="icon"):
    return f'<svg class="{cls}" aria-hidden="true"><use href="#i-{name}"></use></svg>'


# nav key -> (href, icon, i18n key, fallback label, counter name)
NAV_SECTIONS = [
    ("nav.group.vault", [
        ("overview",       "/",               "overview", "nav.overview",       "Overview",       None),
        ("passwords",      "/passwords",      "key", "nav.passwords",      "Passwords",      "passwords"),
        ("notes",          "/notes",          "note", "nav.notes",          "Secure Notes",   "notes"),
        ("passphrases",    "/passphrases",    "phrase", "nav.passphrases",    "Passphrases",    "passphrases"),
        ("authenticators", "/authenticators", "authenticator", "nav.authenticators", "Authenticators", "authenticators"),
        ("backup-codes",   "/backup-codes",   "backup", "nav.backup_codes",   "Backup Codes",   "backups"),
    ]),
    ("nav.group.tools", [
        ("security",  "/security",  "shield", "nav.security",  "Security",        None),
        ("history",   "/history",   "history", "nav.history",   "History",         None),
        ("events",    "/events",    "shield", "nav.events",    "Security Events", None),
        ("generator", "/generator", "generator", "nav.generator", "Generator",       None),
        ("transfer",  "/transfer",  "transfer", "nav.transfer",  "Export / Import", None),
    ]),
    ("nav.group.settings", [
        ("settings", "/settings", "gear", "nav.master_password", "Master Password", None),
    ]),
]

if WEBAUTHN_ENABLED:
    # Only offered when a relying-party id is configured. Without one the
    # endpoints 404, and a nav entry pointing at a 404 is worse than no entry.
    # It sits in Settings next to the master password because both answer the
    # same question -- how this vault gets opened -- and having one of them
    # under Tools made the gear a half-answer.
    NAV_SECTIONS[2][1].append(
        ("unlock-settings", "/unlock/settings", "shield", "nav.unlock",
         "Biometric Unlock", None))


def _nav_html(active, counts):
    out = []
    for group_key, items in NAV_SECTIONS:
        label = {"nav.group.vault": "Vault", "nav.group.tools": "Tools",
                 "nav.group.settings": "Settings"}[group_key]
        out.append(f'<div class="nav-label" data-i18n="{group_key}">{label}</div>')
        # A nav landmark, not a div: this is how a screen-reader user jumps
        # straight to the navigation instead of walking the page.
        out.append('<nav class="nav" aria-label="%s">' % label)
        for key, href, ico, i18n, fallback, counter in items:
            cls = "nav-item active" if key == active else "nav-item"
            badge = ""
            if counter is not None:
                n = counts.get(counter, 0)
                if n:
                    badge = f'<span class="nav-count">{n}</span>'
            out.append(
                f'<a class="{cls}" href="{href}" title="{html.escape(fallback)}" '
                f'data-i18n-title="{i18n}">'
                f'<span class="nav-ico" aria-hidden="true">{_icon(ico)}</span>'
                f'<span class="nav-text" data-i18n="{i18n}">{fallback}</span>{badge}</a>'
            )
        out.append("</nav>")
    return "".join(out)


RAIL_BOOTSTRAP = """
<script>
/* Runs inline, immediately after <body> opens, because reading the
   preference in DOMContentLoaded paints the sidebar expanded and then snaps
   it to the rail -- which reads as the page glitching rather than as a
   remembered setting. Any storage failure leaves the sidebar expanded,
   which is the state that needs no explanation. */
(function () {
  try {
    if (localStorage.getItem("spm.rail") === "1" &&
        window.matchMedia && window.matchMedia("(min-width: 901px)").matches) {
      document.body.classList.add("rail");
    }
  } catch (e) {}
})();
</script>
"""


LANG_BOOTSTRAP = """
<script>
/* Resolve language from the cookie on the client. Keeping it out of the
   server response means no request-scoped state has to be threaded through
   every template - which matters because the server is threaded. */
window.SPM_LANG = (function () {
  var m = document.cookie.match(/(?:^|;\\s*)spm_lang=([^;]*)/);
  var v = m ? decodeURIComponent(m[1]) : "en";
  return ["en", "id", "ja"].indexOf(v) >= 0 ? v : "en";
})();
</script>
"""


def render_shell(content, active, version, vault_path, title="Sans Password Manager",
                 counts=None, flash="", searchable=False):
    """Wrap page content in the shared app shell (sidebar + topbar)."""
    counts = counts or {}
    search_html = ""
    if searchable:
        # A GET form, so typing still filters the current table instantly and
        # Enter escalates to the cross-type search. No JS is required for the
        # escalation, which keeps it working if a script is ever blocked.
        search_html = (
            '<form class="search" method="get" action="/search" role="search">'
            f'<span class="search-ico" aria-hidden="true">{_icon("search", "icon icon-sm")}</span>'
            '<label class="sr-only" for="q" data-i18n="search.label">Search this vault</label>'
            '<input id="q" name="q" type="search" autocomplete="off" spellcheck="false" '
            'data-i18n-placeholder="search.placeholder" placeholder="Search this vault...">'
            '<kbd>/</kbd></form>'
        )
    else:
        search_html = '<div class="search" aria-hidden="true"></div>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)} · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{RAIL_BOOTSTRAP}
{ICON_SPRITE}
<a class="skip-link" href="#main-content">Skip to vault content</a>
<div class="scrim" aria-hidden="true"></div>
<div class="app">
  <aside class="sidebar" id="mobile-navigation" aria-label="Main">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <div class="brand-text">
        <div class="brand-name">SPM</div>
        <div class="brand-meta">v{html.escape(version)}</div>
      </div>
    </div>
    {_nav_html(active, counts)}
    <div class="sidebar-foot">
      <div class="vault-chip" title="{html.escape(vault_path)}">
        <span class="dot" aria-hidden="true"></span>
        <span class="path">{html.escape(vault_path)}</span>
      </div>
      <a class="btn btn-ghost btn-sm btn-block" href="/logout"
         title="Logout" data-i18n-title="header.logout">
        {_icon("logout", "icon icon-sm")}
        <span class="rail-label" data-i18n="header.logout">Logout</span>
      </a>
    </div>
  </aside>

  <div class="main">
    <header class="topbar">
      <button class="icon-btn menu-btn" type="button" aria-label="Menu"
        aria-controls="mobile-navigation" aria-expanded="false">{_icon("menu", "icon icon-sm")}</button>
      {search_html}
      <div class="topbar-right">
        <div class="lockbar" id="lockbar" title="Idle auto-lock">
          <span class="lbl" aria-live="off">Locks in 30s</span>
          <span class="track"><span class="fill"></span></span>
        </div>
        <select class="select" id="lang-picker" aria-label="Language">
          <option value="en">EN</option>
          <option value="id">ID</option>
          <option value="ja">JP</option>
        </select>
      </div>
    </header>

    <main class="content" id="main-content" tabindex="-1">
      {flash}
      {content}
    </main>
  </div>
</div>
<div id="toast" role="status" aria-live="polite"></div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
{UNLOCK_BOOTSTRAP}
{LOCKBAR_SCRIPT}
</body>
</html>"""


def _esc(v):
    return html.escape(v if v is not None else "")


def _empty(icon, title_key, title, desc_key, desc, cta_html="", colspan=4):
    return (
        f'<tr class="empty-row"><td colspan="{colspan}">'
        f'<div class="empty"><div class="empty-ico" aria-hidden="true">{_icon(icon, "icon icon-lg")}</div>'
        f'<div class="empty-t" data-i18n="{title_key}">{title}</div>'
        f'<div class="empty-d" data-i18n="{desc_key}">{desc}</div>{cta_html}</div>'
        f'</td></tr>'
    )


def _actions(view_href, edit_href, delete_action, item_id, confirm_key, confirm_text):
    bits = ['<div class="icon-row">']
    if view_href:
        bits.append(f'<a class="icon-btn" href="{view_href}" title="View" aria-label="View">{_icon("view", "icon icon-sm")}</a>')
    if edit_href:
        bits.append(f'<a class="icon-btn" href="{edit_href}" title="Edit" aria-label="Edit">{_icon("edit", "icon icon-sm")}</a>')
    if delete_action:
        bits.append(
            f'<form class="inline" method="post" action="{delete_action}" '
            f'data-confirm-key="{confirm_key}" data-confirm-text="{html.escape(confirm_text, quote=True)}">'
            f'<input type="hidden" name="id" value="{item_id}">'
            f'<button type="submit" class="icon-btn danger" title="Delete" aria-label="Delete">{_icon("trash", "icon icon-sm")}</button>'
            f'</form>'
        )
    bits.append("</div>")
    return "".join(bits)


# --------------------------------------------------------------------------
# Row builders  (each row carries data-row for the instant client-side filter)
# --------------------------------------------------------------------------
def build_rows_html(entries):
    if not entries:
        return _empty("key", "empty.passwords.t", "No passwords yet",
                      "empty.passwords.d", "Entries you add will appear here.",
                      '<a class="btn btn-primary btn-sm" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>', 4)
    rows = []
    now = time.time()
    limit = rotation_days()
    for _, parts in entries:
        eid, name, user = _esc(parts[0]), _esc(parts[1]), _esc(parts[2])
        tags = entry_tags(parts)
        # Tags join the filter key so the existing instant filter matches them
        # without a second mechanism.
        key = " ".join([f"{name} {user} {eid}".lower()] + ["#" + t for t in tags])
        # Display only -- the clickable chips live in the tag bar above the
        # table, which is the single control that drives filtering.
        chips = "".join(f'<span class="chip">#{_esc(t)}</span>' for t in tags)
        age = _entry_age_days(parts[5] if len(parts) > 5 else "", now)
        aging = ('<span class="chip chip-warn" data-i18n="badge.aging">rotate</span>'
                 if age is not None and age > limit else "")
        rows.append(
            f'<tr data-row="{key}">'
            f'<td class="num">{eid}</td>'
            f'<td class="strong">{name} {aging}{chips}</td>'
            f'<td class="muted">{user or "&mdash;"}</td>'
            f'<td class="actions">{_actions(f"/view?id={eid}", f"/edit?id={eid}", "/delete", eid, "confirm.delete_entry", "Delete this entry?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_tag_filter_html(entries):
    """Tag chips above the password table; filtering reuses the search box."""
    tags = []
    for _, parts in entries:
        for tag in entry_tags(parts):
            if tag not in tags:
                tags.append(tag)
    if not tags:
        return ""
    chips = "".join(
        f'<button class="chip chip-btn" type="button" data-act="tag" data-tag="#{_esc(t)}">#{_esc(t)}</button>'
        for t in sorted(tags))
    return (f'<div class="tagbar"><button class="chip chip-btn" type="button" data-act="tag" data-tag="" '
            f'data-i18n="tags.all">All</button>{chips}</div>')


def build_notes_rows_html(notes):
    if not notes:
        return _empty("note", "empty.notes.t", "No secure notes",
                      "empty.notes.d", "Encrypted notes live inside the same vault.",
                      '<a class="btn btn-primary btn-sm" href="/notes-add" data-i18n="btn.add_note">+ Add Note</a>', 3)
    rows = []
    for _, parts in notes:
        nid, title = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(title + " " + nid).lower()}">'
            f'<td class="num">{nid}</td>'
            f'<td class="strong">{title}</td>'
            f'<td class="actions">{_actions(f"/notes-view?id={nid}", None, "/notes-delete", nid, "confirm.delete_entry", "Delete this note?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_passphrase_rows_html(passphrases):
    if not passphrases:
        return _empty("phrase", "empty.passphrases.t", "No passphrases",
                      "empty.passphrases.d", "Store API tokens or recovery phrases here.",
                      '<a class="btn btn-primary btn-sm" href="/passphrase-add" data-i18n="btn.add_passphrase">+ Add Passphrase</a>', 3)
    rows = []
    for _, parts in passphrases:
        pid, label = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(label + " " + pid).lower()}">'
            f'<td class="num">{pid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td class="actions">{_actions(f"/passphrase-view?id={pid}", f"/passphrase-edit?id={pid}", "/passphrase-delete", pid, "confirm.delete_passphrase", "Delete this passphrase?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_backup_rows_html(backups):
    if not backups:
        return _empty("backup", "empty.backups.t", "No backup codes",
                      "empty.backups.d", "Keep one-time recovery codes safe here.",
                      '<a class="btn btn-primary btn-sm" href="/backup-codes-add" data-i18n="btn.add_backups">+ Add Backup Codes</a>', 3)
    rows = []
    for _, parts in backups:
        bid, label = _esc(parts[1]), _esc(parts[2])
        rows.append(
            f'<tr data-row="{(label + " " + bid).lower()}">'
            f'<td class="num">{bid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td class="actions">{_actions(f"/backup-codes-view?id={bid}", f"/backup-codes-edit?id={bid}", "/backup-codes-delete", bid, "confirm.delete_backup", "Delete these backup codes?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


def build_auth_rows_html(auths):
    if not auths:
        return _empty("authenticator", "empty.auth.t", "No authenticators",
                      "empty.auth.d", "Add a TOTP secret to generate 2FA codes.",
                      '<a class="btn btn-primary btn-sm" href="/authenticator-add" data-i18n="btn.add_authenticator">+ Add Authenticator</a>', 5)
    rows = []
    for _, parts in auths:
        aid, label = _esc(parts[1]), _esc(parts[2])
        interval = _esc(parts[4] if len(parts) > 4 else "30")
        algo = _esc(parts[6] if len(parts) > 6 else "sha1")
        rows.append(
            f'<tr data-row="{(label + " " + aid + " " + algo).lower()}">'
            f'<td class="num">{aid}</td>'
            f'<td class="strong">{label}</td>'
            f'<td><span class="chip">{interval}s</span></td>'
            f'<td><span class="chip">{algo.upper()}</span></td>'
            f'<td class="actions">{_actions(f"/authenticator-view?id={aid}", f"/authenticator-edit?id={aid}", "/authenticator-delete", aid, "confirm.delete_authenticator", "Delete this authenticator?")}</td>'
            f'</tr>'
        )
    return "".join(rows)


# --------------------------------------------------------------------------
# Generic list page
# --------------------------------------------------------------------------
def list_page(title_key, title, desc_key, desc, add_href, add_key, add_label, headers, rows_html):
    def _th(h):
        cls = ' class="num"' if h[2] == "num" else ""
        sty = ' style="text-align:right"' if h[2] == "act" else ""
        return '<th' + cls + sty + ' data-i18n="' + h[0] + '">' + h[1] + '</th>'
    ths = "".join(_th(h) for h in headers)
    add_btn = (
        f'<a class="btn btn-primary" href="{add_href}" data-i18n="{add_key}">{add_label}</a>'
        if add_href else ""
    )
    ncols = len(headers)
    return f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="{title_key}">{title}</h1>
    <div class="page-sub" data-i18n="{desc_key}">{desc}</div>
  </div>
  <div class="page-actions">{add_btn}</div>
</div>
<div class="card" data-searchable>
  <div class="table-wrap">
    <table class="t">
      <thead><tr>{ths}</tr></thead>
      <tbody>{rows_html}
        <tr class="hidden" data-empty-search>
          <td colspan="{ncols}"><div class="empty"><div class="empty-ico">{_icon("search", "icon icon-lg")}</div>
          <div class="empty-t" data-i18n="search.no_results">Nothing matches your search</div></div></td>
        </tr>
      </tbody>
    </table>
  </div>
</div>"""


def _id_links(ids, key, label, hint_key, hint, suffix=""):
    """One security finding rendered as links into the offending entries.

    `suffix` carries values that must survive translation -- data-i18n replaces
    an element's whole text, so an interpolated number has to sit outside the
    translated node or switching language would silently drop it.
    """
    if not ids:
        return (f'<div class="field"><label data-i18n="{key}">{label}</label>'
                f'<div class="hint" data-i18n="security.none">Nothing to fix here.</div></div>')
    links = " ".join(
        f'<a class="btn btn-ghost btn-sm" href="/view?id={_esc(rid)}">{_esc(rid)}</a>'
        for rid in ids)
    tail = f' <span class="hint" style="display:inline">{_esc(suffix)}</span>' if suffix else ""
    return (f'<div class="field"><label data-i18n="{key}">{label}</label>'
            f'<div class="hint"><span data-i18n="{hint_key}">{hint}</span>{tail}</div>'
            f'<div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:6px">{links}</div></div>')


def security_page(audit):
    """The findings behind the overview's security score.

    Only IDs are rendered. The CLI dashboard states that secrets and
    fingerprints are never printed; this page holds the same line, so it stays
    safe to open on a phone in public.
    """
    score = audit["score"]
    tone = "ok" if score >= 80 else ("warn" if score >= 50 else "bad")
    reused_html = "".join(
        f'<div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:6px">'
        + " ".join(f'<a class="btn btn-ghost btn-sm" href="/view?id={_esc(rid)}">{_esc(rid)}</a>' for rid in group)
        + '</div>'
        for group in audit["reused"])
    if not reused_html:
        reused_html = ('<div class="hint" data-i18n="security.none">Nothing to fix here.</div>')
    breach_status = audit.get("breach_status", "not_checked")
    if breach_status == "checked":
        breached = audit.get("breached", [])
        if breached:
            breach_html = " ".join(
                f'<a class="btn btn-ghost btn-sm" href="/view?id={_esc(item["id"])}">'
                f'{_esc(item["id"])} · {_esc(item["count"])} sightings</a>'
                for item in breached)
        else:
            breach_html = ('<div class="hint" data-i18n="security.none">'
                           'Nothing to fix here.</div>')
    elif breach_status == "unavailable":
        breach_html = ('<div class="hint" data-i18n="security.breach_unavailable">'
                       'The breach service is unavailable. No clean result is assumed.</div>')
    else:
        breach_html = (
            '<div class="hint" data-i18n="security.breach_optin">Opt-in online check. '
            'Passwords and full hashes are never sent.</div>'
            '<a class="btn btn-ghost btn-sm" href="/security?breaches=1" '
            'data-i18n="security.breach_check">Check known breaches</a>')
    days = audit["rotation_days"]
    return f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="nav.security">Security</h1>
    <div class="page-sub" data-i18n="security.sub">What is pulling your vault score down.</div>
  </div>
</div>
<div class="card">
  <div class="card-body">
    <div class="stat" style="pointer-events:none">
      <span class="stat-ico" aria-hidden="true">{_icon("shield")}</span>
      <span><span class="stat-n score-{tone}">{score}</span>
      <span class="stat-l" data-i18n="overview.security_score">Security score</span></span>
    </div>
    <div class="hint" data-i18n="security.scope">Only password entries are scored. IDs are shown; secrets never are.</div>
  </div>
</div>
<div class="card">
  <div class="card-body">
    {_id_links(audit["weak"], "security.weak", "Weak passwords",
               "security.weak_d", "Shorter than 12 characters, or using fewer than three character classes.")}
    <div class="field"><label data-i18n="security.reused">Reused passwords</label>
      <div class="hint" data-i18n="security.reused_d">Each row below is one group of entries sharing a password.</div>
      {reused_html}
    </div>
    {_id_links(audit["old"], "security.aging", "Due for rotation",
               "security.aging_d", "Older than the rotation threshold:", f"{days} days")}
    {_id_links(audit["incomplete"], "security.incomplete", "Missing details",
               "security.incomplete_d", "No service name or no username.")}
    {_id_links(audit["malformed"], "security.malformed", "Malformed authenticators",
               "security.malformed_d", "Missing a secret, or an algorithm SPM cannot generate codes for.")}
    <div class="field"><label data-i18n="security.breached">Known breaches</label>
      <div class="hint" data-i18n="security.breached_d">Matches in Pwned Passwords. Only five SHA-1 prefix characters leave this device.</div>
      <div class="actions" style="justify-content:flex-start;flex-wrap:wrap;gap:6px">{breach_html}</div>
    </div>
  </div>
</div>"""


def _fmt_size(n):
    return f"{n / 1024.0:.1f} KB" if n >= 1024 else f"{n} B"


def build_history_rows_html(snapshots):
    if not snapshots:
        return _empty("history", "empty.history.t", "No snapshots yet",
                      "empty.history.d", "SPM archives the vault before each change.", "", 4)
    rows = []
    for pos, (name, stamp, size) in enumerate(snapshots):
        try:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(stamp, "%Y%m%dT%H%M%S"))
        except ValueError:
            when = stamp
        newest = ' <span class="hint" data-i18n="history.newest">newest</span>' if pos == 0 else ""
        rows.append(
            f'<tr data-row="{_esc(when.lower())}">'
            f'<td class="strong">{_esc(when)} UTC{newest}</td>'
            f'<td class="muted">{_fmt_size(size)}</td>'
            f'<td class="muted">{_esc(name)}</td>'
            f'<td class="actions">'
            f'<form class="inline" method="post" action="/history-restore" '
            f'data-confirm-key="confirm.restore_snapshot" '
            f'data-confirm-text="Restore this snapshot? The current vault is archived first.">'
            f'<input type="hidden" name="name" value="{_esc(name)}">'
            f'<button class="btn btn-ghost btn-sm" type="submit" data-i18n="btn.restore">Restore</button>'
            f'</form></td>'
            f'</tr>')
    return "".join(rows)


def build_search_rows_html(results):
    if not results:
        return _empty("search", "empty.search.t", "Nothing found",
                      "empty.search.d", "No label, name or username matches that text.", "", 3)
    rows = []
    for kind_key, kind, rid, label, href in results:
        rows.append(
            f'<tr data-row="">'
            f'<td class="muted" data-i18n="{kind_key}">{_esc(kind)}</td>'
            f'<td class="num">{_esc(rid)}</td>'
            f'<td class="strong">{_esc(label) or "&mdash;"}</td>'
            f'<td class="actions"><a class="btn btn-ghost btn-sm" href="{href}" data-i18n="btn.view">View</a></td>'
            f'</tr>')
    return "".join(rows)


# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
def overview_page(counts, recent):
    tiles = [
        ("shield", counts.get("security_score", 100), "overview.security_score", "Security score", "/security"),
        ("key", counts.get("passwords", 0), "nav.passwords", "Passwords", "/passwords"),
        ("note", counts.get("notes", 0), "nav.notes", "Secure Notes", "/notes"),
        ("phrase", counts.get("passphrases", 0), "nav.passphrases", "Passphrases", "/passphrases"),
        ("authenticator", counts.get("authenticators", 0), "nav.authenticators", "Authenticators", "/authenticators"),
        ("backup", counts.get("backups", 0), "nav.backup_codes", "Backup Codes", "/backup-codes"),
    ]
    stats = "".join(
        f'<a class="stat" href="{href}">'
        f'<span class="stat-ico" aria-hidden="true">{_icon(ico)}</span>'
        f'<span><span class="stat-n">{n}</span>'
        f'<span class="stat-l" data-i18n="{k}">{lbl}</span></span></a>'
        for ico, n, k, lbl, href in tiles
    )

    if recent:
        items = "".join(
            f'<tr data-row=""><td class="num">{_esc(p[0])}</td>'
            f'<td class="strong">{_esc(p[1])}</td>'
            f'<td class="muted">{_esc(p[2]) or "&mdash;"}</td>'
            f'<td class="actions"><a class="btn btn-ghost btn-sm" href="/view?id={_esc(p[0])}" data-i18n="btn.view">View</a></td></tr>'
            for _, p in recent
        )
        recent_html = f"""
<div class="card">
  <div class="card-head">
    <h2 data-i18n="overview.recent">Recently added</h2>
    <span class="spacer"></span>
    <a class="btn btn-ghost btn-sm" href="/passwords" data-i18n="overview.view_all">View all</a>
  </div>
  <div class="table-wrap"><table class="t">
    <thead><tr>
      <th scope="col" data-i18n="table.id">ID</th>
      <th scope="col" data-i18n="table.service">Service</th>
      <th scope="col" data-i18n="table.username">Username</th>
      <th scope="col"><span class="sr-only" data-i18n="table.actions">Actions</span></th>
    </tr></thead>
    <tbody>{items}</tbody></table></div>
</div>"""
    else:
        recent_html = f"""
<div class="card"><div class="empty">
  <div class="empty-ico" aria-hidden="true">{_icon("lock", "icon icon-lg")}</div>
  <div class="empty-t" data-i18n="empty.vault.t">Your vault is empty</div>
  <div class="empty-d" data-i18n="empty.vault.d">Add your first password to get started.</div>
  <a class="btn btn-primary" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>
</div></div>"""

    total = sum(counts.get(k, 0) for k in ("passwords", "notes", "passphrases", "authenticators", "backups"))
    return f"""
<section class="console-hero" aria-labelledby="overview-command">
  <div class="eyebrow" data-i18n="overview.console_eyebrow">session / local vault / authenticated</div>
  <h1 id="overview-command">spm vault status</h1>
  <div class="console-output" aria-label="Vault status output">
    <span><b>{total}</b> <i data-i18n="overview.console_records">encrypted records indexed</i></span>
    <span data-i18n="overview.console_gpg">GnuPG boundary active on this host</span>
    <span data-i18n="overview.console_lock">idle lock armed for 30 seconds</span>
  </div>
  <p class="lede" data-i18n="overview.console_lede">Inspect, generate, and maintain credentials from one auditable session.</p>
</section>
<div class="page-head">
  <div>
    <h2 class="page-title" data-i18n="nav.overview">Overview</h2>
    <div class="page-sub" data-i18n="overview.sub">Everything in your encrypted vault at a glance.</div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/generator" data-i18n="btn.open_generator">Open Generator</a>
    <a class="btn btn-primary" href="/add" data-i18n="btn.add_entry">+ Add Entry</a>
  </div>
</div>
<div class="stats">{stats}</div>
{recent_html}
<div class="card" style="margin-top:var(--sp-4)">
  <div class="card-foot" style="border-top:none">
    <span data-i18n="passwords.footer">Passwords are never sent anywhere else - all crypto stays on this host with GnuPG.</span>
  </div>
</div>"""


# --------------------------------------------------------------------------
# Forms
# --------------------------------------------------------------------------
def _form_page(title, action, fields_html, message="", back="/", active="overview"):
    msg = f'<div class="msg">{message}</div>' if message and "<div" not in message else (message or "")
    content = f"""
<div class="page-head">
  <div><h1 class="page-title">{html.escape(title)}</h1></div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="{back}" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
{msg}
<div class="card" style="max-width:640px">
  <div class="card-body">
    <form method="post" action="{action}">
      {fields_html}
      <div class="form-actions">
        <button class="btn btn-primary" type="submit" data-i18n="form.save">Save</button>
        <a class="btn btn-ghost" href="{back}" data-i18n="link.back">Cancel</a>
      </div>
    </form>
  </div>
</div>"""
    return render_shell(content, active, VERSION, VAULT_PATH, title=title)


def _field(name, label_key, label, value="", ftype="text", placeholder_key=None, hint=None, required=False, rows=0):
    """One labelled form control.

    The label is tied to the control with for/id. Without that pairing a
    screen reader announces "edit text, blank" for every field on the add and
    edit forms -- the label is on screen but not attached to anything, so it is
    read as loose text somewhere before the control. A hint is tied on with
    aria-describedby for the same reason.

    Every form is one per page and field names are unique within a form, so
    "field-<name>" is a stable unique id.
    """
    field_id = "field-%s" % name
    req = " required" if required else ""
    ph = f' data-i18n-placeholder="{placeholder_key}"' if placeholder_key else ""
    hint_id = f"{field_id}-hint"
    described = f' aria-describedby="{hint_id}"' if hint else ""
    if rows:
        ctrl = (f'<textarea class="input" id="{field_id}" name="{name}" rows="{rows}"'
                f'{ph}{req}{described}>{html.escape(value)}</textarea>')
    else:
        ctrl = (f'<input class="input" id="{field_id}" type="{ftype}" name="{name}" '
                f'value="{html.escape(value)}"{ph}{req}{described} autocomplete="off">')
    hint_html = f'<div class="hint" id="{hint_id}">{hint}</div>' if hint else ""
    return (f'<div class="field"><label for="{field_id}" data-i18n="{label_key}">{label}</label>'
            f'{ctrl}{hint_html}</div>')


def _folder_field(current, known):
    """A free-text folder with the vault's existing ones offered as a datalist.

    Not a <select>: a folder is created by naming one, and a dropdown of only
    what exists would make the first folder impossible to make. The datalist
    keeps people from inventing "Work" a second time by accident.
    """
    options = "".join('<option value="%s"></option>' % html.escape(name)
                      for name in known)
    return f"""
  <div class="field">
    <label for="entry-folder" data-i18n="entry.field.folder">Folder</label>
    <input class="input" id="entry-folder" name="folder" list="entry-folders"
           value="{html.escape(current or "")}" autocomplete="off">
    <datalist id="entry-folders">{options}</datalist>
    <div class="hint" data-i18n="entry.hint.folder">Optional. Type a new name to
      create one.</div>
  </div>"""


def _custom_fields_block(fields):
    """Repeatable name/value pairs.

    Values are ordinary text inputs, not password inputs: these hold things
    like an account number or a security answer, and a field the user cannot
    read back is a field they cannot check. The vault encrypts them either way.
    """
    rows = list(fields or []) + [("", "")]
    body = []
    for index, (name, value) in enumerate(rows):
        body.append(f"""
    <div class="cf-row" style="display:grid;grid-template-columns:1fr 2fr auto;gap:var(--sp-2);margin-bottom:var(--sp-2)">
      <input class="input" name="cf_name_{index}" value="{html.escape(name)}"
             data-i18n-placeholder="entry.field.custom_name" placeholder="Field name"
             aria-label="Custom field name {index + 1}" autocomplete="off">
      <input class="input" name="cf_value_{index}" value="{html.escape(value)}"
             data-i18n-placeholder="entry.field.custom_value" placeholder="Value"
             aria-label="Custom field value {index + 1}" autocomplete="off">
      <button class="btn btn-ghost" type="button" data-act="cf-remove"
              aria-label="Remove this field">&times;</button>
    </div>""")
    return f"""
  <div class="field">
    <label data-i18n="entry.field.custom">Custom fields</label>
    <div id="cf-rows">{"".join(body)}</div>
    <button class="btn btn-ghost" type="button" id="cf-add"
            data-i18n="entry.field.custom_add">Add another field</button>
    <div class="hint" data-i18n="entry.hint.custom">Anything this record needs
      that has no box of its own. Stored in the vault, encrypted like the
      password.</div>
  </div>
<script>
(function () {{
  var host = document.getElementById("cf-rows");
  var add = document.getElementById("cf-add");
  if (!host || !add) return;
  add.addEventListener("click", function () {{
    var last = host.lastElementChild;
    if (!last) return;
    var copy = last.cloneNode(true);
    // Renumber, or the clone submits under the index it was copied from and
    // the two rows collapse into one on the server.
    var next = host.children.length;
    copy.querySelectorAll("input").forEach(function (input) {{
      input.value = "";
      input.name = input.name.replace(/_\d+$/, "_" + next);
      var label = input.getAttribute("aria-label");
      if (label) input.setAttribute("aria-label", label.replace(/\d+$/, next + 1));
    }});
    host.appendChild(copy);
    var first = copy.querySelector("input");
    if (first) first.focus();
  }});
  host.addEventListener("click", function (event) {{
    var target = event.target;
    if (!target || target.getAttribute("data-act") !== "cf-remove") return;
    // Always leave one row, so the control cannot be emptied into a state
    // with nothing to clone from.
    if (host.children.length > 1) {{
      target.closest(".cf-row").remove();
      Array.prototype.forEach.call(host.children, function (row, position) {{
        row.querySelectorAll("input").forEach(function (input) {{
          input.name = input.name.replace(/_\d+$/, "_" + position);
          var label = input.getAttribute("aria-label");
          if (label) input.setAttribute("aria-label", label.replace(/\d+$/, position + 1));
        }});
      }});
    }} else {{
      target.closest(".cf-row").querySelectorAll("input").forEach(
        function (input) {{ input.value = ""; }});
    }}
  }});
}})();
</script>"""


def posted_attrs(data):
    """(folder, [(name, value)], error) from a submitted entry form.

    One reader for add and edit both. Two would drift, and the failure would be
    a record whose custom fields survive an edit but not a create, or the
    reverse -- silent either way.
    """
    folder = (data.get("folder") or [""])[0].strip()
    # Rows are matched by the index in their input names, never by position in
    # two parallel lists. parse_qs drops blank values, so a row whose name was
    # left empty does not merely go missing -- the remaining names and values
    # shift out of step and every later value lands on the wrong field. A user
    # who typed a blank name above "Account = 123-456" would have got
    # "Account = <the value from the blank row>", silently.
    rows = {}
    for key, supplied in data.items():
        for prefix, slot in (("cf_name_", 0), ("cf_value_", 1)):
            if not key.startswith(prefix):
                continue
            suffix = key[len(prefix):]
            if not suffix.isdigit():
                continue
            rows.setdefault(int(suffix), ["", ""])[slot] = (supplied or [""])[0]
    # Custom fields are single-line inputs. A browser cannot put a newline in
    # one, so anything arriving with a tab or a newline came from a script or
    # an import -- and storing it would leave a value the form can never show
    # or edit back correctly. Folded to spaces here rather than at the encoder,
    # which stays able to carry them so a hand-edited vault still round-trips.
    def _one_line(text):
        return " ".join((text or "").split())

    pairs = []
    for index in sorted(rows):
        name, value = rows[index]
        name = _one_line(name)
        value = _one_line(value) if ("\n" in value or "\t" in value) else value
        # A row with a value but no name is a half-filled row, not a field.
        # Dropping it silently would lose what someone typed, so it is an error.
        if not name:
            if value.strip():
                return folder, [], "A custom field has a value but no name."
            continue
        pairs.append((name, value))
    try:
        core.encode_attrs(_one_line(folder), pairs)
    except Exception as exc:
        return folder, pairs, str(exc)
    return _one_line(folder), pairs, ""


def build_entry_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("name", "entry.field.service", "Service", v.get("name", ""), required=True) +
        _field("user", "entry.field.username", "Username / Email", v.get("user", "")) +
        _field("password", "entry.field.password", "Password", v.get("password", "")) +
        # type="url" only nudges the browser; the server still validates, since
        # a form post is not obliged to come from this form.
        _field("url", "entry.field.url", "URL", v.get("url", ""), ftype="url",
               hint='<span data-i18n="entry.hint.url">Used to match this entry to a site. '
                    'http:// or https:// only.</span>') +
        _field("notes", "entry.field.notes", "Notes", v.get("notes", ""), rows=4) +
        _folder_field(v.get("folder", ""), v.get("folders", [])) +
        _custom_fields_block(v.get("fields", []))
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/passwords", "passwords")


def build_note_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("title", "note.field.title", "Title", v.get("title", ""), required=True) +
        _field("content", "note.field.content", "Content", v.get("content", ""), rows=8)
    )
    return _form_page(title, action, f, message, "/notes", "notes")


def build_passphrase_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("label", "pass.field.label", "Label", v.get("label", ""), required=True) +
        _field("secret", "pass.field.secret_hint", "Passphrase (leave blank to auto-generate)", v.get("secret", ""), rows=3)
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/passphrases", "passphrases")


def build_backup_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    f = (
        _field("label", "backup.field.label", "Label", v.get("label", ""), required=True) +
        _field("codes", "backup.field.codes", "Backup codes (one per line)", v.get("codes", ""), rows=8)
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/backup-codes", "backup-codes")


def build_auth_form(title, vault_path, action, values=None, message=""):
    v = values or {}
    algo = (v.get("algo") or "sha1").lower()
    opts = "".join(
        f'<option value="{a}"{" selected" if algo == a else ""} data-i18n="auth.option.{a}">{a.upper()}</option>'
        for a in ("sha1", "sha256", "sha512")
    )
    f = (
        _field("label", "auth.field.label", "Label", v.get("label", ""), required=True) +
        _field("secret", "auth.field.secret", "Base32 secret", v.get("secret", ""), required=True,
               hint="e.g. JBSWY3DPEHPK3PXP") +
        '<div class="row2">' +
        _field("period", "auth.field.period", "Refresh interval (s)", v.get("period", "30") or "30", ftype="number") +
        f'<div class="field"><label data-i18n="auth.field.algorithm">Algorithm</label>'
        f'<select class="input" name="algo">{opts}</select></div>' +
        '</div>'
    )
    extra = f'<input type="hidden" name="id" value="{html.escape(v.get("id",""))}">' if v.get("id") else ""
    return _form_page(title, action, extra + f, message, "/authenticators", "authenticators")


# --------------------------------------------------------------------------
# View pages
# --------------------------------------------------------------------------
def _secret_block(value, label_key, label, elem_id):
    return f"""
<div class="field">
  <label data-i18n="{label_key}">{label}</label>
  <div class="secret">
    <span class="secret-val masked" id="{elem_id}" data-val="{html.escape(value)}">{"•" * min(len(value), 24) if value else "&mdash;"}</span>
    <button class="icon-btn" type="button" data-act="reveal" data-target="{elem_id}" data-title-show="Show" aria-label="Show">{_icon("view", "icon icon-sm")}</button>
    <button class="icon-btn" type="button" data-act="copy-val" data-target="{elem_id}" aria-label="Copy">{_icon("copy", "icon icon-sm")}</button>
  </div>
</div>"""


REVEAL_SCRIPT = """
<script>
window.SPM_reveal = function (id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  var masked = el.classList.contains("masked");
  if (masked) {
    el.textContent = el.dataset.val || "";
    el.classList.remove("masked");
    btn.setAttribute("aria-label", "Hide");
    var use = btn.querySelector("use");
    if (use) use.setAttribute("href", "#i-hide");
    if (window.SPM_AutoLock) window.SPM_AutoLock.restart();
  } else {
    var v = el.dataset.val || "";
    el.textContent = "\\u2022".repeat(Math.min(v.length, 24));
    el.classList.add("masked");
    btn.setAttribute("aria-label", "Show");
    var use = btn.querySelector("use");
    if (use) use.setAttribute("href", "#i-view");
  }
};
</script>
"""


def _attrs_block(column):
    """Folder and custom fields on the view page.

    Custom-field values are masked behind the same reveal control the password
    uses. People put account numbers and security answers in these, and a page
    that printed them in clear while masking the password beside them would be
    protecting the wrong half.
    """
    folder, fields = core.decode_attrs(column)
    if not folder and not fields:
        return ""
    out = []
    if folder:
        out.append(f"""
  <div class="field"><label data-i18n="view.label.folder">Folder</label>
    <div class="secret"><span class="chip">{_esc(folder)}</span></div>
  </div>""")
    for index, (name, value) in enumerate(fields, start=1):
        elem = "cf-%d" % index
        dots = "&bull;" * min(len(value), 24) if value else "&mdash;"
        out.append(f"""
  <div class="field"><label>{_esc(name)}</label>
    <div class="secret">
      <span class="secret-val masked" id="{elem}"
            data-val="{html.escape(value)}">{dots}</span>
      <button class="icon-btn" type="button" data-act="reveal" data-target="{elem}"
              aria-label="Show">{_icon("view", "icon icon-sm")}</button>
      <button class="icon-btn" type="button" data-act="copy-val" data-target="{elem}"
              aria-label="Copy">{_icon("copy", "icon icon-sm")}</button>
    </div>
  </div>""")
    return "".join(out)


def _history_block(history):
    """Previous passwords for an entry, masked like the current one.

    Deliberately not called "History": the sidebar already has a History item
    for vault snapshots, and two things called history on one screen meaning
    different scopes is a maze. "Previous passwords" says which it is.
    """
    if not history:
        return ""
    rows = []
    for index, (when, secret) in enumerate(reversed(history), start=1):
        elem = "pwhist-%d" % index
        dots = "&bull;" * min(len(secret), 24) if secret else "&mdash;"
        rows.append(f"""
  <div class="secret" style="margin-bottom:var(--sp-2)">
    <span class="faint mono" style="min-width:20ch">{html.escape(when)}</span>
    <span class="secret-val masked" id="{elem}" data-val="{html.escape(secret)}">{dots}</span>
    <button class="icon-btn" type="button" data-act="reveal" data-target="{elem}"
      data-title-show="Show" aria-label="Show">{_icon("view", "icon icon-sm")}</button>
    <button class="icon-btn" type="button" data-act="copy-val" data-target="{elem}"
      aria-label="Copy">{_icon("copy", "icon icon-sm")}</button>
  </div>""")
    return f"""
<div class="field">
  <label data-i18n="view.label.previous">Previous passwords</label>
  {"".join(rows)}
  <div class="hint" data-i18n="view.previous.hint">Newest first. Recorded when the password changed; deleting this entry deletes them with it.</div>
</div>"""


def view_entry_page(parts, history=()):
    """Full page for a single password entry."""
    eid, name, user, pw = _esc(parts[0]), _esc(parts[1]), _esc(parts[2]), parts[3] if len(parts) > 3 else ""
    notes = parts[4] if len(parts) > 4 else ""
    created = _esc(parts[5] if len(parts) > 5 else "")
    # Re-checked at render time rather than trusted from the vault. A row can
    # reach this page from an editor session or a hand-edited file, neither of
    # which went through the form validator, and this value becomes an href.
    raw_url = parts[6] if len(parts) > 6 else ""
    safe_url = raw_url if _URL_RE.match(raw_url.strip()) else ""
    if safe_url:
        url_html = (f'<a href="{_esc(safe_url)}" target="_blank" '
                    f'rel="noopener noreferrer nofollow">{_esc(safe_url)}</a>')
    else:
        url_html = "&mdash;"
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title">{name}</h1>
    <div class="page-sub">{user or ""}</div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/edit?id={eid}" data-i18n="btn.edit">Edit</a>
    <a class="btn btn-ghost" href="/passwords" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:680px"><div class="card-body">
  <div class="field"><label data-i18n="view.label.username">Username / Email</label>
    <div class="secret"><span class="secret-val" id="username-value">{user or "&mdash;"}</span>
    <button class="icon-btn" type="button" data-act="copy-text" data-target="username-value" aria-label="Copy">{_icon("copy", "icon icon-sm")}</button></div>
  </div>
  {_secret_block(pw, "view.label.password", "Password", "pw")}
  <div class="field"><label data-i18n="view.label.url">URL</label>
    <div class="secret"><span class="secret-val">{url_html}</span></div>
  </div>
  <div class="field"><label data-i18n="view.label.notes">Notes</label>
    <div class="secret"><span class="secret-val" style="white-space:pre-wrap">{_esc(notes) or "&mdash;"}</span></div>
  </div>
  {_attrs_block(parts[7] if len(parts) > 7 else "")}
  <div class="field"><label data-i18n="view.label.created">Created</label>
    <div class="faint mono">{created or "&mdash;"}</div>
  </div>
  {_history_block(history)}
</div></div>
{REVEAL_SCRIPT}"""
    return render_shell(content, "passwords", VERSION, VAULT_PATH, title=name)


def view_simple_page(title, back, label_key, label, value, created, secret_key, secret_label, active="overview"):
    body = _secret_block(value, secret_key, secret_label, "sec")
    content = f"""
<div class="page-head">
  <div><h1 class="page-title">{html.escape(title)}</h1>
    <div class="page-sub">{html.escape(label)}</div></div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="{back}" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:680px"><div class="card-body">
  {body}
  <div class="field"><label data-i18n="view.label.created">Created</label>
    <div class="faint mono">{html.escape(created) or "&mdash;"}</div></div>
</div></div>
{REVEAL_SCRIPT}"""
    return render_shell(content, active, VERSION, VAULT_PATH, title=title)


def login_page(version, message=""):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Unlock Vault · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{ICON_SPRITE}
<a class="skip-link" href="#main-content">Skip to unlock form</a>
<div class="login-wrap">
  <main class="login-card" id="main-content">
    <div class="login-brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <h1 data-i18n="header.title">Sans Password Manager</h1>
      <p data-i18n="login.sub">Unlock your encrypted vault to continue.</p>
    </div>
    <div class="card"><div class="card-body">
      {message}
      <form method="post" action="/login">
        <div class="field">
          <label for="pw" data-i18n="login.master">Master password</label>
          <input class="input" id="pw" name="password" type="password"
                 autocomplete="current-password" autofocus required>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="login.unlock">Unlock</button>
      </form>
    </div>
    <div class="card-foot">
      <span data-i18n="login.note">All decryption happens locally with GnuPG. Nothing leaves this host.</span>
    </div></div>
    <div style="text-align:center;margin-top:var(--sp-4)">
      <select class="select" id="lang-picker" aria-label="Language">
        <option value="en">EN</option><option value="id">ID</option><option value="ja">JP</option>
      </select>
      <div class="faint" style="margin-top:var(--sp-2)">v{html.escape(version)}</div>
    </div>
  </main>
</div>
<div id="toast" role="status" aria-live="polite"></div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
</body>
</html>"""


# Stamped by _send_html the way __LANG__ is, so the lockbar on every page
# learns whether biometric unlock is usable without each page handler having to
# decrypt the vault to find out.
UNLOCK_BOOTSTRAP = """
<script>window.SPM_UNLOCK = __SPM_UNLOCK__;</script>
"""

UNLOCK_SCRIPT = """
<script>
(function () {
  var btn = document.getElementById("unlock-btn");
  var status = document.getElementById("unlock-status");
  if (!btn || !status) return;
  var CSRF = btn.getAttribute("data-csrf") || "";
  function t(key, fallback) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fallback) : fallback;
  }
  function b64urlToBytes(value) {
    var pad = value.replace(/-/g, "+").replace(/_/g, "/");
    while (pad.length % 4) pad += "=";
    var raw = atob(pad), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf: CSRF}, body || {}))
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || "unlock failed");
        return j;
      });
    });
  }
  function fail(message) {
    status.textContent = message;
    btn.disabled = false;
  }
  btn.addEventListener("click", function () {
    if (!window.PublicKeyCredential) { fail(t("unlock.nosupport", "This browser has no biometric support.")); return; }
    btn.disabled = true;
    status.textContent = t("unlock.waiting", "Waiting for biometric confirmation...");
    post("/unlock/challenge").then(function (c) {
      return navigator.credentials.get({publicKey: {
        challenge: b64urlToBytes(c.challenge),
        rpId: c.rp_id,
        userVerification: "required",
        timeout: 60000,
        allowCredentials: (c.allow || []).map(function (id) {
          return {type: "public-key", id: b64urlToBytes(id)};
        })
      }});
    }).then(function (cred) {
      if (!cred) throw new Error("no credential");
      return post("/unlock/verify", {
        credential_id: cred.id,
        client_data: bytesToB64url(cred.response.clientDataJSON),
        auth_data: bytesToB64url(cred.response.authenticatorData),
        signature: bytesToB64url(cred.response.signature)
      });
    }).then(function () {
      window.location.replace("/");
    }).catch(function (err) {
      fail((err && err.message) ? err.message : t("unlock.failed", "Unlock failed."));
    });
  });
})();
</script>
"""

UNLOCK_REGISTER_SCRIPT = """
<script>
(function () {
  var btn = document.getElementById("register-btn");
  var status = document.getElementById("register-status");
  if (!btn || !status) return;
  var CSRF = btn.getAttribute("data-csrf") || "";
  function t(key, fallback) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fallback) : fallback;
  }
  function b64urlToBytes(value) {
    var pad = value.replace(/-/g, "+").replace(/_/g, "/");
    while (pad.length % 4) pad += "=";
    var raw = atob(pad), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf), s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function post(url, body) {
    return fetch(url, {
      method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(Object.assign({csrf: CSRF}, body || {}))
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || "registration failed");
        return j;
      });
    });
  }
  btn.addEventListener("click", function () {
    if (!window.PublicKeyCredential) { status.textContent = t("unlock.nosupport", "This browser has no biometric support."); return; }
    btn.disabled = true;
    status.textContent = t("register.waiting", "Waiting for the authenticator...");
    var label = (document.getElementById("register-label") || {}).value || "";
    post("/unlock/register/challenge").then(function (c) {
      return navigator.credentials.create({publicKey: {
        challenge: b64urlToBytes(c.challenge),
        rp: {id: c.rp_id, name: "Sans Password Manager"},
        user: {
          id: b64urlToBytes(c.user_id),
          name: c.user_name || "vault",
          displayName: c.user_name || "vault"
        },
        /* ES256 only: it is what every platform authenticator supports, and it
           keeps server-side verification to one openssl code path. */
        pubKeyCredParams: [{type: "public-key", alg: -7}],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "discouraged",
          userVerification: "required"
        },
        attestation: "none",
        timeout: 60000
      }});
    }).then(function (cred) {
      if (!cred) throw new Error("no credential");
      /* getPublicKey() hands back SPKI DER directly, which is what lets this
         server skip a CBOR decoder for the attestation object entirely. */
      var spki = cred.response.getPublicKey ? cred.response.getPublicKey() : null;
      if (!spki) throw new Error("this browser cannot export the credential key");
      return post("/unlock/register/verify", {
        credential_id: cred.id,
        client_data: bytesToB64url(cred.response.clientDataJSON),
        auth_data: bytesToB64url(cred.response.getAuthenticatorData()),
        public_key: bytesToB64url(spki),
        label: label
      });
    }).then(function () {
      window.location.replace("/unlock/settings?msg=registered");
    }).catch(function (err) {
      status.textContent = (err && err.message) ? err.message : t("register.failed", "Registration failed.");
      btn.disabled = false;
    });
  });
})();
</script>
"""


def unlock_page(version, csrf):
    """The locked screen.

    Renders no vault content at all -- a button, a status line and a way out.
    It must also be usable with no JavaScript, so the master-password route is
    a plain link rather than something the script has to enable.
    """
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Locked · SPM</title>
{HEAD_ICONS}
{DESIGN_CSS}
</head>
<body class="theme-dark">
{ICON_SPRITE}
<div class="login-wrap">
  <main class="login-card" id="main-content">
    <div class="login-brand">
      <div class="brand-mark" aria-hidden="true">{_icon("brand")}</div>
      <h1 data-i18n="unlock.title">Vault locked</h1>
      <p data-i18n="unlock.sub">Confirm with your device to continue where you left off.</p>
    </div>
    <div class="card"><div class="card-body">
      <button class="btn btn-primary btn-block" type="button" id="unlock-btn"
              data-csrf="{html.escape(csrf)}" data-i18n="unlock.btn">Unlock with biometrics</button>
      <div class="faint" id="unlock-status" role="status" aria-live="polite"
           style="margin-top:var(--sp-3);min-height:1.2em"></div>
    </div>
    <div class="card-foot">
      <a href="/logout" data-i18n="unlock.fallback">Use master password instead</a>
    </div></div>
    <div style="text-align:center;margin-top:var(--sp-4)">
      <select class="select" id="lang-picker" aria-label="Language">
        <option value="en">EN</option><option value="id">ID</option><option value="ja">JP</option>
      </select>
      <div class="faint" style="margin-top:var(--sp-2)">v{html.escape(version)}</div>
    </div>
  </main>
</div>
{LANG_BOOTSTRAP}
{I18N_SCRIPT}
{SHELL_SCRIPT}
{UNLOCK_SCRIPT}
</body>
</html>"""


def unlock_settings_page(creds, csrf, flash=""):
    """Manage registered unlock credentials.

    Built with list_page like every other listing page rather than a bespoke
    card, so the header, table styling and empty state match the rest of the
    app instead of drifting into a second look.
    """
    rows = []
    for _, cred in creds:
        rows.append(
            # method="post" in double quotes on purpose: _POST_FORM_RE stamps
            # the CSRF token by matching that exact spelling, and a
            # single-quoted form silently receives no token. Same-origin
            # desktop requests would still pass on the Origin check alone, so
            # the breakage would only ever show up on iOS, where a home-screen
            # web app sends Origin: null and the token is all that is left.
            '<tr data-row><td class="num">%s</td><td><strong>%s</strong></td>'
            '<td class="faint">%s</td>'
            '<td style="text-align:right"><form method="post" '
            'action="/unlock/delete" style="display:inline" '
            "onsubmit=\"return confirm('Remove this unlock credential?')\">"
            '<input type="hidden" name="id" value="%s">'
            '<button class="btn btn-danger btn-sm" type="submit" '
            'data-i18n="btn.delete">Delete</button>'
            "</form></td></tr>"
            % (_esc(cred[1]), _esc(cred[5]), _esc(cred[6]), _esc(cred[1]))
        )
    if not rows:
        rows.append(
            '<tr><td colspan="4"><div class="empty">'
            '<div class="empty-ico">%s</div>'
            '<div class="empty-t" data-i18n="unlock.empty">'
            'No device registered yet</div>'
            '<div class="empty-s" data-i18n="unlock.empty_sub">'
            'Register one below, or keep using your master password</div>'
            "</div></td></tr>" % _icon("shield", "icon icon-lg")
        )
    page = list_page(
        "nav.unlock", "Biometric Unlock",
        "page.unlock.desc",
        "Resume the idle lock with this device instead of your master password.",
        "", "", "",
        [("table.id", "ID", "num"),
         ("table.label", "Label", ""),
         ("unlock.registered", "Registered", ""),
         ("table.actions", "Actions", "act")],
        "".join(rows))
    return f"""{flash}{page}
<div class="card" style="margin-top:var(--sp-4)"><div class="card-body">
  <div class="field">
    <label for="register-label" data-i18n="unlock.field.label">Label for this device</label>
    <input class="input" id="register-label" maxlength="64" placeholder="iPhone">
  </div>
  <button class="btn btn-primary" type="button" id="register-btn"
          data-csrf="{html.escape(csrf)}" data-i18n="unlock.register">Register this device</button>
  <div class="faint" id="register-status" role="status" aria-live="polite"
       style="margin-top:var(--sp-3);min-height:1.2em"></div>
  <p class="faint" style="margin-top:var(--sp-3)" data-i18n="unlock.note">The master
  password is still required for the first sign-in, once the session reaches its
  maximum age, and whenever a locked session goes unresumed for too long.</p>
</div></div>
{UNLOCK_REGISTER_SCRIPT}
"""


def settings_page(flash=""):
    """Change the master password.

    Built from the same page-head / card / field primitives as every other form
    page rather than a bespoke layout, so it inherits the focus ring, the
    dark-only palette and the split accent for free. Nothing on this page is an
    emitted value, so nothing here is painted with the value role -- the submit
    is the only accent, and it is a control.
    """
    return f"""{flash}
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="page.settings.title">Master Password</h1>
    <div class="page-sub" data-i18n="page.settings.desc">Change the password that
      encrypts this vault.</div>
  </div>
</div>
<div class="card"><div class="card-body">
  <form method="post" action="/settings/master-password" autocomplete="off">
    <div class="field">
      <label for="mp-current" data-i18n="settings.current">Current master password</label>
      <input class="input" id="mp-current" name="current" type="password"
             autocomplete="current-password" required autofocus>
    </div>
    <div class="field">
      <label for="mp-new" data-i18n="settings.new">New master password</label>
      <input class="input" id="mp-new" name="new" type="password"
             autocomplete="new-password" minlength="{MASTER_MIN_LEN}" required>
    </div>
    <div class="field">
      <label for="mp-confirm" data-i18n="settings.confirm">Confirm new master password</label>
      <input class="input" id="mp-confirm" name="confirm" type="password"
             autocomplete="new-password" minlength="{MASTER_MIN_LEN}" required>
    </div>
    <p class="faint" style="margin-bottom:var(--sp-4)" data-i18n="settings.hint">At least
      {MASTER_MIN_LEN} characters. There is no way to recover a master password you
      forget &mdash; only the recovery file and its private key can reset it.</p>
    <div class="faint" id="mp-status" role="status" aria-live="polite"
         style="margin-bottom:var(--sp-3);min-height:1.2em"></div>
    <button class="btn btn-primary" type="submit"
            data-i18n="settings.submit">Change master password</button>
  </form>
</div></div>
<div class="card" style="margin-top:var(--sp-4)">
  <div class="card-head"><h2 data-i18n="settings.effect">What this does</h2></div>
  <div class="card-body">
    <ul style="margin:0;padding-left:var(--sp-5);line-height:1.9">
      <li data-i18n="settings.effect_vault">Re-encrypts the whole vault under the
        new password.</li>
      <li data-i18n="settings.effect_recovery">Rewrites the recovery file so
        &quot;spm forgot&quot; keeps working.</li>
      <li data-i18n="settings.effect_sessions">Signs out every other browser
        session.</li>
      <li data-i18n="settings.effect_backup">Keeps the previous vault as a .bak
        and a history snapshot.</li>
    </ul>
  </div>
</div>
{SETTINGS_SCRIPT}
"""


SETTINGS_SCRIPT = """
<script>
(function () {
  var form = document.querySelector('form[action="/settings/master-password"]');
  if (!form) return;
  var pw = document.getElementById("mp-new");
  var cf = document.getElementById("mp-confirm");
  var out = document.getElementById("mp-status");
  if (!pw || !cf || !out) return;

  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }

  // Mirror only, never gate: the server re-checks both of these. If this
  // script is blocked the form still submits and still gets a real answer.
  function check() {
    if (!cf.value) { out.textContent = ""; return true; }
    var same = pw.value === cf.value;
    out.textContent = same ? "" : t("settings.mismatch", "The two new passwords do not match.");
    return same;
  }
  pw.addEventListener("input", check);
  cf.addEventListener("input", check);
})();
</script>"""


GENERATOR_SCRIPT = """
<script>
(function () {
  var WORDS = ["sun","moon","star","river","ocean","cloud","stone","tree","leaf","fern","fire","ember",
    "storm","wind","breeze","shadow","light","silver","gold","amber","flame","nova","comet","aurora",
    "pulse","echo","vapor","wave","mist","dawn","dusk","zen","sage","whale","lynx","orca","hawk","raven"];

  function t(key, fb) {
    return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(key, fb) : fb;
  }

  /* Uniform random int in [0, bound) from the platform CSPRNG.
     Rejection sampling keeps the distribution flat - a plain % bound would
     bias the low end of the charset. */
  function randBelow(bound) {
    if (bound <= 0) return 0;
    var limit = Math.floor(4294967296 / bound) * bound;
    var buf = new Uint32Array(1);
    for (var i = 0; i < 64; i++) {
      crypto.getRandomValues(buf);
      if (buf[0] < limit) return buf[0] % bound;
    }
    return buf[0] % bound;
  }

  function charset(sym, up, low, dig) {
    var b = "";
    if (up)  b += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (low) b += "abcdefghijklmnopqrstuvwxyz";
    if (dig) b += "0123456789";
    if (sym) b += "!@#$%^&*()_-+=[]{}:;,.?/|~";
    if (!b) b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return b;
  }

  function genSecure(len, o) {
    var chars = charset(o.symbols, o.upper, o.lower, o.digits), out = "";
    for (var i = 0; i < len; i++) out += chars.charAt(randBelow(chars.length));
    return { pw: out, size: chars.length };
  }

  function genEasy(count, o) {
    count = Math.min(8, Math.max(2, count));
    var parts = [];
    for (var i = 0; i < count; i++) {
      var w = WORDS[randBelow(WORDS.length)];
      if (o.upper && !o.lower) w = w.toUpperCase();
      else if (o.upper) w = w.charAt(0).toUpperCase() + w.slice(1);
      else if (!o.lower) w = w.toUpperCase();
      parts.push(w);
    }
    var pw = parts.join("-");
    if (o.digits) pw += "-" + String(randBelow(100)).padStart(2, "0");
    if (o.symbols) { var s = "!@#$%^&*"; pw += s.charAt(randBelow(s.length)); }
    var size = 0;
    if (o.upper) size += 26;
    if (o.lower) size += 26;
    if (o.digits) size += 10;
    if (o.symbols) size += 10;
    return { pw: pw, size: size || 26 };
  }

  function entropy(pw, size) {
    if (!pw || size <= 1) return 0;
    return pw.length * Math.log(size) / Math.log(2);
  }

  /* NOTE: the local accumulator must not be named `t` - it would shadow the
     translation helper above and throw "t is not a function". */
  function crackTime(bits) {
    var seconds = Math.pow(2, bits) / 1e10;
    var units = [["sec", 60], ["min", 60], ["hr", 24], ["day", 365], ["yr", 100], ["century", 10]];
    var val = seconds, label = "sec";
    for (var i = 0; i < units.length; i++) {
      if (val >= units[i][1]) { val /= units[i][1]; label = units[i][0]; }
      else break;
    }
    return val.toFixed(1) + " " + t("generator.unit." + label, label);
  }

  function updateStats(pw, size) {
    var bits = entropy(pw, size), key = "generator.strength.weak", fb = "Weak", pct = 25, col = "var(--danger)";
    if (bits >= 100)     { key = "generator.strength.excellent"; fb = "Excellent"; pct = 100; col = "var(--ok)"; }
    else if (bits >= 80) { key = "generator.strength.strong";    fb = "Strong";    pct = 78;  col = "var(--ok)"; }
    else if (bits >= 60) { key = "generator.strength.moderate";  fb = "Moderate";  pct = 55;  col = "var(--warn)"; }
    else if (bits < 40)  { key = "generator.strength.very_weak"; fb = "Very weak"; pct = 15;  col = "var(--danger)"; }
    var meter = document.getElementById("meter-fill");
    if (meter) { meter.style.transform = "scaleX(" + (pct / 100) + ")"; meter.style.background = col; }
    var el = document.getElementById("pw-stats");
    if (el) {
      el.textContent = t(key, fb) + " \\u00b7 ~" + bits.toFixed(1) + " " + t("generator.stats.bits", "bits") +
                       " \\u00b7 ~" + crackTime(bits) + " " + t("generator.stats.suffix", "to brute-force (est.)");
    }
  }

  function opts() {
    return {
      symbols: document.getElementById("symbols").checked,
      upper:   document.getElementById("upper").checked,
      lower:   document.getElementById("lower").checked,
      digits:  document.getElementById("digits").checked
    };
  }

  function mode() {
    var m = document.querySelector('input[name="gmode"]:checked');
    return m ? m.value : "secure";
  }

  function regen() {
    var len = parseInt(document.getElementById("len").value, 10) || 16, r;
    if (mode() === "easy") {
      var words = Math.min(8, Math.max(2, Math.round(len / 6)));
      document.getElementById("len-label").textContent = t("generator.words_prefix", "Words") + ": " + words;
      r = genEasy(words, opts());
    } else {
      if (len < 4) len = 4;
      document.getElementById("len-label").textContent = len;
      r = genSecure(len, opts());
    }
    document.getElementById("pw-out").textContent = r.pw;
    updateStats(r.pw, r.size);
  }

  window.SPM_regen = regen;
  window.SPM_copyPw = function () {
    var pw = document.getElementById("pw-out").textContent || "";
    if (pw) window.SPM_copy(pw, t("toast.copy_success", "Copied to clipboard."));
  };

  document.addEventListener("DOMContentLoaded", function () {
    ["len", "symbols", "upper", "lower", "digits"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.addEventListener("input", regen);
    });
    document.querySelectorAll('input[name="gmode"]').forEach(function (el) {
      el.addEventListener("change", regen);
    });
    regen();
  });
})();
</script>
"""


def generator_page():
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="generator.title">Password Generator</h1>
    <div class="page-sub" data-i18n="section.generator_desc">Create strong passwords with length, mode, and symbol toggles.</div>
  </div>
  <div class="page-actions">
    <a class="btn btn-ghost" href="/" data-i18n="link.back">Back</a>
  </div>
</div>
<div class="grid2">
  <div class="card"><div class="card-body">
    <div class="gen-out" id="pw-out">&nbsp;</div>
    <div class="meter"><i id="meter-fill"></i></div>
    <div class="faint" id="pw-stats" style="margin-top:var(--sp-3);text-align:center"
         data-i18n="generator.stats.placeholder">Adjust the options to see strength.</div>
    <div class="form-actions" style="justify-content:center">
      <button class="btn btn-primary" type="button" data-act="regen" data-i18n="generator.btn.regen">Regenerate</button>
      <button class="btn" type="button" data-act="copy-pw" data-i18n="generator.btn.copy">Copy</button>
    </div>
  </div></div>

  <div class="card"><div class="card-body">
    <div class="field">
      <label><span data-i18n="generator.length">Length</span> &middot; <b id="len-label">16</b></label>
      <input id="len" type="range" min="4" max="64" value="16"
             aria-label="Password length" data-i18n-label="generator.length">
    </div>
    <div class="field">
      <label data-i18n="generator.mode">Mode</label>
      <div style="display:flex;gap:var(--sp-4)">
        <label style="display:flex;gap:6px;align-items:center;font-weight:400">
          <input type="radio" name="gmode" value="secure" checked>
          <span data-i18n="generator.mode_secure">Secure</span></label>
        <label style="display:flex;gap:6px;align-items:center;font-weight:400">
          <input type="radio" name="gmode" value="easy">
          <span data-i18n="generator.mode_easy">Memorable</span></label>
      </div>
    </div>
    <div class="switch-row"><label for="upper" data-i18n="generator.opt.upper">Uppercase</label><input id="upper" type="checkbox" checked></div>
    <div class="switch-row"><label for="lower" data-i18n="generator.opt.lower">Lowercase</label><input id="lower" type="checkbox" checked></div>
    <div class="switch-row"><label for="digits" data-i18n="generator.opt.digits">Digits</label><input id="digits" type="checkbox" checked></div>
    <div class="switch-row"><label for="symbols" data-i18n="generator.opt.symbols">Symbols</label><input id="symbols" type="checkbox" checked></div>
  </div></div>
</div>
{GENERATOR_SCRIPT}"""
    return render_shell(content, "generator", VERSION, VAULT_PATH, title="Password Generator")


EXPORT_FORMATS = ["csv", "json", "tsv", "ndjson", "jsonl", "md", "html", "txt", "yaml", "yml",
                  "xml", "sql", "ini", "psv", "rst", "toml", "org", "scsv", "csv-noheader", "jsonc"]


def transfer_page():
    opts = "".join(
        f'<option value="{f}">{f}{" (default)" if f == "csv" else ""}</option>'
        for f in EXPORT_FORMATS
    )
    # The import picker carries the Bitwarden entries as well, labelled so it
    # is obvious which file each one wants.
    bitwarden_labels = {
        "bitwarden-json": "Bitwarden — JSON export",
        "bitwarden-csv": "Bitwarden — CSV export",
        "bitwarden-protected": "Bitwarden — password-protected JSON",
    }
    import_opts = opts + "".join(
        f'<option value="{f}">{bitwarden_labels[f]}</option>'
        for f in BITWARDEN_FORMATS
    )
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="import.title">Export / Import</h1>
    <div class="page-sub" data-i18n="import.subtitle">Download or paste data (csv/json + extended formats).</div>
  </div>
</div>
<div class="grid2">
  <div class="card">
    <div class="card-head"><h2 data-i18n="import.download">Download</h2></div>
    <div class="card-body">
      <form method="get" action="/export">
        <div class="field">
          <label for="export-fmt" data-i18n="import.format_label">Format</label>
          <select class="input" name="fmt" id="export-fmt">{opts}</select>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="import.download">Download</button>
      </form>
    </div>
    <div class="card-foot"><span data-i18n="import.supports">Supports passwords, notes, passphrases, authenticators, backup codes.</span></div>
  </div>

  <div class="card" style="position:relative" id="import-card">
    <div class="overlay" id="import-overlay" aria-live="polite">
      <div class="overlay-in">
        <div class="spinner"></div>
        <div id="import-overlay-text" data-i18n="import.overlay_upload">Uploading...</div>
      </div>
    </div>
    <div class="card-head"><h2 data-i18n="import.submit">Import</h2></div>
    <div class="card-body">
      <form method="post" action="/import" enctype="multipart/form-data" id="import-form">
        <div class="field">
          <label for="import-fmt" data-i18n="import.import_label">Import format</label>
          <select class="input" name="fmt" id="import-fmt">{import_opts}</select>
        </div>
        <div class="field">
          <label for="import-file" data-i18n="import.upload_label">Upload export file</label>
          <input class="input" id="import-file" type="file" name="file">
        </div>
        <div class="field hidden" id="import-pw-field">
          <label for="import-export-password" data-i18n="import.export_password">Export password</label>
          <input class="input" id="import-export-password" type="password" name="export_password" autocomplete="off"
                 data-i18n-placeholder="import.export_password_hint"
                 placeholder="The password you set when exporting from Bitwarden">
          <div class="hint" data-i18n="import.export_password_note">Only needed for a password-protected Bitwarden export. It is used to read the file and is never stored.</div>
        </div>
        <div class="field">
          <label for="import-data" data-i18n="import.paste_label">Or paste file contents</label>
          <textarea class="input" id="import-data" name="data" rows="6"
                    data-i18n-placeholder="import.placeholder" placeholder="Paste exported data here"></textarea>
        </div>
        <button class="btn btn-primary btn-block" type="submit" data-i18n="import.submit">Import</button>
      </form>
    </div>
  </div>
</div>
<script>
(function () {{
  var form = document.getElementById("import-form");
  if (!form) return;
  // The export password applies to exactly one format, so asking for it the
  // rest of the time would be a field nobody can answer.
  var fmt = document.getElementById("import-fmt");
  var pwField = document.getElementById("import-pw-field");
  function syncPasswordField() {{
    if (!fmt || !pwField) return;
    pwField.classList.toggle("hidden", fmt.value !== "bitwarden-protected");
  }}
  if (fmt) fmt.addEventListener("change", syncPasswordField);
  syncPasswordField();
  form.addEventListener("submit", function () {{
    var ov = document.getElementById("import-overlay");
    if (ov) ov.classList.add("on");
    if (window.SPM_AutoLock) window.SPM_AutoLock.pause();
  }});
}})();
</script>"""
    return render_shell(content, "transfer", VERSION, VAULT_PATH, title="Export / Import")


def events_page(events):
    """The security log: what was done to this vault, and when.

    Deliberately carries no record identity. The log has none to show -- that
    is its whole design -- and a page that invented one by cross-referencing
    the vault would put back exactly what the log is careful to leave out.
    """
    label_for = {"unlock": "Unlock", "write": "Write", "rewrap": "Master change",
                 "recover": "Recovery", "restore": "Restore", "archive": "Snapshot"}
    failures = sum(1 for e in events if e["outcome"] == "fail")
    rows = []
    for index, event in enumerate(events, start=1):
        detail = event.get("detail", {})
        bits = []
        if detail.get("records"):
            bits.append("%s record(s)" % _esc(detail["records"]))
        if detail.get("reason"):
            bits.append({"bad-master": "wrong master password or damaged file",
                         "missing": "file not found",
                         "corrupt": "unreadable container",
                         "unreadable": "could not be read"}.get(
                             detail["reason"], _esc(detail["reason"])))
        if detail.get("scope") == "other":
            bits.append("not the live vault")
        failed = event["outcome"] == "fail"
        rows.append(
            "<tr>"
            f'<td class="num">{index}</td>'
            f'<td class="mono">{_esc(event["when"])}</td>'
            f'<td><span class="chip">{_esc(label_for.get(event["kind"], event["kind"]))}</span></td>'
            f'<td>{"<strong>Failed</strong>" if failed else "OK"}</td>'
            f'<td class="muted">{" &middot; ".join(bits) or "&mdash;"}</td>'
            "</tr>")

    if not events:
        body = ('<div class="card"><div class="card-body">'
                '<p data-i18n="events.empty">Nothing recorded yet.</p>'
                '<p class="hint" data-i18n="events.empty_sub">Unlocks, writes and '
                'master-password changes will appear here as they happen.</p>'
                '</div></div>')
    else:
        body = f"""
<div class="card">
  <div class="card-head"><h2>{len(events)} event(s), newest first</h2></div>
  <div class="table-wrap"><table class="t">
    <thead><tr>
      <th scope="col" data-i18n="table.id">ID</th>
      <th scope="col" data-i18n="events.when">When (UTC)</th>
      <th scope="col" data-i18n="events.kind">Event</th>
      <th scope="col" data-i18n="events.outcome">Outcome</th>
      <th scope="col" data-i18n="events.detail">Detail</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
</div>"""

    warning = ""
    if failures:
        warning = (f'<div class="flash error" style="display:block">'
                   f'<strong>{failures} failed attempt(s) recorded.</strong> '
                   f'A failed unlock is a wrong master password or a damaged '
                   f'file; SPM cannot tell which apart, so it says so rather '
                   f'than guessing.</div>')

    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="nav.events">Security Events</h1>
    <div class="page-sub" data-i18n="page.events.desc">Operations on this vault.
      Recorded outside the vault and holding no record names, usernames or
      secrets.</div>
  </div>
</div>
{warning}
{body}"""
    return render_shell(content, "events", VERSION, VAULT_PATH,
                        title="Security Events")


def import_preview_page(classified, stats, skipped, token, csrf):
    """What an upload would add, before anything is written.

    Secrets are masked with the same control the rest of the dashboard uses.
    A review page that prints every imported password in clear text on one
    screen is a worse hazard than the mistake it is guarding against.
    """
    label_for = {"password": "Password", "note": "Note",
                 "passphrase": "Passphrase", "backup_code": "Backup codes",
                 "authenticator": "Authenticator"}
    body = []
    for index, (kind, row) in enumerate(classified, start=1):
        elem = "imp-%d" % index
        secret = str(row.get("secret", "") or "")
        dots = "&bull;" * min(len(secret), 24) if secret else "&mdash;"
        body.append(
            "<tr>"
            f'<td class="num">{index}</td>'
            f'<td><span class="chip">{html.escape(label_for.get(kind, kind))}</span></td>'
            f'<td class="strong">{_esc(row.get("label", "")) or "&mdash;"}</td>'
            f'<td class="muted">{_esc(row.get("username", "")) or "&mdash;"}</td>'
            f'<td><span class="secret-val masked" id="{elem}" '
            f'data-val="{html.escape(secret)}">{dots}</span> '
            f'<button class="icon-btn" type="button" data-act="reveal" '
            f'data-target="{elem}" aria-label="Show">{_icon("view", "icon icon-sm")}</button></td>'
            "</tr>")

    # "1 passwords" is the kind of thing only a rendered page shows you.
    names = {"passwords": ("password", "passwords"),
             "notes": ("note", "notes"),
             "passphrases": ("passphrase", "passphrases"),
             "backups": ("backup-code record", "backup-code records"),
             "authenticators": ("authenticator", "authenticators")}
    counts = (" &middot; ".join(f"{v} {names[k][0 if v == 1 else 1]}"
                                for k, v in stats.items() if v)
              or "Nothing in this file can be imported")
    skipped_html = ""
    if skipped:
        rows = "".join(
            f'<li>{_esc(str(r.get("label") or r.get("type") or "(unnamed)"))}</li>'
            for r in skipped[:20])
        more = (f"<li>and {len(skipped) - 20} more</li>" if len(skipped) > 20 else "")
        count = ("1 row will not be imported" if len(skipped) == 1
                 else f"{len(skipped)} rows will not be imported")
        skipped_html = f"""
<div class="flash error" style="display:block">
  <div><strong>{count}</strong>, because SPM has no matching record type for
  them. They are listed so nothing disappears without being named.</div>
  <ul style="margin:var(--sp-2) 0 0 var(--sp-4)">{rows}{more}</ul>
</div>"""

    # Nothing importable is a real outcome, not an error page: the rows above
    # name what the file held and why none of it fits. Offering a confirm
    # button here would offer a button whose only outcome is a failure.
    if classified:
        actions = f"""<form method="post" action="/import" class="form-actions">
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      <input type="hidden" name="confirm" value="{html.escape(token)}">
      <button class="btn btn-primary" type="submit" data-i18n="import.preview.confirm">Import these records</button>
      <a class="btn btn-ghost" href="/transfer" data-i18n="import.preview.cancel">Cancel</a>
    </form>"""
        table = f"""
  <div class="table-wrap"><table class="t">
    <thead><tr>
      <th scope="col" data-i18n="table.id">ID</th>
      <th scope="col" data-i18n="import.preview.kind">Type</th>
      <th scope="col" data-i18n="table.service">Service</th>
      <th scope="col" data-i18n="table.username">Username</th>
      <th scope="col" data-i18n="import.preview.secret">Secret</th>
    </tr></thead>
    <tbody>{"".join(body)}</tbody>
  </table></div>"""
    else:
        # A header row over no rows says nothing the panel above has not
        # already said, and reads as a table that failed to load.
        table = ""
        actions = ('<a class="btn" href="/transfer" '
                   'data-i18n="import.preview.back">Back to Export / Import</a>')

    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title" data-i18n="import.preview.title">Review this import</h1>
    <div class="page-sub" data-i18n="import.preview.sub">Nothing has been written yet.</div>
  </div>
</div>
{skipped_html}
<div class="card">
  <div class="card-head"><h2>{counts}</h2></div>{table}
  <div class="card-foot">{actions}</div>
</div>
{REVEAL_SCRIPT}"""
    return render_shell(content, "transfer", VERSION, VAULT_PATH,
                        title="Review this import")


def auth_view_page(aid, label, secret, period, algo, created):
    content = f"""
<div class="page-head">
  <div>
    <h1 class="page-title">{html.escape(label)}</h1>
    <div class="page-sub"><span class="chip">{html.escape(period)}s</span> <span class="chip">{html.escape(algo).upper()}</span></div>
  </div>
  <div class="page-actions">
    <a class="btn" href="/authenticator-edit?id={html.escape(aid)}" data-i18n="btn.edit">Edit</a>
    <a class="btn btn-ghost" href="/authenticators" data-i18n="form.back_list">Back to list</a>
  </div>
</div>
<div class="card" style="max-width:520px;margin:0 auto">
  <div class="totp">
    <div class="totp-code" id="code">------</div>
    <div class="totp-ring" id="ring"><i></i></div>
    <div class="faint" id="cd" data-i18n="auth.status.no_code">Waiting for code...</div>
    <button class="btn btn-primary" type="button" data-act="copy-text" data-target="code"
            data-i18n="btn.copy_code">Copy code</button>
  </div>
  <div class="card-body" style="border-top:1px solid var(--border)">
    {_secret_block(secret, "auth.view.secret", "Secret", "sec")}
    <div class="field"><label data-i18n="auth.view.created">Created</label>
      <div class="faint mono">{html.escape(created) or "&mdash;"}</div></div>
  </div>
</div>
{REVEAL_SCRIPT}
<script>
(function () {{
  var id = {jsonlib.dumps(aid)}, period = {jsonlib.dumps(int(period) if str(period).isdigit() else 30)};
  var left = 0;
  function t(k, fb) {{ return (window.SPM_I18N && window.SPM_I18N.t) ? window.SPM_I18N.t(k, fb) : fb; }}
  function paint() {{
    var ring = document.getElementById("ring");
    if (ring) ring.style.setProperty("--pct", Math.max(0, left / period * 100));
    var cd = document.getElementById("cd");
    if (cd) {{
      /* The catalogue strings carry an {{n}} placeholder ("Refreshes in {{n}}s",
         "{{n}}秒で更新") and t() does no interpolation, so substitute here or the
         placeholder renders literally next to a stray count. */
      var secs = Math.max(0, left);
      var tpl = t("auth.countdown.refresh_in", "Refreshes in {{n}}s");
      cd.textContent = tpl.indexOf("{{n}}") >= 0
        ? tpl.replace("{{n}}", secs)
        : tpl + " " + secs + "s";
    }}
  }}
  function fetchCode() {{
    fetch("/authenticator-code?id=" + encodeURIComponent(id), {{ credentials: "same-origin" }})
      .then(function (r) {{ return r.json(); }})
      .then(function (d) {{
        var code = document.getElementById("code");
        var nextCode = d.code || "------";
        if (code && code.textContent !== nextCode) {{
          code.textContent = nextCode;
          code.classList.remove("code-updated");
          if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {{
            requestAnimationFrame(function () {{ code.classList.add("code-updated"); }});
          }}
        }}
        left = d.expires_in || period;
        paint();
      }})
      .catch(function () {{
        var cd = document.getElementById("cd");
        if (cd) cd.textContent = t("auth.status.no_code", "No code available");
      }});
  }}
  fetchCode();
  setInterval(function () {{
    left -= 1;
    if (left <= 0) fetchCode(); else paint();
  }}, 1000);
}})();
</script>"""
    return render_shell(content, "authenticators", VERSION, VAULT_PATH, title=label)


# ----- The trusted core ------------------------------------------------------
# The vault format, key wrapping, vault mutation, history archiving and the
# recovery file all live in spm_core.py, which the CLI half of SPM uses too.
# This file used to carry its own copy of every one of them, and the regression
# suite carried a test whose only job was to prove the two copies still agreed.
# What remains here is the adapter: the dashboard's call sites keep their names
# and the core keeps the decisions.

def _load_core():
    import importlib.util
    bases = [os.environ.get("SPM_CORE_DIR")]
    try:
        # Normally the core sits beside this file, installed by the same
        # function that wrote it. __file__ is absent when something execs this
        # source rather than importing it, which the test suite does.
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    except NameError:
        pass
    bases.append(os.path.join(
        os.environ.get("XDG_DATA_HOME")
        or os.path.join(os.path.expanduser("~"), ".local", "share"), "spm"))
    for base in bases:
        if not base:
            continue
        candidate = os.path.join(base, "spm_core.py")
        if os.path.isfile(candidate):
            spec = importlib.util.spec_from_file_location("spm_core", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("spm_core.py was not found; run `spm web` to install it")


core = _load_core()

VAULT_FORMAT_VERSION = core.VAULT_FORMAT_VERSION
RECOVERY_PATH = core.recovery_path(VAULT_PATH)
_fsync_path = core._fsync_path
_fsync_dir = core._fsync_dir
stamp_vault_version = core.stamp_version
vault_format_version = core.format_version
recovery_pubkey_pem = core.recovery_pubkey_pem


def decrypt_vault_file(path: str, master: str) -> str:
    return core.read_vault(path, master)[0]


def decrypt_vault(master: str) -> str:
    return core.read_vault(VAULT_PATH, master)[0]


# The plaintext this request last read, so a write can tell which passwords
# changed without every one of the nineteen save sites threading it through.
# Thread-local because the server is threaded: two requests must never see
# each other's vault contents, and a stale value would attribute one user's
# rotation to another request.
_LAST_READ = threading.local()


def load_vault(master: str, session=None) -> str:
    """Vault plaintext, reusing this session's unwrapped vault key when it can.

    A format-3 read costs two gpg invocations: the key envelope under the
    master password, then the data under that key. The envelope's answer is
    the same for every request of a session, so holding the key removes that
    half from every read after the first -- measured at roughly half the time
    of a full read.

    The key lives in the session record and nowhere else, so it dies with the
    session, at the same moment the master password does. It is not a new
    class of exposure: the session already holds the password it derives from.

    A cached key that no longer opens the vault is not an error. A restore or
    a sync can replace the file under a live session, so the fallback
    re-derives from the master and re-caches, and the session keeps working.

    This is an adapter, not vault crypto -- every byte operation below it is
    still the core's.
    """
    if session is not None:
        cached = session.get("vault_key")
        if cached:
            try:
                plaintext = core.read_vault_with_key(VAULT_PATH, cached)
                if plaintext is not None:
                    _LAST_READ.plaintext = plaintext
                    return plaintext
            except Exception:
                pass
        plaintext, key = core.read_vault(VAULT_PATH, master)
        session["vault_key"] = key or ""
        _LAST_READ.plaintext = plaintext
        return plaintext
    plaintext = decrypt_vault(master)
    _LAST_READ.plaintext = plaintext
    return plaintext


def unwrap_vault_key(master: str, path=None):
    return core.unwrap_key(path or VAULT_PATH, master)


def encrypt_vault(master: str, plaintext: str, vault_key=None) -> str:
    return core.write_vault(VAULT_PATH, master, plaintext, vault_key)


def save_vault(master: str, plaintext: str, session=None) -> None:
    """Write the vault, handing the core the session's key when it has one.

    Given no key, write_vault unwraps one from the master password first --
    the same expensive invocation the read path avoids, paid again on every
    save. The write returns the key it used, which is also how a session that
    has just migrated a legacy vault picks one up.

    Per-record password history is recorded here rather than at each of the
    nineteen places that edit a record, so a new edit path cannot forget it.
    Every one of those places reads the vault first, which is what makes the
    comparison available without threading it through them all.
    """
    previous = getattr(_LAST_READ, "plaintext", None)
    if previous is not None:
        plaintext = core.record_password_history(previous, plaintext)
        # Consumed, not kept: a second save in the same request must compare
        # against what it actually read, not against a stale first read.
        _LAST_READ.plaintext = None
    key = session.get("vault_key") or None if session is not None else None
    written = encrypt_vault(master, plaintext, key)
    if session is not None:
        session["vault_key"] = written or ""


def rewrap_vault_key(old_master: str, new_master: str) -> None:
    core.rewrap(VAULT_PATH, old_master, new_master)


def _archive_vault_generation():
    core.archive_generation(VAULT_PATH)


def rewrite_recovery_file(plaintext: str, vault_key: str) -> None:
    core.install_recovery(
        VAULT_PATH, core.stage_recovery(VAULT_PATH, plaintext, vault_key))


# A master password shorter than this is refused on the way in. Dashboard
# policy, not vault format: the CLI has no floor at all, which is a gap rather
# than a decision worth copying, since this is the one password that protects
# every other one and nothing rate-limits an attacker who holds the vault file.
MASTER_MIN_LEN = 12



def totp_code(secret_b32: str, period: int = 30, algo: str = "sha1") -> str:
    import hashlib, hmac, struct, base64
    secret = secret_b32.replace(" ", "").upper()
    if not secret:
        return ""
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(time.time() // max(period, 1))
    msg = struct.pack(">Q", counter)
    algo = (algo or "sha1").lower()
    digest_mod = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}.get(algo, hashlib.sha1)
    h = hmac.new(key, msg, digest_mod).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff
    return str(code_int % 10**6).zfill(6)

SUPPORTED_FORMATS = ("csv","json","tsv","ndjson","jsonl","md","markdown","html","txt","yaml","yml","xml","sql","ini","psv","rst","toml","org","scsv","csv-noheader","jsonc",
                     "bitwarden-json","bitwarden-csv","bitwarden-protected")

# Import-only. There is no exporting *to* Bitwarden, so these belong in the
# import picker and nowhere else.
BITWARDEN_FORMATS = ("bitwarden-json", "bitwarden-csv", "bitwarden-protected")

def _export_rows(plaintext: str):
    import base64, html as htmlmod
    rows = []
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag.isdigit():  # password
            rows.append({
                "type": "password",
                "id": parts[0],
                "label": parts[1] if len(parts) > 1 else "",
                "username": parts[2] if len(parts) > 2 else "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": parts[4] if len(parts) > 4 else "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": "",
                "url": parts[6] if len(parts) > 6 else "",
                **_row_attrs_columns(parts[7] if len(parts) > 7 else ""),
            })
        elif tag == "NOTE":
            rows.append({
                "type": "note",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "PASSPHRASE":
            rows.append({
                "type": "passphrase",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "BACKUP_CODE":
            rows.append({
                "type": "backup_code",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": base64.b64decode(parts[3]).decode("utf-8", errors="replace") if len(parts) > 3 else "",
                "notes": "",
                "created": parts[4] if len(parts) > 4 else "",
                "extra": "",
                "url": ""
            })
        elif tag == "AUTH":
            rows.append({
                "type": "authenticator",
                "id": parts[1] if len(parts) > 1 else "",
                "label": parts[2] if len(parts) > 2 else "",
                "username": "",
                "secret": parts[3] if len(parts) > 3 else "",
                "notes": "",
                "created": parts[5] if len(parts) > 5 else "",
                "extra": f"period={parts[4] if len(parts)>4 else ''};algo={parts[6] if len(parts)>6 else 'sha1'}",
                "url": ""
            })
    return rows

def export_content(fmt: str, plaintext: str):
    import csv, json, html as htmlmod, io
    rows = _export_rows(plaintext)
    fieldnames = ["type","id","label","username","secret","notes","created","extra","url",
                  "folder","fields"]
    fmt = fmt.lower()
    if fmt == "json":
        return json.dumps(rows, ensure_ascii=False, indent=2)
    if fmt in ("ndjson","jsonl"):
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
    if fmt == "tsv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt in ("md","markdown"):
        out = ["| " + " | ".join(fieldnames) + " |", "|" + "|".join([" --- "]*len(fieldnames)) + "|"]
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            out.append("| " + " | ".join(cells) + " |")
        return "\n".join(out) + "\n"
    if fmt == "html":
        out = ["<table border='1' cellpadding='4' cellspacing='0'>", "<tr>" + "".join(f"<th>{htmlmod.escape(k)}</th>" for k in fieldnames) + "</tr>"]
        for r in rows:
            out.append("<tr>" + "".join(f"<td>{htmlmod.escape(str(r.get(k,'') or ''))}</td>" for k in fieldnames) + "</tr>")
        out.append("</table>")
        return "\n".join(out)
    if fmt == "toml":
        out=[]
        for r in rows:
            out.append("[[item]]")
            for k in fieldnames:
                val = str(r.get(k, "") or "").replace("\\","\\\\").replace("\n","\\n").replace('"','\\"')
                out.append(f'{k} = "{val}"')
            out.append("")
        return "\n".join(out)
    if fmt == "org":
        header = "| " + " | ".join(fieldnames) + " |"
        sep = "|" + "+".join("-" * (len(k)+2) for k in fieldnames) + "|"
        out = [header, sep]
        for r in rows:
            cells = [json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames]
            out.append("| " + " | ".join(cells) + " |")
        return "\n".join(out) + "\n"
    if fmt == "scsv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=";")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt == "csv-noheader":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=",")
        writer.writerows(rows)
        return buf.getvalue()
    if fmt == "jsonc":
        import json
        return json.dumps(rows, ensure_ascii=False)
    if fmt in ("yaml","yml"):
        out=[]
        for r in rows:
            out.append("-")
            for k in fieldnames:
                val = str(r.get(k, "") or "")
                out.append(f"  {k}: {json.dumps(val, ensure_ascii=False)}")
        return "\n".join(out) + "\n"
    if fmt == "xml":
        out=["<?xml version=\"1.0\" encoding=\"UTF-8\"?>","<data>"]
        for r in rows:
            out.append("  <item>")
            for k in fieldnames:
                val = htmlmod.escape(str(r.get(k,"") or ""))
                out.append(f"    <{k}>{val}</{k}>")
            out.append("  </item>")
        out.append("</data>")
        return "\n".join(out)
    if fmt == "sql":
        out=["CREATE TABLE spm_export(type TEXT,id TEXT,label TEXT,username TEXT,secret TEXT,notes TEXT,created TEXT,extra TEXT);"]
        for r in rows:
            vals=[str(r.get(k,"") or "") for k in fieldnames]
            safe=[v.replace("'", "''") for v in vals]
            out.append("INSERT INTO spm_export(type,id,label,username,secret,notes,created,extra) VALUES ('%s');" % ("','".join(safe)))
        return "\n".join(out) + "\n"
    if fmt == "ini":
        out=[]
        for r in rows:
            sect = f"{r.get('type','unknown')}_{r.get('id','')}"
            out.append(f"[{sect}]")
            for k in fieldnames:
                val = json.dumps(str(r.get(k,'') or ''), ensure_ascii=False)
                out.append(f"{k}={val}")
            out.append("")
        return "\n".join(out)
    if fmt == "psv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter="|")
        writer.writeheader(); writer.writerows(rows)
        return buf.getvalue()
    if fmt == "rst":
        encoded_rows=[{k:json.dumps(str(r.get(k,"") or ""), ensure_ascii=False).replace("|", "\\u007c") for k in fieldnames} for r in rows]
        widths={k:max(len(k), max(len(r[k]) for r in encoded_rows) if encoded_rows else 0) for k in fieldnames}
        def sep(char="+"):
            return char + char.join("-" * (widths[k]+2) for k in fieldnames) + char
        def row(vals):
            return "|" + "|".join(" " + v.ljust(widths[k]) + " " for k,v in vals) + "|"
        out=[sep(), row([(k,k) for k in fieldnames]), sep("+")]
        for r in encoded_rows:
            out.append(row([(k, r[k]) for k in fieldnames]))
            out.append(sep())
        return "\n".join(out) + "\n"
    # default csv/txt
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, delimiter=",")
    writer.writeheader(); writer.writerows(rows)
    return buf.getvalue()

def _parse_import_rows(fmt: str, content: str):
    import configparser, csv, json, re
    import xml.etree.ElementTree as ET
    from html.parser import HTMLParser
    fmt = fmt.lower()
    if fmt in ("json","jsonc"):
        return json.loads(content)
    if fmt in ("ndjson","jsonl"):
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    if fmt == "html":
        class TableParser(HTMLParser):
            def __init__(self):
                super().__init__(); self.rows=[]; self.row=[]; self.cell=[]; self.in_cell=False
            def handle_starttag(self, tag, attrs):
                if tag.lower() in ("td", "th"): self.in_cell=True; self.cell=[]
            def handle_data(self, data):
                if self.in_cell: self.cell.append(data)
            def handle_endtag(self, tag):
                tag=tag.lower()
                if tag in ("td", "th") and self.in_cell:
                    self.row.append("".join(self.cell)); self.in_cell=False
                elif tag == "tr" and self.row:
                    self.rows.append(self.row); self.row=[]
        parser=TableParser(); parser.feed(content)
        if not parser.rows: return []
        return [dict(zip(parser.rows[0], row)) for row in parser.rows[1:]]
    if fmt in ("yaml", "yml"):
        rows=[]; current=None
        for line in content.splitlines():
            if line.strip() == "-":
                if current is not None: rows.append(current)
                current={}
            elif current is not None and ":" in line:
                key, value=line.strip().split(":", 1)
                value=value.strip()
                try: value=json.loads(value)
                except json.JSONDecodeError: value=value.strip('"')
                current[key]=value
        if current is not None: rows.append(current)
        return rows
    if fmt == "xml":
        root=ET.fromstring(content)
        return [{child.tag: (child.text or "") for child in item} for item in root.findall("item")]
    if fmt == "sql":
        rows=[]; fields=["type","id","label","username","secret","notes","created","extra","url"]
        for values in re.findall(r"INSERT\s+INTO\s+spm_export\s*\([^)]*\)\s*VALUES\s*\((.*?)\)\s*;", content, re.I | re.S):
            parsed=next(csv.reader([values], delimiter=",", quotechar="'", doublequote=True, skipinitialspace=True))
            rows.append(dict(zip(fields, parsed)))
        return rows
    if fmt == "ini":
        cfg=configparser.ConfigParser(interpolation=None); cfg.optionxform=str; cfg.read_string(content)
        return [{k: (json.loads(v) if v.startswith('"') and v.endswith('"') else v) for k,v in cfg.items(section)} for section in cfg.sections()]
    if fmt == "toml":
        import tomllib
        return tomllib.loads(content).get("item", [])
    delim = "," if fmt in ("csv","csv-noheader","jsonc","txt") else ";" if fmt=="scsv" else "\t" if fmt=="tsv" else "|"
    rows=[]
    if fmt=="csv-noheader":
        # StringIO, not splitlines(): csv needs the embedded newlines intact
        # to reassemble quoted multi-line fields into a single row.
        reader = csv.reader(io.StringIO(content), delimiter=delim)
        for row in reader:
            rows.append({
                "type": row[0] if len(row)>0 else "",
                "id": row[1] if len(row)>1 else "",
                "label": row[2] if len(row)>2 else "",
                "username": row[3] if len(row)>3 else "",
                "secret": row[4] if len(row)>4 else "",
                "notes": row[5] if len(row)>5 else "",
                "created": row[6] if len(row)>6 else "",
                "extra": row[7] if len(row)>7 else "",
                "url": row[8] if len(row)>8 else "",
            })
        return rows
    reader = csv.DictReader(io.StringIO(content), delimiter=delim)
    return list(reader)

def _detect_bitwarden(fmt: str, content: str):
    """The bitwarden-* format this content really is, or "" if it is not one."""
    import csv as csvlib
    if fmt in ("json", "jsonc"):
        try:
            payload = jsonlib.loads(content)
        except Exception:
            return ""
        if isinstance(payload, dict) and payload.get("encrypted"):
            return "bitwarden-protected"
        if core.looks_like_bitwarden_json(payload):
            return "bitwarden-json"
        return ""
    if fmt == "csv":
        try:
            reader = csvlib.DictReader(io.StringIO(content))
            if core.looks_like_bitwarden_csv_header(reader.fieldnames):
                return "bitwarden-csv"
        except Exception:
            return ""
    return ""


def _bitwarden_import_rows(fmt: str, content: str, export_password: str = ""):
    """Rows in SPM's import schema from any of Bitwarden's three export files.

    The mapping itself lives in the core, so the CLI and the dashboard cannot
    come to different conclusions about what a Bitwarden file contains.
    """
    import csv as csvlib
    if fmt == "bitwarden-csv":
        reader = csvlib.DictReader(io.StringIO(content))
        return core.bitwarden_csv_rows(list(reader))

    payload = jsonlib.loads(content)
    if fmt == "bitwarden-protected" or (isinstance(payload, dict) and payload.get("encrypted")):
        if not export_password:
            raise ValueError("This export is password-protected. Enter the export password.")
        payload = jsonlib.loads(core.decrypt_bitwarden_export(payload, export_password))
    if not core.looks_like_bitwarden_json(payload):
        raise ValueError("This does not look like a Bitwarden JSON export.")
    return core.bitwarden_rows(payload)


def parse_plain_table(text):
    import json
    rows=[]
    headers=None
    for ln in text.splitlines():
        ln=ln.strip()
        if not ln or ln.startswith("#") or ln.startswith("| ---") or ln.startswith("+"):
            continue
        if "|" in ln:
            parts=[p.strip() for p in ln.strip("|").split("|")]
        else:
            parts=[p.strip() for p in ln.split()]
        if len(parts) < 2:
            continue
        if parts[0].lower() == "type":
            headers=[p.lower() for p in parts]
            continue
        parts=[json.loads(p) if p.startswith('"') and p.endswith('"') else p for p in parts]
        if headers:
            rows.append(dict(zip(headers, parts)))
        else:
            rows.append({
                "type": parts[0],
                "label": parts[1] if len(parts)>1 else "",
                "username": parts[2] if len(parts)>2 else "",
                "secret": parts[3] if len(parts)>3 else "",
                "notes": parts[4] if len(parts)>4 else "",
                "created": parts[5] if len(parts)>5 else "",
                "extra": parts[6] if len(parts)>6 else "",
                "url": parts[7] if len(parts)>7 else "",
            })
    return rows


def _import_rows(fmt: str, content: str, export_password: str = ""):
    """Rows an upload would add, without touching the vault.

    Split out of _apply_import so a preview runs exactly the parse the commit
    will run. Two code paths that agree today would not agree for long, and a
    preview that shows something other than what gets written is worse than no
    preview at all.
    """
    if fmt in BITWARDEN_FORMATS:
        rows = _bitwarden_import_rows(fmt, content, export_password)
    elif fmt in ("json","jsonc","ndjson","jsonl","csv","csv-noheader","tsv","scsv","psv","txt","html","yaml","yml","xml","sql","ini","toml"):
        # A Bitwarden file picked as plain json or csv is still a Bitwarden
        # file. Detecting it rather than failing means choosing the wrong entry
        # in the dropdown is not a silent, partial import -- which is what a
        # Bitwarden CSV used to produce: one empty note and every login lost.
        detected = _detect_bitwarden(fmt, content)
        rows = (_bitwarden_import_rows(detected, content, export_password)
                if detected else _parse_import_rows(fmt, content))
    else:
        rows = parse_plain_table(content)
    if not rows:
        raise ValueError("No records detected in upload.")
    return rows


IMPORT_KINDS = (
    ("password", ("password", "pass", "")),
    ("note", ("note", "notes")),
    ("passphrase", ("phrase", "passphrase", "secret")),
    ("backup_code", ("backup_code", "backup", "codes", "backupcode")),
    ("authenticator", ("authenticator", "auth")),
)


def classify_import_row(row):
    """The record kind an import row becomes, or "" when it becomes nothing.

    The same reading the commit uses, so a preview cannot count a row the
    commit then drops -- which is the failure a preview exists to catch.
    """
    kind = (row.get("type", "") or "").lower()
    for name, aliases in IMPORT_KINDS:
        if kind in aliases:
            return name
    return ""


def preview_import(fmt: str, content: str, export_password: str = ""):
    """(rows, stats, skipped) for an upload, having written nothing."""
    rows = _import_rows(fmt, content, export_password)
    stats = {"passwords": 0, "notes": 0, "passphrases": 0,
             "backups": 0, "authenticators": 0}
    bucket = {"password": "passwords", "note": "notes",
              "passphrase": "passphrases", "backup_code": "backups",
              "authenticator": "authenticators"}
    kept, skipped = [], []
    for row in rows:
        kind = classify_import_row(row)
        if not kind:
            skipped.append(row)
            continue
        stats[bucket[kind]] += 1
        kept.append((kind, row))
    return kept, stats, skipped


# A reviewed import waits here, not in the browser. Sending parsed rows back to
# the client for the confirm step would mean handing a decrypted
# password-protected export to the page that just uploaded it -- strictly worse
# than today, where the decrypted form never leaves the server. It lives in the
# session record instead, so it dies with the session exactly as the vault key
# does, and it is short-lived on top of that: a review left open over lunch
# should not still be committable.
PENDING_IMPORT_TTL = 300


def stash_pending_import(session, classified, stats, skipped):
    """Hold a reviewed import for confirmation; returns its one-use token."""
    token = secrets.token_hex(16)
    session["pending_import"] = {
        "token": token, "classified": classified, "stats": stats,
        "skipped": len(skipped), "at": time.time(),
    }
    return token


def take_pending_import(session, token):
    """The held import, consumed. Raises if it is absent, stale or unmatched."""
    pending = session.get("pending_import")
    # Cleared whatever happens next: a token that failed to match must not get
    # a second attempt, and a successful one must not be replayable.
    session["pending_import"] = None
    if not pending:
        raise ValueError("Nothing to confirm. Upload the file again.")
    if time.time() - pending["at"] > PENDING_IMPORT_TTL:
        raise ValueError("That preview expired. Upload the file again.")
    if not hmac.compare_digest(pending["token"], str(token or "")):
        raise ValueError("That confirmation did not match the preview.")
    return pending["classified"]


def _apply_import(fmt: str, content: str, plaintext: str, export_password: str = ""):
    """Parse an upload and apply it. Kept for callers that do both at once."""
    fmt = fmt.lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError("Unsupported format")
    classified, _stats, _skipped = preview_import(fmt, content, export_password)
    return apply_import_rows(classified, plaintext)


def _row_attrs_columns(column):
    """The folder and fields columns an export carries for one record.

    Exported as their own columns rather than as the stored base64 blob: an
    export is meant to be readable, and a column of opaque base64 is neither
    readable nor editable by whatever the user opens it with.
    """
    folder, fields = core.decode_attrs(column)
    return {
        "folder": folder,
        "fields": jsonlib.dumps(
            [{"name": n, "value": v} for n, v in fields],
            separators=(",", ":"), ensure_ascii=False) if fields else "",
    }


def _attrs_from_row(row):
    """The attributes column for an imported row.

    Tolerant on purpose: an import is the one place rows arrive from software
    that never heard of this format. A folder or a fields list that does not
    parse is dropped rather than failing the import, because losing one
    optional column is better than refusing a file of real passwords.
    """
    folder = str(row.get("folder", "") or "")
    fields = []
    raw = row.get("fields", "")
    if isinstance(raw, list):
        candidates = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            candidates = jsonlib.loads(raw)
        except Exception:
            candidates = []
    else:
        candidates = []
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict):
                name, value = item.get("name"), item.get("value")
                if isinstance(name, str) and name.strip():
                    fields.append((name, str(value if value is not None else "")))
    try:
        return core.encode_attrs(folder, fields)
    except Exception:
        return ""


def apply_import_rows(classified, plaintext: str):
    """Write already-classified rows into `plaintext`.

    Takes the classification rather than redoing it, so a confirmed import
    writes exactly the records the preview showed. Re-parsing here would let
    the two drift, and a preview that disagrees with the commit is worse than
    no preview: it invites trust it has not earned.
    """
    import base64
    tab = "\t"

    def next_id(tag, lines):
        max_id = 0
        for ln in lines:
            if not ln:
                continue
            parts = ln.split(tab)
            if tag == "PASS" and parts[0].isdigit():
                max_id = max(max_id, int(parts[0]))
            elif parts[0] == tag and len(parts) > 1 and parts[1].isdigit():
                max_id = max(max_id, int(parts[1]))
        return max_id + 1

    lines = plaintext.splitlines()

    stats = {"passwords": 0, "notes": 0, "passphrases": 0, "backups": 0, "authenticators": 0}

    def _vurl(value):
        # Same allowlist as sanitize_url in the CLI. An import is the least
        # trusted way a value enters the vault, so a foreign CSV carrying
        # "javascript:..." in its url column is dropped rather than stored --
        # the field renders as a link and will feed the browser extension.
        text = _vf(value).strip()
        if not text:
            return ""
        return text if re.match(r"(?i)^https?://[^\s/]+", text) else ""

    def add_password(r):
        pid = str(next_id("PASS", lines))
        lines.append(tab.join([
            pid,
            _vf(r.get("label","")),
            _vf(r.get("username","")),
            _vf(r.get("secret","")),
            _vf(r.get("notes","")),
            _vf(r.get("created","")),
            _vurl(r.get("url","")),
            _attrs_from_row(r),
        ]))
        stats["passwords"] += 1

    def add_note(r):
        nid = str(next_id("NOTE", lines))
        body_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "NOTE",
            nid,
            _vf(r.get("label","")),
            body_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["notes"] += 1

    def add_passphrase(r):
        pid = str(next_id("PASSPHRASE", lines))
        secret_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "PASSPHRASE",
            pid,
            _vf(r.get("label","")),
            secret_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["passphrases"] += 1

    def add_backup(r):
        bid = str(next_id("BACKUP_CODE", lines))
        codes_b64 = base64.b64encode((r.get("secret","") or "").encode("utf-8")).decode("ascii")
        lines.append(tab.join([
            "BACKUP_CODE",
            bid,
            _vf(r.get("label","")),
            codes_b64,
            _vf(r.get("created","")),
            "-"
        ]))
        stats["backups"] += 1

    def add_auth(r):
        aid = str(next_id("AUTH", lines))
        extra = str(r.get("extra","") or "")
        algo = "sha1"
        if "algo=" in extra:
            for part in extra.split(";"):
                if part.startswith("algo="):
                    algo = part.split("=",1)[1] or "sha1"
        algo = (r.get("algorithm","") or algo or "sha1").lower()
        if algo not in ("sha1","sha256","sha512"):
            algo = "sha1"
        period_val = ""
        if "period=" in extra:
            for part in extra.split(";"):
                if part.startswith("period="):
                    period_val = part.split("=",1)[1]
        period_val = period_val or str(r.get("period","") or r.get("extra","")).replace("period=","") or "30"
        lines.append(tab.join([
            "AUTH",
            aid,
            _vf(r.get("label","")),
            _vf(r.get("secret","")),
            _vf(period_val or "30"),
            _vf(r.get("created","")),
            algo
        ]))
        stats["authenticators"] += 1

    writer = {"password": add_password, "note": add_note,
              "passphrase": add_passphrase, "backup_code": add_backup,
              "authenticator": add_auth}
    for kind, row in classified:
        writer[kind](row)

    total_added = sum(stats.values())
    if total_added == 0:
        raise ValueError("No supported records found in upload.")
    return "\n".join(lines) + "\n", stats

def parse_multipart(body_bytes: bytes, content_type: str):
	"""
	Minimal multipart/form-data parser using email.parser (avoids deprecated cgi).
	Returns dict name -> raw bytes.
	"""
	ctype = (content_type or "")
	if "multipart/form-data" not in ctype.lower():
		return {}
	boundary = ""
	for part in ctype.split(";"):
		part = part.strip()
		if part.lower().startswith("boundary="):
			boundary = part.split("=", 1)[1].strip()
			if boundary.startswith('"') and boundary.endswith('"'):
				boundary = boundary[1:-1]
			break
	if not boundary:
		return {}
	header = f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n".encode("utf-8", "ignore")
	msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(header + body_bytes)
	out = {}
	for part in msg.iter_parts():
		name = part.get_param("name", header="content-disposition") or ""
		if not name:
			continue
		payload = part.get_payload(decode=True) or b""
		out[name] = payload
	return out

def parse_entries(plaintext: str):
    """Password entries.

    A password row is identified the way the CLI identifies one: field 1 is a
    number. Listing every other row type by prefix was a denylist, and it had
    already fallen behind -- ATTACHMENT and PASSKEY rows are both six fields or
    longer, so they were being listed as passwords with their base64 payload
    sitting in the password column, and counted in the security score. Anything
    SPM adds later is excluded by default now instead of by remembering to add
    it here.
    """
    lines = plaintext.splitlines()
    entries = []
    for idx, line in enumerate(lines):
        if not line or line.startswith("#") or line.startswith("META_"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6 and parts[0].isdigit():
            entries.append((idx, parts))
    return lines, entries

def parse_notes(plaintext: str):
    """Secure notes with prefix NOTE."""
    lines = plaintext.splitlines()
    notes = []
    for idx, line in enumerate(lines):
        if not line.startswith("NOTE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            notes.append((idx, parts))
    return lines, notes

def parse_passphrases(plaintext: str):
    """Passphrases stored as PASSPHRASE rows."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("PASSPHRASE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items

def parse_backup_codes(plaintext: str):
    """Backup codes stored as BACKUP_CODE rows."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("BACKUP_CODE\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items

def parse_authenticators(plaintext: str):
    """Authenticators stored as AUTH rows (TOTP)."""
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("AUTH\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            items.append((idx, parts))
    return lines, items


def parse_webauthn(plaintext: str):
    """Unlock credentials stored as WEBAUTHN rows.

    Deliberately a separate row type from PASSKEY. A PASSKEY row is metadata
    about a passkey held somewhere else -- `spm passkey-add` says as much when
    it prints "private key remains in the platform authenticator". These are
    credentials to this vault, and listing SPM's own unlock keys in
    `spm passkey-list` would be actively misleading.

    Layout: WEBAUTHN, id, credential_id (b64url), public key (SPKI, b64),
    rp_id, label, created.
    """
    lines = plaintext.splitlines()
    items = []
    for idx, line in enumerate(lines):
        if not line.startswith("WEBAUTHN\t"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            items.append((idx, parts))
    return lines, items


def _b64url_decode(value):
    """Decode base64url without padding, rejecting anything else."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    stripped = value.strip()
    if not stripped or not re.match(r"^[A-Za-z0-9_-]+=*$", stripped):
        raise ValueError("not base64url")
    padding = "=" * (-len(stripped.rstrip("=")) % 4)
    return base64.urlsafe_b64decode(stripped.rstrip("=") + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _spki_to_pem(spki_der: bytes) -> str:
    body = base64.b64encode(spki_der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def verify_es256(spki_der: bytes, signature: bytes, signed: bytes) -> bool:
    """Verify an ES256 signature against an SPKI public key.

    Python's standard library has no asymmetric verify, and this server has no
    third-party dependencies. openssl is already a hard requirement of SPM (it
    backs the recovery-key flow), so verification shells out the same way vault
    access already shells out to gpg.

    Only public data touches the filesystem here: an SPKI public key, a
    signature and the signed bytes. No secret is written.
    """
    if not spki_der or not signature or not signed:
        return False
    tmpdir = tempfile.mkdtemp(prefix="spm-webauthn-")
    try:
        pem_path = os.path.join(tmpdir, "key.pem")
        sig_path = os.path.join(tmpdir, "sig.der")
        msg_path = os.path.join(tmpdir, "msg.bin")
        with open(pem_path, "w", encoding="ascii") as handle:
            handle.write(_spki_to_pem(spki_der))
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        with open(msg_path, "wb") as handle:
            handle.write(signed)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pem_path,
             "-signature", sig_path, msg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return result.returncode == 0
    except (OSError, ValueError):
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_authenticator_data(auth_data: bytes):
    """Split the fixed header of an authenticatorData blob.

    Only the header is needed: the RP id hash, the flag byte and the signature
    counter. Attested credential data and extensions sit past byte 37 and are
    not parsed, which is what keeps this server free of a CBOR decoder.
    """
    if len(auth_data) < 37:
        raise ValueError("authenticatorData too short")
    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    return rp_id_hash, flags, sign_count


def check_authenticator_data(auth_data: bytes):
    """Common authenticatorData checks for both ceremonies.

    User verification is required, not merely user presence. Without the UV
    check a bare tap on the authenticator satisfies the ceremony and Face ID
    becomes decoration on top of an unlock anyone holding the phone can do.
    """
    rp_id_hash, flags, sign_count = parse_authenticator_data(auth_data)
    if not hmac.compare_digest(rp_id_hash, hashlib.sha256(WEBAUTHN_RP_ID.encode("utf-8")).digest()):
        return None, "relying party mismatch"
    if not flags & 0x01:
        return None, "user presence flag not set"
    if not flags & 0x04:
        return None, "user verification flag not set"
    return sign_count, ""


def check_client_data(raw_json: bytes, expected_type: str, expected_challenge: bytes):
    """Validate clientDataJSON for either ceremony."""
    try:
        data = jsonlib.loads(raw_json.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "malformed clientDataJSON"
    if not isinstance(data, dict):
        return "malformed clientDataJSON"
    if data.get("type") != expected_type:
        return "wrong ceremony type"
    try:
        supplied = _b64url_decode(data.get("challenge") or "")
    except ValueError:
        return "malformed challenge"
    if not hmac.compare_digest(supplied, expected_challenge):
        return "challenge mismatch"
    # The Origin *header* is "null" inside an iOS home-screen web app, which is
    # why _write_authorized has a branch for it. The origin recorded in
    # clientDataJSON is the real one even there, so it can be compared exactly.
    if data.get("origin") != WEBAUTHN_ORIGIN:
        return "origin mismatch"
    return ""


def rotation_days():
    """Age after which a password is flagged for rotation."""
    try:
        value = int(os.environ.get("SPM_ROTATION_DAYS", "365"))
    except ValueError:
        return 365
    return value if value > 0 else 365


def _entry_age_days(created, now):
    """Age of a record in days, or None when the timestamp is unreadable."""
    try:
        stamp = time.mktime(time.strptime(created.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return None
    return (now - stamp) / 86400.0


def compute_security(entries, plaintext, check_breaches=False):
    """Score the vault and name the offending IDs.

    The CLI's `spm security-dashboard` and this function have to agree: two
    copies of the same weighting drifted apart once already (the CLI penalised
    malformed authenticators, the web did not, so the same vault scored
    differently depending on where you looked). This is now the single
    implementation for the SPM Dashboard, and the regression suite asserts parity with
    the CLI.

    Secrets are read to compare and measure them; only IDs are ever returned.
    """
    del entries  # retained for call-site compatibility; the core parses once.
    return core.security_report(
        plaintext, rotation_days(), check_breaches=check_breaches)


# A tag is a #word in a plaintext field. The lookbehind keeps "C#" and the
# fragment in "http://host/page#anchor" from becoming tags.
_TAG_RE = re.compile(r"(?<!\S)#([A-Za-z0-9][\w-]{0,31})")


def extract_tags(*fields):
    """Tags parsed from plaintext fields only -- never from a secret.

    SPM has no tag column. Rather than migrate every record, tags are a
    convention inside fields the user already edits: a password's service name
    and notes, and the title/label of every other record type. Secret fields
    and base64 bodies are never scanned, so a tag can never be a secret.
    """
    found = []
    for text in fields:
        for tag in _TAG_RE.findall(text or ""):
            tag = tag.lower()
            if tag not in found:
                found.append(tag)
    return found


def entry_tags(parts):
    """Tags for a password row: service name (field 2) and notes (field 5)."""
    name = parts[1] if len(parts) > 1 else ""
    notes = parts[4] if len(parts) > 4 else ""
    return extract_tags(name, notes)


def search_vault(plaintext, term):
    """Search every record type by label, name, username, url and id.

    Secret fields are deliberately not searched. If a query could match a
    password, the result count would answer "is this string in the vault?" for
    anyone who reached an unlocked session -- a confirmation oracle. The url is
    safe to index for the same reason the label is: it is not a secret, it is
    already shown on the entry page, and matching it is how you find the login
    for a site you are looking at.
    """
    needle = (term or "").strip().lower()
    if not needle:
        return []
    out = []
    _, entries = parse_entries(plaintext)
    for _, p in entries:
        url = p[6] if len(p) > 6 else ""
        if needle in " ".join((p[0], p[1], p[2], url)).lower():
            out.append(("nav.passwords", "Password", p[0], p[1], f"/view?id={urllib.parse.quote(p[0])}"))
    for kind_key, kind, parser, href in (
            ("nav.notes", "Note", parse_notes, "/notes-view?id="),
            ("nav.passphrases", "Passphrase", parse_passphrases, "/passphrase-view?id="),
            ("nav.backup_codes", "Backup codes", parse_backup_codes, "/backup-codes-view?id="),
            ("nav.authenticators", "Authenticator", parse_authenticators, "/authenticator-view?id=")):
        _, items = parser(plaintext)
        for _, p in items:
            rid = p[1] if len(p) > 1 else ""
            label = p[2] if len(p) > 2 else ""
            if needle in (rid + " " + label).lower():
                out.append((kind_key, kind, rid, label, href + urllib.parse.quote(rid)))
    return out


def _history_dir():
    """Where the CLI keeps encrypted vault generations.

    Must stay identical to _archive_vault_generation() below and to the CLI's
    history_dir(); a mismatch would silently show an empty history rather than
    fail, so both derivations live here.
    """
    data_dir = os.environ.get("SPM_DATA_DIR") or os.path.join(
        os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"), "spm")
    scope = hashlib.sha256(os.path.abspath(VAULT_PATH).encode("utf-8")).hexdigest()[:16]
    return os.path.join(data_dir, "history", scope)


# Snapshot names are generated, so they can be matched exactly rather than
# screened for traversal: an allowlist cannot be talked past with "..%2f".
_SNAPSHOT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}\.[0-9]+\.[0-9a-f]{6,64}\.gpg$")


def list_history_snapshots():
    """Newest-first list of (name, taken_utc, size) for the current vault.

    Ordered and dated by the timestamp inside the filename, not by mtime.
    Snapshots are made with shutil.copy2, which copies the *source* file's
    mtime, so an mtime sort returns the age of the vault each snapshot came
    from rather than the order they were taken -- which put an older snapshot
    at the top of the list. The name is generated as UTC %Y%m%dT%H%M%S, so a
    lexical sort on it is chronological.
    """
    hist = _history_dir()
    out = []
    try:
        names = os.listdir(hist)
    except OSError:
        return out
    for name in names:
        if not _SNAPSHOT_RE.match(name):
            continue
        try:
            size = os.stat(os.path.join(hist, name)).st_size
        except OSError:
            continue
        out.append((name, name.split(".", 1)[0], size))
    out.sort(key=lambda row: row[0], reverse=True)
    return out


class SPMServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}  # token -> {"master", "vault_key", "created", "last_seen", "state", ...}
        self.login_failures = {}  # client ip -> {"count": int, "until": float}
        self.webauthn_counters = {}  # credential id -> highest signature counter seen
        self.auth_lock = threading.RLock()
        # Every mutation is a decrypt -> modify -> encrypt transaction. Without
        # one lock around that whole sequence, concurrent requests calculate the
        # same next ID, overwrite each other's records, and race on .webtmp.
        self.vault_lock = threading.RLock()
        self.vault_lock_file = open(VAULT_PATH + ".lock", "a+", encoding="utf-8")
        os.chmod(VAULT_PATH + ".lock", 0o600)

# Idle timeout enforced by the server. The 30-second auto-lock users actually
# see is implemented in the browser, which means it is not a control at all
# against a client whose JavaScript does not run -- and that is not a
# hypothetical: a CDN rewriting inline scripts disabled it outright once. This
# is the backstop that holds when the browser lock does not. It cannot match
# the browser's 30 seconds, because the browser resets on mouse and touch
# activity that reaches no server; 5 minutes is long enough to read a page and
# far short of the half hour this used to grant.
SESSION_TTL = 300
# Absolute lifetime: the idle TTL above slides on every request, so without
# this a session (and the plaintext master password it holds) could live for
# as long as the browser kept poking it.
SESSION_MAX_AGE = 12 * 3600
# A suspended session still holds the plaintext master password in memory so a
# biometric can resume it without a retyped password. That memory residency is
# the entire cost of the feature, so it is bounded separately and does not
# slide: once this much time has passed since the screen locked, the session is
# swept and the master password is required again. SESSION_MAX_AGE still caps
# the total -- an unlock never resets "created".
def _suspend_max_age():
    try:
        value = int(os.environ.get("SPM_WEB_SUSPEND_MAX", "28800"))
    except ValueError:
        return 28800
    # Zero or negative would mean "resumable forever" if used as a comparison
    # bound; treat anything nonsensical as the default rather than as no limit.
    return value if 0 < value <= SESSION_MAX_AGE else 28800

SUSPEND_MAX_AGE = _suspend_max_age()
# Web mode can bind beyond loopback, so an unauthenticated master-password
# guess has to cost something. Lock a client out briefly once it burns through
# this many attempts.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
MAX_POST_BYTES = 2 * 1024 * 1024
MAX_IMPORT_BYTES = 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    # Set per request by _get_cookie_session(). None on every unauthenticated
    # path, which is what makes the vault helpers fall back to the master.
    _session_rec = None

    def log_message(self, fmt, *args):
        sys.stderr.write("[SPM Dashboard] " + fmt % args + "\n")

    def end_headers(self):
        # Decrypted credentials and one-time codes must never enter browser or
        # proxy caches. Apply the baseline to every response, including JSON,
        # downloads, redirects, and errors produced by BaseHTTPRequestHandler.
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # script-src carried 'unsafe-inline' until every inline handler was
        # replaced by a delegated listener. The remaining <script> blocks are
        # stamped with this response's nonce in _send_html.
        nonce = getattr(self, "_csp_nonce", "")
        script_src = "'self' 'nonce-%s'" % nonce if nonce else "'self'"
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src " + script_src + "; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'",
        )
        super().end_headers()

    _POST_FORM_RE = re.compile(r'(<form\b[^>]*\bmethod="post"[^>]*>)', re.IGNORECASE)
    _SCRIPT_RE = re.compile(r'<script(?![^>]*\bnonce=)([^>]*)>', re.IGNORECASE)

    def _send_html(self, code, body):
        lang = html.escape(self._get_lang())
        if "__LANG__" in body:
            body = body.replace("__LANG__", lang)
        if "__SPM_UNLOCK__" in body:
            _, session = self._session_record()
            available = bool(
                WEBAUTHN_ENABLED and session is not None
                and session.get("has_cred")
            )
            body = body.replace("__SPM_UNLOCK__", jsonlib.dumps({
                "available": available,
                "csrf": (session or {}).get("csrf", ""),
            }))
        # A fresh nonce per response, stamped centrally so a page added later
        # cannot ship a script the CSP will refuse.
        #
        # data-cfasync="false" rides along because a CDN in front of this server
        # may rewrite inline scripts. Cloudflare's Rocket Loader replaces every
        # <script> type with a private token so the browser skips it, then
        # re-injects the code itself -- and the re-injected copy carries no
        # nonce, so our own CSP refuses it. The result is a page with no
        # JavaScript at all: the mobile nav never opens and, far worse, the
        # idle auto-lock never runs, because that lock lives entirely in the
        # browser. data-cfasync="false" is the documented opt-out and is inert
        # everywhere else, so it costs nothing to send unconditionally.
        self._csp_nonce = secrets.token_urlsafe(16)
        body = self._SCRIPT_RE.sub(
            lambda m: '<script nonce="%s" data-cfasync="false"%s>'
            % (self._csp_nonce, m.group(1)), body)
        # Stamp every POST form centrally rather than in each builder, so a
        # form added later cannot silently ship without a token.
        csrf = self._session_csrf()
        if csrf:
            field = '<input type="hidden" name="csrf" value="%s">' % csrf
            body = self._POST_FORM_RE.sub(lambda m: m.group(1) + field, body)
        self.send_response(code)
        self._add_cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _send_asset(self, content_type, body):
        # Static bytes: no session, no language substitution, and no CORS
        # headers, unlike _send_html above.
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session_cookie_attrs(self):
        # A "Secure" cookie is withheld by browsers on plain HTTP, and this
        # server never speaks TLS itself. Sending it unconditionally made login
        # impossible on the non-loopback binds (0.0.0.0 / custom IP) that web
        # mode offers: the browser silently drops the session cookie and the
        # user is bounced back to the login form forever. Mark it Secure only
        # when the browser's origin really is HTTPS, i.e. behind a TLS reverse
        # proxy that sets X-Forwarded-Proto.
        proto = (self.headers.get("X-Forwarded-Proto", "") or "").split(",")[0].strip().lower()
        attrs = "HttpOnly; Path=/; SameSite=Strict"
        if proto == "https":
            attrs += "; Secure"
        return attrs

    def _expire_session(self):
        """Drop a session whose master password no longer opens the vault."""
        self.send_response(302)
        self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
        self.send_header("Location", "/login")
        self.end_headers()
        return

    def _counts(self, plaintext):
        """Sidebar badge counts, so a new page does not have to rebuild them."""
        _, entries = parse_entries(plaintext)
        _, notes = parse_notes(plaintext)
        _, passphrases = parse_passphrases(plaintext)
        _, backups = parse_backup_codes(plaintext)
        _, auths = parse_authenticators(plaintext)
        return {
            "passwords": len(entries), "notes": len(notes),
            "passphrases": len(passphrases), "backups": len(backups),
            "authenticators": len(auths),
        }

    def _add_cors(self):
        origin = self.headers.get("Origin", "")
        allowed = {"http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT}
        if origin in allowed:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
            self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

    def _parse_cookies(self):
        cookie = self.headers.get("Cookie", "") or ""
        cookies = {}
        if not cookie:
            return cookies
        for part in cookie.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, value = part.split("=", 1)
            cookies[name.strip()] = urllib.parse.unquote(value.strip())
        return cookies

    def _sweep_sessions(self, now):
        # Expired entries used to be dropped only when their own token came
        # back, so an abandoned session kept its master password in memory for
        # the life of the process. Sweep the whole table instead.
        for tok, sess in list(self.server.sessions.items()):
            if now - sess.get("created", 0) > SESSION_MAX_AGE:
                self.server.sessions.pop(tok, None)
                continue
            if sess.get("state") == "suspended":
                # A suspended session is idle by definition, so the idle TTL
                # would kill it within minutes and there would be nothing left
                # to resume. Its own bound applies instead, and unlike
                # last_seen it does not slide -- the clock starts when the
                # screen locks and runs regardless of what the browser does.
                if now - sess.get("suspended_at", 0) > SUSPEND_MAX_AGE:
                    self.server.sessions.pop(tok, None)
                continue
            if now - sess.get("last_seen", 0) > SESSION_TTL:
                self.server.sessions.pop(tok, None)

    def _login_client(self):
        try:
            peer = ipaddress.ip_address(self.client_address[0])
        except (AttributeError, IndexError, ValueError):
            return "unknown"
        # Only a loopback reverse proxy is trusted to identify the visitor. A
        # direct network client must never be able to choose its own throttle key.
        if peer.is_loopback:
            forwarded = (self.headers.get("X-Real-IP", "") or "").strip()
            try:
                return str(ipaddress.ip_address(forwarded)) if forwarded else str(peer)
            except ValueError:
                return str(peer)
        return str(peer)

    def _sweep_login_failures_locked(self, now):
        for client, entry in list(self.server.login_failures.items()):
            if now - entry.get("last_seen", 0) > LOGIN_LOCKOUT_SECONDS:
                self.server.login_failures.pop(client, None)
        if len(self.server.login_failures) > 4096:
            oldest = sorted(self.server.login_failures,
                key=lambda key: self.server.login_failures[key].get("last_seen", 0))
            for client in oldest[:-4096]:
                self.server.login_failures.pop(client, None)

    def _login_lockout_remaining(self):
        now = time.time()
        with self.server.auth_lock:
            self._sweep_login_failures_locked(now)
            entry = self.server.login_failures.get(self._login_client())
            if not entry:
                return 0
            return max(0, int(entry.get("until", 0) - now))

    def _record_login_failure(self):
        client = self._login_client()
        now = time.time()
        with self.server.auth_lock:
            self._sweep_login_failures_locked(now)
            entry = self.server.login_failures.get(client) or {"count": 0, "until": 0}
            entry["count"] = entry.get("count", 0) + 1
            entry["last_seen"] = now
            if entry["count"] >= LOGIN_MAX_FAILURES:
                entry["until"] = now + LOGIN_LOCKOUT_SECONDS
            self.server.login_failures[client] = entry
        self.log_message("failed login from %s (%d/%d)", client, entry["count"], LOGIN_MAX_FAILURES)

    def _clear_login_failures(self):
        with self.server.auth_lock:
            self.server.login_failures.pop(self._login_client(), None)

    def _get_cookie_session(self):
        """The master password for an ACTIVE session, else None.

        A suspended session returns None here on purpose. Every authenticated
        route already treats None as "not signed in", so suspension fails
        closed for routes written before this feature existed and for any route
        added after it -- no per-route opt-in to forget. The unlock endpoints
        reach past this with _session_record().
        """
        now = time.time()
        self._sweep_sessions(now)
        token = self._parse_cookies().get("spm_session")
        if not token:
            return None
        session = self.server.sessions.get(token)
        if not session:
            return None
        if session.get("state") == "suspended":
            return None
        session["last_seen"] = now
        # Held for this request only, so the read and write helpers can reach
        # the session's cached vault key without every call site threading the
        # record through. The handler instance is per-request, so this cannot
        # leak between connections.
        self._session_rec = session
        return session.get("master", "")

    def _session_record(self):
        """The raw session record whatever its state, plus its token."""
        now = time.time()
        self._sweep_sessions(now)
        token = self._parse_cookies().get("spm_session")
        if not token:
            return "", None
        return token, self.server.sessions.get(token)

    def _suspended_session(self):
        """The session record only when it is suspended."""
        token, session = self._session_record()
        if session and session.get("state") == "suspended":
            return token, session
        return "", None

    def _session_csrf(self):
        token = self._parse_cookies().get("spm_session")
        if not token:
            return ""
        session = self.server.sessions.get(token) or {}
        return session.get("csrf", "")

    def _read_body(self, limit=MAX_POST_BYTES):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (ValueError, TypeError):
            self.send_error(400, "Invalid Content-Length")
            return None
        if length < 0 or length > limit:
            self.send_error(413, "Request body too large")
            return None
        return self.rfile.read(length)

    def _get_lang(self):
        cookies = self._parse_cookies()
        return sanitize_lang(cookies.get("spm_lang"))

    def _deny_unauthenticated(self):
        """Answer a request that has no active session.

        A suspended session is a different situation from no session at all:
        the vault is still open in memory and a biometric can resume it, so
        send the visitor to the unlock page instead of asking for a password
        they do not need to retype yet.
        """
        _, suspended = self._suspended_session()
        if suspended is not None and WEBAUTHN_ENABLED:
            self.send_response(302)
            self.send_header("Location", "/unlock")
            self.end_headers()
            return
        page = login_page(VERSION)
        self._send_html(200, page)

    def _require_login(self):
        master = self._get_cookie_session()
        if not master:
            self._deny_unauthenticated()
            return None
        return master

    def _send_json(self, code, payload):
        body = jsonlib.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_authorized(self):
        """Read a JSON ceremony body after checking CSRF and origin.

        Returns None when the response has already been sent.
        """
        raw = self._read_body(limit=64 * 1024)
        if raw is None:
            return None
        if not self._write_authorized(raw, {}):
            self._send_json(403, {"error": "rejected"})
            return None
        try:
            payload = jsonlib.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_json(400, {"error": "malformed request"})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "malformed request"})
            return None
        return payload

    def _issue_challenge(self, session, kind):
        challenge = secrets.token_bytes(32)
        session["challenge"] = challenge
        session["challenge_at"] = time.time()
        session["challenge_kind"] = kind
        return challenge

    def _take_challenge(self, session, kind):
        """Consume the stored challenge, whatever the caller then does with it.

        Reading it clears it unconditionally. A challenge that survived a failed
        verification could be replayed against a second guess, so failure has to
        burn it just as success does.
        """
        challenge = session.get("challenge") or b""
        issued_at = session.get("challenge_at", 0)
        stored_kind = session.get("challenge_kind", "")
        session["challenge"] = b""
        session["challenge_at"] = 0
        session["challenge_kind"] = ""
        if not challenge or stored_kind != kind:
            return b""
        if time.time() - issued_at > WEBAUTHN_CHALLENGE_TTL:
            return b""
        return challenge

    def _handle_unlock_post(self, path):
        """WebAuthn ceremonies. Returns False when the path is not one of them.

        These live above the normal session gate because two of them act on a
        suspended session, which _get_cookie_session deliberately reports as no
        session at all.
        """
        if not WEBAUTHN_ENABLED:
            return False
        if path not in ("/unlock/suspend", "/unlock/challenge", "/unlock/verify",
                        "/unlock/register/challenge", "/unlock/register/verify"):
            return False

        if path in ("/unlock/challenge", "/unlock/verify"):
            token, session = self._suspended_session()
        elif path == "/unlock/suspend":
            # Suspending accepts a session that is already suspended, because
            # two tabs share one session and both lock bars fire. Refusing the
            # second told it "no session", and the lock bar treats any refusal
            # as a reason to log out -- which destroyed the suspended session
            # the first tab was about to resume.
            token, session = self._session_record()
            if session is not None and session.get("state") not in ("active", "suspended"):
                session = None
        else:
            token, session = self._session_record()
            if session is not None and session.get("state") != "active":
                session = None
        if session is None:
            self._send_json(403, {"error": "no session"})
            return True

        payload = self._read_json_authorized()
        if payload is None:
            return True

        if path == "/unlock/suspend":
            if session.get("state") == "suspended":
                # Already locked by another tab. Deliberately does not touch
                # suspended_at: refreshing it every time a tab reports in would
                # let an idle browser hold the master password in memory past
                # SUSPEND_MAX_AGE indefinitely.
                self._send_json(200, {"ok": True, "already_suspended": True})
                return True
            # A suspended session can be resumed by nothing except a registered
            # credential, so suspending without one strands the user on a page
            # that cannot let them back in -- they can only log out and retype
            # the master password, which is the exact friction this feature
            # exists to remove.
            #
            # has_cred alone is not enough to decide: it is cached per session
            # at login, so a session that was already open when the credential
            # was deleted (or when SPM_WEB_RP_ID changed) still believes one
            # exists. Ask the vault, which is the only authority.
            try:
                plaintext = load_vault(session.get("master", ""), session)
            except Exception:
                self._send_json(403, {"error": "vault unavailable"})
                return True
            _, creds = parse_webauthn(plaintext)
            if not any(parts[4] == WEBAUTHN_RP_ID for _, parts in creds):
                # Correct the stale flag so later pages stop advertising it,
                # and refuse. The lock bar falls through to /logout, which is
                # exactly what it did before this feature existed.
                session["has_cred"] = False
                self.log_message("refusing to suspend: no usable unlock credential")
                self._send_json(409, {"error": "no credential registered"})
                return True
            session["has_cred"] = True
            session["state"] = "suspended"
            session["suspended_at"] = time.time()
            # Nothing may carry over from the active session into the locked
            # one: a challenge issued before the lock must not be spendable
            # after it.
            self._take_challenge(session, "")
            self.log_message("session suspended, awaiting biometric unlock")
            self._send_json(200, {"ok": True})
            return True

        if path == "/unlock/register/challenge":
            challenge = self._issue_challenge(session, "create")
            self._send_json(200, {
                "challenge": _b64url_encode(challenge),
                "rp_id": WEBAUTHN_RP_ID,
                "user_id": _b64url_encode(hashlib.sha256(
                    os.path.abspath(VAULT_PATH).encode("utf-8")).digest()[:16]),
                "user_name": os.path.basename(VAULT_PATH),
            })
            return True

        if path == "/unlock/register/verify":
            self._webauthn_register(session, payload)
            return True

        if path == "/unlock/challenge":
            try:
                plaintext = load_vault(session.get("master", ""), session)
            except Exception:
                self._send_json(403, {"error": "vault unavailable"})
                return True
            _, creds = parse_webauthn(plaintext)
            allowed = [parts[2] for _, parts in creds if parts[4] == WEBAUTHN_RP_ID]
            if not allowed:
                self._send_json(400, {"error": "no credential registered"})
                return True
            challenge = self._issue_challenge(session, "get")
            self._send_json(200, {
                "challenge": _b64url_encode(challenge),
                "rp_id": WEBAUTHN_RP_ID,
                "allow": allowed,
            })
            return True

        if path == "/unlock/verify":
            self._webauthn_unlock(token, session, payload)
            return True

        return False

    def _webauthn_register(self, session, payload):
        """Finish a registration ceremony and store the credential."""
        expected = self._take_challenge(session, "create")
        if not expected:
            self._send_json(400, {"error": "challenge expired"})
            return
        try:
            client_data = _b64url_decode(payload.get("client_data") or "")
            auth_data = _b64url_decode(payload.get("auth_data") or "")
            spki = _b64url_decode(payload.get("public_key") or "")
            cred_id = (payload.get("credential_id") or "").strip()
            _b64url_decode(cred_id)
        except ValueError:
            self._send_json(400, {"error": "malformed credential"})
            return
        if not spki:
            # getPublicKey() returned null: the browser could not export the
            # key. Reaching it would mean decoding the CBOR attestation object,
            # and a CBOR decoder is exactly the dependency this server does not
            # have. Fail with something the user can act on instead.
            self._send_json(400, {"error": "this browser cannot export the credential key"})
            return
        problem = check_client_data(client_data, "webauthn.create", expected)
        if problem:
            self._send_json(400, {"error": problem})
            return
        _, problem = check_authenticator_data(auth_data)
        if problem:
            self._send_json(400, {"error": problem})
            return

        label = (payload.get("label") or "").strip() or "Biometric unlock"
        label = re.sub(r"[\t\r\n]", " ", label)[:64]
        master = session.get("master", "")
        try:
            plaintext = load_vault(master, self._session_rec)
        except Exception:
            self._send_json(403, {"error": "vault unavailable"})
            return
        lines, creds = parse_webauthn(plaintext)
        if any(parts[2] == cred_id for _, parts in creds):
            self._send_json(400, {"error": "credential already registered"})
            return
        next_id = 1
        for _, parts in creds:
            try:
                next_id = max(next_id, int(parts[1]) + 1)
            except (TypeError, ValueError):
                continue
        row = "\t".join([
            "WEBAUTHN", str(next_id), cred_id,
            base64.b64encode(spki).decode("ascii"),
            WEBAUTHN_RP_ID, label,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ])
        lines.append(row)
        try:
            save_vault(master, "\n".join(lines) + "\n", self._session_rec)
        except Exception:
            self._send_json(500, {"error": "could not save credential"})
            return
        session["has_cred"] = True
        self.log_message("registered unlock credential %s", next_id)
        self._send_json(200, {"ok": True})

    def _webauthn_unlock(self, token, session, payload):
        """Verify an assertion and resume a suspended session."""
        locked_for = self._login_lockout_remaining()
        if locked_for > 0:
            self._send_json(429, {"error": "too many attempts", "retry_after": locked_for})
            return
        expected = self._take_challenge(session, "get")
        if not expected:
            self._send_json(400, {"error": "challenge expired"})
            return
        try:
            client_data = _b64url_decode(payload.get("client_data") or "")
            auth_data = _b64url_decode(payload.get("auth_data") or "")
            signature = _b64url_decode(payload.get("signature") or "")
            cred_id = (payload.get("credential_id") or "").strip()
            _b64url_decode(cred_id)
        except ValueError:
            self._record_login_failure()
            self._send_json(400, {"error": "malformed assertion"})
            return

        problem = check_client_data(client_data, "webauthn.get", expected)
        if problem:
            self._record_login_failure()
            self._send_json(403, {"error": problem})
            return
        sign_count, problem = check_authenticator_data(auth_data)
        if problem:
            self._record_login_failure()
            self._send_json(403, {"error": problem})
            return

        try:
            plaintext = load_vault(session.get("master", ""), session)
        except Exception:
            self._send_json(403, {"error": "vault unavailable"})
            return
        _, creds = parse_webauthn(plaintext)
        match = None
        for _, parts in creds:
            if hmac.compare_digest(parts[2], cred_id) and parts[4] == WEBAUTHN_RP_ID:
                match = parts
                break
        if match is None:
            self._record_login_failure()
            self._send_json(403, {"error": "unknown credential"})
            return
        try:
            spki = base64.b64decode(match[3].encode("ascii"), validate=True)
        except Exception:
            self._send_json(403, {"error": "unreadable credential"})
            return

        signed = auth_data + hashlib.sha256(client_data).digest()
        if not verify_es256(spki, signature, signed):
            self._record_login_failure()
            self._send_json(403, {"error": "signature rejected"})
            return

        # Signature counters are held per process rather than written back to
        # the vault: persisting one would mean a full read-modify-write of the
        # encrypted vault on every unlock, and Apple's platform authenticator
        # reports 0 forever anyway. Compare only when both sides are non-zero.
        counters = self.server.webauthn_counters
        previous = counters.get(cred_id, 0)
        if sign_count and previous and sign_count <= previous:
            self._record_login_failure()
            self.log_message("signature counter regression on credential %s", match[1])
            self._send_json(403, {"error": "signature counter regression"})
            return
        if sign_count:
            counters[cred_id] = sign_count

        self._clear_login_failures()
        session["state"] = "active"
        session["suspended_at"] = 0
        session["last_seen"] = time.time()
        # "created" is deliberately untouched: SESSION_MAX_AGE still caps the
        # session, so biometric unlocks cannot chain into an unbounded life.
        session["csrf"] = secrets.token_hex(32)
        self.log_message("session resumed by credential %s", match[1])
        self._send_json(200, {"ok": True})

    def _body_csrf(self, raw_body_bytes, data):
        token = (data.get("csrf") or [""])[0].strip()
        if token:
            return token
        ctype = self.headers.get("Content-Type", "") or ""
        # The import form is multipart, so its fields are not in parse_qs.
        if "multipart/form-data" in ctype.lower():
            try:
                fields = parse_multipart(raw_body_bytes, ctype)
            except Exception:
                return ""
            raw = fields.get("csrf")
            if isinstance(raw, bytes):
                return raw.decode("utf-8", errors="ignore").strip()
            return ""
        # The WebAuthn ceremonies post JSON from fetch(), so their token is in
        # neither parse_qs output nor a multipart part. Read it from the object
        # itself. Only a string counts: a JSON body can carry a list or a dict
        # where a token is expected, and str() on either would produce
        # something that compares as a token-shaped value.
        if "application/json" in ctype.lower():
            try:
                payload = jsonlib.loads(raw_body_bytes.decode("utf-8"))
            except (AttributeError, UnicodeDecodeError, ValueError):
                return ""
            if not isinstance(payload, dict):
                return ""
            raw = payload.get("csrf")
            return raw.strip() if isinstance(raw, str) else ""
        return ""

    def _write_authorized(self, raw_body_bytes, data):
        """Authorise an authenticated write.

        Origin is checked when the browser sends it. Safari omits Origin on
        same-origin form submissions, which made every write fail with a 403,
        and Referer cannot cover the gap because this server sends
        Referrer-Policy: no-referrer. So a per-session CSRF token in the form
        is the primary defence and the Origin check is the second layer.
        """
        origin = (self.headers.get("Origin", "") or "").strip()
        # "null" is an opaque origin, not a foreign one: iOS home-screen web
        # apps send it for their own same-origin form posts, and so do
        # sandboxed contexts. It carries no information about the sender, so
        # treat it like an absent origin and let the token decide -- an
        # attacker in a sandboxed frame still cannot read the token.
        if origin and origin.lower() != "null":
            # Present, parseable and wrong is a genuine cross-origin attempt:
            # refuse it regardless of what token the body carries.
            return self._same_origin_post()
        expected = self._session_csrf()
        supplied = self._body_csrf(raw_body_bytes, data)
        return bool(expected) and hmac.compare_digest(expected, supplied)

    def _same_origin_post(self):
        """Require authenticated browser writes to come from this exact origin."""
        origin = (self.headers.get("Origin", "") or "").strip()
        host = (self.headers.get("Host", "") or "").strip().lower()
        if not origin or not host:
            return False
        try:
            parsed = urllib.parse.urlparse(origin)
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host

    def do_OPTIONS(self):
        self.send_response(200)
        self._add_cors()
        self.end_headers()
        return

    # ---- Handlers -----------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path or "/"

        if path == "/lang":
            params = urllib.parse.parse_qs(parsed.query)
            raw = (params.get("lang") or params.get("value") or [""])[0]
            lang = sanitize_lang(raw)
            self.send_response(200)
            self.send_header("Set-Cookie", f"spm_lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jsonlib.dumps({"ok": True, "lang": lang}).encode("utf-8"))
            return

        if path.startswith("/logout"):
            token = self._parse_cookies().get("spm_session")
            if token:
                self.server.sessions.pop(token, None)
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
            self.send_header("Location", "/login")
            self.end_headers()
            return

        if path == "/login":
            page = login_page(VERSION)
            self._send_html(200, page)
            return

        # These must answer above the login gate. Unknown paths fall through to
        # _require_login(), which replies with the login page as HTTP 200
        # rather than redirecting, so an icon request would be answered with
        # HTML and iOS would fall back to screenshotting the page instead of
        # showing the mark. /favicon.ico and the -precomposed alias are
        # requested unprompted by Safari, so both are handled here too.
        if path in ("/apple-touch-icon.png",
                    "/apple-touch-icon-precomposed.png",
                    "/favicon.ico"):
            self._send_asset("image/png", APP_ICON_PNG)
            return

        if path == "/favicon.svg":
            self._send_asset("image/svg+xml", FAVICON_SVG.encode("utf-8"))
            return

        if path == "/manifest.webmanifest":
            self._send_asset("application/manifest+json",
                             MANIFEST_JSON.encode("utf-8"))
            return

        # Above the login gate because a suspended session has no active
        # session by design, and this is the page that fixes that. It renders
        # no vault content -- only a button and a way out.
        if path == "/unlock":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            _, suspended = self._suspended_session()
            if suspended is None:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._send_html(200, unlock_page(VERSION, self._session_csrf()))
            return

        master = self._require_login()
        if master is None:
            return

        if path == "/":
            flash = ""
            note = (parsed.query or "")
            params = urllib.parse.parse_qs(parsed.query)
            msg = (params.get("msg") or [""])[0]
            err = (params.get("err") or [""])[0]
            if msg == "import-ok":
                flash = "<div class='flash'>Import completed.</div>"
            elif err:
                flash = f"<div class='flash error'>{html.escape(err)}</div>"
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                self.send_response(302)
                self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
                self.send_header("Location", "/login")
                self.end_headers()
                return

            _, entries = parse_entries(plaintext)
            _, notes = parse_notes(plaintext)
            _, passphrases = parse_passphrases(plaintext)
            _, backups = parse_backup_codes(plaintext)
            _, auths = parse_authenticators(plaintext)
            counts = {
                "passwords": len(entries), "notes": len(notes),
                "passphrases": len(passphrases), "backups": len(backups),
                "authenticators": len(auths),
            }
            audit = compute_security(entries, plaintext)
            counts["security_score"] = audit["score"]
            counts["aging"] = len(audit["old"])
            counts["attachments"] = sum(1 for line in plaintext.splitlines() if line.startswith("ATTACHMENT\t"))
            counts["passkeys"] = sum(1 for line in plaintext.splitlines() if line.startswith("PASSKEY\t"))
            recent = list(reversed(entries))[:5]
            body = render_shell(overview_page(counts, recent), "overview",
                                VERSION, VAULT_PATH, title="Overview",
                                counts=counts, flash=flash)
            self._send_html(200, body)
            return

        if path == "/transfer":
            self._send_html(200, transfer_page())
            return

        if path == "/security":
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            _, entries = parse_entries(plaintext)
            params = urllib.parse.parse_qs(parsed.query)
            check_breaches = (params.get("breaches") or [""])[0] == "1"
            audit = compute_security(entries, plaintext, check_breaches)
            self._send_html(200, render_shell(
                security_page(audit), "security", VERSION, VAULT_PATH,
                title="Security", counts=self._counts(plaintext)))
            return

        if path == "/unlock/settings":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            _, creds = parse_webauthn(plaintext)
            params = urllib.parse.parse_qs(parsed.query)
            flash = ""
            if (params.get("msg") or [""])[0] == "registered":
                flash = "<div class='flash'>Unlock credential registered.</div>"
            elif (params.get("msg") or [""])[0] == "deleted":
                flash = "<div class='flash'>Unlock credential removed.</div>"
            self._send_html(200, render_shell(
                unlock_settings_page(creds, self._session_csrf(), flash),
                "unlock-settings", VERSION, VAULT_PATH,
                title="Biometric Unlock", counts=self._counts(plaintext)))
            return

        if path == "/settings":
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            params = urllib.parse.parse_qs(parsed.query)
            flash = ""
            if (params.get("msg") or [""])[0] == "changed":
                flash = ("<div class='flash'>Master password changed. The recovery "
                         "file was rewritten and every other session was signed "
                         "out.</div>")
            self._send_html(200, render_shell(
                settings_page(flash), "settings", VERSION, VAULT_PATH,
                title="Master Password", counts=self._counts(plaintext)))
            return

        if path == "/events":
            # No master password is read here and the vault is never opened:
            # the log lives beside it. That is deliberate -- the events worth
            # reading most are the failed unlocks, and a page that needed the
            # vault open could not show them to someone who is locked out.
            events = list(reversed(core.read_events(VAULT_PATH, 500)))
            self._send_html(200, events_page(events))
            return

        if path == "/history":
            hist_flash = ""
            if (urllib.parse.parse_qs(parsed.query).get("flash") or [""])[0] == "restored":
                hist_flash = "<div class='flash'>Snapshot restored. The previous vault was archived.</div>"
            snapshots = list_history_snapshots()
            content = list_page(
                "nav.history", "History", "page.history.desc",
                "Encrypted vault snapshots kept before each change.", "", "", "",
                [("history.when", "When", ""), ("history.size", "Size", ""),
                 ("history.name", "Snapshot", ""), ("table.actions", "Actions", "act")],
                build_history_rows_html(snapshots))
            self._send_html(200, render_shell(
                content, "history", VERSION, VAULT_PATH,
                title="History", flash=hist_flash, searchable=True))
            return

        if path == "/search":
            term = (urllib.parse.parse_qs(parsed.query).get("q") or [""])[0].strip()
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            results = search_vault(plaintext, term) if term else []
            content = list_page(
                "search.title", "Search", "search.desc",
                f"Matches for “{html.escape(term)}” across every record type." if term
                else "Type in the search box to look across every record type.",
                "", "", "",
                [("search.kind", "Type", ""), ("table.id", "ID", "num"),
                 ("table.label", "Label", ""), ("table.actions", "Actions", "act")],
                build_search_rows_html(results))
            self._send_html(200, render_shell(
                content, "", VERSION, VAULT_PATH, title="Search",
                counts=self._counts(plaintext), searchable=True))
            return

        if path in ("/passwords", "/notes", "/passphrases", "/authenticators", "/backup-codes"):
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                self.send_response(302)
                self.send_header("Set-Cookie", f"spm_session=deleted; Max-Age=0; {self._session_cookie_attrs()}")
                self.send_header("Location", "/login")
                self.end_headers()
                return
            _, entries = parse_entries(plaintext)
            _, notes = parse_notes(plaintext)
            _, passphrases = parse_passphrases(plaintext)
            _, backups = parse_backup_codes(plaintext)
            _, auths = parse_authenticators(plaintext)
            counts = {
                "passwords": len(entries), "notes": len(notes),
                "passphrases": len(passphrases), "backups": len(backups),
                "authenticators": len(auths),
            }
            spec = {
                "/passwords": ("nav.passwords", "Passwords", "page.passwords.desc",
                               "Login credentials stored in your vault.", "/add",
                               "btn.add_entry", "+ Add Entry",
                               [("table.id", "ID", "num"), ("table.name", "Name", ""),
                                ("table.username", "Username", ""), ("table.actions", "Actions", "act")],
                               build_rows_html(entries), "passwords"),
                "/notes": ("nav.notes", "Secure Notes", "page.notes.desc",
                           "Encrypted notes stored inside the same vault.", "/notes-add",
                           "btn.add_note", "+ Add Note",
                           [("table.id", "ID", "num"), ("table.title", "Title", ""),
                            ("table.actions", "Actions", "act")],
                           build_notes_rows_html(notes), "notes"),
                "/passphrases": ("nav.passphrases", "Passphrases", "page.passphrases.desc",
                                 "API tokens and recovery phrases.", "/passphrase-add",
                                 "btn.add_passphrase", "+ Add Passphrase",
                                 [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                  ("table.actions", "Actions", "act")],
                                 build_passphrase_rows_html(passphrases), "passphrases"),
                "/authenticators": ("nav.authenticators", "Authenticators", "page.authenticators.desc",
                                    "Time-based one-time password codes.", "/authenticator-add",
                                    "btn.add_authenticator", "+ Add Authenticator",
                                    [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                     ("table.every", "Every", ""), ("table.algo", "Algo", ""),
                                     ("table.actions", "Actions", "act")],
                                    build_auth_rows_html(auths), "authenticators"),
                "/backup-codes": ("nav.backup_codes", "Backup Codes", "page.backups.desc",
                                  "One-time recovery codes for your accounts.", "/backup-codes-add",
                                  "btn.add_backups", "+ Add Backup Codes",
                                  [("table.id", "ID", "num"), ("table.label", "Label", ""),
                                   ("table.actions", "Actions", "act")],
                                  build_backup_rows_html(backups), "backup-codes"),
            }[path]
            content = list_page(spec[0], spec[1], spec[2], spec[3], spec[4], spec[5], spec[6], spec[7], spec[8])
            if path == "/passwords":
                content = build_tag_filter_html(entries) + content
            self._send_html(200, render_shell(content, spec[9], VERSION, VAULT_PATH,
                                              title=spec[1], counts=counts, searchable=True))
            return

        if path == "/generator":
            page = generator_page()
            self._send_html(200, page)
            return

        query = urllib.parse.parse_qs(parsed.query)

        if path == "/add":
            page = build_entry_form(
                title="Add Entry",
                vault_path=VAULT_PATH,
                action="/add",
                values={"folders": core.record_folders(
                    load_vault(master, self._session_rec))},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/edit":
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)
            found = None
            for idx, parts in entries:
                if parts[0] == entry_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Entry not found")
                return

            stored_folder, stored_fields = core.decode_attrs(
                found[7] if len(found) > 7 else "")
            values = {
                "name": found[1],
                "user": found[2],
                "password": found[3],
                "notes": found[4],
                "url": found[6] if len(found) > 6 else "",
                "folder": stored_folder,
                "fields": stored_fields,
                "folders": core.record_folders(plaintext),
            }
            page = build_entry_form(
                title=f"Edit Entry #{entry_id}",
                vault_path=VAULT_PATH,
                action="/edit?id=" + urllib.parse.quote(entry_id),
                values=values,
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/view":
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, entries = parse_entries(plaintext)
            found = None
            for _, parts in entries:
                if parts[0] == entry_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Entry not found")
                return

            page = view_entry_page(found, core.password_history(plaintext, entry_id))
            self._send_html(200, page)
            return

        if path == "/notes-add":
            page = build_note_form(
                title="Add Secure Note",
                vault_path=VAULT_PATH,
                action="/notes-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/notes-view":
            note_id = (query.get("id") or [""])[0]
            if not note_id:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, notes = parse_notes(plaintext)
            found = None
            for _, parts in notes:
                if parts[1] == note_id:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Note not found")
                return
            title = found[2]
            try:
                content = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                content = "[Decode error]"
            created = found[4]

            page = view_simple_page(title, "/notes", "note.field.title", title,
                                    content, created, "note.field.content", "Content", "notes")
            self._send_html(200, page)
            return

        if path == "/passphrase-add":
            page = build_passphrase_form(
                title="Add Passphrase",
                vault_path=VAULT_PATH,
                action="/passphrase-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/passphrase-edit":
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, passphrases = parse_passphrases(plaintext)
            found = None
            for _, parts in passphrases:
                if parts[1] == pid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Passphrase not found")
                return
            secret = ""
            try:
                secret = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                secret = ""
            page = build_passphrase_form(
                title=f"Edit Passphrase #{pid}",
                vault_path=VAULT_PATH,
                action="/passphrase-edit?id=" + urllib.parse.quote(pid),
                values={"label": found[2], "secret": secret},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/passphrase-view":
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, passphrases = parse_passphrases(plaintext)
            found = None
            for _, parts in passphrases:
                if parts[1] == pid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Passphrase not found")
                return
            secret = ""
            try:
                secret = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                secret = "[Decode error]"
            created = found[4]
            page = view_simple_page(found[2], "/passphrases", "pass.field.label", found[2],
                                    secret, created, "pass.view.secret", "Passphrase", "passphrases")
            self._send_html(200, page)
            return

        if path == "/authenticator-add":
            page = build_auth_form(
                title="Add Authenticator",
                vault_path=VAULT_PATH,
                action="/authenticator-add",
                values={"period": "30", "algo": "sha1"},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/authenticator-edit":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            algo = found[6] if len(found) > 6 else "sha1"
            page = build_auth_form(
                title=f"Edit Authenticator #{aid}",
                vault_path=VAULT_PATH,
                action="/authenticator-edit?id=" + urllib.parse.quote(aid),
                values={"label": found[2], "secret": found[3], "period": found[4], "algo": algo},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/authenticator-view":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            created = found[5] if len(found) > 5 else ""
            algo = (found[6] if len(found) > 6 else "sha1") or "sha1"
            page = auth_view_page(aid, found[2], found[3], found[4] or "30", algo, created)
            self._send_html(200, page)
            return

        if path == "/backup-codes-add":
            page = build_backup_form(
                title="Add Backup Codes",
                vault_path=VAULT_PATH,
                action="/backup-codes-add",
                values={},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/backup-codes-edit":
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, backups = parse_backup_codes(plaintext)
            found = None
            for _, parts in backups:
                if parts[1] == bid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Backup code not found")
                return
            codes = ""
            try:
                codes = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                codes = ""
            page = build_backup_form(
                title=f"Edit Backup Codes #{bid}",
                vault_path=VAULT_PATH,
                action="/backup-codes-edit?id=" + urllib.parse.quote(bid),
                values={"label": found[2], "codes": codes},
                message=""
            )
            self._send_html(200, page)
            return

        if path == "/backup-codes-view":
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, backups = parse_backup_codes(plaintext)
            found = None
            for _, parts in backups:
                if parts[1] == bid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Backup code not found")
                return
            codes = ""
            try:
                codes = base64.b64decode(found[3].encode("ascii")).decode("utf-8", errors="replace")
            except Exception:
                codes = "[Decode error]"
            created = found[4]
            page = view_simple_page(found[2], "/backup-codes", "backup.field.label", found[2],
                                    codes, created, "backup.field.codes", "Backup codes", "backup-codes")
            self._send_html(200, page)
            return

        if path == "/authenticator-code":
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            _, auths = parse_authenticators(plaintext)
            found = None
            for _, parts in auths:
                if parts[1] == aid:
                    found = parts
                    break
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            period = 30
            algo = (found[6] if len(found) > 6 else "sha1") or "sha1"
            try:
                period = int(found[4])
            except Exception:
                period = 30
            try:
                code = totp_code(found[3], period, algo) or "------"
            except Exception:
                code = "------"
            expires_in = period - int(time.time()) % max(period, 1)
            import json
            body = jsonlib.dumps({"code": code, "expires_in": expires_in, "algo": algo})
            self.send_response(200)
            self._add_cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        if path == "/export":
            fmt = (query.get("fmt") or ["csv"])[0].lower()
            if fmt not in SUPPORTED_FORMATS:
                self.send_error(400, "Unsupported format")
                return
            plaintext = load_vault(master, self._session_rec)
            content = export_content(fmt, plaintext)
            filename = f"spm_export_{time.strftime('%Y%m%d_%H%M%S')}.{fmt if fmt!='csv-noheader' else 'csv'}"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))
            return

        self.send_error(404, "Not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path or "/"
        if path in ("/login", "/lang"):
            return self._do_POST()
        # Serialize the complete authenticated read-modify-write transaction,
        # not only the final os.replace, so no successful request is lost. The
        # file lock extends that guarantee across two server processes.
        with self.server.vault_lock:
            fcntl.flock(self.server.vault_lock_file.fileno(), fcntl.LOCK_EX)
            try:
                return self._do_POST()
            finally:
                fcntl.flock(self.server.vault_lock_file.fileno(), fcntl.LOCK_UN)

    def _do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path or "/"

        if path == "/lang":
            raw_body = self._read_body(limit=4096)
            if raw_body is None:
                return
            raw_body = raw_body.decode("utf-8", errors="ignore")
            data = urllib.parse.parse_qs(raw_body)
            lang = sanitize_lang((data.get("lang") or [""])[0])
            self.send_response(200)
            self.send_header("Set-Cookie", f"spm_lang={lang}; Path=/; Max-Age=31536000; SameSite=Lax")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(jsonlib.dumps({"ok": True, "lang": lang}).encode("utf-8"))
            return

        if path == "/login":
            locked_for = self._login_lockout_remaining()
            if locked_for > 0:
                page = login_page(
                    VERSION,
                    "<div class='msg'>Too many failed attempts. Try again in %d seconds.</div>" % locked_for,
                )
                self._send_html(429, page)
                return

            raw_body = self._read_body(limit=64 * 1024)
            if raw_body is None:
                return
            body = raw_body.decode("utf-8", errors="ignore")
            data = urllib.parse.parse_qs(body)
            password = data.get("password", [""])[0]

            if not password:
                page = login_page(VERSION, "<div class='msg'>Password required.</div>")
                self._send_html(200, page)
                return

            try:
                # This read unwraps the key envelope anyway, so keep what it
                # produced; discarding it would make the first page render pay
                # for the same unwrap a second time.
                opened, opened_key = core.read_vault(VAULT_PATH, password)
            except subprocess.CalledProcessError:
                self._record_login_failure()
                page = login_page(VERSION, "<div class='msg'>Invalid master password.</div>")
                self._send_html(200, page)
                return

            # Counted once here rather than on every page render: the answer
            # only changes when a credential is registered or removed, and both
            # of those already hold the plaintext vault open.
            _, opened_creds = parse_webauthn(opened)
            has_cred = any(parts[4] == WEBAUTHN_RP_ID for _, parts in opened_creds)

            self._clear_login_failures()
            token = secrets.token_hex(32)
            self.server.sessions[token] = {
                "master": password,
                "vault_key": opened_key or "",
                "csrf": secrets.token_hex(32),
                "created": time.time(),
                "last_seen": time.time(),
                "state": "active",
                "suspended_at": 0,
                "challenge": b"",
                "challenge_at": 0,
                "challenge_kind": "",
                "has_cred": has_cred,
            }
            self.send_response(302)
            self.send_header("Set-Cookie", f"spm_session={token}; {self._session_cookie_attrs()}")
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path.startswith("/unlock/"):
            handled = self._handle_unlock_post(path)
            if handled:
                return

        master = self._get_cookie_session()
        if not master:
            self._deny_unauthenticated()
            return

        raw_body_bytes = self._read_body()
        if raw_body_bytes is None:
            return
        raw_body = raw_body_bytes.decode("utf-8", errors="ignore")
        data = urllib.parse.parse_qs(raw_body)

        if not self._write_authorized(raw_body_bytes, data):
            self.send_error(403, "Cross-origin write rejected")
            return

        if path == "/settings/master-password":
            current = (data.get("current") or [""])[0]
            new_pw = (data.get("new") or [""])[0]
            confirm = (data.get("confirm") or [""])[0]

            def _reject(message):
                self._send_html(200, render_shell(
                    settings_page("<div class='flash error'>%s</div>" % message),
                    "settings", VERSION, VAULT_PATH, title="Master Password"))

            # Compared against the copy this session already proved at login
            # rather than by decrypting again: a typo should not cost a gpg
            # spawn, and the session holds the authoritative answer anyway.
            # Encoded first because compare_digest rejects non-ASCII str.
            if not hmac.compare_digest(current.encode("utf-8"),
                                       master.encode("utf-8")):
                self.log_message("master password change refused: wrong current password")
                _reject("Current master password is incorrect.")
                return
            if new_pw != confirm:
                _reject("The two new passwords do not match.")
                return
            if len(new_pw) < MASTER_MIN_LEN:
                _reject("The new master password must be at least %d characters."
                        % MASTER_MIN_LEN)
                return
            if hmac.compare_digest(new_pw.encode("utf-8"),
                                   current.encode("utf-8")):
                _reject("The new master password is the same as the current one.")
                return

            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()

            # Two steps, never one. A legacy vault is migrated to the
            # container format while `master` is STILL the live password, so
            # its key envelope and its recovery file agree at every instant;
            # only then is the envelope rewrapped to the new password. Sealing
            # the envelope under new_pw during the migration would leave a
            # window where .recovery names a password that opens nothing, and
            # that is the one state `spm forgot` cannot get out of.
            try:
                if unwrap_vault_key(master) is None:
                    save_vault(master, plaintext, self._session_rec)
            except Exception as exc:
                self.log_message("vault migration aborted before write: %s", exc)
                _reject("The vault could not be migrated to the current format, "
                        "so it was left unchanged. Run &#39;spm doctor&#39; to check it.")
                return

            try:
                # Only the small key envelope is rewritten. The vault
                # ciphertext and the recovery file both key off the vault key,
                # which does not change -- so a master-password change no
                # longer depends on the recovery pubkey being usable at all.
                rewrap_vault_key(master, new_pw)
            except Exception as exc:
                self.log_message("master password change failed on rewrap: %s", exc)
                _reject("The master password could not be changed and the vault "
                        "was left unchanged.")
                return

            # Every other session is holding the old password in memory, and
            # its next decrypt would fail anyway. Drop them now so the sign-out
            # is immediate rather than whenever they happen to poll.
            token = self._parse_cookies().get("spm_session")
            for other in list(self.server.sessions):
                if other != token:
                    self.server.sessions.pop(other, None)
            session = self.server.sessions.get(token)
            if session is not None:
                session["master"] = new_pw
                # rewrap re-seals the same key under the new password, so the
                # cached value stays correct -- but proving that here on every
                # future change is not worth one extra unwrap now.
                session["vault_key"] = ""
            self.log_message("master password changed; other sessions cleared")

            self.send_response(302)
            self.send_header("Location", "/settings?msg=changed")
            self.end_headers()
            return

        if path == "/add":
            name = (data.get("name") or [""])[0].strip()
            user = (data.get("user") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            notes = (data.get("notes") or [""])[0]
            url_raw = (data.get("url") or [""])[0]
            url = _vurl(url_raw)
            folder, custom, attrs_error = posted_attrs(data)

            if not name or url is None or attrs_error:
                plaintext = load_vault(master, self._session_rec)
                if not name:
                    problem = "Name / service is required."
                elif url is None:
                    problem = "URL must start with http:// or https://."
                else:
                    problem = attrs_error
                page = build_entry_form(
                    title="Add Entry",
                    vault_path=VAULT_PATH,
                    action="/add",
                    values={"name": name, "user": user, "password": password,
                            "notes": notes, "url": url_raw, "folder": folder,
                            "fields": custom,
                            "folders": core.record_folders(plaintext)},
                    message="<div class='msg'>%s</div>" % html.escape(problem),
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)
            max_id = 0
            for _, parts in entries:
                try:
                    max_id = max(max_id, int(parts[0]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            new_line = "\t".join([
                str(new_id),
                _vf(name),
                _vf(user),
                _vf(password),
                _vf(notes),
                now,
                url,
                core.encode_attrs(folder, custom),
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            entry_id = (query.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return

            name = (data.get("name") or [""])[0].strip()
            user = (data.get("user") or [""])[0].strip()
            password = (data.get("password") or [""])[0]
            notes = (data.get("notes") or [""])[0]
            url_raw = (data.get("url") or [""])[0]
            url = _vurl(url_raw)
            folder, custom, attrs_error = posted_attrs(data)

            plaintext = load_vault(master, self._session_rec)
            lines, entries = parse_entries(plaintext)

            idx_to_update = None
            old_created = ""
            for idx, parts in entries:
                if parts[0] == entry_id:
                    idx_to_update = idx
                    if len(parts) >= 6:
                        old_created = parts[5]
                    break

            if idx_to_update is None:
                self.send_error(404, "Entry not found")
                return

            if not name or url is None or attrs_error:
                if not name:
                    problem = "Name / service is required."
                elif url is None:
                    problem = "URL must start with http:// or https://."
                else:
                    problem = attrs_error
                values = {
                    "name": name,
                    "user": user,
                    "password": password,
                    "notes": notes,
                    "url": url_raw,
                    "folder": folder,
                    "fields": custom,
                    "folders": core.record_folders(plaintext),
                }
                page = build_entry_form(
                    title=f"Edit Entry #{entry_id}",
                    vault_path=VAULT_PATH,
                    action="/edit?id=" + urllib.parse.quote(entry_id),
                    values=values,
                    message="<div class='msg'>%s</div>" % html.escape(problem),
                )
                self._send_html(200, page)
                return

            new_line = "\t".join([
                entry_id,
                _vf(name),
                _vf(user),
                _vf(password),
                _vf(notes),
                old_created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                url,
                core.encode_attrs(folder, custom),
            ])
            lines[idx_to_update] = new_line
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/delete":
            entry_id = (data.get("id") or [""])[0]
            if not entry_id:
                self.send_error(400, "Missing id")
                return

            plaintext = load_vault(master, self._session_rec)
            lines, _ = parse_entries(plaintext)

            ids_to_remove = {entry_id}
            new_lines = []
            for line in lines:
                if not line or line.startswith("#") or line.startswith("META_") or line.startswith("NOTE\t"):
                    new_lines.append(line)
                    continue
                parts = line.split("\t")
                if parts and parts[0] in ids_to_remove:
                    continue
                new_lines.append(line)

            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/unlock/delete":
            if not WEBAUTHN_ENABLED:
                self.send_error(404, "Not found")
                return
            target = (data.get("id") or [""])[0].strip()
            if not target.isdigit():
                self.send_error(400, "Invalid credential id")
                return
            try:
                plaintext = load_vault(master, self._session_rec)
            except Exception:
                return self._expire_session()
            lines, creds = parse_webauthn(plaintext)
            drop = {idx for idx, parts in creds if parts[1] == target}
            if not drop:
                self.send_error(404, "Credential not found")
                return
            kept = [line for idx, line in enumerate(lines) if idx not in drop]
            save_vault(master, "\n".join(kept) + "\n", self._session_rec)
            _, remaining = parse_webauthn("\n".join(kept))
            _, current = self._session_record()
            if current is not None:
                current["has_cred"] = any(parts[4] == WEBAUTHN_RP_ID for _, parts in remaining)
            self.send_response(302)
            self.send_header("Location", "/unlock/settings?msg=deleted")
            self.end_headers()
            return

        if path == "/history-restore":
            name = (data.get("name") or [""])[0]
            # Match the generated snapshot name exactly. A traversal denylist
            # would have to anticipate every encoding of "..", an allowlist
            # does not.
            if not _SNAPSHOT_RE.match(name):
                self.send_error(400, "Invalid snapshot name")
                return
            source = os.path.join(_history_dir(), name)
            if not os.path.isfile(source):
                self.send_error(404, "Snapshot not found")
                return
            # Prove the snapshot opens with THIS master password before
            # touching the live vault: restoring a snapshot written under an
            # older password would lock the user out of their own vault with
            # no way back.
            # A snapshot is the same container the live vault is, and carries
            # its own vault key. Open it through the shared reader; the key it
            # yields is deliberately discarded, because restoring is a copy of
            # the file and not a re-encryption under the live vault's key.
            try:
                decrypt_vault_file(source, master)
            except Exception:
                self.send_error(409, "Snapshot does not open with the current master password; vault unchanged")
                return
            vault_dir = os.path.dirname(os.path.abspath(VAULT_PATH)) or "."
            # Archive first: restoring is itself an edit, and undoing a restore
            # has to be possible too.
            _archive_vault_generation()
            tmp_fd, tmp_path = tempfile.mkstemp(prefix=os.path.basename(VAULT_PATH) + ".restore.", dir=vault_dir)
            os.close(tmp_fd)
            try:
                shutil.copy2(source, tmp_path)
                os.chmod(tmp_path, 0o600)
                _fsync_path(tmp_path)
                os.replace(tmp_path, VAULT_PATH)
                _fsync_dir(vault_dir)
            except Exception:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                self.send_error(500, "Restore failed; vault unchanged")
                return
            self.send_response(302)
            self.send_header("Location", "/history?flash=restored")
            self.end_headers()
            return

        if path == "/notes-add":
            title = (data.get("title") or [""])[0].strip()
            content = (data.get("content") or [""])[0]

            if not title:
                page = build_note_form(
                    title="Add Secure Note",
                    vault_path=VAULT_PATH,
                    action="/notes-add",
                    values={"title": title, "content": content},
                    message="<div class='msg'>Title is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, notes = parse_notes(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in notes:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "NOTE",
                str(new_id),
                _vf(title),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/notes-delete":
            note_id = (data.get("id") or [""])[0]
            if not note_id:
                self.send_error(400, "Missing id")
                return

            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("NOTE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == note_id:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/import":
            master = self._require_login()
            if master is None:
                return

            is_async = self.headers.get("X-Requested-With", "").lower() == "fetch"

            def respond_error(message, status=400):
                if is_async:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(jsonlib.dumps({"ok": False, "message": message}).encode("utf-8"))
                else:
                    self.send_response(302)
                    self.send_header("Location", f"/?err={urllib.parse.quote(message)}")
                    self.end_headers()

            def respond_success(message="Import complete."):
                if is_async:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(jsonlib.dumps({"ok": True, "message": message}).encode("utf-8"))
                else:
                    self.send_response(302)
                    self.send_header("Location", "/?msg=import-ok")
                    self.end_headers()

            content_type = (self.headers.get("Content-Type", "") or "")

            # A confirmation carries no file: it names an import already
            # reviewed in this session. Handled before the body checks below,
            # which exist for uploads and would reject it for being small.
            confirm_token = ""
            if "multipart/form-data" not in content_type.lower():
                confirm_token = (data.get("confirm") or [""])[0]
            if confirm_token:
                try:
                    classified = take_pending_import(self._session_rec, confirm_token)
                    plaintext = load_vault(master, self._session_rec)
                    new_plain, stats = apply_import_rows(classified, plaintext)
                    save_vault(master, new_plain, self._session_rec)
                    sys.stderr.write(f"[import] Vault successfully updated ({stats}).\n")
                    summary = ", ".join(f"{v} {k}" for k, v in stats.items() if v)
                    respond_success(f"Import complete: {summary}.")
                except Exception as exc:
                    sys.stderr.write(f"[import] Confirmation failed: {exc}\n")
                    respond_error(str(exc) or "Import failed.")
                return

            body_bytes = raw_body_bytes or b""
            body_len = len(body_bytes)

            if body_len <= 0:
                respond_error("No data provided.")
                return

            if body_len > MAX_IMPORT_BYTES:
                respond_error("Payload too large (max 1MB).", status=413)
                return

            sys.stderr.write(f'[import] Reading {body_len} bytes from request body...\n')

            fmt = "csv"
            content = ""
            export_password = ""

            if "multipart/form-data" in content_type.lower():
                try:
                    fields = parse_multipart(body_bytes, content_type)
                    fmt_raw = fields.get("fmt") or b"csv"
                    fmt = fmt_raw.decode("utf-8", "ignore").lower()
                    export_password = fields.get("export_password", b"").decode("utf-8", "ignore")
                    file_bytes = fields.get("file", b"")
                    if file_bytes:
                        content = file_bytes.decode("utf-8", "ignore")
                        sys.stderr.write('[import] Processed file upload via multipart parser\n')
                    elif fields.get("data"):
                        content = fields.get("data", b"").decode("utf-8", "ignore")
                        sys.stderr.write('[import] Processed pasted data via multipart parser\n')
                    else:
                        respond_error("Failed to parse upload.")
                        return
                except Exception as e:
                    sys.stderr.write(f"[import] Multipart parse failed: {e}\n")
                    respond_error("Failed to parse upload.")
                    return
            else:
                body_str = body_bytes.decode("utf-8", "ignore")
                data = urllib.parse.parse_qs(body_str)
                fmt = (data.get("fmt") or ["csv"])[0].lower()
                export_password = (data.get("export_password") or [""])[0]
                content = (data.get("data") or [""])[0]
                if not content and body_str:
                    content = body_str

            if fmt not in SUPPORTED_FORMATS:
                respond_error(f"Unsupported format {fmt}")
                return

            if not content.strip():
                respond_error("No content to import.")
                return

            try:
                classified, stats, skipped = preview_import(fmt, content, export_password)
                token = stash_pending_import(self._session_rec, classified, stats, skipped)
                sys.stderr.write(f"[import] Parsed for review ({stats}, "
                                 f"{len(skipped)} unsupported).\n")
                if is_async:
                    # A caller that asked for JSON gets the same verdict as the
                    # page: what would be added, and the token to commit it.
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(jsonlib.dumps({
                        "ok": True, "preview": True, "stats": stats,
                        "skipped": len(skipped), "confirm": token,
                    }).encode("utf-8"))
                else:
                    self._send_html(200, import_preview_page(
                        classified, stats, skipped, token, self._session_csrf()))
            except Exception as e:
                sys.stderr.write(f"[import] Import process failed: {e}\n")
                __import__("traceback").print_exc(file=sys.stderr)
                respond_error(str(e) or "Import failed.")
            return

        if path == "/passphrase-add":
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0]

            if not label:
                page = build_passphrase_form(
                    title="Add Passphrase",
                    vault_path=VAULT_PATH,
                    action="/passphrase-add",
                    values={"label": label, "secret": secret},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, passphrases = parse_passphrases(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in passphrases:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if not secret:
                secret = secrets.token_urlsafe(32)
            encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "PASSPHRASE",
                str(new_id),
                _vf(label),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/passphrase-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            pid = (query.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0]

            plaintext = load_vault(master, self._session_rec)
            lines, passphrases = parse_passphrases(plaintext)
            idx_to_update = None
            created = ""
            existing_secret = ""
            for idx, parts in passphrases:
                if parts[1] == pid:
                    idx_to_update = idx
                    if len(parts) >= 5:
                        created = parts[4]
                    if len(parts) >= 4:
                        existing_secret = parts[3]
                    break
            if idx_to_update is None:
                self.send_error(404, "Passphrase not found")
                return
            if not label:
                page = build_passphrase_form(
                    title=f"Edit Passphrase #{pid}",
                    vault_path=VAULT_PATH,
                    action="/passphrase-edit?id=" + urllib.parse.quote(pid),
                    values={"label": label, "secret": secret},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return
            if not secret:
                try:
                    # reuse existing secret if not provided
                    secret = base64.b64decode(existing_secret.encode("ascii"), validate=True).decode("utf-8", errors="strict")
                except Exception:
                    self.send_error(500, "Stored passphrase cannot be decoded; vault was not changed")
                    return
            encoded = base64.b64encode(secret.encode("utf-8")).decode("ascii")
            lines[idx_to_update] = "\t".join([
                "PASSPHRASE",
                pid,
                _vf(label),
                encoded,
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "-",
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/passphrase-delete":
            pid = (data.get("id") or [""])[0]
            if not pid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("PASSPHRASE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == pid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-add":
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0].replace(" ", "")
            period = (data.get("period") or ["30"])[0]
            algo_in = (data.get("algo") or [""])[0].lower()
            algo = ((data.get("algo") or ["sha1"])[0] or "sha1").lower()
            if algo not in ("sha1","sha256","sha512"):
                algo = "sha1"

            if not label or not secret:
                page = build_auth_form(
                    title="Add Authenticator",
                    vault_path=VAULT_PATH,
                    action="/authenticator-add",
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Label and secret are required.</div>",
                )
                self._send_html(200, page)
                return

            try:
                period_int = int(period)
                if period_int <= 0:
                    period_int = 30
            except Exception:
                period_int = 30

            try:
                _ = totp_code(secret, period_int, algo)
            except Exception:
                page = build_auth_form(
                    title="Add Authenticator",
                    vault_path=VAULT_PATH,
                    action="/authenticator-add",
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Invalid Base32 secret.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, auths = parse_authenticators(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in auths:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            new_line = "\t".join([
                "AUTH",
                str(new_id),
                _vf(label),
                _vf(secret),
                str(period_int),
                now,
                algo,
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            aid = (query.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            secret = (data.get("secret") or [""])[0].replace(" ", "")
            period = (data.get("period") or ["30"])[0]
            algo_in = (data.get("algo") or [""])[0].lower()

            plaintext = load_vault(master, self._session_rec)
            lines, auths = parse_authenticators(plaintext)
            idx_to_update = None
            created = ""
            algo = "sha1"
            for idx, parts in auths:
                if parts[1] == aid:
                    idx_to_update = idx
                    if len(parts) >= 6:
                        created = parts[5]
                    if len(parts) >= 7 and parts[6]:
                        algo = parts[6].lower()
                    if not label:
                        label = parts[2]
                    if not secret:
                        secret = parts[3]
                    try:
                        if not period:
                            period = parts[4]
                    except Exception:
                        pass
                    break

            if algo_in in ("sha1","sha256","sha512"):
                algo = algo_in

            if idx_to_update is None:
                self.send_error(404, "Authenticator not found")
                return

            try:
                period_int = int(period)
                if period_int <= 0:
                    period_int = 30
            except Exception:
                period_int = 30

            try:
                _ = totp_code(secret, period_int, algo)
            except Exception:
                page = build_auth_form(
                    title=f"Edit Authenticator #{aid}",
                    vault_path=VAULT_PATH,
                    action="/authenticator-edit?id=" + urllib.parse.quote(aid),
                    values={"label": label, "secret": secret, "period": period, "algo": algo},
                    message="<div class='msg'>Invalid Base32 secret.</div>",
                )
                self._send_html(200, page)
                return

            lines[idx_to_update] = "\t".join([
                "AUTH",
                aid,
                _vf(label),
                _vf(secret),
                str(period_int),
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                algo,
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/authenticator-delete":
            aid = (data.get("id") or [""])[0]
            if not aid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            found = False
            for line in lines:
                if line.startswith("AUTH\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == aid:
                        found = True
                        continue
                new_lines.append(line)
            if not found:
                self.send_error(404, "Authenticator not found")
                return
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-add":
            label = (data.get("label") or [""])[0].strip()
            codes = (data.get("codes") or [""])[0]
            if not label:
                page = build_backup_form(
                    title="Add Backup Codes",
                    vault_path=VAULT_PATH,
                    action="/backup-codes-add",
                    values={"label": label, "codes": codes},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return

            plaintext = load_vault(master, self._session_rec)
            lines, backups = parse_backup_codes(plaintext)
            lines = plaintext.splitlines()

            max_id = 0
            for _, parts in backups:
                try:
                    max_id = max(max_id, int(parts[1]))
                except ValueError:
                    continue
            new_id = max_id + 1
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            encoded = base64.b64encode(codes.encode("utf-8")).decode("ascii")
            new_line = "\t".join([
                "BACKUP_CODE",
                str(new_id),
                _vf(label),
                encoded,
                now,
                "-",
            ])
            lines.append(new_line)
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-edit":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            bid = (query.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            label = (data.get("label") or [""])[0].strip()
            codes = (data.get("codes") or [""])[0]

            plaintext = load_vault(master, self._session_rec)
            lines, backups = parse_backup_codes(plaintext)
            idx_to_update = None
            created = ""
            backups_by_id = {}
            for idx, parts in backups:
                if len(parts) >= 4:
                    backups_by_id[parts[1]] = parts[3]
                if parts[1] == bid:
                    idx_to_update = idx
                    if len(parts) >= 5:
                        created = parts[4]
                    break
            if idx_to_update is None:
                self.send_error(404, "Backup code not found")
                return
            if not label:
                page = build_backup_form(
                    title=f"Edit Backup Codes #{bid}",
                    vault_path=VAULT_PATH,
                    action="/backup-codes-edit?id=" + urllib.parse.quote(bid),
                    values={"label": label, "codes": codes},
                    message="<div class='msg'>Label is required.</div>",
                )
                self._send_html(200, page)
                return
            if not codes:
                # A blank field means "leave them alone", never "erase them".
                # Recovery codes cannot be regenerated from the vault, so an
                # unreadable stored value must stop rather than be replaced.
                stored = backups_by_id.get(bid, "")
                try:
                    codes = base64.b64decode(stored.encode("ascii"), validate=True).decode("utf-8", errors="strict")
                except Exception:
                    self.send_error(500, "Stored backup codes cannot be decoded; vault was not changed")
                    return
            encoded = base64.b64encode(codes.encode("utf-8")).decode("ascii")
            lines[idx_to_update] = "\t".join([
                "BACKUP_CODE",
                bid,
                _vf(label),
                encoded,
                created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "-",
            ])
            new_plain = "\n".join(lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/backup-codes-delete":
            bid = (data.get("id") or [""])[0]
            if not bid:
                self.send_error(400, "Missing id")
                return
            plaintext = load_vault(master, self._session_rec)
            lines = plaintext.splitlines()
            new_lines = []
            for line in lines:
                if line.startswith("BACKUP_CODE\t"):
                    parts = line.split("\t")
                    if len(parts) >= 2 and parts[1] == bid:
                        continue
                new_lines.append(line)
            new_plain = "\n".join(new_lines) + "\n"
            save_vault(master, new_plain, self._session_rec)

            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        self.send_error(404, "Not found")

def run():
    with SPMServer((BIND_ADDR, PORT), Handler) as httpd:
        print(f"[SPM Dashboard] Serving on http://{BIND_ADDR}:{PORT}/")
        print("[SPM Dashboard] Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[SPM Dashboard] Shutting down...")

if __name__ == "__main__":
    run()

"""SPM trusted core: vault format, key handling and vault mutation.

Everything that decides how a vault is protected lives here and nowhere else.
The CLI reaches it through the command interface at the bottom of this file;
the SPM Dashboard imports it directly. Before this module both surfaces
carried their own copy of the container format, the key wrapping, the version
stamping and the history archiving, and a regression test existed purely to
prove the two copies still agreed -- which is a test that a shared
implementation does not need.

Secrets never appear in argv. The command interface reads them from stdin,
and gpg receives them on a dedicated file descriptor, because argv is
world-readable through `ps` and /proc/<pid>/cmdline.
"""

import base64
import calendar
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse
import urllib.request

# ----- format and policy -----------------------------------------------------

# The vault records the format it was written in, so a later change can migrate
# instead of guessing. A vault with no META_VAULT_VERSION row predates this and
# is format 1; every write stamps the current version.
VAULT_FORMAT_VERSION = 4

CONTAINER_MAGIC = b"SPM-VAULT-3"

# Key derivation is pinned rather than inherited: a user's gpg.conf can change
# all of it underneath the application, and a security parameter that is
# implicit can be neither reviewed nor migrated. GnuPG 2.2 already defaults to
# s2k mode 3 at the maximum count, so the measurable change is the digest,
# whose default is SHA1.
S2K_ARGS = ["--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
            "--s2k-count", "65011712"]

HISTORY_RETENTION_DEFAULT = 20


class VaultError(Exception):
    """Anything that should reach a user as a refusal rather than a traceback."""


# ----- gpg backend -----------------------------------------------------------

def _passphrase_fd(secret):
    """A read fd holding `secret`, for gpg's --passphrase-fd.

    A pipe rather than argv: argv is world-readable through `ps` and
    /proc/<pid>/cmdline, so every local user could read the master password.
    """
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, secret.encode("utf-8"))
    finally:
        os.close(write_fd)
    return read_fd


def gpg_encrypt(secret, payload, timeout=60):
    fd = _passphrase_fd(secret)
    try:
        return subprocess.check_output(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(fd)] + S2K_ARGS +
            ["--cipher-algo", "AES256", "-c"],
            input=payload, stderr=subprocess.DEVNULL,
            timeout=timeout, pass_fds=(fd,))
    finally:
        os.close(fd)


def gpg_decrypt(secret, payload, timeout=60):
    fd = _passphrase_fd(secret)
    try:
        return subprocess.check_output(
            ["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(fd), "-d"],
            input=payload, stderr=subprocess.DEVNULL,
            timeout=timeout, pass_fds=(fd,))
    finally:
        os.close(fd)


# ----- container -------------------------------------------------------------
# A format-3 vault is one file: a header line, the vault key sealed under the
# master password, then the vault ciphertext sealed under that key. Keeping it
# to a single self-contained file is why every path that copies, backs up,
# syncs or bundles "the vault" needed no change when the format did.

def is_container(raw):
    return raw.startswith(CONTAINER_MAGIC + b"\n")


def build_container(envelope, cipher):
    return (CONTAINER_MAGIC + b"\nKEY " + base64.b64encode(envelope) +
            b"\nDATA\n" + base64.b64encode(cipher) + b"\n")


def parse_container(raw):
    """(envelope, cipher), or None when `raw` predates the container format."""
    if not is_container(raw):
        return None
    try:
        key_line, data = raw.split(b"\nDATA\n", 1)
        envelope = base64.b64decode(key_line.split(b"\nKEY ", 1)[1])
        cipher = base64.b64decode(data)
    except Exception as exc:
        raise VaultError("vault key container is corrupt") from exc
    if not envelope or not cipher:
        raise VaultError("vault key container is incomplete")
    return envelope, cipher


def new_vault_key():
    return base64.b64encode(os.urandom(32)).decode("ascii")


# ----- version stamping ------------------------------------------------------

def stamp_version(plaintext):
    """Exactly one current META_VAULT_VERSION row, first, on every write.

    Refuses to restamp a vault written by a newer SPM. Without this an older
    build opens a newer vault, keeps only the columns it knows, and writes it
    back stamped with its own version -- a silent downgrade that discards
    whatever the newer format added. The vault reads fine afterwards, which is
    what makes it dangerous: nothing announces the loss.

    Reading stays permitted. This guards the write, which is where the loss
    would happen.
    """
    found = format_version(plaintext)
    if found > VAULT_FORMAT_VERSION:
        raise VaultError(
            "this vault is format %d and this SPM understands %d; upgrade SPM "
            "rather than writing it back and losing what it holds"
            % (found, VAULT_FORMAT_VERSION))
    lines = plaintext.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    rows = [l for l in lines if l.split("\t", 1)[0] != "META_VAULT_VERSION"]
    head = "META_VAULT_VERSION\t%d\t-\t-\t-\t-" % VAULT_FORMAT_VERSION
    return "\n".join([head] + rows) + "\n"


def format_version(plaintext):
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if parts[0] == "META_VAULT_VERSION" and len(parts) > 1:
            try:
                return int(parts[1])
            except ValueError:
                return 1
    return 1


# ----- durability ------------------------------------------------------------

# The `read` command returns the vault key on stdout, so an output path that
# resolves to stdout would interleave plaintext with it and silently lose both.
# Refusing is better than a corrupted read that looks like it worked.
_STDOUT_ALIASES = ("-", "/dev/stdout", "/dev/fd/1", "/proc/self/fd/1")


def write_plaintext(path, text):
    """Write decrypted vault material to a file, restricted to its owner."""
    if path in _STDOUT_ALIASES:
        raise VaultError("refusing to write vault plaintext to stdout; "
                         "give a file path")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    try:
        if stat.S_ISREG(os.stat(path).st_mode):
            os.chmod(path, 0o600)
    except OSError:
        pass


def _fsync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path):
    # A directory fsync is what makes a rename survive a crash. Not every
    # filesystem permits it, so a refusal must not fail the write.
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# ----- history ---------------------------------------------------------------
# The CLI and the dashboard must agree on this hash exactly, or the two would
# write snapshots into different directories and each would see only its own.

def vault_scope_id(vault_path):
    return hashlib.sha256(
        os.path.abspath(vault_path).encode("utf-8")).hexdigest()[:16]


def data_dir():
    explicit = os.environ.get("SPM_DATA_DIR")
    if explicit:
        return explicit
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "spm")


def history_dir(vault_path):
    return os.path.join(data_dir(), "history", vault_scope_id(vault_path))


def _retention():
    try:
        keep = int(os.environ.get("SPM_HISTORY_RETENTION", ""))
    except ValueError:
        return HISTORY_RETENTION_DEFAULT
    return keep if keep > 0 else HISTORY_RETENTION_DEFAULT


# ----- security events -------------------------------------------------------
#
# What this is for: noticing that someone else opened, or tried to open, your
# vault. That is the whole reason it exists, and it decides both of the awkward
# choices below.
#
# It lives outside the vault, in plaintext. Inside would be tidier and would be
# encrypted, but a failed unlock is exactly the event you most want recorded
# and exactly the one that cannot be written into a vault nobody could open.
#
# So it must carry nothing worth reading. No labels, no usernames, no URLs, no
# paths, no secrets -- only a time, what kind of operation it was, whether it
# succeeded, and a detail drawn from a fixed vocabulary. Someone who can read
# this file can already see the vault file beside it and its modification time,
# so "this vault was opened at these times" is not new information to them.
# Anything beyond that would be.

EVENT_RETENTION_DEFAULT = 500
# The dashboard reads the vault on nearly every page view, so an event per read
# buries the handful of lines anyone actually came to see. Identical successful
# events inside this window are recorded once.
#
# Failures are never coalesced, whatever the window says. A burst of failed
# unlocks is precisely the signal this log exists to show, and collapsing five
# attempts into one would be the log lying about the thing it is for.
EVENT_COALESCE_DEFAULT = 60
EVENT_KINDS = ("unlock", "write", "rewrap", "recover", "restore", "archive")
EVENT_OUTCOMES = ("ok", "fail")
# Details are key=value with both sides constrained, rather than free text.
# Free text is how a label ends up in a log one day: someone adds a helpful
# "which record" to an error path and nobody notices it is now on disk in the
# clear. A closed vocabulary makes that a test failure instead of a leak.
EVENT_DETAIL_KEYS = ("records", "format", "scope", "reason")
EVENT_REASONS = ("bad-master", "corrupt", "missing", "unreadable")
EVENT_SCOPES = ("live", "other")


# ----- record attributes: folders and custom fields --------------------------
#
# Format 4 appends one optional column to a password row, after the URL. It
# holds a folder name and any number of user-named fields, base64-encoded JSON
# so that a tab, a newline or a non-ASCII name in a value cannot break the
# row-per-line format that everything else depends on.
#
# A column rather than new row types: a folder and a custom field belong to the
# record they describe, and keeping them on the row means every existing path
# that moves, exports or deletes a record carries them along without being
# taught to. The cost is that an older SPM writing this vault back would drop
# them, which is what the guard in stamp_version exists to prevent.

ATTRS_FOLDER_MAX = 128
ATTRS_FIELD_NAME_MAX = 128
ATTRS_FIELD_VALUE_MAX = 4096
ATTRS_FIELD_MAX = 64


def encode_attrs(folder="", fields=None):
    """The attributes column for a record, or "" when there is nothing to say.

    Empty is empty rather than an encoded empty object, so a record that uses
    none of this is byte-identical to how format 3 wrote it.
    """
    folder = (folder or "").strip()
    fields = [(str(n).strip(), str(v)) for n, v in (fields or []) if str(n).strip()]
    if not folder and not fields:
        return ""
    if len(folder) > ATTRS_FOLDER_MAX:
        raise VaultError("folder name is longer than %d characters"
                         % ATTRS_FOLDER_MAX)
    if len(fields) > ATTRS_FIELD_MAX:
        raise VaultError("a record may carry at most %d custom fields"
                         % ATTRS_FIELD_MAX)
    seen = set()
    for name, value in fields:
        if len(name) > ATTRS_FIELD_NAME_MAX:
            raise VaultError("custom field name is longer than %d characters"
                             % ATTRS_FIELD_NAME_MAX)
        if len(value) > ATTRS_FIELD_VALUE_MAX:
            raise VaultError("custom field value is longer than %d characters"
                             % ATTRS_FIELD_VALUE_MAX)
        key = name.casefold()
        if key in seen:
            raise VaultError("duplicate custom field name %r" % (name,))
        seen.add(key)
    payload = {}
    if folder:
        payload["folder"] = folder
    if fields:
        payload["fields"] = [{"name": n, "value": v} for n, v in fields]
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_attrs(column):
    """(folder, [(name, value)]) for an attributes column.

    Never raises. A column this build cannot read is a record it should still
    show, minus the part it did not understand -- refusing would make one bad
    row hide a whole vault.
    """
    column = (column or "").strip()
    if not column:
        return "", []
    try:
        payload = json.loads(base64.b64decode(column, validate=True)
                             .decode("utf-8"))
    except Exception:
        return "", []
    if not isinstance(payload, dict):
        return "", []
    folder = payload.get("folder") or ""
    if not isinstance(folder, str):
        folder = ""
    fields = []
    raw = payload.get("fields")
    if isinstance(raw, list):
        for item in raw[:ATTRS_FIELD_MAX]:
            if not isinstance(item, dict):
                continue
            name, value = item.get("name"), item.get("value")
            if isinstance(name, str) and name.strip() and isinstance(value, str):
                fields.append((name, value))
    return folder[:ATTRS_FOLDER_MAX], fields


def record_folders(plaintext):
    """Every folder in use, sorted, without duplicates differing only in case."""
    seen = {}
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        if not parts or parts[0].startswith("META_") or not parts[0].isdigit():
            continue
        folder, _ = decode_attrs(parts[7] if len(parts) > 7 else "")
        if folder:
            seen.setdefault(folder.casefold(), folder)
    return [seen[k] for k in sorted(seen)]


def _record_count(plaintext):
    """Rows that are records rather than META_ headers. A count, and nothing
    that says what any of them are."""
    return sum(1 for line in (plaintext or "").splitlines()
               if line.strip() and not line.startswith("META_"))


def events_path(vault_path):
    return os.path.join(data_dir(), "events",
                        vault_scope_id(vault_path) + ".log")


def _event_retention():
    try:
        keep = int(os.environ.get("SPM_EVENT_RETENTION", ""))
    except ValueError:
        return EVENT_RETENTION_DEFAULT
    return keep if keep > 0 else EVENT_RETENTION_DEFAULT


def _event_coalesce_window():
    try:
        seconds = int(os.environ.get("SPM_EVENT_COALESCE", ""))
    except ValueError:
        return EVENT_COALESCE_DEFAULT
    return seconds if seconds >= 0 else EVENT_COALESCE_DEFAULT


def _last_event(path):
    """The final line of the log, without reading the whole file."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            handle.seek(max(0, size - 4096))
            tail = handle.read().decode("utf-8", "ignore").splitlines()
    except OSError:
        return None
    return tail[-1] if tail else None


def _coalesces(path, kind, outcome, detail, now):
    """True when this event repeats the last one inside the window."""
    if outcome != "ok":
        return False
    window = _event_coalesce_window()
    if window <= 0:
        return False
    previous = _last_event(path)
    if not previous:
        return False
    fields = previous.split("\t")
    if len(fields) != 4:
        return False
    if (fields[1], fields[2], fields[3]) != (kind, outcome, detail):
        return False
    try:
        before = calendar.timegm(time.strptime(fields[0], "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return False
    return 0 <= now - before < window


def event_line(when, kind, outcome, detail=""):
    """One log line, or ValueError if it would carry something it should not.

    Deliberately strict and deliberately raising: misuse here is a programming
    error and should fail a test. Callers wrap it so that a rejected line can
    never take a vault operation down with it.
    """
    if kind not in EVENT_KINDS:
        raise ValueError("unknown event kind %r" % (kind,))
    if outcome not in EVENT_OUTCOMES:
        raise ValueError("unknown event outcome %r" % (outcome,))
    parts = []
    for item in (detail or "").split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError("event detail %r is not key=value" % (item,))
        key, value = item.split("=", 1)
        if key not in EVENT_DETAIL_KEYS:
            raise ValueError("event detail key %r is not permitted" % (key,))
        if key == "reason" and value not in EVENT_REASONS:
            raise ValueError("event reason %r is not permitted" % (value,))
        if key == "scope" and value not in EVENT_SCOPES:
            raise ValueError("event scope %r is not permitted" % (value,))
        if key in ("records", "format") and not value.isdigit():
            raise ValueError("event %s must be a number, got %r" % (key, value))
        parts.append("%s=%s" % (key, value))
    return "\t".join((when, kind, outcome, ",".join(parts)))


def _audit_target():
    """The vault whose log receives events, or "" when there is none.

    Taken from the environment rather than from the path being operated on, so
    that reading a snapshot or a .bak records against the vault the session is
    actually about instead of scattering a log file per file touched.
    """
    return os.environ.get("SPM_VAULT_PATH", "") or ""


def record_event(kind, outcome="ok", detail="", vault_path=None):
    """Append one event. Never raises, and never fails the caller.

    Same rule as archive_generation below: losing a log line is a nuisance,
    losing the operation it describes is data loss.
    """
    try:
        target = vault_path or _audit_target()
        if not target:
            return False
        now = time.time()
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        line = event_line(when, kind, outcome, detail)
        path = events_path(target)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # Computed from the formatted line so the comparison is against exactly
        # what was written, not against a detail string that might normalise
        # differently on the way in.
        written = line.split("\t")
        if _coalesces(path, written[1], written[2], written[3], now):
            return False
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(handle, (line + "\n").encode("utf-8"))
        finally:
            os.close(handle)
        _prune_events(path)
        return True
    except Exception:
        return False


def _prune_events(path):
    """Keep the log bounded, rewritten atomically so a reader sees one or the
    other. Trimmed only when it has drifted well past the limit, so an append
    is an append almost every time rather than a whole-file rewrite."""
    keep = _event_retention()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return
    if len(lines) <= keep * 2:
        return
    staged = path + ".tmp"
    with open(staged, "w", encoding="utf-8") as handle:
        handle.writelines(lines[-keep:])
    os.chmod(staged, 0o600)
    os.replace(staged, path)


def read_events(vault_path=None, limit=None):
    """Recorded events, oldest first. Malformed lines are skipped, not raised:
    a log is a record of what happened, not a thing that gets to fail."""
    target = vault_path or _audit_target()
    if not target:
        return []
    try:
        with open(events_path(target), "r", encoding="utf-8") as handle:
            raw = handle.read().splitlines()
    except OSError:
        return []
    out = []
    for line in raw:
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        when, kind, outcome = fields[0], fields[1], fields[2]
        if kind not in EVENT_KINDS or outcome not in EVENT_OUTCOMES:
            continue
        detail = {}
        for item in (fields[3] if len(fields) > 3 else "").split(","):
            if "=" in item:
                key, value = item.split("=", 1)
                if key in EVENT_DETAIL_KEYS:
                    detail[key] = value
        out.append({"when": when, "kind": kind,
                    "outcome": outcome, "detail": detail})
    if limit and limit > 0:
        return out[-limit:]
    return out


def _scope_of(vault_path):
    try:
        target = _audit_target()
        if not target:
            return "other"
        same = os.path.abspath(vault_path) == os.path.abspath(target)
        return "live" if same else "other"
    except Exception:
        return "other"


def archive_generation(vault_path):
    """Snapshot the current ciphertext before it is replaced.

    Failure here must never fail the write it protects: losing an undo point
    is bad, losing the edit is worse.
    """
    if not os.path.exists(vault_path):
        return
    try:
        target = history_dir(vault_path)
        os.makedirs(target, exist_ok=True)
        os.chmod(target, 0o700)
        with open(vault_path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()[:12]
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        snapshot = os.path.join(
            target, "%s.%d.%s.gpg" % (stamp, os.getpid(), digest))
        shutil.copy2(vault_path, snapshot)
        os.chmod(snapshot, 0o600)
        _prune(target, ".gpg", _retention())
    except Exception:
        return


def _prune(directory, suffix, keep):
    try:
        entries = [os.path.join(directory, n) for n in os.listdir(directory)
                   if n.endswith(suffix)]
        entries = [p for p in entries if os.path.isfile(p)]
        entries.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
        for stale in entries[keep:]:
            os.remove(stale)
    except Exception:
        return


# ----- recovery --------------------------------------------------------------

def recovery_path(vault_path):
    return vault_path + ".recovery"


def recovery_pubkey_pem(plaintext):
    """The vault's own recovery public key, or an exception saying why not."""
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if parts[0] == "META_RECOVERY_PUBKEY" and len(parts) > 1 and parts[1].strip():
            try:
                return base64.b64decode(parts[1].strip())
            except Exception:
                raise VaultError("recovery public key is not valid base64")
    raise VaultError("no META_RECOVERY_PUBKEY row in vault")


def stage_recovery(vault_path, plaintext, vault_key):
    """Seal `vault_key` under the vault's recovery pubkey; return a staged path.

    Staging is the safety property. Decoding the stored key only proves it is
    base64; the vault must not be touched until openssl has actually accepted
    it and produced the ciphertext. The caller installs the result once the
    vault it describes is in place.

    Deliberately the same `openssl rsautl -encrypt -pubin` the rest of the
    project uses. It is deprecated in OpenSSL 3, but `spm doctor` and
    `spm forgot` read this file back with `rsautl -decrypt`; switching only the
    writer would be a padding decision made in one place out of three.
    """
    pub_pem = recovery_pubkey_pem(plaintext)
    target = recovery_path(vault_path)
    rec_dir = os.path.dirname(os.path.abspath(target)) or "."
    pub_fd, pub_file = tempfile.mkstemp(prefix="spm.recpub.")
    staged = ""
    try:
        os.write(pub_fd, pub_pem)
        os.close(pub_fd)
        pub_fd = -1
        out_fd, staged = tempfile.mkstemp(
            prefix="." + os.path.basename(target) + ".stage.", dir=rec_dir)
        os.close(out_fd)
        os.chmod(staged, 0o600)
        proc = subprocess.Popen(
            ["openssl", "rsautl", "-encrypt", "-pubin",
             "-inkey", pub_file, "-out", staged],
            stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            proc.communicate(input=vault_key.encode("utf-8"), timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise VaultError("recovery encryption timed out")
        if proc.returncode != 0 or not os.path.getsize(staged):
            raise VaultError("the recovery public key was not usable")
        _fsync_path(staged)
        result, staged = staged, ""
        return result
    finally:
        if pub_fd != -1:
            os.close(pub_fd)
        if os.path.exists(pub_file):
            os.remove(pub_file)
        if staged and os.path.exists(staged):
            os.remove(staged)


# ----- tidying imported entries ----------------------------------------------
# A vault filled by importing from a phone arrives in two states worth fixing in
# bulk. Its notes carry the folder the entry belonged to, as text, because the
# exporting app had folders and the export format did not. And its service names
# are Android package identifiers -- com.duolingo, id.go.kemensos.pelaporan --
# which are what the phone knew the app by and not what its owner does.
#
# Both are proposals, never edits. `tidy_proposals` computes what would change
# and touches nothing; `apply_tidy` performs exactly the changes it was handed.
# Nothing here guesses in place: with hundreds of records the difference between
# a preview and a surprise is the whole feature.

TIDY_ORIGINAL_PREFIX = "app:"
_TIDY_FOLDER_RE = re.compile(r"(?i)\bfolder\s*:\s*(.*)$")
# A later "word:" ends the folder value. Notes are stored with their line breaks
# collapsed to spaces, so "folder: Work url: https://..." is one string and the
# folder is not the rest of it.
_TIDY_MARKER_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{0,20}\s*:")

# The first label of a reverse-DNS package identifier. A name whose *first*
# segment is one of these reads backwards -- com.duolingo -- where a name whose
# *last* segment is one reads forwards, as duolingo.com does.
_TIDY_TLDS = frozenset("""
com net org edu gov mil int io co me app dev xyz info biz online site
id uk de fr jp cn au ca in br ru it es nl se no fi dk pl ch at be cz gr pt
ro hu tr kr tw hk sg my th vn ph nz za mx ar cl pe ve ir sa ae il eg ng ke
""".split())
# Second-level labels that are part of the suffix rather than the name, so
# example.co.uk yields "Example" and not "Co".
_TIDY_SECOND_LEVEL = frozenset(("co", "com", "net", "org", "ac", "gov", "edu",
                                "go", "or", "ne", "sch", "mil"))
# Trailing segments that name the platform rather than the app, so
# com.example.android resolves to "Example".
_TIDY_GENERIC_TAIL = frozenset(("android", "app", "apps", "mobile", "client",
                                "application", "main", "prod", "release",
                                "free", "pro", "lite", "beta"))


def _tidy_titlecase(word):
    parts = [p for p in re.split(r"[_\-\s]+", word) if p]
    out = []
    for part in parts:
        # Something already capitalised the way a brand is stays as it is:
        # "eBay" and "PayPal" must not become "Ebay" and "Paypal".
        out.append(part if any(c.isupper() for c in part) else part.capitalize())
    return " ".join(out)


def derive_app_name(label):
    """A human name for a package identifier or domain, or "" to leave it be.

    Deliberately conservative: anything that does not clearly read as a package
    identifier or a hostname is returned unchanged, because a label somebody
    typed themselves is not this function's business.
    """
    text = (label or "").strip()
    if not text or " " in text or "/" in text:
        return ""
    parts = [p for p in text.split(".") if p]
    if len(parts) < 2 or len(parts) != text.count(".") + 1:
        return ""
    if not all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts):
        return ""

    head, tail = parts[0].lower(), parts[-1].lower()
    if head in _TIDY_TLDS and tail not in _TIDY_TLDS:
        # Reverse-DNS: com.duolingo, id.go.kemensos.pelaporan.
        chosen = parts[-1]
        if chosen.lower() in _TIDY_GENERIC_TAIL and len(parts) > 2:
            chosen = parts[-2]
    elif tail in _TIDY_TLDS:
        # Forward hostname: mail.google.com, example.co.uk.
        index = -2
        if len(parts) >= 3 and parts[-2].lower() in _TIDY_SECOND_LEVEL:
            index = -3
        chosen = parts[index]
    else:
        return ""

    if chosen.lower() in _TIDY_TLDS or chosen.lower() in _TIDY_SECOND_LEVEL:
        return ""
    name = _tidy_titlecase(chosen)
    if not name or name == text:
        return ""
    return name


def folder_from_notes(notes):
    """The folder a note names, or "" when it names none."""
    match = _TIDY_FOLDER_RE.search(notes or "")
    if not match:
        return ""
    value = match.group(1)
    following = _TIDY_MARKER_RE.search(value)
    if following:
        value = value[:following.start()]
    value = " ".join(value.split())
    if not value or len(value) > ATTRS_FOLDER_MAX:
        return ""
    return value


def _tidy_note_with_original(notes, original):
    """Keep the identifier the phone knew, once, and only if it is not there."""
    text = notes or ""
    marker = "%s %s" % (TIDY_ORIGINAL_PREFIX, original)
    if original in text:
        return text
    return ("%s %s" % (text.strip(), marker)).strip() if text.strip() else marker


def tidy_proposals(plaintext):
    """What a tidy would change, as data. Changes nothing.

    Each proposal names the record, what is proposed for it, and the before and
    after of every field involved, so a caller can render it for review without
    knowing any of the rules above.
    """
    proposals = []
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].isdigit() or len(parts) < 6:
            continue
        record_id, label = parts[0], parts[1]
        notes = parts[4] if len(parts) > 4 else ""
        attrs = parts[7] if len(parts) > 7 else ""
        folder, fields = decode_attrs(attrs)

        changes = {}
        proposed_folder = folder_from_notes(notes)
        if proposed_folder and proposed_folder != folder:
            changes["folder"] = {"from": folder, "to": proposed_folder}

        new_notes = notes
        proposed_label = derive_app_name(label)
        if proposed_label and proposed_label != label:
            changes["label"] = {"from": label, "to": proposed_label}
            new_notes = _tidy_note_with_original(notes, label)
            if new_notes != notes:
                changes["notes"] = {"from": notes, "to": new_notes}

        if changes:
            proposals.append({"id": record_id, "label": label,
                              "changes": changes})
    return proposals


TIDY_LABEL_MAX = 200


def apply_tidy(plaintext, selections):
    """Apply reviewed changes. `selections` maps record id -> {"label": str}.

    No rule here decides anything. The guess `tidy_proposals` made is only a
    guess -- no heuristic gets both com.lsdroid.cerberuss and com.spotify.music
    right -- so what gets written is what came back from the review, and this
    function's job is to refuse anything that review should not be able to say.

    A record may only be touched if it had a proposal: a stale preview, or a
    request naming a record that has since changed, must not be able to write
    something the vault was never asked about. The folder is taken from the
    record's own notes rather than from the request, because that one is not a
    guess and there is nothing to review.
    """
    proposals = {p["id"]: p for p in tidy_proposals(plaintext)}
    chosen = {}
    for record_id, values in (selections or {}).items():
        key = str(record_id)
        if key not in proposals:
            continue
        chosen[key] = values or {}
    if not chosen:
        return plaintext, 0

    out, changed = [], 0
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        record_id = parts[0] if parts else ""
        if not record_id.isdigit() or record_id not in chosen:
            out.append(line)
            continue
        while len(parts) < 8:
            parts.append("")
        proposal = proposals[record_id]
        changes = proposal["changes"]
        touched = False

        if "label" in changes:
            label = str(chosen[record_id].get("label") or "").strip()
            if not label:
                label = changes["label"]["to"]
            label = " ".join(label.split())[:TIDY_LABEL_MAX]
            if label and label != parts[1]:
                original = parts[1]
                parts[1] = label
                parts[4] = _tidy_note_with_original(parts[4], original)
                touched = True

        if "folder" in changes:
            _, fields = decode_attrs(parts[7])
            parts[7] = encode_attrs(changes["folder"]["to"], fields)
            touched = True

        out.append("\t".join(parts))
        if touched:
            changed += 1
    return "\n".join(out) + ("\n" if (plaintext or "").endswith("\n") else ""), changed


# ----- split recovery --------------------------------------------------------
# The recovery file and its private key have to survive together: lose the PEM
# and the capsule is inert, leak the PEM while somebody holds the capsule and
# the vault is open. Shamir shares replace that pair with a threshold -- any
# `t` of `n` reconstruct the vault key, any `t - 1` reveal nothing at all --
# so the material can be spread across people or places without any single one
# of them being either a single point of failure or a single point of trust.
#
# What is split is the vault key itself, which is stable for the life of the
# vault: `rewrap` changes only the master-password envelope around it. Shares
# minted once therefore keep working after a master-password change, which is
# the property that makes them worth writing on paper. They are also exactly
# what `recover()` already consumes, so this adds an input to the existing
# recovery path rather than a second one beside it.

SHARE_MAGIC = "SPMS1"
SHARE_SET_BYTES = 4
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _build_gf_tables():
    """Log tables for GF(2**8) with the AES polynomial, generator 3.

    Not generator 2: 2 has multiplicative order 51 under 0x11b, so powers of it
    reach a fifth of the field and the tables would be silently wrong for the
    rest. 3 is primitive and enumerates all 255 non-zero elements.
    """
    x = 1
    for power in range(255):
        _GF_EXP[power] = x
        _GF_LOG[x] = power
        # x * 3 == (x * 2) XOR x, with the reduction when the high bit is set.
        doubled = (x << 1) ^ (0x11B if x & 0x80 else 0)
        x = doubled ^ x
    for power in range(255, 512):
        _GF_EXP[power] = _GF_EXP[power - 255]


_build_gf_tables()


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a):
    if a == 0:
        raise VaultError("share arithmetic divided by zero")
    return _GF_EXP[255 - _GF_LOG[a]]


def split_secret(secret, threshold, count):
    """Split `secret` (bytes) into `count` shares, any `threshold` sufficing.

    Every coefficient above the constant term is drawn uniformly, including
    the highest, and including zero. That is deliberate and should not be
    "fixed" into drawing the top coefficient from 1..255: the security proof
    needs the polynomial to be uniform over all of degree <= threshold-1, and
    forcing the leading term non-zero excludes one candidate secret for any
    given set of threshold-1 shares. Uniform coefficients leak exactly nothing.
    """
    if not isinstance(secret, bytes) or not secret:
        raise VaultError("there is no secret to split")
    if not 2 <= threshold <= 255:
        raise VaultError("threshold must be between 2 and 255")
    if not threshold <= count <= 255:
        raise VaultError(
            "a set of %d shares cannot have a threshold of %d"
            % (count, threshold))

    shares = [bytearray() for _ in range(count)]
    for byte in secret:
        coefficients = [byte] + list(os.urandom(threshold - 1))
        for index in range(count):
            x = index + 1  # never 0: f(0) is the secret itself
            acc = 0
            for coefficient in reversed(coefficients):
                acc = _gf_mul(acc, x) ^ coefficient
            shares[index].append(acc)
    return [(index + 1, bytes(share)) for index, share in enumerate(shares)]


def combine_shares(shares):
    """Reconstruct the secret from (x, bytes) pairs by interpolating at 0."""
    if len(shares) < 2:
        raise VaultError("at least two shares are needed")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise VaultError("the same share was given more than once")
    if any(not 1 <= x <= 255 for x in xs):
        raise VaultError("a share carries an impossible index")
    lengths = {len(payload) for _, payload in shares}
    if len(lengths) != 1:
        raise VaultError("these shares are different lengths and cannot belong "
                         "to one set")

    secret = bytearray()
    for position in range(lengths.pop()):
        total = 0
        for i, (xi, payload) in enumerate(shares):
            numerator, denominator = 1, 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = _gf_mul(numerator, xj)
                denominator = _gf_mul(denominator, xi ^ xj)
            total ^= _gf_mul(payload[position],
                             _gf_mul(numerator, _gf_inv(denominator)))
        secret.append(total)
    return bytes(secret)


def _share_body(threshold, index, set_id, payload):
    return "%s-%d-%d-%s-%s" % (
        SHARE_MAGIC, threshold, index, set_id.hex().upper(),
        base64.b32encode(payload).decode("ascii").rstrip("="))


def _share_checksum(body):
    return hashlib.sha256(body.encode("ascii")).hexdigest()[:4].upper()


def encode_share(threshold, index, set_id, payload):
    """One share as a single transcribable token, with its own checksum.

    The checksum covers the share's own text, not the secret. A mistyped share
    is then rejected the moment it is read, rather than combining cleanly into
    a wrong key that only fails later against the vault -- at which point
    nothing says which of the shares was wrong.
    """
    body = _share_body(threshold, index, set_id, payload)
    return "%s-%s" % (body, _share_checksum(body))


def decode_share(text):
    """(threshold, index, set_id, payload) or an exception naming the problem."""
    token = "".join((text or "").split()).upper()
    parts = token.split("-")
    if len(parts) != 6 or parts[0] != SHARE_MAGIC:
        raise VaultError("this is not an SPM recovery share")
    _, threshold_text, index_text, set_text, data_text, checksum = parts
    body = "-".join(parts[:5])
    if _share_checksum(body) != checksum:
        raise VaultError("share %s did not survive transcription; its checksum "
                         "does not match" % (index_text or "?"))
    if not threshold_text.isdigit() or not index_text.isdigit():
        raise VaultError("a share carries a non-numeric threshold or index")
    threshold, index = int(threshold_text), int(index_text)
    if not 2 <= threshold <= 255 or not 1 <= index <= 255:
        raise VaultError("a share carries an impossible threshold or index")
    try:
        set_id = bytes.fromhex(set_text)
    except ValueError:
        raise VaultError("a share carries a malformed set identifier")
    if len(set_id) != SHARE_SET_BYTES:
        raise VaultError("a share carries a set identifier of the wrong size")
    padding = "=" * (-len(data_text) % 8)
    try:
        payload = base64.b32decode(data_text + padding)
    except Exception:
        raise VaultError("a share carries a malformed payload")
    if not payload:
        raise VaultError("a share carries no payload")
    return threshold, index, set_id, payload


def shares_meta(plaintext):
    """(set_id, threshold, count, minted) for the vault's share set, or None.

    The row records that a set exists and which one, never any share. It is
    what lets `doctor` say a vault has split recovery and what catches shares
    from a different vault before they are combined.
    """
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if parts[0] == "META_RECOVERY_SHARES" and len(parts) >= 5:
            try:
                set_id = bytes.fromhex(parts[1].strip())
            except ValueError:
                return None
            if len(set_id) != SHARE_SET_BYTES:
                return None
            if not parts[2].strip().isdigit() or not parts[3].strip().isdigit():
                return None
            return (set_id, int(parts[2].strip()), int(parts[3].strip()),
                    parts[4].strip())
    return None


def stamp_shares_meta(plaintext, set_id, threshold, count, minted):
    """Replace any existing share row; a vault has at most one live set."""
    rows = [line for line in plaintext.splitlines()
            if line.split("\t", 1)[0] != "META_RECOVERY_SHARES"]
    row = "META_RECOVERY_SHARES\t%s\t%d\t%d\t%s" % (
        set_id.hex().upper(), threshold, count, minted)
    # After the version row, which stamp_version keeps first.
    insert_at = 1 if rows and rows[0].split("\t", 1)[0] == "META_VAULT_VERSION" else 0
    rows.insert(insert_at, row)
    return "\n".join(rows) + ("\n" if plaintext.endswith("\n") else "")


def install_recovery(vault_path, staged):
    target = recovery_path(vault_path)
    os.replace(staged, target)
    os.chmod(target, 0o600)
    _fsync_dir(os.path.dirname(os.path.abspath(target)) or ".")


# ----- reading ---------------------------------------------------------------

def unwrap_key(vault_path, master):
    """The vault key alone, or None when the vault predates the container."""
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        return None
    key = gpg_decrypt(master, parts[0]).decode("utf-8")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return key


def read_vault(vault_path, master):
    """(plaintext, vault_key) for any vault file, whatever format it is in.

    Not only the live vault: .bak files, history snapshots and synced copies
    are the same container, and everything that proves one opens before
    overwriting the live vault has to come through here.

    vault_key is None for formats 1 and 2, which were sealed under the master
    password directly.
    """
    scope = "scope=%s" % _scope_of(vault_path)
    try:
        with open(vault_path, "rb") as handle:
            raw = handle.read()
    except OSError:
        record_event("unlock", "fail", scope + ",reason=missing")
        raise
    try:
        parts = parse_container(raw)
        if parts is None:
            plaintext = gpg_decrypt(master, raw).decode("utf-8", errors="ignore")
            record_event("unlock", "ok", scope)
            return plaintext, None
        key = gpg_decrypt(master, parts[0]).decode("utf-8")
        if not key:
            raise VaultError("vault key envelope decrypted to nothing")
        plaintext = gpg_decrypt(key, parts[1]).decode("utf-8", errors="ignore")
    except Exception:
        # A wrong master password and a damaged file are indistinguishable from
        # here -- gpg refuses both the same way -- so the log says the honest
        # thing rather than guessing which it was.
        record_event("unlock", "fail", scope + ",reason=bad-master")
        raise
    record_event("unlock", "ok", scope)
    return plaintext, key


def read_vault_with_key(vault_path, vault_key):
    """Plaintext from a format-3 vault using a key that is already unwrapped.

    Returns None when the file is not a container -- formats 1 and 2 are sealed
    under the master password directly and have no separate key -- so a caller
    holding a stale key falls back to the master rather than failing.

    A format-3 read is two gpg invocations: one to unwrap the key envelope
    under the master password, one to decrypt the data under that key. The
    envelope is the expensive half and its answer does not change between
    reads, so a caller that can hold the key skips it. Nothing here weakens the
    format: the key is exactly what the master password would have produced.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    parts = parse_container(raw)
    if parts is None:
        return None
    return gpg_decrypt(vault_key, parts[1]).decode("utf-8", errors="ignore")


# ----- writing ---------------------------------------------------------------

def write_vault(vault_path, master, plaintext, vault_key=None):
    """Install `plaintext` as a format-3 vault. Returns the vault key used.

    A write reuses the key the vault already has. Minting a fresh one whenever
    the caller did not supply it would strand every .bak, history snapshot and
    synced copy that the current recovery file can still open, and the whole
    point of a separate vault key is that it survives password changes.

    Migration from formats 1 and 2 is ordered so that no instant is
    unrecoverable. The new recovery file is staged first, before anything is
    encrypted, so a vault whose recovery pubkey is unusable refuses with
    nothing changed. The container is then installed BEFORE the recovery file
    is swapped, with the key envelope sealed under the master password that
    .recovery still names -- which makes the window between the two harmless,
    because the recovered secret still opens the vault as a password. The
    reverse order has no such route.
    """
    vault_dir = os.path.dirname(os.path.abspath(vault_path)) or "."
    vault_name = os.path.basename(vault_path)
    plaintext = stamp_version(plaintext)

    migrating = False
    if vault_key is None and os.path.exists(vault_path):
        vault_key = unwrap_key(vault_path, master)
    if vault_key is None:
        vault_key = new_vault_key()
        migrating = True

    staged_recovery = stage_recovery(vault_path, plaintext, vault_key) if migrating else ""

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="." + vault_name + ".stage.", dir=vault_dir)
    os.close(tmp_fd)
    try:
        os.chmod(tmp_path, 0o600)
        envelope = gpg_encrypt(master, vault_key.encode("utf-8"))
        cipher = gpg_encrypt(vault_key, plaintext.encode("utf-8"))
        with open(tmp_path, "wb") as handle:
            handle.write(build_container(envelope, cipher))

        if os.path.exists(vault_path):
            archive_generation(vault_path)
            shutil.copy2(vault_path, vault_path + ".bak")
            os.chmod(vault_path + ".bak", 0o600)

        # The rename is atomic but not durable on its own: flush the ciphertext
        # first so a crash cannot leave the new name over unwritten blocks.
        _fsync_path(tmp_path)
        os.replace(tmp_path, vault_path)
        tmp_path = ""
        os.chmod(vault_path, 0o600)
        _fsync_dir(vault_dir)

        if staged_recovery:
            # Second, deliberately. A failure here leaves .recovery naming the
            # master password, which still unwraps this container, so it is
            # reported rather than undoing the user's save.
            try:
                install_recovery(vault_path, staged_recovery)
                staged_recovery = ""
            except Exception as exc:
                sys.stderr.write(
                    "warning: the vault was migrated but its recovery file "
                    "still holds the master password (%s)\n" % exc)
        # After os.replace and the fsync, so a recorded write is one that
        # actually reached the disk rather than one that was attempted.
        record_event("write", "ok", "scope=%s,records=%d" % (
            _scope_of(vault_path), _record_count(plaintext)))
        return vault_key
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
        if staged_recovery and os.path.exists(staged_recovery):
            os.remove(staged_recovery)


def rewrap(vault_path, old_master, new_master):
    """Change only the master-password envelope, given the old password."""
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        raise VaultError("vault must be migrated before its key can be rewrapped")
    key = gpg_decrypt(old_master, parts[0]).decode("utf-8")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return rewrap_with_key(vault_path, key, new_master)


def rewrap_with_key(vault_path, vault_key, new_master):
    """Change only the master-password envelope, given the vault key.

    The vault ciphertext stays byte-identical and the recovery file is not
    touched at all, because both key off the vault key, which does not change.
    This is the reason for separating the vault key: a password change stops
    being a re-encryption of everything the user owns.

    Taking the key rather than the old password lets a caller that has just
    read the vault skip an entire gpg invocation, which is the dominant cost
    of any vault operation.
    """
    with open(vault_path, "rb") as handle:
        parts = parse_container(handle.read())
    if parts is None:
        raise VaultError("vault must be migrated before its key can be rewrapped")
    key = vault_key
    updated = build_container(gpg_encrypt(new_master, key.encode("utf-8")), parts[1])

    vault_dir = os.path.dirname(os.path.abspath(vault_path)) or "."
    fd, staged = tempfile.mkstemp(
        prefix="." + os.path.basename(vault_path) + ".rewrap.", dir=vault_dir)
    try:
        os.write(fd, updated)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.chmod(staged, 0o600)
        archive_generation(vault_path)
        shutil.copy2(vault_path, vault_path + ".bak")
        os.chmod(vault_path + ".bak", 0o600)
        os.replace(staged, vault_path)
        staged = ""
        os.chmod(vault_path, 0o600)
        _fsync_dir(vault_dir)
    finally:
        if fd != -1:
            os.close(fd)
        if staged and os.path.exists(staged):
            os.remove(staged)
    record_event("rewrap", "ok", "scope=%s" % _scope_of(vault_path))
    return key


def recover(vault_path, secret, out_path):
    """Open a vault with a secret recovered from the .recovery file.

    What that file holds depends on when it was last written: format 3 stores
    the vault key, the formats before it stored the master password, and a
    vault caught mid-migration is described by neither. Try every reading
    rather than assume -- the master-password route is also what makes the
    migration window recoverable, because the key envelope of a just-migrated
    vault is sealed under exactly the password the stale file still names.

    Returns (vault_key, recovery_is_stale). A stale recovery file recovered
    this vault by luck and will not recover it again once the envelope is
    rewrapped, so the caller must refresh it.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    parts = parse_container(raw)

    if parts is None:
        # Formats 1 and 2: the recovery file can only hold the password.
        write_plaintext(out_path, gpg_decrypt(secret, raw).decode("utf-8", errors="ignore"))
        return None, False

    try:
        plaintext = gpg_decrypt(secret, parts[1]).decode("utf-8", errors="ignore")
        key, stale = secret, False
    except subprocess.CalledProcessError:
        try:
            key = gpg_decrypt(secret, parts[0]).decode("utf-8")
        except subprocess.CalledProcessError:
            raise VaultError("the recovery file does not open this vault")
        if not key:
            raise VaultError("vault key envelope decrypted to nothing")
        plaintext = gpg_decrypt(key, parts[1]).decode("utf-8", errors="ignore")
        stale = True
    write_plaintext(out_path, plaintext)
    return key, stale


# ----- command interface -----------------------------------------------------
# How the shell half reaches the core. Secrets arrive on stdin, one per line,
# never in argv. A master password cannot contain a newline: every prompt that
# collects one reads a single line.

# ----- foreign export formats ------------------------------------------------
# Bitwarden's export is the one people arrive with, and its shape has nothing
# in common with SPM's. Normalising it here rather than in either surface means
# the CLI and the dashboard cannot disagree about what a Bitwarden file means.

# Bitwarden item types. 3 and 4 carry structured data with no SPM equivalent,
# so they become notes rather than being dropped -- an import that silently
# loses a card is worse than one that stores it as text the user can read.
BITWARDEN_LOGIN = 1
BITWARDEN_SECURE_NOTE = 2
BITWARDEN_CARD = 3
BITWARDEN_IDENTITY = 4


def looks_like_bitwarden_json(payload):
    return isinstance(payload, dict) and isinstance(payload.get("items"), list)


def looks_like_bitwarden_csv_header(fieldnames):
    names = {(name or "").strip().lower() for name in (fieldnames or ())}
    return "login_password" in names or "login_username" in names


def _bitwarden_uri(item):
    login = item.get("login") or {}
    for entry in login.get("uris") or []:
        if isinstance(entry, dict) and entry.get("uri"):
            return entry["uri"]
        if isinstance(entry, str) and entry:
            return entry
    return ""


def _bitwarden_structured(item):
    """Card and identity fields rendered as readable lines."""
    for key in ("card", "identity"):
        section = item.get(key)
        if isinstance(section, dict):
            pairs = [(k, v) for k, v in section.items() if v not in (None, "")]
            if pairs:
                return "\n".join("%s: %s" % (k, v) for k, v in sorted(pairs))
    return ""


def _hkdf_expand_sha256(prk, info, length=32):
    """HKDF-Expand, the half Bitwarden uses to split one key into enc and mac."""
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _split_cipher_string(value):
    """(type, iv, ciphertext, mac) from Bitwarden's "2.iv|ct|mac" encoding."""
    text = (value or "").strip()
    if "." not in text:
        raise VaultError("malformed encrypted field in the export")
    kind, _, rest = text.partition(".")
    parts = rest.split("|")
    if kind != "2" or len(parts) != 3:
        raise VaultError(
            "unsupported encryption type %r in the export; SPM reads "
            "AesCbc256_HmacSha256_B64 exports" % kind)
    try:
        return (kind, base64.b64decode(parts[0]),
                base64.b64decode(parts[1]), base64.b64decode(parts[2]))
    except Exception:
        raise VaultError("the encrypted field is not valid base64")


def decrypt_bitwarden_export(payload, password):
    """The plaintext JSON inside a Bitwarden password-protected export.

    Two deliberate refusals rather than approximations:

    Argon2id (kdfType 1) is not derivable here for the same reason SPM does not
    use it for its own vaults -- no stdlib implementation, and no dependency
    this project is willing to take. Such an export is refused by name.

    AES-256-CBC needs a real implementation. `cryptography` is used when it is
    importable and the import is refused when it is not. The alternatives were
    to shell out to `openssl enc -K`, which puts the key in argv where any
    local user can read it and which this module forbids by design, or to
    hand-write AES, which is not something that belongs in a password
    manager's trusted core for the sake of a one-off conversion.
    """
    if not isinstance(payload, dict) or not payload.get("encrypted"):
        raise VaultError("this file is not an encrypted Bitwarden export")

    kdf_type = payload.get("kdfType", 0)
    if kdf_type not in (0, None):
        raise VaultError(
            "this export was protected with Argon2id, which SPM cannot derive. "
            "Re-export from Bitwarden without a password, or export as CSV.")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise VaultError(
            "reading a password-protected export needs the python3 "
            "'cryptography' package, which is not installed. Re-export from "
            "Bitwarden without a password, or install it and try again.")

    salt = (payload.get("salt") or "").encode("utf-8")
    iterations = int(payload.get("kdfIterations") or 600000)
    if not salt:
        raise VaultError("the export carries no salt")

    master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iterations, dklen=32)
    enc_key = _hkdf_expand_sha256(master, b"enc", 32)
    mac_key = _hkdf_expand_sha256(master, b"mac", 32)

    _, iv, ciphertext, mac = _split_cipher_string(payload.get("data"))

    # Authenticate before decrypting, and compare in constant time. A wrong
    # password fails here, which is why it is reported as a wrong password
    # rather than as corrupt data.
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise VaultError("wrong export password, or the file has been altered")

    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    if not padded:
        raise VaultError("the export decrypted to nothing")
    pad = padded[-1]
    if pad < 1 or pad > 16 or padded[-pad:] != bytes([pad]) * pad:
        raise VaultError("the export did not decrypt cleanly")
    return padded[:-pad].decode("utf-8")


def parse_otpauth(value):
    """(secret, period, algorithm) from a TOTP value Bitwarden might store.

    Bitwarden's `totp` field is either a bare base32 secret or a whole
    otpauth:// URI. SPM's authenticator row holds the secret, the period and
    the algorithm in separate fields, so a URI stored verbatim produces an
    authenticator that cannot generate a code -- it would try to base32-decode
    the URI itself.
    """
    text = (value or "").strip()
    if not text:
        return "", "30", "sha1"
    if not text.lower().startswith("otpauth://"):
        return text, "30", "sha1"
    query = urllib.parse.urlparse(text).query
    params = urllib.parse.parse_qs(query)
    secret = (params.get("secret") or [""])[0].strip()
    period = (params.get("period") or ["30"])[0].strip() or "30"
    algorithm = (params.get("algorithm") or ["sha1"])[0].strip().lower() or "sha1"
    if not period.isdigit():
        period = "30"
    if algorithm not in ("sha1", "sha256", "sha512"):
        algorithm = "sha1"
    return secret, period, algorithm


def bitwarden_rows(payload):
    """Bitwarden's JSON export as rows in SPM's import schema.

    Custom fields, folder names and TOTP secrets are carried across rather than
    dropped. A TOTP becomes an authenticator row; everything else Bitwarden
    kept as structure is appended to the notes, because silently losing it
    during a migration is the kind of failure people notice months later.
    """
    rows = []
    folders = {}
    for folder in payload.get("folders") or []:
        if isinstance(folder, dict) and folder.get("id"):
            folders[folder["id"]] = folder.get("name") or ""

    for item in payload.get("items") or []:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or ""
        created = item.get("creationDate") or ""
        extras = []
        for field in item.get("fields") or []:
            if isinstance(field, dict) and field.get("name"):
                extras.append("%s: %s" % (field["name"], field.get("value") or ""))
        structured = _bitwarden_structured(item)
        if structured:
            extras.append(structured)
        folder = folders.get(item.get("folderId") or "", "")
        if folder:
            extras.append("folder: %s" % folder)
        notes = "\n".join([n for n in [item.get("notes") or ""] + extras if n])

        login = item.get("login") or {}
        if item.get("type") == BITWARDEN_LOGIN or login:
            rows.append({"type": "password", "label": name,
                         "username": login.get("username") or "",
                         "secret": login.get("password") or "",
                         "notes": notes, "created": created,
                         "url": _bitwarden_uri(item)})
            secret, period, algorithm = parse_otpauth(login.get("totp"))
            if secret:
                rows.append({"type": "authenticator", "label": name,
                             "secret": secret, "period": period,
                             "algorithm": algorithm, "notes": "",
                             "created": created})
        else:
            rows.append({"type": "note", "label": name, "secret": notes,
                         "notes": "", "created": created})
    return rows


def bitwarden_csv_rows(records):
    """Bitwarden's CSV export as rows in SPM's import schema."""
    rows = []
    for record in records:
        def field(key):
            return (record.get(key) or "").strip()
        name = field("name")
        extras = [v for v in (field("fields"),) if v]
        if field("folder"):
            extras.append("folder: %s" % field("folder"))
        notes = "\n".join([n for n in [record.get("notes") or ""] + extras if n])

        if field("type").lower() == "login" or field("login_password") or field("login_username"):
            rows.append({"type": "password", "label": name,
                         "username": field("login_username"),
                         "secret": record.get("login_password") or "",
                         "notes": notes, "created": "",
                         "url": field("login_uri")})
            secret, period, algorithm = parse_otpauth(field("login_totp"))
            if secret:
                rows.append({"type": "authenticator", "label": name,
                             "secret": secret, "period": period,
                             "algorithm": algorithm, "notes": "",
                             "created": ""})
        else:
            rows.append({"type": "note", "label": name, "secret": notes,
                         "notes": "", "created": ""})
    return rows


# ----- per-record password history -------------------------------------------

# A rotated credential keeps its predecessors, so a bad rotation is recoverable
# without restoring a whole vault generation. Distinct from the vault-level
# snapshots in history_dir(), which capture everything at a point in time; this
# captures one field's past.
HISTORY_TAG = "PWHIST"

# Per record, not per vault. A credential rotated on a schedule would otherwise
# grow without bound inside the vault it is stored in.
HISTORY_KEEP = 10


def _password_rows(plaintext):
    """{id: fields} for password rows, identified the way every surface does."""
    rows = {}
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6 and parts[0].isdigit():
            rows[parts[0]] = parts
    return rows


def record_password_history(old_plaintext, new_plaintext, when=None,
                            keep=HISTORY_KEEP):
    """new_plaintext with a history row for every password that just changed.

    Called at the write boundary rather than at each place that edits a record,
    so a new edit path cannot forget to record history -- the same reasoning
    that makes parse_entries an allowlist.

    Three rules, all of them things a caller would otherwise get wrong:

    - A secret that did not change writes nothing. Saving an unrelated field
      must not manufacture a history entry.
    - An empty previous secret is not history. A record created empty and then
      filled in has no predecessor worth keeping.
    - History for a deleted record is deleted with it. Otherwise removing an
      entry would leave its old passwords in the vault, which is the opposite
      of what deleting it means.
    """
    stamp = when or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    before = _password_rows(old_plaintext)
    after = _password_rows(new_plaintext)

    kept = []
    carried = {}
    for line in new_plaintext.splitlines():
        parts = line.split("\t")
        if parts and parts[0] == HISTORY_TAG and len(parts) >= 4:
            carried.setdefault(parts[1], []).append(parts)
            continue
        kept.append(line)

    for record_id, old_parts in before.items():
        new_parts = after.get(record_id)
        if new_parts is None:
            continue
        old_secret = old_parts[3] if len(old_parts) > 3 else ""
        new_secret = new_parts[3] if len(new_parts) > 3 else ""
        if not old_secret or old_secret == new_secret:
            continue
        carried.setdefault(record_id, []).append([
            HISTORY_TAG, record_id,
            base64.b64encode(old_secret.encode("utf-8")).decode("ascii"),
            stamp, "-", "-",
        ])

    lines = [line for line in kept if line != ""]
    for record_id in sorted(carried, key=lambda v: (len(v), v)):
        if record_id not in after:
            # The record is gone; its history goes with it.
            continue
        entries = carried[record_id][-keep:]
        for parts in entries:
            lines.append("\t".join(parts))
    return "\n".join(lines) + "\n"


def password_history(plaintext, record_id):
    """[(when, secret)] oldest first, for one record."""
    out = []
    for line in plaintext.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == HISTORY_TAG and parts[1] == record_id:
            try:
                secret = base64.b64decode(parts[2]).decode("utf-8", errors="replace")
            except Exception:
                continue
            out.append((parts[3], secret))
    return out


# ----- local security and opt-in breach review ------------------------------

PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def _password_security_rows(plaintext):
    """Password rows and malformed authenticators, with no secret in output."""
    rows, malformed = [], []
    for line in plaintext.splitlines():
        if not line or line.startswith("#") or line.startswith("META_"):
            continue
        parts = line.split("\t")
        if len(parts) >= 6 and parts[0].isdigit():
            rows.append(parts)
        elif parts[0] == "AUTH" and (
                len(parts) < 7 or parts[6] not in ("sha1", "sha256", "sha512")
                or not parts[3]):
            malformed.append(parts[1] if len(parts) > 1 else "?")
    return rows, malformed


def _pwned_range(prefix, timeout=5, opener=None):
    """Suffix -> breach count for one HIBP range response.

    Only a five-character SHA-1 prefix reaches the service. Add-Padding asks
    for dummy rows so response size does not reveal how many real suffixes the
    range contains. The caller has already made an explicit opt-in decision.
    """
    if not re.fullmatch(r"[0-9A-F]{5}", prefix):
        raise VaultError("invalid breach-check prefix")
    request = urllib.request.Request(
        PWNED_PASSWORDS_RANGE_URL + prefix,
        headers={"Add-Padding": "true", "User-Agent": "Sans-Password-Manager"})
    open_url = opener or urllib.request.urlopen
    try:
        response = open_url(request, timeout=timeout)
        try:
            payload = response.read().decode("ascii", errors="strict")
        finally:
            close = getattr(response, "close", None)
            if close:
                close()
    except Exception as exc:
        raise VaultError("breach service unavailable") from exc
    found = {}
    for line in payload.splitlines():
        suffix, separator, raw_count = line.partition(":")
        suffix = suffix.strip().upper()
        raw_count = raw_count.strip()
        if (separator and re.fullmatch(r"[0-9A-F]{35}", suffix)
                and raw_count.isdigit()):
            found[suffix] = int(raw_count)
    if not found:
        raise VaultError("invalid breach-service response")
    return found


def breached_password_ids(rows, timeout=5, opener=None):
    """[{id, count}] for passwords present in Pwned Passwords.

    Full hashes remain in memory on this device and are never returned. One
    request is made per unique five-character prefix, not per record.
    """
    by_prefix = {}
    for parts in rows:
        secret = parts[3] if len(parts) > 3 else ""
        if not secret:
            continue
        try:
            digest = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()
        except Exception as exc:
            raise VaultError("breach hashing unavailable") from exc
        by_prefix.setdefault(digest[:5], []).append((parts[0], digest[5:]))
    breached = []
    prefixes = sorted(by_prefix)
    if not prefixes:
        return breached
    # A slow service must not cost one full timeout per password, but the
    # client also must not turn a large vault into unbounded request fan-out.
    workers = min(4, len(prefixes))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        ranges = pool.map(
            lambda prefix: _pwned_range(prefix, timeout=timeout, opener=opener),
            prefixes)
        fetched = dict(zip(prefixes, ranges))
    for prefix in prefixes:
        suffixes = fetched[prefix]
        for record_id, suffix in by_prefix[prefix]:
            count = suffixes.get(suffix, 0)
            if count:
                breached.append({"id": record_id, "count": count})
    return breached


def security_report(plaintext, rotation_days=365, check_breaches=False,
                    timeout=5, opener=None):
    """One secret-free security report shared by CLI and Dashboard."""
    rows, malformed = _password_security_rows(plaintext)
    now = time.time()
    seen = {}
    weak, old, incomplete = [], [], []
    for parts in rows:
        record_id = parts[0]
        secret = parts[3] if len(parts) > 3 else ""
        seen.setdefault(secret, []).append(record_id)
        classes = sum(bool(re.search(pattern, secret)) for pattern in
                      (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
        if len(secret) < 12 or classes < 3:
            weak.append(record_id)
        if not parts[1] or not parts[2]:
            incomplete.append(record_id)
        try:
            stamp = time.mktime(time.strptime(
                parts[5].replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
            if (now - stamp) / 86400.0 > rotation_days:
                old.append(record_id)
        except (IndexError, ValueError, OverflowError):
            pass
    reused = [ids for secret, ids in seen.items() if secret and len(ids) > 1]
    reused_flat = [record_id for ids in reused for record_id in ids]
    penalty = min(100, len(weak) * 12 + len(reused_flat) * 10
                  + len(old) * 4 + len(incomplete) * 3 + len(malformed) * 8)
    report = {
        "score": max(0, 100 - penalty), "passwords": len(rows),
        "weak": weak, "reused": reused, "reused_flat": reused_flat,
        "old": old, "incomplete": incomplete, "malformed": malformed,
        "rotation_days": rotation_days, "breach_status": "not_checked",
        "breached": [],
    }
    if check_breaches:
        try:
            report["breached"] = breached_password_ids(
                rows, timeout=timeout, opener=opener)
            report["breach_status"] = "checked"
        except VaultError:
            report["breach_status"] = "unavailable"
    return report


# ----- diagnostics -----------------------------------------------------------

# Characters that splitlines() honours but a TAB-delimited, line-based record
# format does not survive. A value carrying one of these was written as a
# single record and reads back as two, so the tail becomes an orphan fragment
# that no surface displays. See the 2.10.12 sanitiser, which stops new ones.
RECORD_BREAKS = {
    "\v": "U+000B VERTICAL TAB",
    "\f": "U+000C FORM FEED",
    "\x1c": "U+001C FILE SEPARATOR",
    "\x1d": "U+001D GROUP SEPARATOR",
    "\x1e": "U+001E RECORD SEPARATOR",
    "\x85": "U+0085 NEXT LINE",
    "\u2028": "U+2028 LINE SEPARATOR",
    "\u2029": "U+2029 PARAGRAPH SEPARATOR",
}

# Field 3 holds the secret in every record shape SPM writes, so nothing here
# ever reads it. Only type, id and label are reported.
_RECORD_TAGS = {"NOTE": "NOTE", "PASSPHRASE": "PASSPHRASE",
                "BACKUP_CODE": "BACKUP_CODE", "AUTH": "AUTHENTICATOR"}


def _describe_record(line):
    parts = line.split("\t")
    tag = parts[0] if parts else ""
    if tag in _RECORD_TAGS:
        return (_RECORD_TAGS[tag],
                parts[1] if len(parts) > 1 else "?",
                parts[2] if len(parts) > 2 else "")
    if tag.isdigit():
        return "PASSWORD", tag, (parts[1] if len(parts) > 1 else "")
    return tag or "(unknown)", "?", ""


def _safe_text(text, limit=32):
    """A label rendered for a terminal: no raw control characters, ever."""
    out = []
    for ch in text:
        if ch in RECORD_BREAKS or ch == "\t":
            out.append("\u2423")
        elif unicodedata.category(ch).startswith("C"):
            out.append("?")
        else:
            out.append(ch)
    shown = "".join(out)
    return shown[:limit] + ("..." if len(shown) > limit else "")


def scan_broken_records(plaintext):
    """(broken, orphans) for records split by an embedded line break.

    Split on "\n" only, because that is how the record was physically written.
    """
    broken, orphans = [], []
    for number, line in enumerate(plaintext.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        hits = [name for ch, name in RECORD_BREAKS.items() if ch in line]
        if hits:
            kind, rid, label = _describe_record(line)
            broken.append((number, kind, rid, _safe_text(label), hits))
            continue
        if line.startswith("META_"):
            continue
        if len(line.split("\t")) < 5:
            orphans.append((number, _safe_text(line, 48)))
    return broken, orphans


def vault_counts(plaintext):
    """Record counts, duplicate password ids and empty password fields."""
    counts = {"passwords": 0, "notes": 0, "passphrases": 0,
              "backup_codes": 0, "authenticators": 0}
    by_tag = {"NOTE": "notes", "PASSPHRASE": "passphrases",
              "BACKUP_CODE": "backup_codes", "AUTH": "authenticators"}
    seen, duplicates, empty = {}, [], 0
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag in by_tag:
            counts[by_tag[tag]] += 1
        elif tag.isdigit():
            counts["passwords"] += 1
            seen[tag] = seen.get(tag, 0) + 1
            if len(parts) > 3 and not parts[3]:
                empty += 1
    duplicates = sorted((rid for rid, n in seen.items() if n > 1), key=int)
    return counts, duplicates, empty


def _check(identifier, status, summary, **extra):
    entry = {"id": identifier, "status": status, "summary": summary}
    entry.update(extra)
    return entry


def doctor_report(plaintext, vault_path, recovery_status="unchecked",
                  sensitive_files=()):
    """A machine-readable health report. Never contains a secret.

    Structured as a list of checks with stable ids rather than a bag of
    booleans, so a caller can act on one without parsing prose, and so a check
    added later does not change the shape of the ones already there.
    """
    checks = []
    counts, duplicates, empty = vault_counts(plaintext)

    if duplicates:
        checks.append(_check("duplicate_ids", "fail",
                             "%d password id(s) appear more than once" % len(duplicates),
                             ids=duplicates))
    else:
        checks.append(_check("duplicate_ids", "ok", "no duplicate password ids"))

    if empty:
        checks.append(_check("empty_passwords", "warn",
                             "%d entr(y/ies) have an empty password field" % empty,
                             count=empty))
    else:
        checks.append(_check("empty_passwords", "ok", "no empty password fields"))

    broken, orphans = scan_broken_records(plaintext)
    if broken or orphans:
        checks.append(_check(
            "split_records", "fail",
            "%d record(s) contain a line-break character; %d orphan fragment(s)"
            % (len(broken), len(orphans)),
            broken=[{"line": n, "kind": k, "id": i, "label": l, "characters": h}
                    for n, k, i, l, h in broken],
            orphans=[{"line": n, "text": t} for n, t in orphans]))
    else:
        checks.append(_check("split_records", "ok",
                             "no records split by a line-break character"))

    found = format_version(plaintext)
    if found >= VAULT_FORMAT_VERSION:
        checks.append(_check("vault_format", "ok",
                             "format version %d is current" % found,
                             found=found, current=VAULT_FORMAT_VERSION))
    else:
        checks.append(_check(
            "vault_format", "warn",
            "format version %d; %d is available and the next write upgrades in place"
            % (found, VAULT_FORMAT_VERSION),
            found=found, current=VAULT_FORMAT_VERSION))

    try:
        recovery_pubkey_pem(plaintext)
        checks.append(_check("recovery_pubkey", "ok",
                             "recovery public key present and decodable"))
    except VaultError as exc:
        checks.append(_check("recovery_pubkey", "fail", str(exc)))

    pairing = {
        "match-current": ("ok", "recovery file holds this vault's current key"),
        "match-legacy": ("ok", "recovery file decrypts; this format predates vault keys"),
        "match-stale": ("fail", "recovery file does not hold this vault's key; "
                                "run change-master to refresh it"),
        "mismatch": ("fail", "private key does not match the recovery file"),
        "no-private-key": ("fail", "no default private key found"),
        "no-recovery-file": ("fail", "no recovery file found"),
        "unchecked": ("warn", "recovery pairing was not checked"),
    }
    status, summary = pairing.get(recovery_status,
                                  ("warn", "unrecognised recovery state"))
    checks.append(_check("recovery_pairing", status, summary, state=recovery_status))

    # Split recovery is optional, so its absence is not a defect on its own.
    # The combination is: a vault whose recovery file or private key is gone
    # AND which records no share set has no way back at all, and neither check
    # can see that alone.
    shares = shares_meta(plaintext)
    if shares:
        set_id, threshold, count, minted = shares
        checks.append(_check(
            "split_recovery", "ok",
            "%d of %d shares recorded, set %s" % (
                threshold, count, set_id.hex().upper()),
            state="set", threshold=threshold, shares=count,
            set_id=set_id.hex().upper(), minted=minted))
    elif status == "fail":
        checks.append(_check(
            "split_recovery", "fail",
            "no share set and no usable recovery file: this vault has no "
            "recovery path left",
            state="none"))
    else:
        checks.append(_check(
            "split_recovery", "ok",
            "no share set recorded; recovery rests on the recovery file",
            state="none"))

    exposed = []
    for path in sensitive_files:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            continue
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            exposed.append({"path": path, "mode": "%03o" % mode})
    if exposed:
        checks.append(_check("file_permissions", "fail",
                             "%d sensitive file(s) readable by other users" % len(exposed),
                             files=exposed))
    else:
        checks.append(_check("file_permissions", "ok",
                             "sensitive files are not group- or world-accessible"))

    failed = sum(1 for c in checks if c["status"] == "fail")
    warned = sum(1 for c in checks if c["status"] == "warn")
    return {
        "schema": 1,
        "vault": {"path": vault_path,
                  "format_version": found,
                  "current_format_version": VAULT_FORMAT_VERSION},
        "counts": counts,
        "checks": checks,
        "summary": {"failed": failed, "warned": warned,
                    "status": "fail" if failed else ("warn" if warned else "ok")},
    }


def _secrets(count):
    data = sys.stdin.buffer.read().decode("utf-8")
    fields = data.split("\n")
    if len(fields) < count:
        raise VaultError("expected %d secret(s) on stdin" % count)
    return fields[:count]


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: spm_core.py <command> [args]\n")
        return 2
    command = argv[1]
    try:
        if command == "read":
            # read <vault> <out> ; stdin: master ; stdout: vault key (may be empty)
            vault, out = argv[2], argv[3]
            (master,) = _secrets(1)
            plaintext, key = read_vault(vault, master)
            write_plaintext(out, plaintext)
            sys.stdout.write(key or "")
        elif command == "write":
            # write <vault> <plainfile> ; stdin: master[\nvault key]
            vault, source = argv[2], argv[3]
            fields = sys.stdin.buffer.read().decode("utf-8").split("\n")
            master = fields[0]
            key = fields[1] if len(fields) > 1 and fields[1] else None
            with open(source, "r", encoding="utf-8") as handle:
                plaintext = handle.read()
            sys.stdout.write(write_vault(vault, master, plaintext, key))
        elif command == "rewrap":
            # rewrap <vault> ; stdin: old master\nnew master
            old, new = _secrets(2)
            rewrap(argv[2], old, new)
        elif command == "rewrap-key":
            # rewrap-key <vault> ; stdin: vault key\nnew master
            key, new = _secrets(2)
            if not key:
                raise VaultError("a vault key is required")
            rewrap_with_key(argv[2], key, new)
        elif command == "shares-split":
            # shares-split <vault> <threshold> <count> ; stdin: master
            # stdout: set id, then one share per line
            vault = argv[2]
            threshold, count = int(argv[3]), int(argv[4])
            (master,) = _secrets(1)
            plaintext, key = read_vault(vault, master)
            if not key:
                raise VaultError(
                    "this vault predates the key container and has no vault "
                    "key to split; open and save it once to migrate it")
            set_id = os.urandom(SHARE_SET_BYTES)
            minted = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            parts = split_secret(key.encode("utf-8"), threshold, count)
            # The vault records that a set exists before the shares are shown.
            # A crash between the two leaves a recorded set nobody holds, which
            # `shares status` reports and a re-split replaces; the reverse
            # order would leave live shares the vault never mentions.
            write_vault(vault, master,
                        stamp_shares_meta(plaintext, set_id, threshold, count,
                                          minted),
                        key)
            sys.stdout.write("%s\n" % set_id.hex().upper())
            for index, payload in parts:
                sys.stdout.write("%s\n" % encode_share(
                    threshold, index, set_id, payload))
        elif command == "shares-combine":
            # shares-combine <vault> ; stdin: one share per line
            # stdout: the vault key, once it has been shown to open the vault
            vault = argv[2]
            lines = [line.strip() for line
                     in sys.stdin.buffer.read().decode("utf-8").splitlines()]
            decoded = [decode_share(line) for line in lines if line]
            if not decoded:
                raise VaultError("no shares were given")
            thresholds = {threshold for threshold, _, _, _ in decoded}
            sets = {set_id for _, _, set_id, _ in decoded}
            if len(sets) != 1:
                raise VaultError(
                    "these shares come from %d different sets; every share "
                    "must carry the same set identifier" % len(sets))
            if len(thresholds) != 1:
                raise VaultError("these shares disagree about the threshold")
            threshold = thresholds.pop()
            set_id = sets.pop()
            seen = {index for _, index, _, _ in decoded}
            if len(seen) != len(decoded):
                raise VaultError("the same share was given more than once")
            if len(decoded) < threshold:
                raise VaultError(
                    "%d share(s) given; this set needs %d"
                    % (len(decoded), threshold))
            secret = combine_shares(
                [(index, payload) for _, index, _, payload in decoded])
            # Reconstruction always produces *something*. Proving it is the
            # right something means opening the vault with it -- the share
            # format deliberately carries no digest of the secret to check
            # against, because that digest would be the one thing an attacker
            # holding threshold-1 shares could attack offline.
            try:
                key = secret.decode("utf-8")
            except UnicodeDecodeError:
                raise VaultError(
                    "these shares did not reconstruct a usable key; one of "
                    "them is probably from a different set")
            with open(vault, "rb") as handle:
                container = parse_container(handle.read())
            if container is None:
                raise VaultError("this vault predates the key container")
            try:
                gpg_decrypt(key, container[1])
            except subprocess.CalledProcessError:
                raise VaultError(
                    "these shares reconstructed a key that does not open this "
                    "vault; check that every share belongs to set %s"
                    % set_id.hex().upper())
            sys.stdout.write(key)
        elif command == "shares-status":
            # shares-status <vault> ; stdin: master ; stdout: tsv or nothing
            (master,) = _secrets(1)
            plaintext, _ = read_vault(argv[2], master)
            meta = shares_meta(plaintext)
            if meta:
                set_id, threshold, count, minted = meta
                sys.stdout.write("%s\t%d\t%d\t%s\n"
                                 % (set_id.hex().upper(), threshold, count,
                                    minted))
        elif command == "recover":
            # recover <vault> <out> ; stdin: recovered secret
            # stdout: "<vault key>\n<1 if the recovery file is stale else 0>"
            (secret,) = _secrets(1)
            key, stale = recover(argv[2], secret, argv[3])
            sys.stdout.write("%s\n%d\n" % (key or "", 1 if stale else 0))
        elif command == "unwrap":
            # unwrap <vault> ; stdin: master ; stdout: vault key
            (master,) = _secrets(1)
            sys.stdout.write(unwrap_key(argv[2], master) or "")
        elif command == "is-container":
            with open(argv[2], "rb") as handle:
                return 0 if is_container(handle.read(len(CONTAINER_MAGIC) + 1)) else 1
        elif command == "format-version":
            with open(argv[2], "r", encoding="utf-8", errors="ignore") as handle:
                sys.stdout.write("%d\n" % format_version(handle.read()))
        elif command == "stamp-version":
            with open(argv[2], "r", encoding="utf-8") as handle:
                stamped = stamp_version(handle.read())
            with open(argv[3], "w", encoding="utf-8") as handle:
                handle.write(stamped)
        elif command == "write-recovery":
            # write-recovery <vault> <plainfile> ; stdin: vault key
            (key,) = _secrets(1)
            with open(argv[3], "r", encoding="utf-8") as handle:
                plaintext = handle.read()
            install_recovery(argv[2], stage_recovery(argv[2], plaintext, key))
        elif command == "attrs-encode":
            # attrs-encode <folder> ; stdin: name\tvalue per line
            # stdout: the attributes column
            rows = []
            for line in sys.stdin.read().splitlines():
                if not line.strip():
                    continue
                name, _, value = line.partition("\t")
                rows.append((name, value))
            sys.stdout.write(encode_attrs(argv[2] if len(argv) > 2 else "", rows))
        elif command == "attrs-decode":
            # attrs-decode <column> ; stdout: one JSON document
            folder, fields = decode_attrs(argv[2] if len(argv) > 2 else "")
            sys.stdout.write(json.dumps(
                {"folder": folder,
                 "fields": [{"name": n, "value": v} for n, v in fields]}) + "\n")
        elif command == "folders":
            # folders <plainfile> ; stdout: one folder per line
            with open(argv[2], "r", encoding="utf-8", errors="ignore") as handle:
                for name in record_folders(handle.read()):
                    sys.stdout.write(name + "\n")
        elif command == "security-report":
            # security-report <plainfile> [rotation-days] [--breaches]
            # stdout is secret-free JSON; breach checking is explicit opt-in.
            days = int(argv[3]) if len(argv) > 3 and argv[3] else 365
            check_breaches = "--breaches" in argv[4:]
            with open(argv[2], "r", encoding="utf-8", errors="replace") as handle:
                report = security_report(handle.read(), days, check_breaches)
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
        elif command == "events":
            # events <vault> [limit] ; stdout: one JSON document
            limit = int(argv[3]) if len(argv) > 3 and argv[3] else 0
            sys.stdout.write(json.dumps(
                {"events": read_events(argv[2], limit)}, indent=2) + "\n")
        elif command == "events-path":
            sys.stdout.write(events_path(argv[2]) + "\n")
        elif command == "scope-id":
            sys.stdout.write(vault_scope_id(argv[2]))
        elif command == "current-version":
            sys.stdout.write("%d\n" % VAULT_FORMAT_VERSION)
        elif command == "history-dir":
            sys.stdout.write(history_dir(argv[2]) + "\n")
        elif command == "archive":
            archive_generation(argv[2])
        elif command == "record-history":
            # record-history <previous plainfile> <new plainfile> <out>
            # Writes <new> plus a history row for every password that changed.
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                previous = handle.read()
            with open(argv[3], "r", encoding="utf-8", errors="surrogateescape") as handle:
                current = handle.read()
            write_plaintext(argv[4], record_password_history(previous, current))
        elif command == "password-history":
            # password-history <plainfile> <record id> ; stdout: TSV of when/secret
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                plaintext = handle.read()
            for when, secret in password_history(plaintext, argv[3]):
                sys.stdout.write("%s\t%s\n" % (when, secret))
        elif command == "scan-records":
            # scan-records <plainfile> ; stdout: the TSV the CLI's doctor renders
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                broken, orphans = scan_broken_records(handle.read())
            for number, kind, rid, label, hits in broken:
                sys.stdout.write("BROKEN\t%d\t%s\t%s\t%s\t%s\n"
                                 % (number, kind, rid, label, "; ".join(hits)))
            for number, text in orphans:
                sys.stdout.write("ORPHAN\t%d\t%s\n" % (number, text))
            sys.stdout.write("SUMMARY\t%d\t%d\n" % (len(broken), len(orphans)))
        elif command == "doctor-report":
            # doctor-report <plainfile> <vault> <recovery state> [sensitive file ...]
            # stdout: JSON. Exit 1 when any check failed, so a script can gate
            # on the status without parsing the document.
            with open(argv[2], "r", encoding="utf-8", errors="surrogateescape") as handle:
                plaintext = handle.read()
            report = doctor_report(plaintext, argv[3], argv[4], argv[5:])
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
            return 1 if report["summary"]["failed"] else 0
        elif command == "self-test":
            return 0
        else:
            sys.stderr.write("unknown command: %s\n" % command)
            return 2
    except VaultError as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    except subprocess.CalledProcessError:
        sys.stderr.write("gpg refused the supplied secret\n")
        return 1
    except (OSError, IndexError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

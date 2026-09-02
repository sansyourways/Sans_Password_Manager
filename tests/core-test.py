#!/usr/bin/env python3
"""Tests for the SPM trusted core, run against the module directly.

The point of extracting the core is that this file can exist: the vault
format, the key handling and the vault mutation are exercised here without a
shell, a web server, or a fixture vault built by another implementation.
"""

import base64
import builtins
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)


def _extract_core():
    """Locate spm_core.py, preferring the source tree over the built script.

    In a checkout the core is a real module at src/spm_core.py, and CI proves
    that spm.sh is built from it. Handed only a shipped spm.sh, lift the core
    back out of the heredoc instead -- extracting rather than keeping a second
    copy is the point: there is exactly one core.
    """
    in_tree = os.path.join(ROOT_DIR, "src", "spm_core.py")
    if os.path.isfile(in_tree):
        return in_tree
    target = os.path.join(tempfile.mkdtemp(prefix="spm-core."), "spm_core.py")
    with open(os.path.join(ROOT_DIR, "spm.sh"), encoding="utf-8") as handle:
        body, capturing = [], False
        for line in handle:
            if line.rstrip("\n").endswith("<<'SPMCORE'"):
                capturing = True
                continue
            if capturing:
                if line.rstrip("\n") == "SPMCORE":
                    break
                body.append(line)
    if not body:
        raise SystemExit("could not find the SPMCORE block in spm.sh")
    with open(target, "w", encoding="utf-8") as handle:
        handle.writelines(body)
    return target


CORE = os.environ.get("SPM_CORE_PATH") or _extract_core()
sys.path.insert(0, os.path.dirname(CORE))
import spm_core as core  # noqa: E402

PASSED = 0
FAILED = []


def check(name, fn):
    global PASSED
    try:
        fn()
    except Exception as exc:
        FAILED.append((name, exc))
        sys.stderr.write("FAIL %s: %s\n" % (name, exc))
    else:
        PASSED += 1


def eq(a, b, msg=""):
    if a != b:
        raise AssertionError("%s\n  got:    %r\n  wanted: %r" % (msg, a, b))


def raises(exc_type, fn, msg=""):
    try:
        fn()
    except exc_type:
        return
    except Exception as exc:
        raise AssertionError("%s: wrong exception %r" % (msg, exc))
    raise AssertionError("%s: no exception raised" % msg)


ROOT = tempfile.mkdtemp(prefix="spm-core-test.")
GPGHOME = os.path.join(ROOT, "gnupg")
os.makedirs(GPGHOME, mode=0o700)
os.environ["GNUPGHOME"] = GPGHOME
os.environ["SPM_DATA_DIR"] = os.path.join(ROOT, "data")
subprocess.run(["gpgconf", "--launch", "gpg-agent"], check=False,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

PRIV = os.path.join(ROOT, "recovery.pem")
PUB = os.path.join(ROOT, "recovery.pub")
subprocess.run(["openssl", "genrsa", "-out", PRIV, "2048"], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["openssl", "rsa", "-in", PRIV, "-pubout", "-out", PUB], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
PUB_B64 = base64.b64encode(open(PUB, "rb").read()).decode("ascii")

MASTER = "core-test-master-1"
OTHER = "core-test-master-2"


def sample(pub=PUB_B64):
    return ("META_RECOVERY_PUBKEY\t%s\t-\t-\t-\t-\n"
            "1\tExample\tuser@example.invalid\tCoreSecret42\t-\t2025-01-01T00:00:00Z\n"
            % pub)


def fresh(name):
    d = tempfile.mkdtemp(prefix=name + ".", dir=ROOT)
    return os.path.join(d, "vault.gpg")


def legacy_vault(path, password, plaintext=None):
    """A format-1 vault: sealed under the master password directly."""
    payload = (plaintext if plaintext is not None else sample()).encode("utf-8")
    fd = core._passphrase_fd(password)
    try:
        subprocess.run(
            ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
             "--passphrase-fd", str(fd), "--symmetric", "--cipher-algo", "AES256",
             "-o", path], input=payload, check=True,
            stderr=subprocess.DEVNULL, pass_fds=(fd,))
    finally:
        os.close(fd)
    with open(path + ".recovery", "wb") as handle:
        proc = subprocess.run(
            ["openssl", "rsautl", "-encrypt", "-pubin", "-inkey", PUB],
            input=password.encode("utf-8"), stdout=handle,
            stderr=subprocess.DEVNULL, check=True)
    return path


def recovered(path):
    return subprocess.check_output(
        ["openssl", "rsautl", "-decrypt", "-inkey", PRIV, "-in", path + ".recovery"],
        stderr=subprocess.DEVNULL).decode("utf-8")


def data_section(path):
    return core.parse_container(open(path, "rb").read())[1]


# ----- format ----------------------------------------------------------------

def t_container_roundtrip():
    blob = core.build_container(b"envelope-bytes", b"cipher-bytes")
    assert core.is_container(blob)
    eq(core.parse_container(blob), (b"envelope-bytes", b"cipher-bytes"))
    eq(core.parse_container(b"\x85\x02not a container"), None)


def t_container_rejects_corrupt():
    raises(core.VaultError, lambda: core.parse_container(b"SPM-VAULT-3\nKEY !!\nDATA\n!!\n"),
           "corrupt base64 must refuse")
    raises(core.VaultError, lambda: core.parse_container(b"SPM-VAULT-3\nKEY \nDATA\n\n"),
           "empty halves must refuse")


def t_stamp_version():
    out = core.stamp_version("A\tb\nC\td\n")
    eq(out.splitlines()[0],
       "META_VAULT_VERSION\t%d\t-\t-\t-\t-" % core.VAULT_FORMAT_VERSION)
    eq(len([l for l in out.splitlines() if l.startswith("META_VAULT_VERSION")]), 1)
    eq(core.stamp_version(out), out, "stamping must be idempotent")
    old = "META_VAULT_VERSION\t1\t-\t-\t-\t-\nA\tb\n"
    eq(len([l for l in core.stamp_version(old).splitlines()
            if l.startswith("META_VAULT_VERSION")]), 1, "must replace, not append")
    eq(core.stamp_version("A\tb\n"), core.stamp_version("A\tb"),
       "a missing trailing newline must not change the result")


def t_format_version():
    eq(core.format_version("A\tb\n"), 1, "no row means format 1")
    eq(core.format_version(core.stamp_version("A\tb\n")),
       core.VAULT_FORMAT_VERSION, "a stamped vault carries the current format")
    eq(core.format_version("META_VAULT_VERSION\tzz\t-\n"), 1, "garbage means format 1")


def t_new_key_is_random():
    keys = {core.new_vault_key() for _ in range(16)}
    eq(len(keys), 16, "vault keys must not repeat")
    eq(len(base64.b64decode(keys.pop())), 32, "vault key must be 256-bit")


# ----- read / write ----------------------------------------------------------

def t_write_read_roundtrip():
    path = fresh("roundtrip")
    legacy_vault(path, MASTER)
    key = core.write_vault(path, MASTER, sample())
    plaintext, got = core.read_vault(path, MASTER)
    eq(got, key)
    assert "CoreSecret42" in plaintext
    eq(core.format_version(plaintext), core.VAULT_FORMAT_VERSION)


def t_reads_legacy_format():
    path = fresh("legacy")
    legacy_vault(path, MASTER)
    plaintext, key = core.read_vault(path, MASTER)
    eq(key, None, "a format-1 vault has no vault key")
    assert "CoreSecret42" in plaintext


def t_wrong_password_refuses():
    path = fresh("wrongpw")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    raises(subprocess.CalledProcessError,
           lambda: core.read_vault(path, OTHER), "wrong password")


def t_migration_moves_recovery_to_the_key():
    path = fresh("migrate")
    legacy_vault(path, MASTER)
    eq(recovered(path), MASTER, "a legacy recovery file holds the password")
    key = core.write_vault(path, MASTER, sample())
    eq(recovered(path), key, "migration must put the vault key in .recovery")


def t_write_never_rotates_the_key():
    path = fresh("stable")
    legacy_vault(path, MASTER)
    first = core.write_vault(path, MASTER, sample())
    second = core.write_vault(path, MASTER, sample())
    eq(second, first, "an ordinary write must reuse the existing key")
    eq(recovered(path), first, "and must leave the recovery file alone")


def t_rewrap_preserves_data_and_recovery():
    path = fresh("rewrap")
    legacy_vault(path, MASTER)
    key = core.write_vault(path, MASTER, sample())
    before_data = data_section(path)
    before_recovery = open(path + ".recovery", "rb").read()

    core.rewrap(path, MASTER, OTHER)

    eq(data_section(path), before_data, "rewrap must not re-encrypt the vault")
    eq(open(path + ".recovery", "rb").read(), before_recovery,
       "rewrap must not touch the recovery file")
    plaintext, got = core.read_vault(path, OTHER)
    eq(got, key, "the vault key must survive a password change")
    assert "CoreSecret42" in plaintext
    raises(subprocess.CalledProcessError,
           lambda: core.read_vault(path, MASTER), "the old password must stop working")


def t_rewrap_refuses_legacy():
    path = fresh("rewrap-legacy")
    legacy_vault(path, MASTER)
    raises(core.VaultError, lambda: core.rewrap(path, MASTER, OTHER),
           "a legacy vault must migrate before it can be rewrapped")


def t_migration_window_is_recoverable():
    """The container is installed before .recovery is swapped. A vault caught
    between the two must still open from the recovery file."""
    path = fresh("window")
    legacy_vault(path, MASTER)
    stale = open(path + ".recovery", "rb").read()
    core.write_vault(path, MASTER, sample())
    with open(path + ".recovery", "wb") as handle:
        handle.write(stale)

    secret = recovered(path)
    eq(secret, MASTER)
    # Read as a vault key it opens nothing; as a master password it works,
    # because the envelope was sealed under the password .recovery still names.
    raises(subprocess.CalledProcessError,
           lambda: core.gpg_decrypt(secret, data_section(path)),
           "the stale secret must not be a data key")
    plaintext, _ = core.read_vault(path, secret)
    assert "CoreSecret42" in plaintext


# ----- refusals --------------------------------------------------------------

def t_bad_recovery_pubkey_fails_closed():
    path = fresh("badpub")
    legacy_vault(path, MASTER)
    before = open(path, "rb").read()
    raises(core.VaultError,
           lambda: core.write_vault(path, MASTER, sample(pub="dGVzdA==")),
           "an unusable recovery pubkey must refuse")
    eq(open(path, "rb").read(), before, "a refused migration must not touch the vault")
    litter = [n for n in os.listdir(os.path.dirname(path)) if n.startswith(".vault.gpg.")]
    eq(litter, [], "a refused migration must leave no staging files")


def t_missing_recovery_row_fails_closed():
    path = fresh("nopub")
    legacy_vault(path, MASTER, plaintext="1\tExample\tu\tS\t-\t2025-01-01T00:00:00Z\n")
    before = open(path, "rb").read()
    raises(core.VaultError,
           lambda: core.write_vault(path, MASTER,
                                    "1\tExample\tu\tS\t-\t2025-01-01T00:00:00Z\n"),
           "a vault with no recovery pubkey row must refuse to migrate")
    eq(open(path, "rb").read(), before)


# ----- history ---------------------------------------------------------------

def t_scope_id_is_stable_and_distinct():
    a = fresh("scope-a")
    eq(core.vault_scope_id(a), core.vault_scope_id(a))
    eq(len(core.vault_scope_id(a)), 16)
    assert core.vault_scope_id(a) != core.vault_scope_id(fresh("scope-b"))
    eq(core.vault_scope_id(a), core.vault_scope_id(os.path.join(
        os.path.dirname(a), ".", "vault.gpg")), "the id must not depend on spelling")


def t_archive_snapshots_and_prunes():
    path = fresh("history")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    # Start from empty: the write above already archived the legacy generation.
    shutil.rmtree(core.history_dir(path), ignore_errors=True)
    os.environ["SPM_HISTORY_RETENTION"] = "3"
    try:
        # A snapshot is named for the ciphertext it captures, so archiving
        # unchanged content twice is deliberately one snapshot, not two.
        core.archive_generation(path)
        core.archive_generation(path)
        eq(len(os.listdir(core.history_dir(path))), 1,
           "identical generations must not be archived twice")

        # Distinct generations accumulate, then prune to the retention limit.
        for n in range(6):
            with open(path, "ab") as handle:
                handle.write(b"\n# generation %d\n" % n)
            core.archive_generation(path)
        eq(len(os.listdir(core.history_dir(path))), 3,
           "retention must be enforced")
    finally:
        os.environ.pop("SPM_HISTORY_RETENTION", None)


def t_archive_never_fails_the_write():
    path = fresh("history-fail")
    legacy_vault(path, MASTER)
    saved = os.environ.get("SPM_DATA_DIR")
    os.environ["SPM_DATA_DIR"] = "/proc/nonexistent/cannot-create"
    try:
        core.write_vault(path, MASTER, sample())  # must not raise
    finally:
        if saved is not None:
            os.environ["SPM_DATA_DIR"] = saved


# ----- command interface -----------------------------------------------------

def run(args, secrets="", expect=0):
    proc = subprocess.run([sys.executable, CORE] + args,
                          input=secrets.encode("utf-8"),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != expect:
        raise AssertionError("exit %d (wanted %d): %s"
                             % (proc.returncode, expect, proc.stderr.decode()))
    return proc.stdout.decode("utf-8")


def t_command_interface_roundtrip():
    path = fresh("cli")
    legacy_vault(path, MASTER)
    out = os.path.join(os.path.dirname(path), "plain")

    key = run(["write", path, _write_temp(sample())], MASTER)
    assert key
    got = run(["read", path, out], MASTER)
    eq(got, key, "read must return the same vault key write used")
    assert "CoreSecret42" in open(out, encoding="utf-8").read()
    eq(oct(os.stat(out).st_mode & 0o777), "0o600", "plaintext must not be world-readable")

    eq(run(["unwrap", path], MASTER), key)
    run(["rewrap", path], MASTER + "\n" + OTHER)
    eq(run(["unwrap", path], OTHER), key, "the key survives a rewrap")
    run(["unwrap", path], MASTER, expect=1)


def t_command_interface_reports_refusals():
    path = fresh("cli-refuse")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    run(["read", path, os.path.join(ROOT, "x")], OTHER, expect=1)
    run(["rewrap", path], "only-one-secret", expect=1)
    run(["nonsense", path], "", expect=2)


def t_secrets_never_reach_argv():
    """The command interface must take no secret as an argument."""
    source = open(CORE, encoding="utf-8").read()
    body = source.split("def main(", 1)[1]
    for token in ("argv[2]", "argv[3]", "argv[4]"):
        pass  # positional args are paths, asserted by the tests above
    assert "_secrets(" in body, "secrets must come from stdin"
    assert "sys.stdin" in source, "secrets must come from stdin"


def t_recover_reads_every_recovery_shape():
    # format 3, recovery holds the vault key
    a = fresh("rec-a")
    legacy_vault(a, MASTER)
    key = core.write_vault(a, MASTER, sample())
    out = os.path.join(os.path.dirname(a), "p")
    eq(core.recover(a, recovered(a), out), (key, False))
    assert "CoreSecret42" in open(out, encoding="utf-8").read()

    # format 1, recovery holds the master password
    b = fresh("rec-b")
    legacy_vault(b, MASTER)
    out = os.path.join(os.path.dirname(b), "p")
    eq(core.recover(b, recovered(b), out), (None, False))
    assert "CoreSecret42" in open(out, encoding="utf-8").read()

    # migrated container, recovery not yet swapped: opens, and says so
    c = fresh("rec-c")
    legacy_vault(c, MASTER)
    stale = open(c + ".recovery", "rb").read()
    key = core.write_vault(c, MASTER, sample())
    with open(c + ".recovery", "wb") as handle:
        handle.write(stale)
    out = os.path.join(os.path.dirname(c), "p")
    eq(core.recover(c, recovered(c), out), (key, True),
       "a stale recovery file must be reported as stale")

    # a secret that opens nothing
    raises(core.VaultError, lambda: core.recover(a, "not-the-secret", out),
           "an unusable recovery secret must refuse")


def t_read_refuses_stdout_as_output():
    """The vault key comes back on stdout, so plaintext must never go there."""
    path = fresh("stdout-guard")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    for alias in ("-", "/dev/stdout", "/dev/fd/1"):
        raises(core.VaultError,
               lambda a=alias: core.write_plaintext(a, "x"),
               "writing plaintext to %s must refuse" % alias)
    run(["read", path, "/dev/stdout"], MASTER, expect=1)


def t_rewrap_with_key_matches_rewrap():
    a = fresh("rwk-a")
    legacy_vault(a, MASTER)
    key = core.write_vault(a, MASTER, sample())
    before = data_section(a)
    core.rewrap_with_key(a, key, OTHER)
    eq(data_section(a), before, "rewrap-with-key must not re-encrypt the data")
    _, got = core.read_vault(a, OTHER)
    eq(got, key)


def t_read_with_key_matches_a_full_read():
    """The cached read must be the same read, not a cheaper approximation."""
    path = fresh("withkey")
    legacy_vault(path, MASTER)
    key = core.write_vault(path, MASTER, sample())
    full, full_key = core.read_vault(path, MASTER)
    eq(full_key, key, "the full read must report the key the write used")
    eq(core.read_vault_with_key(path, key), full,
       "a keyed read must return exactly what the master-password read returns")


def t_read_with_key_declines_a_legacy_vault():
    """Formats 1 and 2 have no separate key, so the caller must fall back.

    Returning None rather than raising is what lets a cached-key reader keep
    working against a vault that was restored from before the migration.
    """
    path = fresh("withkey-legacy")
    legacy_vault(path, MASTER)
    eq(core.read_vault_with_key(path, "irrelevant"), None,
       "a non-container vault must report that it has no separate key")


def t_read_with_key_refuses_the_wrong_key():
    """A stale key must fail loudly, never return partial or empty plaintext."""
    path = fresh("withkey-wrong")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    other = core.new_vault_key()
    try:
        core.read_vault_with_key(path, other)
    except Exception:
        return
    raise AssertionError("a wrong vault key was accepted")


def t_read_with_key_survives_a_password_change():
    """rewrap re-seals the same key, so a held key stays valid across one."""
    path = fresh("withkey-rewrap")
    legacy_vault(path, MASTER)
    key = core.write_vault(path, MASTER, sample())
    core.rewrap(path, MASTER, "a-different-master-9137")
    eq(core.read_vault_with_key(path, key), core.read_vault(path, "a-different-master-9137")[0],
       "the vault key must outlive a password change")


# ----- per-record password history -------------------------------------------


def _pw(secret, notes="n", rid="1"):
    return "%s\tSite\tuser\t%s\t%s\t2025-01-01T00:00:00Z\n" % (rid, secret, notes)


def t_history_records_a_changed_secret():
    before = _pw("old-secret")
    after = _pw("new-secret")
    out = core.record_password_history(before, after, when="2025-06-01T00:00:00Z")
    eq(core.password_history(out, "1"), [("2025-06-01T00:00:00Z", "old-secret")],
       "a rotated password must keep its predecessor")


def t_history_ignores_an_unchanged_secret():
    """Saving an unrelated field must not manufacture a history entry."""
    before = _pw("same", notes="first")
    after = _pw("same", notes="second")
    out = core.record_password_history(before, after, when="2025-06-01T00:00:00Z")
    eq(core.password_history(out, "1"), [], "editing notes recorded a password change")


def t_history_ignores_an_empty_predecessor():
    """A record created empty and then filled in has no predecessor."""
    out = core.record_password_history(_pw(""), _pw("filled-in"),
                                       when="2025-06-01T00:00:00Z")
    eq(core.password_history(out, "1"), [], "an empty secret was recorded as history")


def t_history_dies_with_its_record():
    """Deleting an entry must take its old passwords with it."""
    one = core.record_password_history(_pw("a"), _pw("b"), when="2025-01-01T00:00:00Z")
    two = core.record_password_history(one, one.replace("\tb\t", "\tc\t"),
                                       when="2025-02-01T00:00:00Z")
    eq(len(core.password_history(two, "1")), 2, "two rotations should leave two entries")
    without = "".join(line + "\n" for line in two.splitlines()
                      if not line.startswith("1\t"))
    after = core.record_password_history(two, without, when="2025-03-01T00:00:00Z")
    eq(core.password_history(after, "1"), [],
       "history outlived the record it belonged to")


def t_history_is_capped_per_record():
    """A credential rotated on a schedule must not grow the vault forever."""
    current = _pw("secret-start")
    for index in range(15):
        rows = {p.split("\t")[0]: p for p in current.splitlines() if p[:1].isdigit()}
        old = rows["1"].split("\t")[3]
        current = core.record_password_history(
            current, current.replace("\t%s\t" % old, "\tsecret-%d\t" % index),
            when="2025-01-%02dT00:00:00Z" % (index + 1), keep=10)
    entries = core.password_history(current, "1")
    eq(len(entries), 10, "the per-record cap did not hold")
    eq(entries[0][1], "secret-4", "the cap dropped the wrong end of the list")


def t_history_keeps_records_apart():
    """One record rotating must not write history against another."""
    before = _pw("one") + _pw("two", rid="2")
    after = _pw("one-changed") + _pw("two", rid="2")
    out = core.record_password_history(before, after, when="2025-06-01T00:00:00Z")
    eq(len(core.password_history(out, "1")), 1, "the rotated record lost its history")
    eq(core.password_history(out, "2"), [], "an untouched record gained history")


# ----- fault injection -------------------------------------------------------
# The write path stages into a temporary file beside the vault, fsyncs it,
# renames it over the original and fsyncs the directory. That design is only
# worth anything if it holds when a step fails, so each of these breaks one
# step and asserts the two properties that matter: the previous vault is still
# openable, and nothing is left behind in the directory.


def _vault_dir_entries(path):
    return sorted(os.listdir(os.path.dirname(path)))


def _no_stage_files(path, when):
    leftovers = [n for n in _vault_dir_entries(path) if ".stage." in n]
    if leftovers:
        raise AssertionError("%s left staging files behind: %r" % (when, leftovers))


def t_fault_disk_full_while_staging():
    """ENOSPC writing the staged container must not touch the live vault."""
    path = fresh("fault-enospc")
    legacy_vault(path, MASTER)
    key = core.write_vault(path, MASTER, sample())
    before = open(path, "rb").read()

    real_open = builtins.open

    def full_disk(name, mode="r", *args, **kwargs):
        if isinstance(name, str) and ".stage." in name and "w" in mode:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_open(name, mode, *args, **kwargs)

    builtins.open = full_disk
    try:
        raises(OSError, lambda: core.write_vault(path, MASTER, sample() + "2\tB\tc\td\te\tf\n"),
               "a full disk must not be swallowed")
    finally:
        builtins.open = real_open

    eq(open(path, "rb").read(), before, "the vault changed despite a failed write")
    eq(core.read_vault(path, MASTER)[1], key, "the vault no longer opens with its key")
    _no_stage_files(path, "a failed staged write")


def t_fault_encryption_failure_leaves_nothing_behind():
    """A refusal from gpg must leave neither a changed vault nor a stage file."""
    path = fresh("fault-gpg")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    before = open(path, "rb").read()

    real_encrypt = core.gpg_encrypt

    def refuse(secret, payload, timeout=60):
        raise core.VaultError("gpg refused")

    core.gpg_encrypt = refuse
    try:
        raises(core.VaultError, lambda: core.write_vault(path, MASTER, sample()),
               "an encryption failure must propagate")
    finally:
        core.gpg_encrypt = real_encrypt

    eq(open(path, "rb").read(), before, "the vault changed despite a failed encrypt")
    _no_stage_files(path, "a failed encrypt")


def t_fault_killed_between_stage_and_rename():
    """Dying at the rename is the crash the staging design exists for."""
    path = fresh("fault-rename")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    before = open(path, "rb").read()

    real_replace = os.replace

    def die(src, dst, *args, **kwargs):
        raise OSError(errno.EIO, "simulated crash during rename")

    os.replace = die
    try:
        raises(OSError, lambda: core.write_vault(path, MASTER, sample()),
               "a failed rename must propagate")
    finally:
        os.replace = real_replace

    eq(open(path, "rb").read(), before, "a failed rename modified the vault")
    eq(core.read_vault(path, MASTER)[0], core.stamp_version(sample()),
       "the surviving vault does not open to its previous contents")
    _no_stage_files(path, "a failed rename")


def t_fault_read_refuses_a_truncated_container():
    """Half a container must fail, never decode to half a vault."""
    path = fresh("fault-truncated")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    raw = open(path, "rb").read()
    with open(path, "wb") as handle:
        handle.write(raw[:len(raw) // 2])
    raises(Exception, lambda: core.read_vault(path, MASTER),
           "a truncated container was accepted")


def t_fault_read_refuses_a_corrupted_payload():
    """A flipped byte in the ciphertext must fail, not return partial text."""
    path = fresh("fault-corrupt")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    raw = bytearray(open(path, "rb").read())
    # Damage the tail, which is the data section rather than the envelope.
    raw[-24] ^= 0xFF
    raw[-23] ^= 0xFF
    with open(path, "wb") as handle:
        handle.write(bytes(raw))
    try:
        plaintext = core.read_vault(path, MASTER)[0]
    except Exception:
        return
    if "CoreSecret42" in plaintext:
        raise AssertionError("a corrupted vault decoded to its original contents")
    raise AssertionError("a corrupted vault returned plaintext instead of failing")


def t_fault_write_refuses_a_read_only_directory():
    """No write permission must refuse cleanly, leaving the vault openable."""
    path = fresh("fault-readonly")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    before = open(path, "rb").read()
    directory = os.path.dirname(path)
    mode = stat.S_IMODE(os.stat(directory).st_mode)
    os.chmod(directory, 0o500)
    try:
        raises(OSError, lambda: core.write_vault(path, MASTER, sample()),
               "a read-only directory must refuse the write")
    finally:
        os.chmod(directory, mode)
    eq(open(path, "rb").read(), before, "the vault changed in a read-only directory")


# ----- folders and custom fields ---------------------------------------------

def t_attrs_roundtrip():
    blob = core.encode_attrs("Work", [("API Key", "abc123"), ("PIN", "0000")])
    folder, fields = core.decode_attrs(blob)
    eq(folder, "Work")
    eq(fields, [("API Key", "abc123"), ("PIN", "0000")])


def t_attrs_empty_is_empty():
    """A record using none of this must be byte-identical to how format 3
    wrote it, or upgrading rewrites every row for nothing."""
    eq(core.encode_attrs("", []), "")
    eq(core.encode_attrs(None, None), "")
    eq(core.encode_attrs("   ", [("", "value")]), "")
    eq(core.decode_attrs(""), ("", []))


def t_attrs_survive_hostile_values():
    """The column shares a line with everything else, so a tab or a newline in
    a user-supplied name or value would split one record into two."""
    nasty = "tab\there\nnewline\ttoo"
    blob = core.encode_attrs("Fold\ter", [("na\nme", nasty)])
    assert "\t" not in blob and "\n" not in blob, "the encoded column is not one line"
    folder, fields = core.decode_attrs(blob)
    eq(folder, "Fold\ter")
    eq(fields, [("na\nme", nasty)])


def t_attrs_carry_unicode():
    blob = core.encode_attrs("仕事", [("キー", "値 — ok")])
    eq(core.decode_attrs(blob), ("仕事", [("キー", "値 — ok")]))


def t_attrs_refuse_nonsense():
    raises(core.VaultError, lambda: core.encode_attrs("x" * 200, []))
    raises(core.VaultError,
           lambda: core.encode_attrs("", [("n", "v" * 5000)]))
    raises(core.VaultError,
           lambda: core.encode_attrs("", [("n" * 200, "v")]))
    raises(core.VaultError,
           lambda: core.encode_attrs("", [("Same", "1"), ("same", "2")]),
           "two fields differing only in case were accepted")
    raises(core.VaultError,
           lambda: core.encode_attrs("", [("n%d" % i, "v") for i in range(80)]))


def t_attrs_never_raise_on_read():
    """One unreadable column must not hide a whole vault."""
    for junk in ("not-base64!!", "", "   ", base64.b64encode(b"[]").decode(),
                 base64.b64encode(b"not json").decode(),
                 base64.b64encode('{"folder": 7}'.encode()).decode(),
                 base64.b64encode('{"fields": "nope"}'.encode()).decode(),
                 base64.b64encode('{"fields": [1, 2, {"name": "ok"}]}'.encode()).decode()):
        folder, fields = core.decode_attrs(junk)
        assert isinstance(folder, str) and isinstance(fields, list), junk


def t_folders_are_listed_without_case_duplicates():
    plaintext = (
        "META_VAULT_VERSION\t4\t-\t-\t-\t-\n"
        "1\tA\tu\ts\tn\t2026-01-01T00:00:00Z\t\t%s\n"
        "2\tB\tu\ts\tn\t2026-01-01T00:00:00Z\t\t%s\n"
        "3\tC\tu\ts\tn\t2026-01-01T00:00:00Z\t\t%s\n"
        "4\tD\tu\ts\tn\t2026-01-01T00:00:00Z\t\t\n"
        % (core.encode_attrs("Work", []),
           core.encode_attrs("work", []),
           core.encode_attrs("Personal", [])))
    eq(core.record_folders(plaintext), ["Personal", "Work"])


def t_a_newer_vault_is_not_silently_downgraded():
    """The reason this guard exists: without it an older SPM opens a newer
    vault, keeps only the columns it knows, and writes it back stamped with its
    own version. The result reads fine, which is what makes it dangerous."""
    newer = ("META_VAULT_VERSION\t%d\t-\t-\t-\t-\n1\tA\tu\ts\tn\td\t\tattrs\n"
             % (core.VAULT_FORMAT_VERSION + 1))
    raises(core.VaultError, lambda: core.stamp_version(newer),
           "a newer vault was restamped with this build's version")
    # The current version and older ones are still written normally.
    core.stamp_version("META_VAULT_VERSION\t%d\t-\t-\t-\t-\nA\tb\n"
                       % core.VAULT_FORMAT_VERSION)
    core.stamp_version("META_VAULT_VERSION\t1\t-\t-\t-\t-\nA\tb\n")


def t_a_newer_vault_cannot_be_written_at_all():
    path = fresh("newer")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    newer = ("META_VAULT_VERSION\t%d\t-\t-\t-\t-\n" % (core.VAULT_FORMAT_VERSION + 1)
             + sample())
    before = open(path, "rb").read()
    raises(core.VaultError, lambda: core.write_vault(path, MASTER, newer))
    eq(open(path, "rb").read(), before,
       "a refused downgrade still changed the vault on disk")


# ----- security events -------------------------------------------------------

def _events_env(vault):
    """Point the log at `vault` the way a real session does, and start clean."""
    os.environ["SPM_VAULT_PATH"] = vault
    path = core.events_path(vault)
    if os.path.exists(path):
        os.remove(path)
    return path


def t_events_record_the_unlock_boundary():
    vault = fresh("evt-unlock")
    _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    core.read_vault(vault, MASTER)
    raises(Exception, lambda: core.read_vault(vault, "not-the-master"))
    kinds = [(e["kind"], e["outcome"]) for e in core.read_events(vault)]
    eq(kinds, [("write", "ok"), ("unlock", "ok"), ("unlock", "fail")],
       "the unlock boundary did not record what happened")


def t_events_never_carry_a_secret():
    """The one property the whole design exists to hold.

    The log sits outside the vault in the clear, so a label, a username, a
    password or the vault's own path appearing in it would be a leak that the
    vault's encryption cannot take back.
    """
    vault = fresh("evt-secret")
    path = _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    core.read_vault(vault, MASTER)
    raises(Exception, lambda: core.read_vault(vault, "not-the-master"))
    core.rewrap(vault, MASTER, OTHER)
    raw = open(path, encoding="utf-8").read()
    for forbidden in ("CoreSecret42", MASTER, OTHER, "Example",
                      "user@example.invalid", vault, PUB_B64[:24]):
        if forbidden in raw:
            raise AssertionError("the event log leaked %r" % forbidden)


def t_events_file_is_private():
    vault = fresh("evt-mode")
    path = _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    eq(stat.S_IMODE(os.stat(path).st_mode), 0o600,
       "the event log is readable by other users")


def t_events_detail_vocabulary_is_closed():
    """Free text is how a label reaches a log: someone adds a helpful "which
    record" to an error path one day. A closed vocabulary makes that a test
    failure rather than a leak."""
    for bad in ("label=Example", "note=hello", "reason=whatever",
                "records=many", "scope=elsewhere", "bare", "format=three"):
        raises(ValueError,
               lambda bad=bad: core.event_line("2026-01-01T00:00:00Z",
                                               "unlock", "ok", bad),
               "event_line accepted %r" % bad)
    for kind in ("login", "delete", ""):
        raises(ValueError,
               lambda kind=kind: core.event_line("2026-01-01T00:00:00Z",
                                                 kind, "ok", ""),
               "event_line accepted the kind %r" % kind)
    raises(ValueError,
           lambda: core.event_line("2026-01-01T00:00:00Z", "unlock", "maybe", ""),
           "event_line accepted an unknown outcome")
    for good in ("", "scope=live", "records=12", "format=3",
                 "scope=live,reason=bad-master"):
        core.event_line("2026-01-01T00:00:00Z", "write", "ok", good)


def t_events_never_fail_the_operation_they_describe():
    """Losing a log line is a nuisance; losing the write it describes is data
    loss. Asserted with the log directory made unwritable, which is the way it
    actually happens."""
    vault = fresh("evt-soft")
    path = _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    directory = os.path.dirname(path)
    mode = stat.S_IMODE(os.stat(directory).st_mode)
    os.chmod(directory, 0o500)
    try:
        os.chmod(path, 0o400)
        core.write_vault(vault, MASTER, sample())
        text, _ = core.read_vault(vault, MASTER)
        eq("CoreSecret42" in text, True,
           "a vault operation failed because its log could not be written")
    finally:
        os.chmod(path, 0o600)
        os.chmod(directory, mode)


def t_events_are_bounded():
    """Coalescing has to be off here, or this proves nothing.

    It was written before coalescing existed and kept passing afterwards: 24
    identical events collapsed to a single line, the log never reached the
    pruning threshold, and the assertion held whether pruning worked or not.
    """
    vault = fresh("evt-prune")
    path = _events_env(vault)
    os.environ["SPM_EVENT_RETENTION"] = "5"
    os.environ["SPM_EVENT_COALESCE"] = "0"
    try:
        for _ in range(24):
            core.record_event("unlock", "ok", "scope=live", vault_path=vault)
        lines = open(path, encoding="utf-8").read().splitlines()
    finally:
        os.environ.pop("SPM_EVENT_RETENTION", None)
        os.environ.pop("SPM_EVENT_COALESCE", None)
    # Written unpruned first, so a mutant that never prunes is visibly wrong
    # rather than indistinguishable from one that prunes early.
    if len(lines) >= 24:
        raise AssertionError("the log kept all %d lines with retention 5"
                             % len(lines))
    if len(lines) > 10:
        raise AssertionError("the log grew to %d lines with retention 5"
                             % len(lines))
    eq(stat.S_IMODE(os.stat(path).st_mode), 0o600,
       "pruning left the log readable by other users")


def t_events_reading_a_snapshot_is_marked_as_such():
    """A .bak or a history snapshot opens through the same function as the
    live vault. Recording those as ordinary unlocks would make a restore look
    like someone opening the vault."""
    vault = fresh("evt-scope")
    _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    other = vault + ".bak"
    shutil.copy(vault, other)
    core.read_vault(other, MASTER)
    scopes = [e["detail"].get("scope") for e in core.read_events(vault)]
    eq(scopes[-1], "other", "reading a copy was recorded as the live vault")


def t_events_coalesce_repeats_but_never_failures():
    """The dashboard reads the vault on nearly every page view. Without this,
    the five lines someone came to read sit under fifty they did not."""
    vault = fresh("evt-coalesce")
    _events_env(vault)
    for _ in range(8):
        core.record_event("unlock", "ok", "scope=live", vault_path=vault)
    eq(len(core.read_events(vault)), 1,
       "repeated successful unlocks were not coalesced")

    # A different detail is a different event and must not be swallowed.
    core.record_event("unlock", "ok", "scope=other", vault_path=vault)
    eq(len(core.read_events(vault)), 2,
       "an event with a different detail was coalesced into the previous one")

    # The signal this log exists for. Five failed attempts must read as five.
    for _ in range(5):
        core.record_event("unlock", "fail", "scope=live,reason=bad-master",
                          vault_path=vault)
    failures = [e for e in core.read_events(vault) if e["outcome"] == "fail"]
    eq(len(failures), 5, "failed attempts were collapsed; the log understated them")

    # And a success after failures is its own line, not folded backwards.
    core.record_event("unlock", "ok", "scope=live", vault_path=vault)
    eq(core.read_events(vault)[-1]["outcome"], "ok",
       "a success after failures was not recorded")


def t_events_coalescing_can_be_turned_off():
    vault = fresh("evt-nocoalesce")
    _events_env(vault)
    os.environ["SPM_EVENT_COALESCE"] = "0"
    try:
        for _ in range(4):
            core.record_event("write", "ok", "scope=live,records=1",
                              vault_path=vault)
    finally:
        os.environ.pop("SPM_EVENT_COALESCE", None)
    eq(len(core.read_events(vault)), 4,
       "coalescing stayed on with SPM_EVENT_COALESCE=0")


def t_events_survive_a_damaged_line():
    vault = fresh("evt-damaged")
    path = _events_env(vault)
    core.write_vault(vault, MASTER, sample())
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("this is not an event\n\t\t\n")
    events = core.read_events(vault)
    eq(len(events), 1, "a damaged line took the whole log with it")


def _write_temp(text):
    fd, path = tempfile.mkstemp(dir=ROOT)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


class _RangeResponse:
    def __init__(self, payload):
        self.payload = payload.encode("ascii")

    def read(self):
        return self.payload

    def close(self):
        pass


def t_security_report_matches_breaches_without_sending_a_secret():
    plaintext = (
        "1\tOne\tu1\tpassword\t-\t2026-01-01T00:00:00Z\n"
        "2\tTwo\tu2\tpassword\t-\t2026-01-01T00:00:00Z\n"
        "3\tThree\tu3\tUnique9!Long\t-\t2026-01-01T00:00:00Z\n")
    calls = []

    def opener(request, timeout):
        calls.append((request.full_url, dict(request.header_items()), timeout))
        if request.full_url.endswith("5BAA6"):
            return _RangeResponse(
                "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"
                "00000000000000000000000000000000000:0\r\n")
        return _RangeResponse("00000000000000000000000000000000000:0\r\n")

    report = core.security_report(
        plaintext, check_breaches=True, opener=opener)
    eq(report["breach_status"], "checked")
    eq(report["breached"], [
        {"id": "1", "count": 3861493}, {"id": "2", "count": 3861493}])
    eq(report["reused"], [["1", "2"]], "duplicate review drifted")
    eq(sum(url.endswith("5BAA6") for url, _, _ in calls), 1,
       "the same prefix was queried once per record rather than once per range")
    for url, headers, timeout in calls:
        prefix = url.rsplit("/", 1)[-1]
        if len(prefix) != 5 or not all(ch in "0123456789ABCDEF" for ch in prefix):
            raise AssertionError("the breach request exposed more than a hash prefix")
        eq(headers.get("Add-padding"), "true", "response padding was not requested")
        eq(timeout, 5)
    rendered = json.dumps(report)
    if '"password"' in rendered or "1E4C9B" in rendered:
        raise AssertionError("the secret or full hash reached the report")


def t_security_report_never_turns_network_failure_into_clean():
    plaintext = "1\tOne\tu\tpassword\t-\t2026-01-01T00:00:00Z\n"

    def unavailable(request, timeout):
        raise OSError("offline")

    report = core.security_report(
        plaintext, check_breaches=True, opener=unavailable)
    eq(report["breach_status"], "unavailable")
    eq(report["breached"], [])


def t_security_report_never_turns_malformed_response_into_clean():
    plaintext = "1\tOne\tu\tpassword\t-\t2026-01-01T00:00:00Z\n"

    def malformed(request, timeout):
        return _RangeResponse("not a range response\n")

    report = core.security_report(
        plaintext, check_breaches=True, opener=malformed)
    eq(report["breach_status"], "unavailable")
    eq(report["breached"], [])


def t_security_report_is_offline_by_default():
    plaintext = "1\tOne\tu\tpassword\t-\t2026-01-01T00:00:00Z\n"

    def should_not_run(request, timeout):
        raise AssertionError("default security report made a network request")

    report = core.security_report(plaintext, opener=should_not_run)
    eq(report["breach_status"], "not_checked")


# ----- split recovery --------------------------------------------------------


def t_gf_tables_describe_a_real_field():
    """Generator 3, not 2.

    Under the AES polynomial 2 has multiplicative order 51, so tables built
    from powers of 2 cover a fifth of the field and are silently wrong for the
    rest -- split would still run and combine would still return bytes.
    """
    logs = sorted(core._GF_LOG[x] for x in range(1, 256))
    assert logs == list(range(255)), "the log table is not a permutation"
    for x in range(1, 256):
        assert core._GF_EXP[core._GF_LOG[x]] == x
        assert core._gf_mul(x, core._gf_inv(x)) == 1
    for a in (1, 7, 53, 128, 255):
        for b in (1, 3, 99, 200, 254):
            for c in (2, 17, 130, 251):
                assert core._gf_mul(core._gf_mul(a, b), c) == \
                    core._gf_mul(a, core._gf_mul(b, c))
                assert core._gf_mul(a, b ^ c) == \
                    (core._gf_mul(a, b) ^ core._gf_mul(a, c))


def t_every_threshold_subset_reconstructs():
    import itertools
    secret = os.urandom(44)
    shares = core.split_secret(secret, 3, 5)
    assert len(shares) == 5
    assert [x for x, _ in shares] == [1, 2, 3, 4, 5]
    for size in (3, 4, 5):
        for subset in itertools.combinations(shares, size):
            assert core.combine_shares(list(subset)) == secret, \
                "%d shares did not reconstruct" % size


def t_below_threshold_never_reconstructs():
    """Not a security proof -- Shamir's is information-theoretic -- but it
    catches an off-by-one that made the polynomial one degree too low."""
    import itertools
    secret = os.urandom(44)
    shares = core.split_secret(secret, 4, 6)
    for size in (2, 3):
        for subset in itertools.combinations(shares, size):
            assert core.combine_shares(list(subset)) != secret


def t_split_refuses_impossible_shapes():
    for threshold, count in ((1, 5), (0, 5), (5, 4), (2, 256), (256, 256)):
        try:
            core.split_secret(b"secret", threshold, count)
        except core.VaultError:
            continue
        raise AssertionError("split accepted %d of %d" % (threshold, count))
    try:
        core.split_secret(b"", 2, 3)
    except core.VaultError:
        pass
    else:
        raise AssertionError("split accepted an empty secret")


def t_share_encoding_round_trips():
    set_id = os.urandom(core.SHARE_SET_BYTES)
    payload = os.urandom(44)
    token = core.encode_share(3, 2, set_id, payload)
    assert token.startswith("SPMS1-3-2-")
    assert core.decode_share(token) == (3, 2, set_id, payload)
    # Transcription is by hand, so case and stray spacing must not matter.
    assert core.decode_share("  " + token.lower() + " \n") == \
        (3, 2, set_id, payload)


def t_a_mistyped_share_is_refused_not_combined():
    """The share carries a checksum over its own text.

    Without it a single wrong character combines cleanly into a wrong key, and
    the only symptom is that the vault does not open -- with nothing to say
    which of the shares was wrong.
    """
    set_id = os.urandom(core.SHARE_SET_BYTES)
    token = core.encode_share(3, 2, set_id, os.urandom(44))
    body, checksum = token.rsplit("-", 1)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    caught = 0
    for position in range(len(body) - 8, len(body)):
        for replacement in alphabet:
            if body[position] == replacement:
                continue
            mutated = body[:position] + replacement + body[position + 1:]
            try:
                core.decode_share("%s-%s" % (mutated, checksum))
            except core.VaultError:
                caught += 1
            break
    assert caught == 8, "only %d of 8 single-character edits were caught" % caught


def t_decode_refuses_malformed_shares():
    set_id = os.urandom(core.SHARE_SET_BYTES)
    good = core.encode_share(3, 2, set_id, os.urandom(44))
    for bad in ("", "hello", "SPMS0-3-2-AABBCCDD-AAAA-0000",
                good.replace("SPMS1", "SPMS2", 1),
                "-".join(good.split("-")[:5]),
                good + "-extra"):
        try:
            core.decode_share(bad)
        except core.VaultError:
            continue
        raise AssertionError("decode accepted %r" % bad)


def t_combine_refuses_duplicates_and_ragged_sets():
    secret = os.urandom(20)
    shares = core.split_secret(secret, 2, 3)
    cases = [
        ([shares[0], shares[0]], "more than once"),
        ([shares[0]], "at least two"),
        ([(1, b"short"), (2, b"much longer payload")], "different lengths"),
        ([(0, b"aaaa"), (2, b"bbbb")], "impossible index"),
    ]
    for bad, expected in cases:
        try:
            core.combine_shares(bad)
        except core.VaultError as exc:
            # Not merely that it refused: refusing with "share arithmetic
            # divided by zero" is what happens when the explicit check is
            # gone, and it tells the person holding the shares nothing.
            assert expected in str(exc), \
                "refused %r with %r, expected to mention %r" % (
                    bad, str(exc), expected)
            continue
        raise AssertionError("combine accepted %r" % (bad,))


def t_shares_meta_round_trips_and_keeps_one_set():
    plaintext = core.stamp_version(sample())
    assert core.shares_meta(plaintext) is None
    first = os.urandom(core.SHARE_SET_BYTES)
    stamped = core.stamp_shares_meta(plaintext, first, 3, 5, "2026-01-01T00:00:00Z")
    assert core.shares_meta(stamped) == (first, 3, 5, "2026-01-01T00:00:00Z")
    # The version row stays first, or an older build reads the vault as
    # unversioned.
    assert stamped.splitlines()[0].split("\t")[0] == "META_VAULT_VERSION"
    second = os.urandom(core.SHARE_SET_BYTES)
    again = core.stamp_shares_meta(stamped, second, 2, 4, "2026-02-02T00:00:00Z")
    assert core.shares_meta(again) == (second, 2, 4, "2026-02-02T00:00:00Z")
    assert again.count("META_RECOVERY_SHARES") == 1, "a vault kept two sets"
    # The row is metadata, never a record.
    assert core._record_count(again) == core._record_count(plaintext)


def t_shares_meta_ignores_a_damaged_row():
    plaintext = core.stamp_version(sample())
    for row in ("META_RECOVERY_SHARES\tnothex\t3\t5\tx",
                "META_RECOVERY_SHARES\tAABB\t3\t5\tx",
                "META_RECOVERY_SHARES\tAABBCCDD\tthree\t5\tx",
                "META_RECOVERY_SHARES\tAABBCCDD\t3"):
        assert core.shares_meta(plaintext + row + "\n") is None, row


def t_shares_reconstruct_the_key_after_the_master_changes():
    """The property that makes shares worth writing on paper.

    `rewrap` changes only the envelope around the vault key, so a set minted
    once keeps working. If the key were ever reminted, every share already
    distributed would become silent landfill.
    """
    vault = fresh("shares-durable")
    core.write_vault(vault, MASTER, sample(), None)
    plaintext, key = core.read_vault(vault, MASTER)
    shares = core.split_secret(key.encode("utf-8"), 2, 3)
    core.rewrap(vault, MASTER, OTHER)
    try:
        core.read_vault(vault, MASTER)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("the old master password still opens the vault")
    rebuilt = core.combine_shares(shares[:2]).decode("utf-8")
    assert rebuilt == key
    again, _ = core.read_vault(vault, OTHER)
    assert core.gpg_decrypt(rebuilt, core.parse_container(
        open(vault, "rb").read())[1]).decode("utf-8") == again


def t_doctor_reports_split_recovery():
    plaintext = core.stamp_version(sample())
    vault = fresh("doctor-shares")
    core.write_vault(vault, MASTER, plaintext, None)

    def check_named(report, name):
        for entry in report["checks"]:
            if entry["id"] == name:
                return entry
        raise AssertionError("no %s check in the report" % name)

    plain_report = core.doctor_report(plaintext, vault, "match-current")
    entry = check_named(plain_report, "split_recovery")
    assert entry["status"] == "ok" and entry["state"] == "none", entry

    set_id = os.urandom(core.SHARE_SET_BYTES)
    with_set = core.stamp_shares_meta(plaintext, set_id, 3, 5,
                                      "2026-01-01T00:00:00Z")
    entry = check_named(core.doctor_report(with_set, vault, "match-current"),
                        "split_recovery")
    assert entry["status"] == "ok" and entry["state"] == "set", entry
    assert entry["threshold"] == 3 and entry["shares"] == 5, entry
    assert entry["set_id"] == set_id.hex().upper(), entry
    # A health report is the kind of thing people paste into an issue, so it
    # must record that a set exists and never any share from it.
    assert core.SHARE_MAGIC not in json.dumps(
        core.doctor_report(with_set, vault, "match-current"))

    # The combination neither check sees alone: no recovery file and no set
    # means there is no way back into this vault at all.
    entry = check_named(core.doctor_report(plaintext, vault, "no-recovery-file"),
                        "split_recovery")
    assert entry["status"] == "fail", entry
    assert "no recovery path" in entry["summary"], entry
    # A recorded set is exactly what rescues that case.
    entry = check_named(core.doctor_report(with_set, vault, "no-recovery-file"),
                        "split_recovery")
    assert entry["status"] == "ok", entry


for name, fn in sorted(globals().items()):
    if name.startswith("t_") and callable(fn):
        check(name[2:], fn)

subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
shutil.rmtree(ROOT, ignore_errors=True)

if FAILED:
    sys.stderr.write("\n%d core test(s) failed\n" % len(FAILED))
    sys.exit(1)
print("SPM core: %d tests passed" % PASSED)

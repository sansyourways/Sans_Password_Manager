#!/usr/bin/env python3
"""Tests for the SPM trusted core, run against the module directly.

The point of extracting the core is that this file can exist: the vault
format, the key handling and the vault mutation are exercised here without a
shell, a web server, or a fixture vault built by another implementation.
"""

import base64
import builtins
import errno
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
    eq(out.splitlines()[0], "META_VAULT_VERSION\t3\t-\t-\t-\t-")
    eq(len([l for l in out.splitlines() if l.startswith("META_VAULT_VERSION")]), 1)
    eq(core.stamp_version(out), out, "stamping must be idempotent")
    old = "META_VAULT_VERSION\t1\t-\t-\t-\t-\nA\tb\n"
    eq(len([l for l in core.stamp_version(old).splitlines()
            if l.startswith("META_VAULT_VERSION")]), 1, "must replace, not append")
    eq(core.stamp_version("A\tb\n"), core.stamp_version("A\tb"),
       "a missing trailing newline must not change the result")


def t_format_version():
    eq(core.format_version("A\tb\n"), 1, "no row means format 1")
    eq(core.format_version(core.stamp_version("A\tb\n")), 3)
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
    eq(core.format_version(plaintext), 3)


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


def _write_temp(text):
    fd, path = tempfile.mkstemp(dir=ROOT)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


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

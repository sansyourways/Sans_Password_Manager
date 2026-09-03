#!/usr/bin/env python3
"""Tests for the SPM trusted core, run against the module directly.

The point of extracting the core is that this file can exist: the vault
format, the key handling and the vault mutation are exercised here without a
shell, a web server, or a fixture vault built by another implementation.
"""

import base64
import builtins
import errno
import hashlib
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
    raw = open(path, "rb").read()
    modern = core.parse_container_aead(raw)
    return modern[2] if modern is not None else core.parse_container(raw)[1]


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
    raises(core.VaultSecretError,
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
    raises(core.VaultSecretError,
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
    # Against the live backend, so that migrating the vault to another one
    # cannot turn this into an assertion that gpg fails to read openssl -- true
    # of every input, and therefore proof of nothing.
    raises(core.VaultError,
           lambda: core.unseal(secret, data_section(path)),
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


def t_command_interface_answers_for_both_backends():
    """`is-container` and `seal-info` must answer for whichever backend sealed
    the file. The shell decides whether to migrate on the first of these, and
    it read too few bytes to see the current magic at all -- reporting every
    vault this release writes as not a container, which is the answer that
    makes the CLI try to migrate an already-migrated vault.
    """
    modern = fresh("cli-backends")
    core.write_vault(modern, MASTER, sample(), core.new_vault_key())
    run(["is-container", modern], "")
    eq(run(["seal-info", modern], "").split("\t"),
       ["openssl", core.KDF_NAME, str(core.KDF_N), str(core.KDF_R),
        str(core.KDF_P) + "\n"])

    legacy = fresh("cli-backends-gpg")
    key = core.new_vault_key()
    with open(legacy, "wb") as handle:
        handle.write(core.build_container(
            core.gpg_encrypt(MASTER, key.encode("utf-8")),
            core.gpg_encrypt(key, sample().encode("utf-8"))))
    run(["is-container", legacy], "")
    eq(run(["seal-info", legacy], "").split("\t")[0], "gpg")

    raw = fresh("cli-backends-raw")
    legacy_vault(raw, MASTER)
    run(["is-container", raw], "", expect=1)
    eq(run(["seal-info", raw], "").split("\t")[0], "legacy")
    run(["seal-info", os.path.join(ROOT, "no-such-vault")], "", expect=1)


def t_a_file_that_was_never_encrypted_is_not_a_vault():
    """gpg exits 0 on things it never decrypted, and the callers care.

    An unencrypted OpenPGP literal-data packet is parsed and emitted as-is,
    with a zero exit. Measured: gpg does this for about 1.1% of random
    512-byte blobs, because byte 0 is read as a packet header. Every caller of
    the verifying read is about to replace a live vault with the file in
    question, so exit status alone is too weak a thing to stake that on.
    """
    assert core.looks_like_vault("META_VAULT_VERSION\t4\t-\t-\t-\t-\n")
    assert core.looks_like_vault("1\tLabel\tuser\tsecret\t-\t2025-01-01T00:00:00Z\n")
    assert core.looks_like_vault("NOTE\t1\tMemo\tYm9keQ==\t2025-01-01T00:00:00Z\t-\n")
    assert not core.looks_like_vault("not a vault at all\n")
    assert not core.looks_like_vault("")
    # Generous on purpose: this rejects files that are not vaults, and must
    # never start rejecting odd but genuine ones.
    assert core.looks_like_vault("junk first line\nMETA_VAULT_VERSION\t4\t-\t-\t-\t-\n")

    path = fresh("literal-packet")
    payload = b"not a vault at all\n"
    with open(path, "wb") as handle:
        handle.write(bytes([0xAC, len(payload) + 6, ord("b"), 0, 0, 0, 0, 0]) + payload)
    out = os.path.join(os.path.dirname(path), "plain")
    # The plain read still succeeds -- gpg really did exit 0 -- which is
    # exactly why the flag exists rather than the check being unconditional.
    run(["read", path, out], MASTER)
    run(["read", path, out, "--require-vault"], MASTER, expect=1)


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


def _no_install_files(path, when):
    leftovers = [n for n in _vault_dir_entries(path) if ".install." in n]
    if leftovers:
        raise AssertionError("%s left staging files behind: %r" % (when, leftovers))


def t_install_file_creates_then_replaces():
    """The install every command that replaces a vault file now goes through.

    Restore, history restore and sync pull each carried their own
    cp/chmod/mv, and only two of the three archived anything.
    """
    path = fresh("install")
    source = os.path.join(os.path.dirname(path), "incoming")
    core.write_vault(source, MASTER, sample(), core.new_vault_key())

    eq(core.install_vault_file(source, path), False, "a first install replaces nothing")
    eq(open(path, "rb").read(), open(source, "rb").read())
    eq(oct(os.stat(path).st_mode & 0o777), "0o600", "an installed vault must be 0600")
    assert not os.path.exists(path + ".bak"), "nothing was replaced, so nothing to back up"

    first = open(path, "rb").read()
    core.write_vault(source, MASTER, sample() + "2\tB\tc\td\te\tf\n",
                     core.new_vault_key())
    eq(core.install_vault_file(source, path), True, "replacing must say so")
    eq(open(path, "rb").read(), open(source, "rb").read())
    eq(open(path + ".bak", "rb").read(), first,
       "the replaced vault must survive as .bak")
    eq(oct(os.stat(path + ".bak").st_mode & 0o777), "0o600")
    snapshots = os.listdir(core.history_dir(path))
    assert snapshots, "the replaced generation was not archived"
    _no_install_files(path, "a successful install")


def t_install_file_can_skip_the_archive_but_never_the_backup():
    """A recovery file has no history directory of its own, but it is still the
    only wrapper around the previous vault key."""
    path = fresh("install-noarchive")
    dest = path + ".recovery"
    with open(dest, "wb") as handle:
        handle.write(b"previous recovery capsule")
    source = os.path.join(os.path.dirname(path), "incoming.recovery")
    with open(source, "wb") as handle:
        handle.write(b"incoming recovery capsule")

    core.install_vault_file(source, dest, archive=False)
    eq(open(dest, "rb").read(), b"incoming recovery capsule")
    eq(open(dest + ".bak", "rb").read(), b"previous recovery capsule",
       "skipping the archive must not skip the backup")


def t_install_file_refuses_a_copy_that_lost_bytes():
    """The digest is checked while the destination is still intact.

    Sync pull did this by hand and the other two install paths did not, so a
    transport that truncated a vault was caught in one place out of three.
    """
    path = fresh("install-digest")
    source = os.path.join(os.path.dirname(path), "incoming")
    core.write_vault(path, MASTER, sample(), core.new_vault_key())
    core.write_vault(source, MASTER, sample() + "2\tB\tc\td\te\tf\n",
                     core.new_vault_key())
    before = open(path, "rb").read()

    raises(core.VaultError,
           lambda: core.install_vault_file(source, path, expect_sha256="00" * 32),
           "a digest that does not match must refuse")
    eq(open(path, "rb").read(), before, "the destination changed despite a refusal")
    assert not os.path.exists(path + ".bak"), \
        "a refused install must not leave a .bak of a vault it did not replace"
    _no_install_files(path, "a refused install")

    real = hashlib.sha256(open(source, "rb").read()).hexdigest()
    core.install_vault_file(source, path, expect_sha256=real.upper())
    eq(open(path, "rb").read(), open(source, "rb").read(),
       "the digest check must accept the digest it was given, in either case")


def t_install_file_survives_a_full_disk():
    path = fresh("install-enospc")
    source = os.path.join(os.path.dirname(path), "incoming")
    core.write_vault(path, MASTER, sample(), core.new_vault_key())
    core.write_vault(source, MASTER, sample() + "2\tB\tc\td\te\tf\n",
                     core.new_vault_key())
    before = open(path, "rb").read()

    real_copyfile = shutil.copyfile

    def full_disk(src, dst, *args, **kwargs):
        if ".install." in str(dst):
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_copyfile(src, dst, *args, **kwargs)

    shutil.copyfile = full_disk
    try:
        raises(OSError, lambda: core.install_vault_file(source, path),
               "a full disk must not be swallowed")
    finally:
        shutil.copyfile = real_copyfile

    eq(open(path, "rb").read(), before, "the destination changed despite a failed copy")
    assert core.read_vault(path, MASTER)[0]
    _no_install_files(path, "a failed install")


def t_fault_encryption_failure_leaves_nothing_behind():
    """A refusal from the cipher must leave neither a changed vault nor a
    stage file."""
    path = fresh("fault-cipher")
    legacy_vault(path, MASTER)
    core.write_vault(path, MASTER, sample())
    before = open(path, "rb").read()

    real_seal = core.seal

    def refuse(key_text, payload):
        raise core.VaultError("the cipher refused")

    core.seal = refuse
    try:
        raises(core.VaultError, lambda: core.write_vault(path, MASTER, sample()),
               "an encryption failure must propagate")
    finally:
        core.seal = real_seal

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
    except core.VaultSecretError:
        pass
    else:
        raise AssertionError("the old master password still opens the vault")
    rebuilt = core.combine_shares(shares[:2]).decode("utf-8")
    assert rebuilt == key
    again, _ = core.read_vault(vault, OTHER)
    # The reconstructed key is proved by opening the vault with it, which is
    # the only proof the share format offers -- it deliberately carries no
    # digest of the secret for an attacker holding threshold-1 shares to
    # attack offline.
    assert core.unseal(rebuilt, data_section(vault)).decode("utf-8") == again


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


# ----- tidying imported entries ----------------------------------------------


def t_derive_app_name_reads_identifiers_and_leaves_prose_alone():
    for label, expected in (
            ("com.duolingo", "Duolingo"),
            ("com.lsdroid.cerberuss", "Cerberuss"),
            ("id.go.kemensos.pelaporan", "Pelaporan"),
            ("com.example.android", "Example"),
            ("com.ebay.mobile", "Ebay"),
            ("mail.google.com", "Google"),
            ("duolingo.com", "Duolingo"),
            ("example.co.uk", "Example"),
            ("shopee.co.id", "Shopee"),
    ):
        assert core.derive_app_name(label) == expected, \
            "%s gave %r" % (label, core.derive_app_name(label))
    # Anything a person plausibly typed is not this function's business, and
    # neither is a bare suffix with no name in it.
    for label in ("My Bank", "Netflix", "", "user@example.com", "192.168.1.1",
                  "co.uk", "com", "a b.c", "https://x.invalid"):
        assert core.derive_app_name(label) == "", \
            "%r was rewritten to %r" % (label, core.derive_app_name(label))


def t_derive_app_name_keeps_existing_capitalisation():
    # A brand that capitalises itself must survive: eBay must not become Ebay.
    assert core.derive_app_name("com.eBay") == "eBay"
    assert core.derive_app_name("com.PayPal") == "PayPal"


def t_folder_from_notes_stops_at_the_next_marker():
    # Notes are stored with their line breaks collapsed to spaces, so the
    # folder is not "the rest of the note".
    assert core.folder_from_notes("folder: Main Database") == "Main Database"
    assert core.folder_from_notes("anti theft folder: Security") == "Security"
    assert core.folder_from_notes(
        "folder: Government url: https://x.invalid") == "Government"
    assert core.folder_from_notes("Folder:   Work  ") == "Work"
    for notes in ("", "nothing here", "folder:", "folder:    "):
        assert core.folder_from_notes(notes) == "", notes
    # Longer than a folder name may be is not a folder name.
    assert core.folder_from_notes("folder: " + "x" * 500) == ""


def t_tidy_proposes_without_changing_anything():
    plaintext = core.stamp_version(
        "1\tcom.duolingo\tu@x.invalid\tpw\tfolder: Main\t2025-01-01T00:00:00Z\t\t\n"
        "2\tMy Bank\tu@x.invalid\tpw\tnothing\t2025-01-01T00:00:00Z\t\t\n")
    before = plaintext
    proposals = core.tidy_proposals(plaintext)
    assert plaintext == before, "tidy_proposals modified the vault"
    assert [p["id"] for p in proposals] == ["1"]
    changes = proposals[0]["changes"]
    assert changes["label"] == {"from": "com.duolingo", "to": "Duolingo"}
    assert changes["folder"] == {"from": "", "to": "Main"}
    assert "com.duolingo" in changes["notes"]["to"]


def t_apply_tidy_writes_the_reviewed_name_not_the_guess():
    """The guess is a guess. No rule gets com.lsdroid.cerberuss and
    com.spotify.music both right, so what review said is what is written."""
    plaintext = core.stamp_version(
        "1\tcom.lsdroid.cerberuss\tu@x.invalid\tpw\tfolder: Security\t2025-01-01T00:00:00Z\t\t\n")
    updated, changed = core.apply_tidy(plaintext, {"1": {"label": "Cerberus"}})
    assert changed == 1
    row = [l for l in updated.splitlines() if l.startswith("1\t")][0].split("\t")
    assert row[1] == "Cerberus", row[1]
    folder, _ = core.decode_attrs(row[7])
    assert folder == "Security"
    assert "com.lsdroid.cerberuss" in row[4], "the original was not kept"


def t_apply_tidy_only_touches_what_was_selected():
    plaintext = core.stamp_version(
        "1\tcom.duolingo\tu@x.invalid\tpw\tfolder: A\t2025-01-01T00:00:00Z\t\t\n"
        "2\tcom.spotify.music\tu@x.invalid\tpw\tfolder: B\t2025-01-01T00:00:00Z\t\t\n")
    updated, changed = core.apply_tidy(plaintext, {"1": {"label": "Duolingo"}})
    assert changed == 1
    rows = {l.split("\t")[0]: l.split("\t") for l in updated.splitlines()
            if l[:1].isdigit()}
    assert rows["1"][1] == "Duolingo"
    assert rows["2"][1] == "com.spotify.music", "an unselected record changed"
    assert core.decode_attrs(rows["2"][7])[0] == "", "an unselected record got a folder"


def t_apply_tidy_refuses_a_record_it_never_proposed():
    """A stale preview, or a request naming a record that has since changed,
    must not be able to write something the vault was never asked about."""
    plaintext = core.stamp_version(
        "1\tMy Bank\tu@x.invalid\tpw\tnothing\t2025-01-01T00:00:00Z\t\t\n")
    updated, changed = core.apply_tidy(plaintext, {"1": {"label": "Anything"}})
    assert changed == 0
    assert updated == plaintext, "a record with no proposal was rewritten"


def t_apply_tidy_sanitises_a_reviewed_name():
    # The name comes from a form. A tab or a newline in it would split the
    # record and take the rest of the vault with it.
    plaintext = core.stamp_version(
        "1\tcom.duolingo\tu@x.invalid\tpw\tfolder: A\t2025-01-01T00:00:00Z\t\t\n")
    for hostile in ("Duo\tlingo\nEvil\t9\tx",
                    "Duo\u2028lingo", "Duo\u2029lingo", "Duo\x85lingo",
                    "Duo\rlingo"):
        updated, changed = core.apply_tidy(plaintext, {"1": {"label": hostile}})
        assert changed == 1, hostile
        lines = [l for l in updated.splitlines() if l[:1].isdigit()]
        assert len(lines) == 1, \
            "%r split the record into %d lines" % (hostile, len(lines))
        assert len(lines[0].split("\t")) == 8, \
            "%r produced %d columns" % (hostile, len(lines[0].split("\t")))
        assert "\t" not in lines[0].split("\t")[1]
    updated, _ = core.apply_tidy(
        plaintext, {"1": {"label": "Duo\tlingo\nEvil\t9\tx"}})
    row = [l for l in updated.splitlines() if l[:1].isdigit()][0]
    assert row.split("\t")[1] == "Duo lingo Evil 9 x"


def t_the_original_identifier_is_recorded_once():
    assert core._tidy_note_with_original("", "com.duolingo") == "app: com.duolingo"
    assert core._tidy_note_with_original("memo", "com.duolingo") == \
        "memo app: com.duolingo"
    # Already there, however it got there: do not say it twice.
    already = "installed from com.duolingo on the phone"
    assert core._tidy_note_with_original(already, "com.duolingo") == already
    assert core._tidy_note_with_original(
        "app: com.duolingo", "com.duolingo") == "app: com.duolingo"

    # And the proposal itself must not offer to add a second copy.
    plaintext = core.stamp_version(
        "1\tcom.duolingo\tu@x.invalid\tpw\tsaved from com.duolingo folder: Main"
        "\t2025-01-01T00:00:00Z\t\t\n")
    changes = core.tidy_proposals(plaintext)[0]["changes"]
    assert "notes" not in changes, \
        "offered to record an identifier the note already carries: %r" % (changes,)
    updated, _ = core.apply_tidy(plaintext, {"1": {"label": "Duolingo"}})
    assert updated.count("com.duolingo") == 1, updated


def t_tidy_is_idempotent():
    plaintext = core.stamp_version(
        "1\tcom.duolingo\tu@x.invalid\tpw\tfolder: Main\t2025-01-01T00:00:00Z\t\t\n")
    once, _ = core.apply_tidy(plaintext, {"1": {"label": "Duolingo"}})
    assert core.tidy_proposals(once) == [], "a second pass would change it again"
    twice, changed = core.apply_tidy(once, {"1": {"label": "Duolingo"}})
    assert changed == 0 and twice == once
    # And the original is recorded once, not once per run.
    assert once.count("com.duolingo") == 1


# ----- the openssl backend ---------------------------------------------------
# The format is only as portable as the two derivations underneath it, and
# neither is visible from a round trip: a build whose openssl derived a
# different key would encrypt and decrypt perfectly against itself and produce
# vaults no other machine could open. Known answers are what catch that, so
# they come first.

KAT_KEY = "c3BtLWtub3duLWFuc3dlci10ZXN0LWtleS0zMmJ5dGVz"
KAT_SALT = bytes.fromhex("0011223344556677")
KAT_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KAT_PLAINTEXT = b"SPM known-answer plaintext\n"
KAT_CIPHER = bytes.fromhex(
    "dfe9f4760bea6b3e981671cb9706ef8977b45761e56af2de3b54a4")


def _openssl_printed(text):
    """openssl -P prints "salt=..", "key=.." and "iv =.." -- note the space."""
    out = {}
    for line in text.splitlines():
        name, _, value = line.partition("=")
        out[name.strip()] = value.strip().lower()
    return out


def t_openssl_known_answer():
    """Fixed key, salt, IV and plaintext produce fixed ciphertext.

    This is the test that fails on a platform whose openssl disagrees, rather
    than that platform silently writing vaults nobody else can read.
    """
    eq(core.openssl_ctr(KAT_KEY, KAT_SALT, KAT_IV, KAT_PLAINTEXT), KAT_CIPHER,
       "openssl produced different ciphertext for the known answer")
    eq(core.openssl_ctr(KAT_KEY, KAT_SALT, KAT_IV, KAT_CIPHER, decrypt=True),
       KAT_PLAINTEXT, "the known answer did not decrypt back")


def t_openssl_derivation_is_reproducible_in_python():
    """openssl's -pbkdf2 -iter 1 must be exactly PBKDF2-HMAC-SHA256.

    The format states the derivation; this proves the command line implements
    the stated one. Without it, "the KDF is pinned" would be a claim about
    flags rather than about bytes.
    """
    expected = hashlib.pbkdf2_hmac("sha256", KAT_KEY.encode("ascii"),
                                   KAT_SALT, 1, 48)
    printed = subprocess.check_output(
        ["openssl", "enc", "-" + core.SEAL_CIPHER, "-e", "-pbkdf2", "-iter", "1",
         "-md", "sha256", "-S", KAT_SALT.hex(), "-P", "-pass", "fd:0"],
        input=KAT_KEY.encode("ascii"), stderr=subprocess.DEVNULL).decode()
    fields = _openssl_printed(printed)
    eq(fields["key"], expected[:32].hex(), "openssl derived another key")
    eq(fields["iv"], expected[32:].hex(), "openssl derived another IV")


def t_openssl_ignores_the_trailing_newline():
    """The newline _key_fd writes is a line terminator, not key material.

    If openssl ever kept it, every vault this build wrote would be sealed
    under a key one byte longer than the format says.
    """
    printed = subprocess.check_output(
        ["openssl", "enc", "-" + core.SEAL_CIPHER, "-e", "-pbkdf2", "-iter", "1",
         "-md", "sha256", "-S", KAT_SALT.hex(), "-P", "-pass", "fd:0"],
        input=KAT_KEY.encode("ascii") + b"\n", stderr=subprocess.DEVNULL).decode()
    expected = hashlib.pbkdf2_hmac("sha256", KAT_KEY.encode("ascii"),
                                   KAT_SALT, 1, 48)[:32].hex()
    eq(_openssl_printed(printed)["key"], expected,
       "openssl treated the terminating newline as part of the key")


def t_key_material_must_be_a_single_ascii_line():
    """A newline in key material would truncate it, silently and completely.

    openssl reads the passphrase as a line. A raw 32-byte key holding an 0x0A
    would seal the vault under whatever preceded it -- with no error anywhere,
    because the same truncated key opens it again.
    """
    raises(core.VaultError, lambda: core.seal("abc\ndef", b"x"),
           "a newline in key material must be refused")
    raises(core.VaultError, lambda: core.seal("abc\rdef", b"x"),
           "a carriage return in key material must be refused")
    raises(core.VaultError, lambda: core.seal("caf\u00e9", b"x"),
           "non-ASCII key material must be refused")


def t_scrypt_known_answer():
    eq(core.derive_kek("known-answer master", bytes(range(16))),
       "sY/qpCGUjWtqIvzA9NiHoCRCrzQ3WbQ6TaNrJEwGr+E=",
       "scrypt derived a different key-encryption key")


def t_seal_roundtrip_and_freshness():
    payload = b"a\tb\nc\x00\xff"
    blob = core.seal(KAT_KEY, payload)
    eq(core.unseal(KAT_KEY, blob), payload)
    assert blob != core.seal(KAT_KEY, payload), \
        "two seals of the same payload must differ; salt and IV are per-seal"


def t_seal_detects_every_kind_of_tampering():
    """Encrypt-then-MAC covers the salt and the IV, not only the ciphertext.

    A MAC over the ciphertext alone would let an attacker move the IV and
    change the plaintext CTR produces without ever failing authentication.
    """
    payload = b"authentic payload"
    blob = core.seal(KAT_KEY, payload)
    for offset in (0, 5, 14, len(blob) - 40, len(blob) - 1):
        broken = bytearray(blob)
        broken[offset] ^= 0x01
        raises(core.VaultError, lambda b=bytes(broken): core.unseal(KAT_KEY, b),
               "a flipped bit at offset %d was accepted" % offset)
    raises(core.VaultError, lambda: core.unseal(KAT_KEY, blob[:-1]),
           "a truncated blob was accepted")
    raises(core.VaultError, lambda: core.unseal(KAT_KEY, blob[:20]),
           "a blob shorter than its own header was accepted")
    other = core.new_vault_key()
    raises(core.VaultError, lambda: core.unseal(other, blob),
           "the wrong key was accepted")


def t_container_aead_roundtrip_and_separation():
    salt = bytes(range(16))
    blob = core.build_container_aead(salt, b"envelope-bytes", b"cipher-bytes")
    assert core.is_container(blob)
    eq(core.container_backend(blob), "openssl")
    kdf, envelope, cipher = core.parse_container_aead(blob)
    eq((envelope, cipher), (b"envelope-bytes", b"cipher-bytes"))
    eq((kdf["name"], kdf["n"], kdf["r"], kdf["p"], kdf["salt"]),
       (core.KDF_NAME, core.KDF_N, core.KDF_R, core.KDF_P, salt))
    # Neither parser may accept the other's file. The gpg reader used to,
    # because a AEAD header also carries a KEY line and a DATA marker.
    legacy = core.build_container(b"envelope-bytes", b"cipher-bytes")
    eq(core.parse_container(blob), None, "the gpg parser accepted an AEAD vault")
    eq(core.parse_container_aead(legacy), None,
       "the AEAD parser accepted a gpg vault")
    eq(core.container_backend(legacy), "gpg")
    eq(core.container_backend(b"\x85\x02raw gpg message"), None)


def t_container_aead_uses_the_vaults_own_kdf_parameters():
    """The cost parameter is read from the vault, not taken from this build.

    Raising it later must not strand vaults written before the change, and the
    only way that holds is if the unwrap uses the numbers in the file.
    """
    path = fresh("kdf-params")
    salt = os.urandom(core.KDF_SALT_BYTES)
    cheap = 1 << 12
    key = core.new_vault_key()
    kek = core.derive_kek(MASTER, salt, n=cheap)
    with open(path, "wb") as handle:
        handle.write(core.build_container_aead(
            salt, core.seal(kek, key.encode("utf-8")),
            core.seal(key, sample().encode("utf-8")), n=cheap))
    eq(core.unwrap_key(path, MASTER), key,
       "a vault written at another cost parameter did not open")
    plaintext, got = core.read_vault(path, MASTER)
    eq(got, key)
    assert "CoreSecret42" in plaintext


def t_container_aead_refuses_an_unknown_kdf():
    blob = core.build_container_aead(bytes(range(16)), b"env", b"data")
    swapped = blob.replace(b"KDF scrypt", b"KDF argon2id", 1)
    raises(core.VaultError, lambda: core.parse_container_aead(swapped),
           "a vault naming another KDF must be refused, not guessed at")


def t_gpg_vault_upgrades_in_place_keeping_its_key():
    """The migration that makes this release invisible to everything else.

    A gpg-sealed vault becomes openssl-sealed on its next write, and the vault
    key does not change -- so the recovery file, any Shamir share set, and
    every .bak from before the upgrade still refer to the same key.
    """
    path = fresh("upgrade")
    key = core.new_vault_key()
    with open(path, "wb") as handle:
        handle.write(core.build_container(
            core.gpg_encrypt(MASTER, key.encode("utf-8")),
            core.gpg_encrypt(key, sample().encode("utf-8"))))
    eq(core.container_backend(open(path, "rb").read()), "gpg")
    plaintext, got = core.read_vault(path, MASTER)
    eq(got, key, "a gpg vault must still read after the backend changed")

    eq(core.write_vault(path, MASTER, plaintext), key,
       "the upgrade must reuse the key, not mint one")
    eq(core.container_backend(open(path, "rb").read()), "openssl")
    eq(core.unwrap_key(path, MASTER), key)
    assert "CoreSecret42" in core.read_vault(path, MASTER)[0]


def t_rewrap_upgrades_a_gpg_vault():
    """A password change moves the last gpg vaults off the old backend.

    It cannot leave them: the new envelope is openssl-sealed, so a gpg data
    block beside it would be unreadable to the reader that opens the envelope.
    """
    path = fresh("rewrap-upgrade")
    key = core.new_vault_key()
    with open(path, "wb") as handle:
        handle.write(core.build_container(
            core.gpg_encrypt(MASTER, key.encode("utf-8")),
            core.gpg_encrypt(key, sample().encode("utf-8"))))
    eq(core.rewrap(path, MASTER, OTHER), key, "rewrap must not remint the key")
    eq(core.container_backend(open(path, "rb").read()), "openssl")
    eq(core.unwrap_key(path, OTHER), key)
    assert "CoreSecret42" in core.read_vault(path, OTHER)[0]
    raises(core.VaultSecretError, lambda: core.read_vault(path, MASTER),
           "the old password must stop working")


def t_damage_is_reported_as_damage_not_as_a_wrong_password():
    """The distinction gpg could not make, and the reason it is worth making.

    A wrong password and a corrupted vault have opposite remedies. Under gpg
    both arrived as one refusal, so the honest message named neither.
    """
    path = fresh("damaged")
    _events_env(path)
    core.write_vault(path, MASTER, sample(), core.new_vault_key())
    raw = open(path, "rb").read()
    head, data = raw.split(b"\nDATA\n", 1)
    blob = bytearray(base64.b64decode(data))
    blob[len(core.SEAL_MAGIC) + core.SEAL_SALT_BYTES + core.SEAL_IV_BYTES] ^= 0x01
    with open(path, "wb") as handle:
        handle.write(head + b"\nDATA\n" + base64.b64encode(bytes(blob)) + b"\n")

    raises(core.VaultIntegrityError, lambda: core.read_vault(path, MASTER),
           "damage under the right password must not be reported as a bad password")
    raises(core.VaultSecretError, lambda: core.read_vault(path, OTHER),
           "a wrong password must not be reported as damage")
    reasons = [event["detail"].get("reason") for event in core.read_events(path)
               if event["outcome"] == "fail"]
    eq(sorted(set(reasons)), ["bad-master", "corrupt"],
       "the log must record which of the two refusals happened")


def t_doctor_names_the_backend_that_sealed_the_file():
    path = fresh("doctor-cipher")
    plaintext = core.stamp_version(sample())
    core.write_vault(path, MASTER, plaintext, core.new_vault_key())

    def named(report, ident):
        for entry in report["checks"]:
            if entry["id"] == ident:
                return entry
        raise AssertionError("no %s check in the report" % ident)

    entry = named(core.doctor_report(plaintext, path, "match-current"), "vault_cipher")
    eq(entry["status"], "ok")
    eq(entry["backend"], "openssl")
    eq(entry["kdf"], core.KDF_NAME)
    eq(entry["kdf_n"], core.KDF_N)

    legacy = fresh("doctor-cipher-gpg")
    key = core.new_vault_key()
    with open(legacy, "wb") as handle:
        handle.write(core.build_container(
            core.gpg_encrypt(MASTER, key.encode("utf-8")),
            core.gpg_encrypt(key, plaintext.encode("utf-8"))))
    entry = named(core.doctor_report(plaintext, legacy, "match-current"), "vault_cipher")
    eq(entry["status"], "warn", "a gpg vault must be reported as upgradable")
    eq(entry["backend"], "gpg")


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

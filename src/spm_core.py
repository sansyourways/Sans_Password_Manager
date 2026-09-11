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
# 5 because a record may now carry a `hidden` flag inside its attributes, and
# an older build that edited such a record would re-encode the attributes
# without it -- quietly un-hiding an entry someone deliberately hid. Reading a
# format-5 vault still works on 4.1.0; stamp_version is what stops it writing
# one back.
VAULT_FORMAT_VERSION = 6

CONTAINER_MAGIC = b"SPM-VAULT-3"

# Key derivation is pinned rather than inherited: a user's gpg.conf can change
# all of it underneath the application, and a security parameter that is
# implicit can be neither reviewed nor migrated. GnuPG 2.2 already defaults to
# s2k mode 3 at the maximum count, so the measurable change is the digest,
# whose default is SHA1.
#
# From 4.0.0 nothing in production writes a gpg vault -- the openssl backend
# below does -- so this policy now describes only vaults written by earlier
# releases, and gpg_encrypt exists to build them for the tests that prove the
# migration path. It stays here rather than in the suite so that there is still
# exactly one statement of the policy in the repository.
S2K_ARGS = ["--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
            "--s2k-count", "65011712"]

HISTORY_RETENTION_DEFAULT = 20


class VaultError(Exception):
    """Anything that should reach a user as a refusal rather than a traceback."""


class VaultSecretError(VaultError):
    """The supplied secret does not open this vault.

    gpg could not tell a caller this: it refused a wrong passphrase and a
    damaged file with the same non-zero exit, so every caller that wanted to
    say "wrong master password" was guessing. An authenticated envelope makes
    the two separable, and separating them is the point of naming them.
    """


class VaultSecretKeyError(VaultError):
    """This vault is bound to a Secret Key and this machine does not have it.

    Deliberately not a VaultSecretError: nothing was typed wrong. Reporting a
    missing Secret Key as "wrong master password" would send the user to retype
    a password that was correct, which is the one response that cannot help.
    """


class VaultIntegrityError(VaultError):
    """The envelope opened but the sealed data failed authentication.

    Which means the secret was right and the bytes are damaged -- a distinction
    worth surfacing, because the two have opposite remedies: retype, or
    restore.
    """


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
    """Seal under gpg, the way releases before 4.0.0 did.

    No production path calls this any more. It is what the migration tests
    build a pre-4.0.0 vault with, so that they upgrade a real one rather than
    an approximation of one.
    """
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


# ----- openssl backend -------------------------------------------------------
# gpg seals both layers of a vault by stretching a passphrase. That is right
# for the master password and pure waste for the vault key, which is 256
# random bits and has nothing left to stretch -- format 3 established the
# separation and then paid the stretching cost twice anyway. Format 5 stops:
# the master password goes through scrypt, which is memory-hard where gpg's
# SHA512 iteration is not, and the data is sealed under the vault key directly.
#
# openssl is the cipher because it is the only one on every platform SPM
# supports. Python's hashlib carries scrypt, HMAC and PBKDF2 but no AES, and a
# third-party dependency is the portability rule this project is built on.
# Using its command line imposes three constraints, and each one shapes the
# code below rather than being worked around:
#
#   Keys reach it on a file descriptor. `openssl enc -K` puts the key in argv,
#   where any local user reads it out of /proc/<pid>/cmdline. OpenSSL 3 scrubs
#   argv shortly after startup, but there is a window, and LibreSSL is not
#   known to scrub at all. `-pass fd:` has no such window.
#
#   A passphrase read from that descriptor is read as a *line*, so key
#   material handed to openssl must be text containing no newline: a raw
#   32-byte key with an 0x0A byte in it would be silently truncated, and the
#   vault would still encrypt and decrypt perfectly with a key a fifth of the
#   intended length. Everything passed here is base64.
#
#   Authentication is ours. `openssl enc` offers no AEAD mode that carries a
#   tag, so this is encrypt-then-MAC, with a MAC key derived in-process that
#   never crosses to another program at all.

# Named for what it is rather than numbered, deliberately. The gpg container
# was "SPM-VAULT-3" back when the record format was also 3; the two drifted at
# format 4, and a header reading "SPM-VAULT-5" beside a META_VAULT_VERSION row
# saying 4 would invite exactly the confusion that gets a format misread. This
# magic names the sealing generation; the record format keeps its own number.
CONTAINER_MAGIC_AEAD = b"SPM-VAULT-AEAD1"

SEAL_MAGIC = b"SPMSEAL1"
# openssl's PKCS5 salt is eight bytes and it discards anything longer with a
# warning, so eight is what the format carries rather than a size that only
# looks stronger. The IV is separate and full width: a salt collision alone
# must not repeat a CTR keystream, and an IV is not secret, so it is the one
# value here that may travel in argv.
#
# Re-measured before 4.10.0, because "widen the salt to 16" reads like a free
# improvement and is not one. `openssl enc -S` on 3.0.20 answers
# "hex string is too long, ignoring excess" and a 16-byte salt produces
# ciphertext identical to its own first 8 bytes -- so the widening would reach
# the MAC key and nothing else, while the format claimed otherwise. Deriving
# the cipher key in Python instead would use the full width, but openssl's CLI
# can only take a raw key as -K on argv, and argv is world-readable; that is
# the whole reason _key_fd exists. Eight stays, and this note is here so the
# next person measures rather than assuming.
SEAL_SALT_BYTES = 8
SEAL_IV_BYTES = 16
SEAL_TAG_BYTES = 32
SEAL_CIPHER = "aes-256-ctr"
SEAL_MAC_INFO = b"SPMSEAL1-mac"

# The vault records the KDF by name and parameters, which is what turns a
# later move to Argon2id into a value the reader dispatches on instead of
# another format change. It is also what lets this number be raised without
# stranding anything: the reader derives with the vault's own n, not this
# build's, so a vault written at 2**15 keeps opening and moves up on its next
# write.
#
# 2**16 is 64 MiB and measures ~305 ms on the reference machine, against
# ~124 ms at 2**15 -- so an offline guesser drops from about 8 attempts per
# second per core to about 3. 2**17 was measured too (128 MiB, ~547 ms) and
# not taken: scrypt's cost is memory, and SPM runs on phones under Termux
# where a transient 128 MiB allocation is a plausible failure and a vault that
# cannot be opened on the device it lives on is worse than a slower guesser.
KDF_NAME = "scrypt"
KDF_N = 1 << 16
KDF_R = 8
KDF_P = 1
KDF_SALT_BYTES = 16
KDF_DKLEN = 32
# hashlib.scrypt refuses anything past its default maxmem with "memory limit
# exceeded", and the default is below what n=2**15 needs, so the bound is
# stated rather than inherited: 128 * n * r is the working set.
KDF_MAXMEM = 128 * KDF_N * KDF_R * 2

# ----- hardware-held wrapping ------------------------------------------------
# A security key can derive a stable secret from a credential and a salt --
# WebAuthn calls it the PRF extension, CTAP2 calls it hmac-secret. That secret
# never leaves the device except as its output, and the device will not produce
# it without the user verification it was enrolled with.
#
# SPM uses it as key material and nothing more: the vault key is sealed under it
# with the same encrypt-then-MAC the master password path uses, so the only new
# cryptography here is the derivation of a wrapping key from the device's 32
# bytes, and that is one HMAC with a fixed label.
HARDWARE_SECRET_BYTES = 32
HARDWARE_WRAP_INFO = b"SPM-HARDWARE-WRAP-v1"
HARDWARE_SALT_BYTES = 32

# ----- secret key ------------------------------------------------------------
# 128 bits generated once per vault and kept off the vault file, mixed into the
# KEK derivation alongside the master password. What it buys is one thing, and
# only that one thing: a copy of the vault file -- on a sync target, in a
# bundle, in somebody's backup -- stops being attackable offline, because there
# is no longer anything in it to guess at. A weak master password and a strong
# one become equally unbreakable to whoever holds only the file.
#
# What it does not buy is any defence against a compromise of the machine that
# holds both, and the wording of every message here has to keep that honest.
#
# 128 rather than 256: both are unguessable, and only one of them is short
# enough that a person will actually write it down. The value is worthless if
# it is never transcribed, because then the only copy is on the disk it was
# meant to be independent of.
SECRET_KEY_BYTES = 16
SECRET_KEY_INFO = b"SPM-SECRET-KEY-v1"
SECRET_KEY_TAG = "S1"
# Base32 rather than base64: the alphabet is A-Z and 2-7, so it survives being
# read aloud, written on paper and typed back in a different case. The digits
# it excludes are exactly the ones that look like letters -- there is no 0 to
# confuse with O and no 1 to confuse with I or L.
SECRET_KEY_GROUPS = (6, 5, 5, 5, 5)


def _key_fd(key_text):
    """A read fd holding `key_text`, for openssl's -pass fd:.

    Same reasoning as _passphrase_fd: argv is world-readable. The newline is
    what openssl strips when it reads the line back, so it is not part of the
    passphrase.
    """
    try:
        material = key_text.encode("ascii")
    except UnicodeEncodeError:
        # Every key this format seals with is base64, so non-ASCII here means
        # the caller passed something else -- an old master password from a
        # recovery file, which recover() tries speculatively. A refusal it can
        # catch is better than a UnicodeEncodeError out of a crypto path.
        raise VaultError("key material for openssl must be ASCII")
    if b"\n" in material or b"\r" in material:
        raise VaultError("key material for openssl must be a single line")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, material + b"\n")
    finally:
        os.close(write_fd)
    return read_fd


def openssl_ctr(key_text, salt, iv, payload, decrypt=False, timeout=60):
    """AES-256-CTR under a key openssl derives from `key_text` and `salt`.

    The derivation is PBKDF2-HMAC-SHA256 at one iteration, which
    hashlib.pbkdf2_hmac reproduces byte for byte -- the known-answer test in
    the suite depends on exactly that, so a platform whose openssl derives
    differently fails a test rather than writing a vault nothing can open.

    One iteration is not an oversight. Both callers pass full-entropy key
    material -- a random vault key, or an scrypt output -- so this step exists
    to produce a key and an IV, not to stretch a guessable secret. The
    stretching happens once, in scrypt, where the low-entropy secret actually
    is.
    """
    fd = _key_fd(key_text)
    try:
        return subprocess.check_output(
            ["openssl", "enc", "-" + SEAL_CIPHER, "-d" if decrypt else "-e",
             "-pbkdf2", "-iter", "1", "-md", "sha256",
             "-S", salt.hex(), "-iv", iv.hex(), "-pass", "fd:%d" % fd],
            input=payload, stderr=subprocess.DEVNULL,
            timeout=timeout, pass_fds=(fd,))
    finally:
        os.close(fd)


def _seal_mac_key(key_text, salt):
    """A MAC key independent of the encryption key openssl derives.

    openssl computes HMAC(key_text, salt || counter) for its blocks; this
    computes HMAC(key_text, "SPMSEAL1-mac" || salt), a different message under the
    same key, so neither derivation reveals the other.
    """
    return hmac.new(key_text.encode("ascii"), SEAL_MAC_INFO + salt,
                    hashlib.sha256).digest()


def seal(key_text, payload):
    """Encrypt-then-MAC `payload` under `key_text`. Returns one opaque blob."""
    salt = os.urandom(SEAL_SALT_BYTES)
    iv = os.urandom(SEAL_IV_BYTES)
    cipher = openssl_ctr(key_text, salt, iv, payload)
    body = SEAL_MAGIC + salt + iv + cipher
    return body + hmac.new(_seal_mac_key(key_text, salt), body,
                           hashlib.sha256).digest()


def unseal(key_text, blob):
    """`payload` from a blob `seal` produced, or a refusal.

    The tag is checked before anything is decrypted, so a modified blob is
    never fed to a cipher. CTR decryption cannot fail on its own -- it will
    happily turn corrupted input into corrupted output -- which is precisely
    why the tag has to be the gate rather than an afterthought.
    """
    head = len(SEAL_MAGIC) + SEAL_SALT_BYTES + SEAL_IV_BYTES
    if len(blob) < head + SEAL_TAG_BYTES or not blob.startswith(SEAL_MAGIC):
        raise VaultError("sealed block is not in this format")
    body, tag = blob[:-SEAL_TAG_BYTES], blob[-SEAL_TAG_BYTES:]
    salt = body[len(SEAL_MAGIC):len(SEAL_MAGIC) + SEAL_SALT_BYTES]
    iv = body[len(SEAL_MAGIC) + SEAL_SALT_BYTES:head]
    expected = hmac.new(_seal_mac_key(key_text, salt), body, hashlib.sha256)
    if not hmac.compare_digest(expected.digest(), tag):
        raise VaultError("sealed block failed authentication")
    return openssl_ctr(key_text, salt, iv, body[head:], decrypt=True)


def bind_secret_key(master, secret):
    """The password scrypt actually stretches, bound to a Secret Key.

    One HMAC, with the Secret Key as the key and the password as the message.
    That way round rather than the reverse: HMAC's security argument is about
    an unknown key, and here the unknown value is the Secret Key -- the
    password is the part an attacker is willing to enumerate.

    The result is base64 so that everything downstream keeps handling text.
    """
    raw = hmac.new(secret_key_bytes(secret), master.encode("utf-8"),
                   hashlib.sha256).digest()
    return base64.b64encode(raw).decode("ascii")


def derive_kek(master, salt, n=KDF_N, r=KDF_R, p=KDF_P, secret=""):
    """The key-encryption key for the master password, as openssl-safe text.

    `secret` is the vault's Secret Key when it has one. Empty means the vault
    is sealed under the password alone, which is every vault written before
    4.10.0 and every vault whose owner never enabled one.
    """
    if secret:
        master = bind_secret_key(master, secret)
    raw = hashlib.scrypt(master.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                         dklen=KDF_DKLEN, maxmem=KDF_MAXMEM)
    return base64.b64encode(raw).decode("ascii")


# ----- container -------------------------------------------------------------
# A format-3 vault is one file: a header line, the vault key sealed under the
# master password, then the vault ciphertext sealed under that key. Keeping it
# to a single self-contained file is why every path that copies, backs up,
# syncs or bundles "the vault" needed no change when the format did.

def is_container(raw):
    """True for any sealed vault, whichever backend sealed it."""
    return (raw.startswith(CONTAINER_MAGIC + b"\n")
            or raw.startswith(CONTAINER_MAGIC_AEAD + b"\n"))


def container_backend(raw):
    """"openssl", "gpg", or None for a vault that predates the container."""
    if raw.startswith(CONTAINER_MAGIC_AEAD + b"\n"):
        return "openssl"
    if raw.startswith(CONTAINER_MAGIC + b"\n"):
        return "gpg"
    return None


def build_container(envelope, cipher):
    return (CONTAINER_MAGIC + b"\nKEY " + base64.b64encode(envelope) +
            b"\nDATA\n" + base64.b64encode(cipher) + b"\n")


def parse_container(raw):
    """(envelope, cipher) for a gpg-sealed vault, else None.

    The magic is checked exactly rather than through is_container, which
    answers for both backends: an AEAD header also carries a KEY line and a
    DATA marker, so the lenient test parsed one happily and handed back an
    envelope no gpg would ever open.
    """
    if not raw.startswith(CONTAINER_MAGIC + b"\n"):
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


# An AEAD-format vault keeps the shape format 3 established -- one file, a key
# envelope, then the data -- and adds the line that made the whole exercise
# worth doing: the KDF, by name and by parameter. Without it a change of
# stretching function is another format version; with it, it is a value the
# reader already knows how to dispatch on.

def build_container_aead(kdf_salt, envelope, cipher, n=KDF_N, r=KDF_R, p=KDF_P,
                         secret_key=False):
    # sk announces that a Secret Key was mixed into the derivation. It is a
    # field on a line that already carries the KDF's parameters, because that
    # is what it is: without it the reader would derive from the password alone
    # and report a correct password as wrong.
    #
    # Unauthenticated, like everything else in this header, and it fails closed
    # for the same reason the cost parameters do. Stripping sk=1 does not
    # downgrade the vault to a password-only one that opens; it produces a
    # different KEK, the envelope's tag rejects it, and the reader says the
    # secret does not open this vault. There is no weaker-but-working state to
    # push a vault into.
    return (CONTAINER_MAGIC_AEAD +
            b"\nKDF " + KDF_NAME.encode("ascii") +
            b" n=%d r=%d p=%d salt=" % (n, r, p) +
            base64.b64encode(kdf_salt) +
            (b" sk=1" if secret_key else b"") +
            b"\nKEY " + base64.b64encode(envelope) +
            b"\nDATA\n" + base64.b64encode(cipher) + b"\n")


def parse_container_aead(raw):
    """(kdf, envelope, cipher) for an AEAD vault, else None.

    `kdf` is a dict carrying the name and every parameter the vault was
    written with, so the unwrap uses the vault's own numbers rather than this
    build's constants -- which is what lets a cost parameter be raised without
    stranding vaults written before the change.
    """
    if not raw.startswith(CONTAINER_MAGIC_AEAD + b"\n"):
        return None
    try:
        header, data = raw.split(b"\nDATA\n", 1)
        _, kdf_line, key_line = header.split(b"\n", 2)
        name, params = kdf_line[len(b"KDF "):].split(b" ", 1)
        fields = dict(item.split(b"=", 1) for item in params.split(b" "))
        kdf = {"name": name.decode("ascii"),
               "n": int(fields[b"n"]), "r": int(fields[b"r"]),
               "p": int(fields[b"p"]),
               # Absent means no, which is what every vault written before
               # 4.10.0 says by saying nothing. Read by name out of the same
               # dict as the cost parameters, so an old reader meeting a new
               # field ignores it and a new reader meeting an old header gets
               # the right answer without a format bump.
               "sk": fields.get(b"sk") == b"1",
               "salt": base64.b64decode(fields[b"salt"])}
        envelope = base64.b64decode(key_line[len(b"KEY "):])
        cipher = base64.b64decode(data)
    except Exception as exc:
        raise VaultError("vault key container is corrupt") from exc
    if not envelope or not cipher or not kdf["salt"]:
        raise VaultError("vault key container is incomplete")
    if kdf["name"] != KDF_NAME:
        # Named, not guessed. A vault written by a build that adopted a
        # different stretching function must refuse here rather than derive
        # the wrong key and report a wrong master password.
        raise VaultError(
            "this vault was written with the %s key derivation and this SPM "
            "implements %s; upgrade SPM rather than guessing"
            % (kdf["name"], KDF_NAME))
    return kdf, envelope, cipher


def vault_seal_summary(vault_path):
    """(backend, kdf) describing how a vault file on disk is sealed.

    kdf is None for anything gpg sealed, which is the point: the old format
    had no way to say what it stretched a password with, so a report about it
    can only name the backend.
    """
    # An unreadable file is the caller's problem and raises. Only a readable
    # one that is not a container returns None -- "there is no vault here" and
    # "this vault predates the container" are different answers and must not
    # arrive as the same one.
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    backend = container_backend(raw)
    if backend != "openssl":
        return backend, None
    return backend, parse_container_aead(raw)[0]


def unwrap_key_aead(kdf, envelope, master, secret=""):
    kek = derive_kek(master, kdf["salt"], kdf["n"], kdf["r"], kdf["p"],
                     secret=secret)
    try:
        return unseal(kek, envelope).decode("utf-8")
    except VaultError:
        raise VaultSecretError("that secret does not open this vault")


def hardware_kek(secret):
    """The wrapping key for a secret a security key derived.

    The device's output is not used as a key directly. One HMAC under a fixed
    label separates this use from any other the same PRF secret is put to --
    a second application asking the same credential for the same salt gets the
    same 32 bytes, and this makes SPM's wrapping key not be those 32 bytes.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise VaultError("a hardware secret must be bytes")
    if len(secret) != HARDWARE_SECRET_BYTES:
        raise VaultError("a hardware secret must be exactly %d bytes"
                         % HARDWARE_SECRET_BYTES)
    raw = hmac.new(bytes(secret), HARDWARE_WRAP_INFO, hashlib.sha256).digest()
    return base64.b64encode(raw).decode("ascii")


def hardware_wrap_key(secret, vault_key):
    """The vault key sealed under a security key's secret, as base64 text."""
    blob = seal(hardware_kek(secret), vault_key.encode("utf-8"))
    return base64.b64encode(blob).decode("ascii")


def hardware_unwrap_key(secret, wrapped):
    """The vault key back, or a refusal that names the security key.

    Wrong-secret and tampered-blob both arrive here as the same failure from
    `unseal`, which is deliberate: the tag is checked before anything is
    decrypted, so neither case reveals which it was.
    """
    try:
        blob = base64.b64decode(wrapped, validate=True)
    except ValueError as exc:          # binascii.Error subclasses it
        raise VaultSecretError("that security key does not open this vault") from exc
    try:
        return unseal(hardware_kek(secret), blob).decode("utf-8")
    except VaultError as exc:
        raise VaultSecretError("that security key does not open this vault") from exc


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
EVENT_KINDS = ("unlock", "write", "rewrap", "recover", "restore", "archive",
               "hardware", "secret-key")
EVENT_OUTCOMES = ("ok", "fail")
# Details are key=value with both sides constrained, rather than free text.
# Free text is how a label ends up in a log one day: someone adds a helpful
# "which record" to an error path and nobody notices it is now on disk in the
# clear. A closed vocabulary makes that a test failure instead of a leak.
EVENT_DETAIL_KEYS = ("records", "format", "scope", "reason")
# "reason" carries why a security-key event happened as well as why an
# unlock failed. Constrained the same way and for the same reason: a
# free-text detail is how a device label reaches the log in the clear.
EVENT_REASONS = ("bad-master", "corrupt", "missing", "unreadable",
                 "enrolled", "forgotten", "bad-secret", "vault-replaced",
                 "enabled", "disabled", "rotated", "imported")
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


def encode_attrs(folder="", fields=None, hidden=False):
    """The attributes column for a record, or "" when there is nothing to say.

    Empty is empty rather than an encoded empty object, so a record that uses
    none of this is byte-identical to how format 3 wrote it.
    """
    folder = (folder or "").strip()
    fields = [(str(n).strip(), str(v)) for n, v in (fields or []) if str(n).strip()]
    hidden = bool(hidden)
    if not folder and not fields and not hidden:
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
    if hidden:
        payload["hidden"] = True
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_attrs(column):
    """(folder, [(name, value)], hidden) for an attributes column.

    Never raises. A column this build cannot read is a record it should still
    show, minus the part it did not understand -- refusing would make one bad
    row hide a whole vault.

    Three values rather than two, deliberately. Every caller unpacked two, so
    adding `hidden` breaks each of them at the point of use instead of letting
    a writer re-encode a record without the flag it never read. That silent
    drop is exactly how folders and custom fields went missing from twenty
    export formats until 4.1.0.
    """
    column = (column or "").strip()
    if not column:
        return "", [], False
    try:
        payload = json.loads(base64.b64decode(column, validate=True)
                             .decode("utf-8"))
    except Exception:
        return "", [], False
    if not isinstance(payload, dict):
        return "", [], False
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
    return folder[:ATTRS_FOLDER_MAX], fields, payload.get("hidden") is True


# ----- record sanitising -----------------------------------------------------
# Every character str.splitlines() honours, which is eleven and not the three
# people remember. A value carrying one of these is written as one record and
# read back as two, so the tail becomes an orphan fragment no surface displays.
#
# This constant is here because there were two implementations of it and no
# definition: `sanitize_field` in the shell collapses them with tr and sed,
# `_vf` in the dashboard collapses them with a Python loop, and the pair of
# them agreed only because someone kept them in step by hand. RECORD_BREAKS
# below is a third list, for detection rather than prevention, and it omits
# the structural three on purpose. A fourth writer -- typed records -- is what
# made the absence of one definition worth fixing rather than noting.
#
# The shell keeps its own tr/sed rather than calling into here, because this
# runs per field and a Python process per field is not free. The regression
# suite feeds all eleven through both and fails if they disagree, which is the
# guarantee that matters; sharing the code was never the point.
VAULT_BREAK_CHARS = ("\t\r\n\v\f\x1c\x1d\x1e\x85"
                     "\u2028\u2029")


def sanitize_field(value):
    """A value safe to write into one tab-separated, line-based record."""
    text = "" if value is None else str(value)
    for ch in VAULT_BREAK_CHARS:
        text = text.replace(ch, " ")
    return text


# ----- typed records ---------------------------------------------------------
# Seven record types were asked for at once -- API tokens, database
# credentials, cards, identities, licences, Wi-Fi and servers -- and the way
# this repository had added a record type before was a family of shell
# commands, a set of web routes, a nav entry and a dashboard tile, per type.
# `cmd_notes_add` through `cmd_notes_delete` is about 200 lines of shell for
# one type; seven of those is 1,400 lines whose only difference is which
# fields they prompt for, and seven more chances for the CLI and the Dashboard
# to disagree about a record. 4.1.0 is what that disagreement costs: five
# copies of the column order, all twenty export formats silently dropping
# folders and custom fields, and no test failing because SPM was reading back
# exactly what SPM wrote.
#
# So a type is data here, not code. A schema names its fields and says which
# of them hold secrets; every surface -- add, list, view, edit, export,
# redaction, the Security page -- reads the schema instead of knowing the
# type. Adding an eighth type is a dict entry and its translations.
#
# The row is deliberately shaped like NOTE:
#
#     REC:<type>  <id>  <label>  <payload-b64>  <created>  <attrs>
#
# Six tab-separated columns, with the secret-bearing payload in field 3 --
# where NOTE keeps its body and a password row keeps its password. That is not
# cosmetic. `_describe_record` documents that it never reads field 3 because
# every shape SPM writes keeps the secret there, and `scan_broken_records`
# leans on the same column count. A seventh column, or a payload in field 2,
# would have made both of those quietly wrong for the new types only.
#
# The type travels in the tag rather than inside the payload so that counting
# records, listing one type, and describing a damaged row never require
# decoding base64 -- and so a vault stays greppable by someone holding nothing
# but the plaintext and `grep`.

RECORD_TAG_PREFIX = "REC:"
RECORD_TYPE_MAX = 32
RECORD_PAYLOAD_MAX = 65536
RECORD_VALUE_MAX = 8192

# What a field is, rather than how it is drawn. "secret" is the only kind that
# carries meaning below the interface: it decides redaction, what an export
# masks, and what never reaches an event. Everything else is presentation.
FIELD_PLAIN = "plain"
FIELD_SECRET = "secret"

# (name, kind, widget, required)
RECORD_SCHEMAS = {
    "api-token": {
        "label": "API Token",
        "icon": "token",
        "fields": (
            ("service", FIELD_PLAIN, "line", True),
            ("token", FIELD_SECRET, "line", True),
            ("username", FIELD_PLAIN, "line", False),
            ("environment", FIELD_PLAIN, "line", False),
            ("expires", FIELD_PLAIN, "date", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "db-credential": {
        "label": "Database Credential",
        "icon": "database",
        "fields": (
            ("engine", FIELD_PLAIN, "line", False),
            ("host", FIELD_PLAIN, "line", True),
            ("port", FIELD_PLAIN, "number", False),
            ("database", FIELD_PLAIN, "line", False),
            ("username", FIELD_PLAIN, "line", True),
            ("password", FIELD_SECRET, "line", True),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "credit-card": {
        "label": "Credit Card",
        "icon": "card",
        "fields": (
            ("cardholder", FIELD_PLAIN, "line", True),
            ("number", FIELD_SECRET, "line", True),
            ("brand", FIELD_PLAIN, "line", False),
            ("expiry", FIELD_PLAIN, "month", True),
            ("cvv", FIELD_SECRET, "line", False),
            ("pin", FIELD_SECRET, "line", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "identity": {
        "label": "Identity Document",
        "icon": "identity",
        "fields": (
            ("full_name", FIELD_PLAIN, "line", True),
            ("document_type", FIELD_PLAIN, "line", False),
            ("document_number", FIELD_SECRET, "line", True),
            ("nationality", FIELD_PLAIN, "line", False),
            ("issued", FIELD_PLAIN, "date", False),
            ("expires", FIELD_PLAIN, "date", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "software-license": {
        "label": "Software Licence",
        "icon": "licence",
        "fields": (
            ("product", FIELD_PLAIN, "line", True),
            ("license_key", FIELD_SECRET, "line", True),
            ("version", FIELD_PLAIN, "line", False),
            ("licensed_to", FIELD_PLAIN, "line", False),
            ("seats", FIELD_PLAIN, "number", False),
            ("purchased", FIELD_PLAIN, "date", False),
            ("expires", FIELD_PLAIN, "date", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "wifi": {
        "label": "Wi-Fi Network",
        "icon": "wifi",
        "fields": (
            ("ssid", FIELD_PLAIN, "line", True),
            ("password", FIELD_SECRET, "line", True),
            ("security", FIELD_PLAIN, "line", False),
            ("hidden_network", FIELD_PLAIN, "line", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "gpg-key": {
        "label": "GPG Key",
        "icon": "gpg",
        "derive": "gpg",
        "fields": (
            ("private_key", FIELD_SECRET, "multiline", True),
            ("passphrase", FIELD_SECRET, "line", False),
            ("uids", FIELD_PLAIN, "line", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "ssh-key": {
        "label": "SSH Key",
        "icon": "ssh",
        # Facts this type computes from its own values -- see record_derived.
        # A name rather than a function, because the schemas are read before
        # the derivations are defined and because a type staying data is the
        # whole point of this engine.
        "derive": "ssh",
        "fields": (
            # The private key is the record. Its type, size, fingerprint and
            # public half are derived from these bytes rather than stored
            # beside them -- see ssh_key_info -- so the record cannot come to
            # disagree with the key it describes.
            ("private_key", FIELD_SECRET, "multiline", True),
            # Held so the agent can load a sealed key without prompting. A
            # key whose passphrase lives in the same vault is no better
            # protected than the vault, which is the trade the user makes by
            # filling this in; leaving it empty means ssh-add asks.
            ("passphrase", FIELD_SECRET, "line", False),
            ("hosts", FIELD_PLAIN, "line", False),
            ("comment", FIELD_PLAIN, "line", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
    "server": {
        "label": "Server",
        "icon": "server",
        "fields": (
            ("hostname", FIELD_PLAIN, "line", True),
            ("address", FIELD_PLAIN, "line", False),
            ("port", FIELD_PLAIN, "number", False),
            ("username", FIELD_PLAIN, "line", True),
            ("password", FIELD_SECRET, "line", False),
            ("notes", FIELD_PLAIN, "multiline", False),
        ),
    },
}

# Ordered, because a dict's order is an implementation detail and this decides
# the order of a nav menu, a `--type` help listing and an export's rows. Sorted
# rather than hand-listed so a new schema cannot be added to the registry and
# forgotten here.
RECORD_TYPES = tuple(sorted(RECORD_SCHEMAS))


def record_tag(record_type):
    """The row tag for a type. Raises on a type this build does not define."""
    record_schema(record_type)
    return RECORD_TAG_PREFIX + record_type


def type_from_tag(tag):
    """The type a row tag names, or "" when the tag is not a typed record.

    Does not check the type against the registry: a vault written by a newer
    SPM may hold a type this build has no schema for, and the honest answer is
    its name rather than a refusal. Callers that need a schema ask for one.
    """
    if not tag.startswith(RECORD_TAG_PREFIX):
        return ""
    return tag[len(RECORD_TAG_PREFIX):]


def record_schema(record_type):
    """The schema for a type, or VaultError naming what is available."""
    schema = RECORD_SCHEMAS.get(record_type)
    if schema is None:
        raise VaultError("unknown record type %r; known types are %s"
                         % (record_type, ", ".join(RECORD_TYPES)))
    return schema


def record_fields(record_type):
    """The ordered (name, kind, widget, required) tuples for a type."""
    return record_schema(record_type)["fields"]


def record_secret_fields(record_type):
    """The field names that hold secrets, as a frozenset.

    One definition, asked by redaction, by exports and by the event log. A
    surface that decides for itself which of its fields are sensitive is the
    shape of defect 4.1.0 found, and a secret is a worse thing to get wrong
    than a folder.
    """
    return frozenset(name for name, kind, _w, _r in record_fields(record_type)
                     if kind == FIELD_SECRET)


def encode_record_payload(record_type, values):
    """The payload column for a typed record.

    Validates against the schema rather than trusting the caller: an unknown
    field name is a typo that would otherwise be written, stored and never
    displayed, because every surface renders the schema's fields and not the
    payload's keys.
    """
    schema_fields = record_fields(record_type)
    known = {name for name, _k, _w, _r in schema_fields}
    values = {str(k): ("" if v is None else str(v)) for k, v in (values or {}).items()}
    unknown = sorted(set(values) - known)
    if unknown:
        raise VaultError("record type %r has no field %s"
                         % (record_type, ", ".join(repr(u) for u in unknown)))
    for name, _kind, _widget, required in schema_fields:
        value = values.get(name, "")
        if required and not value.strip():
            raise VaultError("record type %r requires a value for %r"
                             % (record_type, name))
        if len(value) > RECORD_VALUE_MAX:
            raise VaultError("field %r is longer than %d characters"
                             % (name, RECORD_VALUE_MAX))
    # Written in schema order and skipping empties, so two records holding the
    # same values encode to the same bytes whatever order the caller built its
    # dict in. An export that round-trips must not change the vault.
    payload = {name: values[name]
               for name, _k, _w, _r in schema_fields
               if values.get(name, "")}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    if len(encoded) > RECORD_PAYLOAD_MAX:
        raise VaultError("this record is larger than %d bytes encoded"
                         % RECORD_PAYLOAD_MAX)
    return encoded


def decode_record_payload(record_type, column):
    """{field: value} for a payload column. Never raises.

    Same rule as decode_attrs: a row this build cannot fully read is still a
    row the user should see. Refusing here would let one damaged record hide
    every record of its type.

    Unknown keys are dropped rather than kept. They can only come from a newer
    SPM, and keeping one would let this build re-encode a record with a field
    it cannot render -- which is the silent downgrade stamp_version exists to
    prevent, arriving by another door.
    """
    try:
        known = {name for name, _k, _w, _r in record_fields(record_type)}
    except VaultError:
        return {}
    column = (column or "").strip()
    if not column or column == "-":
        return {}
    try:
        payload = json.loads(base64.b64decode(column, validate=True)
                             .decode("utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return {k: v for k, v in payload.items()
            if k in known and isinstance(v, str)}


SECRET_MASK = "********"


def redact_record(record_type, values):
    """A copy of `values` with every secret field replaced by a fixed mask.

    A fixed mask rather than one sized to the value: a mask whose length
    tracks the secret leaks the secret's length, which for a CVV or a PIN is
    most of what there is to know.
    """
    secrets = record_secret_fields(record_type)
    return {k: (SECRET_MASK if k in secrets and v else v)
            for k, v in (values or {}).items()}



def build_record_row(record_type, record_id, label, values, created,
                     folder="", fields=None, hidden=False):
    """One tab-separated typed-record row, sanitised and schema-checked."""
    payload = encode_record_payload(record_type, values)
    # A custom field may not take a schema field's name. Both cross an export
    # in the same `fields` column and are told apart on the way back by
    # whether the name is in the schema -- so a wifi record carrying a custom
    # field called "password" would come back with one of the two silently
    # gone. Refusing here is the only place that can still say which was meant.
    shadowed = sorted({str(n).strip() for n, _v in (fields or [])}
                      & {f for f, _k, _w, _r in record_fields(record_type)})
    if shadowed:
        raise VaultError(
            "a custom field may not reuse the field name %s on a %s record"
            % (", ".join(repr(name) for name in shadowed), record_type))
    attrs = encode_attrs(folder=folder, fields=fields, hidden=hidden)
    return "\t".join((record_tag(record_type), str(record_id),
                      sanitize_field(label), payload, str(created),
                      attrs or "-"))


def parse_record_row(line):
    """(type, id, label, values, created, folder, fields, hidden) or None.

    None for any line that is not a typed record, so a caller can walk a whole
    vault and let this decide.
    """
    parts = line.split("\t")
    if len(parts) < 5:
        return None
    record_type = type_from_tag(parts[0])
    if not record_type or record_type not in RECORD_SCHEMAS:
        return None
    values = decode_record_payload(record_type, parts[3])
    folder, custom, hidden = decode_attrs(parts[5] if len(parts) > 5 else "")
    return (record_type, parts[1], parts[2], values, parts[4],
            folder, custom, hidden)


# The column order every export writes and every headerless or positional
# reader maps against. One ordered definition, because the places that had
# their own each stopped at a different column: the SQL writer named eight
# while writing eleven, the SQL reader named nine, and the headerless CSV
# readers stopped at `url`. None of them failed a test, because SPM was
# reading back exactly what SPM wrote.
EXPORT_FIELDNAMES = ("type", "id", "label", "username", "secret", "notes",
                     "created", "extra", "url", "folder", "fields", "hidden")


def export_row_from_values(values):
    """A row dict from a positional record, for headerless and SQL readers."""
    return {name: (values[index] if index < len(values) else "")
            for index, name in enumerate(EXPORT_FIELDNAMES)}


# ----- SSH keys --------------------------------------------------------------
# What SPM can say about a stored SSH key without being handed its passphrase.
#
# The roadmap asks for the public key, the fingerprint and the key type to be
# stored beside the private key. They are derived here instead. A fingerprint
# is the one field a user cannot check by eye -- it exists to be compared
# against what a server presents -- and a typed one that is wrong is worse
# than none at all, because it confirms the wrong key. Deriving it means the
# record cannot disagree with the key it describes.
#
# openssh-key-v1 makes that cheap. The container keeps the public key in the
# clear even when the private half is sealed, so the fingerprint of a
# passphrase-protected key is readable without the passphrase -- the case that
# matters most, since that is the key whose bytes an owner is least able to
# inspect by hand. No ssh-keygen, no temporary file, no prompt: the derivation
# is arithmetic over bytes the vault already holds.

SSH_MAGIC = b"openssh-key-v1\x00"
SSH_OPENSSH_HEAD = "-----BEGIN OPENSSH PRIVATE KEY-----"
SSH_PEM_HEADS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)
# The prefixes an authorized_keys line starts with. sk- covers the FIDO2
# resident keys OpenSSH 8.2 added, which are public keys like any other here.
SSH_PUBLIC_PREFIXES = ("ssh-", "ecdsa-", "sk-")

SSH_FORMAT_OPENSSH = "openssh"
SSH_FORMAT_PEM = "pem"
SSH_FORMAT_PUBLIC = "public"
SSH_FORMAT_UNKNOWN = "unknown"


def _ssh_field(blob, offset):
    """One length-prefixed field of an SSH structure, and the offset past it.

    Every length is checked against what is actually there. These bytes come
    out of a vault, but a vault holds what a user pasted into it, and a length
    header trusted blindly is how a truncated key becomes a slice of unrelated
    memory rather than an error message.
    """
    if offset + 4 > len(blob):
        raise ValueError("truncated SSH key structure")
    length = int.from_bytes(blob[offset:offset + 4], "big")
    offset += 4
    if length > len(blob) - offset:
        raise ValueError("truncated SSH key structure")
    return blob[offset:offset + length], offset + length


def ssh_public_blob(private_key):
    """(public blob, cipher name) from an OpenSSH private key, undecrypted.

    The cipher is "none" for a key stored in the clear; anything else names
    what the private half is sealed under, which is how the agent path decides
    whether it needs a passphrase before it asks for one.
    """
    body = "".join(line.strip() for line in (private_key or "").splitlines()
                   if "-----" not in line)
    raw = base64.b64decode(body)
    if not raw.startswith(SSH_MAGIC):
        raise ValueError("not an openssh-key-v1 private key")
    offset = len(SSH_MAGIC)
    cipher, offset = _ssh_field(raw, offset)
    _kdf, offset = _ssh_field(raw, offset)
    _kdf_options, offset = _ssh_field(raw, offset)
    if offset + 4 > len(raw):
        raise ValueError("truncated SSH key structure")
    count = int.from_bytes(raw[offset:offset + 4], "big")
    offset += 4
    if count < 1:
        raise ValueError("the key file declares no keys")
    public, _offset = _ssh_field(raw, offset)
    return public, cipher.decode("ascii", "replace")


def ssh_public_blob_from_line(line):
    """The blob inside an authorized_keys line, checked against its own name.

    A line names its algorithm twice -- once as text and once inside the blob
    -- and they have to agree. A line whose halves disagree would fingerprint
    as one key while reading as another.
    """
    parts = (line or "").split()
    if len(parts) < 2:
        raise ValueError("not an SSH public key line")
    blob = base64.b64decode(parts[1])
    named, _offset = _ssh_field(blob, 0)
    if named.decode("ascii", "replace") != parts[0]:
        raise ValueError("the key line and the key data name different types")
    return blob


def ssh_fingerprint(public_blob):
    """The SHA256 fingerprint, in the form `ssh-keygen -l` prints it."""
    digest = hashlib.sha256(public_blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def ssh_key_type(public_blob):
    """The algorithm named inside a public blob."""
    algorithm, _offset = _ssh_field(public_blob, 0)
    return algorithm.decode("ascii", "replace")


def ssh_key_bits(public_blob):
    """The size `ssh-keygen -l` reports, or 0 for a type not known here.

    Zero is a real answer rather than a failure: a key type this build has
    never heard of still has a fingerprint, and reporting no size is honest
    where guessing one is not.
    """
    algorithm, offset = _ssh_field(public_blob, 0)
    name = algorithm.decode("ascii", "replace")
    if name in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        return 256
    if name == "ssh-dss":
        return 1024
    if name.startswith("ecdsa-sha2-nistp"):
        digits = name[len("ecdsa-sha2-nistp"):].split("@")[0]
        return int(digits) if digits.isdigit() else 0
    if name == "ssh-rsa":
        _exponent, offset = _ssh_field(public_blob, offset)
        modulus, _offset = _ssh_field(public_blob, offset)
        # The bit length of the modulus, not its byte count: an RSA modulus
        # carries a leading zero byte whenever its top bit is set, and
        # counting bytes would report 2056 bits for a 2048-bit key.
        return int.from_bytes(modulus, "big").bit_length()
    return 0


def ssh_public_line(public_blob, comment=""):
    """The one-line authorized_keys form of a public key."""
    line = "%s %s" % (ssh_key_type(public_blob),
                      base64.b64encode(public_blob).decode("ascii"))
    comment = " ".join((comment or "").split())
    return line + (" " + comment if comment else "")


def ssh_key_info(text, comment=""):
    """Everything SPM can derive from a stored SSH key, without a passphrase.

    Every key of the result is always present, even when it could not be
    filled in, so a surface renders one shape instead of testing for absent
    keys. An unreadable key is not an error either: SPM stores what it is
    given, and a key in a format this build cannot parse is still a key its
    owner wants kept. `problem` says why a field is empty, so the answer on
    screen is a reason rather than a blank.
    """
    info = {"format": SSH_FORMAT_UNKNOWN, "type": "", "bits": 0,
            "fingerprint": "", "public": "", "encrypted": False,
            "problem": ""}
    text = (text or "").strip()
    if not text:
        info["problem"] = "no key stored"
        return info
    try:
        if text.startswith(SSH_PUBLIC_PREFIXES):
            blob = ssh_public_blob_from_line(text)
            info["format"] = SSH_FORMAT_PUBLIC
        elif SSH_OPENSSH_HEAD in text:
            blob, cipher = ssh_public_blob(text)
            info["format"] = SSH_FORMAT_OPENSSH
            info["encrypted"] = cipher != "none"
        elif text.startswith(SSH_PEM_HEADS):
            info["format"] = SSH_FORMAT_PEM
            # A PEM key hides its public half behind the same encryption as
            # its private one, so there is nothing to derive without the
            # passphrase. Said plainly rather than reported as corruption:
            # the key is fine, this format just does not answer the question.
            info["encrypted"] = ("ENCRYPTED" in text.split("\n", 1)[0]
                                 or "Proc-Type: 4,ENCRYPTED" in text)
            info["problem"] = ("a PEM key does not carry its public half in "
                               "the clear; convert it with "
                               "`ssh-keygen -p -m RFC4716` to derive one")
            return info
        else:
            info["problem"] = "unrecognised SSH key format"
            return info
    except Exception as failure:                      # noqa: BLE001
        # Anything a malformed key can raise -- bad base64, a truncated
        # structure, a length that overruns -- is the same answer to the
        # caller: this text is not a key SPM can read.
        info["problem"] = str(failure) or "the key could not be read"
        return info
    info["type"] = ssh_key_type(blob)
    info["bits"] = ssh_key_bits(blob)
    info["fingerprint"] = ssh_fingerprint(blob)
    info["public"] = ssh_public_line(blob, comment)
    return info


# ----- OpenPGP keys -----------------------------------------------------------
# The same shape as the SSH section above, and true for the same reason: an
# OpenPGP secret key carries its public half in the clear. A Secret-Key packet
# is a Public-Key packet with the secret material appended, and the fingerprint
# is a hash of only the public part -- so SPM can name a stored key without the
# passphrase, without gpg, and without writing anything to disk.
#
# Checked against gpg's own answer for RSA 2048 and 4096, ed25519 sealed and
# unsealed, ECDSA nistp256 and an ECDH cv25519 subkey.

PGP_ARMOR_HEAD = "-----BEGIN PGP "
PGP_TAG_SECRET_KEY = 5
PGP_TAG_PUBLIC_KEY = 6
PGP_TAG_SECRET_SUBKEY = 7
PGP_TAG_USER_ID = 13
PGP_TAG_PUBLIC_SUBKEY = 14
PGP_PRIMARY_TAGS = (PGP_TAG_SECRET_KEY, PGP_TAG_PUBLIC_KEY)
PGP_SUBKEY_TAGS = (PGP_TAG_SECRET_SUBKEY, PGP_TAG_PUBLIC_SUBKEY)

PGP_ALGORITHMS = {1: "RSA", 2: "RSA", 3: "RSA", 16: "Elgamal", 17: "DSA",
                  18: "ECDH", 19: "ECDSA", 22: "EdDSA", 25: "X25519",
                  27: "Ed25519", 28: "X448", 29: "Ed448"}

# Curve OIDs as they appear in a key packet, by their hex bytes.
PGP_CURVES = {
    "2b06010401da470f01": "ed25519",
    "2b060104019755010501": "cv25519",
    "2a8648ce3d030107": "nistp256",
    "2b81040022": "nistp384",
    "2b81040023": "nistp521",
    "2b8104000a": "secp256k1",
    "2b2403030208010107": "brainpoolP256r1",
    "2b240303020801010b": "brainpoolP384r1",
    "2b240303020801010d": "brainpoolP512r1",
}
# The size a curve *means*, as against the length of a point encoded on it.
PGP_CURVE_BITS = {"ed25519": 255, "cv25519": 255, "nistp256": 256,
                  "nistp384": 384, "nistp521": 521, "secp256k1": 256,
                  "brainpoolP256r1": 256, "brainpoolP384r1": 384,
                  "brainpoolP512r1": 512}


def pgp_dearmor(text):
    """The bytes inside an ASCII-armored block.

    Armor headers ("Version: ...") and the trailing =CRC24 line are not part
    of the data and are dropped; everything between the BEGIN and END lines
    that is neither is base64.
    """
    body = []
    inside = False
    seen_blank = False
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        if line.startswith(PGP_ARMOR_HEAD):
            inside = True
            continue
        if line.startswith("-----END PGP "):
            break
        if not inside:
            continue
        if not line.strip():
            seen_blank = True
            continue
        if line.startswith("="):            # CRC24 checksum, not data
            continue
        if not seen_blank and ": " in line:  # an armor header
            continue
        body.append(line.strip())
    if not body:
        raise VaultError("no armored data between the BEGIN and END lines")
    return base64.b64decode("".join(body))


def pgp_packets(data):
    """(tag, body) for each packet, in order, in both header formats."""
    offset = 0
    while offset < len(data):
        first = data[offset]
        if not first & 0x80:
            raise VaultError("this is not an OpenPGP packet stream")
        if first & 0x40:                                  # RFC 4880 new format
            tag = first & 0x3F
            offset += 1
            if offset >= len(data):
                raise VaultError("the key ends where a length should be")
            marker = data[offset]
            if marker < 192:
                length = marker
                offset += 1
            elif marker < 224:
                if offset + 1 >= len(data):
                    raise VaultError("the key ends inside a length")
                length = ((marker - 192) << 8) + data[offset + 1] + 192
                offset += 2
            elif marker == 255:
                if offset + 5 > len(data):
                    raise VaultError("the key ends inside a length")
                length = int.from_bytes(data[offset + 1:offset + 5], "big")
                offset += 5
            else:
                # A partial body length streams a packet in chunks. Nothing
                # that exports a key writes one, and guessing at the rest
                # would be inventing data.
                raise VaultError("partial packet lengths are not supported")
        else:                                             # old format
            tag = (first & 0x3C) >> 2
            kind = first & 0x03
            offset += 1
            if kind == 0:
                if offset >= len(data):
                    raise VaultError("the key ends where a length should be")
                length = data[offset]
                offset += 1
            elif kind == 1:
                if offset + 2 > len(data):
                    raise VaultError("the key ends inside a length")
                length = int.from_bytes(data[offset:offset + 2], "big")
                offset += 2
            elif kind == 2:
                if offset + 4 > len(data):
                    raise VaultError("the key ends inside a length")
                length = int.from_bytes(data[offset:offset + 4], "big")
                offset += 4
            else:
                raise VaultError("indeterminate packet lengths are not supported")
        yield tag, data[offset:offset + length]
        offset += length


def _pgp_mpi(body, offset):
    """Step over one multiprecision integer; return the new offset and bits.

    Bounds-checked on both sides. Slicing past the end of a bytes object does
    not raise in Python -- it returns something shorter -- so an unchecked
    walk over a truncated key runs off the end, hashes a short slice, and
    produces a fingerprint that is wrong and looks exactly like a right one.
    A fingerprint is the thing you check to know which key you are holding,
    so being confidently wrong is worse than admitting the key is unreadable.
    """
    if offset + 2 > len(body):
        raise VaultError("the key ends inside a length")
    bits = int.from_bytes(body[offset:offset + 2], "big")
    size = (bits + 7) // 8
    if offset + 2 + size > len(body):
        raise VaultError("the key ends inside a value")
    return offset + 2 + size, bits


def pgp_public_material(body):
    """(length of the public material, algorithm id, bits, curve name).

    The length is what the fingerprint is taken over, and it is also where a
    Secret-Key packet's protection byte begins.
    """
    if len(body) < 6:
        raise VaultError("the key packet is too short to be one")
    version = body[0]
    if version not in (4, 6):
        raise VaultError("unsupported key version %d" % version)
    algorithm = body[5]
    # A v6 packet counts its own public material in four bytes before it.
    offset = 6 if version == 4 else 10
    bits = 0
    if algorithm in (1, 2, 3):                    # RSA: modulus, exponent
        offset, bits = _pgp_mpi(body, offset)
        offset, _ = _pgp_mpi(body, offset)
    elif algorithm == 17:                         # DSA: p, q, g, y
        offset, bits = _pgp_mpi(body, offset)
        for _ in range(3):
            offset, _ = _pgp_mpi(body, offset)
    elif algorithm == 16:                         # Elgamal: p, g, y
        offset, bits = _pgp_mpi(body, offset)
        for _ in range(2):
            offset, _ = _pgp_mpi(body, offset)
    elif algorithm in (18, 19, 22):               # ECDH / ECDSA / EdDSA
        if offset >= len(body):
            raise VaultError("the key ends where the curve should be")
        oid_length = body[offset]
        if offset + 1 + oid_length > len(body):
            raise VaultError("the key ends inside the curve name")
        curve = PGP_CURVES.get(body[offset + 1:offset + 1 + oid_length].hex(), "")
        offset += 1 + oid_length
        offset, point_bits = _pgp_mpi(body, offset)
        if algorithm == 18:                       # ECDH carries KDF parameters
            if offset >= len(body) or offset + 1 + body[offset] > len(body):
                raise VaultError("the key ends inside the KDF parameters")
            offset += 1 + body[offset]
        # The MPI holds an encoded point, not a number, so its bit length is
        # the point's and not the curve's: an Ed25519 point measures 263, a
        # number that looks like a key size and is not one. The curve is the
        # honest answer to "how big is this key", and it is what gpg reports.
        return offset, algorithm, PGP_CURVE_BITS.get(curve, 0) or point_bits, curve
    elif algorithm in (25, 27, 28, 29):           # v6 native, fixed width
        width = 56 if algorithm in (28, 29) else 32
        if offset + width > len(body):
            raise VaultError("the key ends inside the public key")
        return offset + width, algorithm, width * 8, PGP_ALGORITHMS[algorithm].lower()
    else:
        raise VaultError("unsupported public key algorithm %d" % algorithm)
    return offset, algorithm, bits, ""


def pgp_fingerprint(body):
    """The fingerprint of one key packet, as gpg prints it."""
    # pgp_public_material walks the packet with a bounds check on every read,
    # so length is already known not to exceed the body -- there is no second
    # check here on purpose. A redundant guard would be a line no test could
    # make fail, which is the same as a line that is not pulling its weight.
    length, _algorithm, _bits, _curve = pgp_public_material(body)
    material = body[:length]
    if body[0] == 4:
        digest = hashlib.sha1(
            b"\x99" + len(material).to_bytes(2, "big") + material)
    else:
        digest = hashlib.sha256(
            b"\x9b" + len(material).to_bytes(4, "big") + material)
    return digest.hexdigest().upper()


def pgp_key_id(fingerprint):
    """The long key id: the last 16 hex digits of the fingerprint."""
    return fingerprint[-16:]


def pgp_is_sealed(body):
    """Whether a Secret-Key packet's secret half is passphrase-protected.

    The octet after the public material says so, and reading it costs nothing:
    0 means the secret is stored in the clear, anything else means protected.
    No passphrase is attempted to find this out, the same way the SSH side
    reads a cipher name rather than trying it.
    """
    length, _algorithm, _bits, _curve = pgp_public_material(body)
    if length >= len(body):
        raise VaultError("the key ends where its protection should be")
    return body[length] != 0


def pgp_key_info(text):
    """Everything SPM can derive from a stored OpenPGP key, without gpg.

    Every key of the result is always present, so a surface renders one shape
    rather than testing for absent keys, and `problem` says why a field is
    empty. A key SPM cannot read is not an error: it is still a key its owner
    wants kept, and the answer on screen is a reason rather than a blank.
    """
    info = {"fingerprint": "", "keyid": "", "algorithm": "", "bits": 0,
            "curve": "", "created": "", "uids": "", "subkeys": 0,
            "secret": False, "encrypted": False, "problem": ""}
    text = (text or "").strip()
    if not text:
        info["problem"] = "no key stored"
        return info
    if PGP_ARMOR_HEAD not in text:
        info["problem"] = "this is not an ASCII-armored OpenPGP key"
        return info
    try:
        data = pgp_dearmor(text)
        primary = None
        uids = []
        for tag, body in pgp_packets(data):
            if tag in PGP_PRIMARY_TAGS and primary is None:
                primary = (tag, body)
            elif tag in PGP_SUBKEY_TAGS:
                info["subkeys"] += 1
            elif tag == PGP_TAG_USER_ID:
                uids.append(body.decode("utf-8", "replace"))
        if primary is None:
            info["problem"] = "the armor holds no key packet"
            return info
        tag, body = primary
        info["secret"] = tag == PGP_TAG_SECRET_KEY
        length, algorithm, bits, curve = pgp_public_material(body)
        info["fingerprint"] = pgp_fingerprint(body)
        info["keyid"] = pgp_key_id(info["fingerprint"])
        info["algorithm"] = PGP_ALGORITHMS.get(algorithm, str(algorithm))
        info["bits"] = bits
        info["curve"] = curve
        info["created"] = _iso_from_epoch(int.from_bytes(body[1:5], "big"))
        info["uids"] = ", ".join(uids)
        if info["secret"]:
            info["encrypted"] = pgp_is_sealed(body)
        del length
    except VaultError as failure:
        info["problem"] = str(failure)
        return info
    except Exception as failure:                      # noqa: BLE001
        # Bad base64, a length that overruns, a packet stream that is not one:
        # to the caller these are all the same answer, and the answer is not a
        # traceback.
        info["problem"] = str(failure) or "the key could not be read"
        return info
    return info


def _iso_from_epoch(seconds):
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(seconds))
    except Exception:                                 # noqa: BLE001
        return ""


# ----- derived record facts ---------------------------------------------------
# Some record types can say more about themselves than they were told. An SSH
# key knows its own type, size and fingerprint; a surface should be able to
# show that without knowing what an SSH key is.
#
# A type opts in with a "derive" name in its schema and the function lands in
# the registry below, so this stays a dictionary lookup rather than a branch
# per type -- the same rule the rest of the engine follows, and the reason
# adding a type is still a dictionary entry.


def _derived_ssh(values):
    info = ssh_key_info(values.get("private_key", ""),
                        comment=values.get("comment", ""))
    rows = []
    if info["type"]:
        rows.append(("ssh.type", "Type", info["type"]))
    if info["bits"]:
        rows.append(("ssh.bits", "Size", "%d" % info["bits"]))
    if info["fingerprint"]:
        rows.append(("ssh.fingerprint", "Fingerprint", info["fingerprint"]))
    if info["public"]:
        rows.append(("ssh.public", "Public key", info["public"]))
    if info["encrypted"]:
        rows.append(("ssh.sealed",
                     "The private half is passphrase-protected", ""))
    if info["problem"]:
        rows.append(("ssh.unreadable",
                     "SPM cannot derive anything from this key",
                     info["problem"]))
    return rows


def _derived_gpg(values):
    info = pgp_key_info(values.get("private_key", ""))
    rows = []
    if info["fingerprint"]:
        rows.append(("gpg.fingerprint", "Fingerprint", info["fingerprint"]))
        rows.append(("gpg.keyid", "Key ID", info["keyid"]))
    if info["algorithm"]:
        size = info["curve"] or ("%d" % info["bits"] if info["bits"] else "")
        rows.append(("gpg.algorithm", "Algorithm",
                     ("%s %s" % (info["algorithm"], size)).strip()))
    if info["created"]:
        rows.append(("gpg.created", "Created", info["created"]))
    if info["uids"]:
        rows.append(("gpg.uids", "Identities", info["uids"]))
    if info["subkeys"]:
        rows.append(("gpg.subkeys", "Subkeys", "%d" % info["subkeys"]))
    if not info["secret"] and info["fingerprint"]:
        rows.append(("gpg.publiconly",
                     "This is a public key: it cannot sign or decrypt", ""))
    if info["encrypted"]:
        rows.append(("gpg.sealed",
                     "The secret half is passphrase-protected", ""))
    if info["problem"]:
        rows.append(("gpg.unreadable",
                     "SPM cannot derive anything from this key",
                     info["problem"]))
    return rows


RECORD_DERIVERS = {"ssh": _derived_ssh, "gpg": _derived_gpg}


def record_derived(record_type, values):
    """(i18n key, English label, value) rows computed from a record's values.

    Never a secret. Everything here is derived from a secret but is itself
    publishable -- a fingerprint and a public key are meant to be handed out,
    which is what makes deriving them worth doing. A deriver that wanted to
    return a secret would be returning the stored value with extra steps.
    """
    deriver = RECORD_DERIVERS.get(record_derive_name(record_type))
    return deriver(values or {}) if deriver else []


def record_derive_name(record_type):
    """The deriver a type opts into, or "" for a type that derives nothing.

    Surfaces need this as well as the rows: the panel they draw is titled for
    the thing it was derived from, and "Derived from the key" is the SSH
    wording, not a universal one. Reading the name here keeps the title a
    lookup like everything else, so the next deriver is still one dictionary
    entry and its translations.
    """
    return RECORD_SCHEMAS.get(record_type, {}).get("derive", "")

# ----- attributes across an export -------------------------------------------
# A folder and its custom fields cross an export as their own readable columns
# rather than as the stored base64 blob: an export is meant to be opened in a
# spreadsheet, and a column of opaque base64 is neither readable nor editable
# by whatever the user opens it with.
#
# Both directions live here because both surfaces need them and only one of
# them had them. Until 4.1.0 these were private to the dashboard, so a vault
# exported and re-imported through the CLI lost every folder and every custom
# field, on all twenty formats, silently -- which is exactly the disagreement
# between two surfaces that a shared core exists to make impossible.

def json_line_safe(value):
    """json.dumps for a value that will be written on one line.

    json.dumps escapes every C0 control -- newline, tab, the record and group
    separators -- but leaves U+0085, U+2028 and U+2029 as literal characters,
    because they are legal inside a JSON string. They are also three of the
    eleven characters str.splitlines() honours, and the exports that carry
    this output are line-based: ndjson and jsonl put one record on one line,
    and the ndjson, yaml and fallback-toml readers all split before parsing.

    So a custom field holding U+2028 exported as valid JSON and came back as
    two invalid halves. What made it hard to see is that everything a person
    would check agreed the file was fine: bash reads it as one line, `wc -l`
    counts one line, and json.loads parses it. Only str.splitlines() disagrees,
    and only the importer calls that -- so the export looked correct right up
    until the day someone needed it back.

    Escaping the three keeps the JSON identical in meaning -- json.loads
    returns exactly the same string -- while making it safe to put on a line.

    The dashboard already did this for the same three characters when
    embedding JSON in a <script>. The reason is the same and the definition
    belongs in one place.
    """
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False)
            .replace(" ", "\\u2028")
            .replace(" ", "\\u2029")
            .replace("\x85", "\\u0085"))


def attrs_export_columns(column):
    """The folder and fields columns an export carries for one record."""
    folder, fields, hidden = decode_attrs(column)
    return {
        "folder": folder,
        "fields": json_line_safe(
            [{"name": n, "value": v} for n, v in fields]) if fields else "",
        "hidden": "1" if hidden else "",
    }


def attrs_from_export_row(row):
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
            candidates = json.loads(raw)
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
    # Anything a spreadsheet or another manager might put in a truthy cell.
    # An unrecognised value means not hidden, because the safe direction for a
    # flag nobody understood is the one that shows the entry rather than the
    # one that pretends a vault holds less than it does.
    raw_hidden = row.get("hidden", "")
    hidden = (raw_hidden is True
              or (isinstance(raw_hidden, str)
                  and raw_hidden.strip().lower() in ("1", "true", "yes", "y", "hidden")))
    try:
        return encode_attrs(folder, fields, hidden)
    except Exception:
        return ""


def iter_records(plaintext, record_type=""):
    """(line_index, parsed) for every typed record row, in vault order.

    The index is the caller's half of a rewrite: the dashboard edits and
    deletes by replacing one line of the plaintext it already holds, and a
    surface that searched for its own row again by id would be a second
    definition of which row an id names.

    `record_type` narrows to one type. Ids are per type, so a caller holding
    only an id is holding half an address; every route that takes one takes
    the type with it.
    """
    for index, line in enumerate((plaintext or "").splitlines()):
        if not line.startswith(RECORD_TAG_PREFIX):
            continue
        parsed = parse_record_row(line)
        if parsed is None:
            continue
        if record_type and parsed[0] != record_type:
            continue
        yield index, parsed


def find_record(plaintext, record_type, record_id):
    """(line_index, parsed) for one record, or None.

    Both halves of the address are required. A lookup by id alone would find
    the wifi record when the caller meant the server one, because each type
    counts from one.
    """
    for index, parsed in iter_records(plaintext, record_type):
        if parsed[1] == str(record_id):
            return index, parsed
    return None


def record_next_id(plaintext, record_type):
    """The next free id for a type, as a string.

    Ids are allocated per type, so wifi 1 and server 1 both exist and each
    type counts from one. A single sequence across types would make an id
    meaningless without its type anyway, and would renumber nothing while
    looking like it might.

    A row whose id is not a number is ignored rather than refused: it cannot
    have been written by this code, and refusing here would mean one damaged
    row stopped every new record of its type from being added.
    """
    highest = 0
    for _index, parsed in iter_records(plaintext, record_type):
        if parsed[1].isdigit():
            highest = max(highest, int(parsed[1]))
    return str(highest + 1)


def record_counts(plaintext):
    """{type: n} for the types present, plus "" -> the total.

    The total is carried here rather than summed by each caller because the
    nav badge and the overview tile disagreeing about how many records a
    vault holds is the class of defect a shared core exists to prevent.
    """
    counts = {"": 0}
    for _index, parsed in iter_records(plaintext):
        counts[parsed[0]] = counts.get(parsed[0], 0) + 1
        counts[""] += 1
    return counts


def record_folders(plaintext):
    """Every folder in use, sorted, without duplicates differing only in case."""
    seen = {}
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        if not parts or parts[0].startswith("META_") or not parts[0].isdigit():
            continue
        folder, _, _ = decode_attrs(parts[7] if len(parts) > 7 else "")
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
        # A snapshot is named for the ciphertext it captures, so an unchanged
        # vault is one undo point however often it is archived. The name alone
        # cannot enforce that: it also carries the second and the pid, so two
        # archives of identical bytes that straddle a second tick used to land
        # as two files. Retention counts files, so the duplicate evicts the
        # oldest genuinely different generation -- history quietly gets
        # shorter than it says it is. Match on the digest instead: it is the
        # part of the name that means "this ciphertext".
        if any(name.endswith(".%s.gpg" % digest) for name in os.listdir(target)):
            _prune(target, ".gpg", _retention())
            return
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


# The enrolled security keys live beside the vault rather than inside it, for
# the reason that decides the whole shape of this feature: a cold unlock has to
# read them BEFORE anything is decrypted. A META_ row inside the vault could
# only ever be read by someone who had already opened it, which is exactly the
# person who does not need it. The recovery file established this pattern in
# 3.0.0 and this follows it.
#
# What the file discloses if taken: which credential ids are enrolled, and a
# vault key sealed under 32 bytes that exist only inside an authenticator.
# There is no password in that path to guess at, so unlike the master-password
# envelope beside it, this one offers an offline attacker nothing to work on.
def hardware_path(vault_path):
    return vault_path + ".hardware"


def read_hardware(vault_path):
    """{"salt": <b64>, "keys": [...]} for this vault. No file means none.

    One salt for the whole vault rather than one per key, because the salt has
    to be chosen before the ceremony and the ceremony is what reveals which key
    answered. A single salt keeps the request unambiguous, and it costs
    nothing: the PRF secret is per credential, so two keys given the same salt
    still derive two different secrets and seal two different envelopes.
    """
    target = hardware_path(vault_path)
    if not os.path.exists(target):
        return {"salt": "", "keys": []}
    try:
        with open(target, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        entries = document["keys"]
        salt = str(document.get("salt") or "")
        if not isinstance(entries, list):
            raise ValueError("keys is not a list")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Named rather than reported as "no keys enrolled". Turning a damaged
        # file into "your security key was never registered" invites the user
        # to enrol again over the top of it.
        raise VaultError("the security-key file for this vault is unreadable") from exc
    return {"salt": salt,
            "keys": [entry for entry in entries if isinstance(entry, dict)
                     and entry.get("credential_id") and entry.get("wrapped")]}


def write_hardware(vault_path, salt, entries):
    """Replace the security-key file durably, or remove it when empty."""
    target = hardware_path(vault_path)
    if not entries:
        if os.path.exists(target):
            os.remove(target)
            _fsync_dir(os.path.dirname(os.path.abspath(target)) or ".")
        return target
    directory = os.path.dirname(os.path.abspath(target)) or "."
    handle, staged = tempfile.mkstemp(
        prefix="." + os.path.basename(target) + ".stage.", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump({"version": 1, "salt": salt, "keys": entries},
                      out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(staged, 0o600)
        os.replace(staged, target)
        staged = ""
        _fsync_dir(directory)
    finally:
        if staged and os.path.exists(staged):
            os.remove(staged)
    return target


def new_hardware_salt():
    return base64.b64encode(os.urandom(HARDWARE_SALT_BYTES)).decode("ascii")


def hardware_salt(vault_path):
    """The salt an enrolment ceremony must evaluate the PRF with.

    Returned rather than written, because the salt is only worth keeping once a
    key has actually been enrolled under it -- a minted-and-abandoned salt in
    the file would be a vault that claims security keys it does not have.
    add_hardware_key is what persists it, and it refuses a salt that disagrees
    with one already in use.
    """
    return read_hardware(vault_path)["salt"] or new_hardware_salt()


def add_hardware_key(vault_path, credential_id, wrapped, rp_id, label, created,
                     salt=""):
    """Enrol one security key, replacing any entry for the same credential."""
    label = re.sub(r"[\t\r\n]+", " ", str(label or "Security key")).strip()[:64]
    current = read_hardware(vault_path)
    if current["salt"] and salt and salt != current["salt"]:
        # Two enrolments raced, each having minted its own salt while the file
        # was still absent. The loser's envelope was sealed under a secret this
        # vault will never ask an authenticator for again, so it would enrol a
        # key that can never open it. Refusing is the only honest answer; the
        # user retries and picks up the salt that won.
        raise VaultError("this vault already uses a different security-key salt")
    salt = current["salt"] or salt or new_hardware_salt()
    entries = [entry for entry in current["keys"]
               if entry.get("credential_id") != credential_id]
    entries.append({"credential_id": credential_id, "wrapped": wrapped,
                    "rp_id": rp_id, "label": label or "Security key",
                    "created": created})
    write_hardware(vault_path, salt, entries)
    return {"salt": salt, "keys": entries}


def remove_hardware_key(vault_path, credential_id):
    current = read_hardware(vault_path)
    entries = [entry for entry in current["keys"]
               if entry.get("credential_id") != credential_id]
    write_hardware(vault_path, current["salt"], entries)
    return {"salt": current["salt"] if entries else "", "keys": entries}


# ----- the secret key on disk ------------------------------------------------
# Not beside the vault. Every sidecar this file already defines -- .recovery,
# .hardware -- sits next to the vault, and for those it is right: they are
# useless to a thief on their own. A Secret Key is the opposite. Its entire
# value is that it does not travel with the copies of the vault that leave this
# machine, and "next to the vault" is precisely where a careless `cp
# ~/.spm_vault.gpg*` or a directory-level backup would find it.
#
# So it lives in the data directory, keyed by the same scope id the history
# uses. Nothing that copies a vault -- the sync transports, which move one
# file; the bundle exporter; the .bak beside every write -- ever reaches in
# here.
#
# The cost of that choice is that the binding is to the vault's path. Move the
# vault and the scope id changes and the stored key is not found. That is why
# `secret-key show` exists and why the enable path refuses to finish until the
# key has been displayed: the file is a convenience, the transcription is the
# copy that matters.

def secret_key_dir():
    return os.path.join(data_dir(), "secret-keys")


def secret_key_path(vault_path):
    return os.path.join(secret_key_dir(), vault_scope_id(vault_path))


def new_secret_key():
    """A fresh Secret Key in the grouped text form the user sees."""
    return format_secret_key(os.urandom(SECRET_KEY_BYTES))


def format_secret_key(raw):
    """SECRET_KEY_BYTES of entropy as `S1-XXXXXX-XXXXX-...` text."""
    if len(raw) != SECRET_KEY_BYTES:
        raise VaultError("a Secret Key must be exactly %d bytes"
                         % SECRET_KEY_BYTES)
    body = base64.b32encode(bytes(raw)).decode("ascii").rstrip("=")
    out, at = [SECRET_KEY_TAG], 0
    for size in SECRET_KEY_GROUPS:
        out.append(body[at:at + size])
        at += size
    # The groups are chosen to consume the encoding exactly. If they ever stop
    # doing so the display would silently drop entropy, so it is checked rather
    # than assumed.
    if at != len(body):
        raise VaultError("secret key grouping does not match its encoding")
    return "-".join(out)


def secret_key_bytes(text):
    """The 16 raw bytes behind a Secret Key, however the user typed it.

    Case, spacing and dashes are all discarded before decoding: this value is
    read off paper and typed back by hand, and rejecting `s1 a3qk 7f...` for
    its shape would be a refusal about presentation, not about the key.
    """
    if isinstance(text, (bytes, bytearray)):
        raise VaultError("a Secret Key is text, not bytes")
    cleaned = "".join(ch for ch in (text or "") if ch.isalnum()).upper()
    if not cleaned.startswith(SECRET_KEY_TAG):
        raise VaultError("that does not look like a Secret Key; it starts %s-"
                         % SECRET_KEY_TAG)
    body = cleaned[len(SECRET_KEY_TAG):]
    expected = len(base64.b32encode(b"\0" * SECRET_KEY_BYTES).decode("ascii").rstrip("="))
    if len(body) != expected:
        raise VaultError("a Secret Key carries %d characters after %s-, not %d"
                         % (expected, SECRET_KEY_TAG, len(body)))
    padded = body + "=" * (-len(body) % 8)
    try:
        raw = base64.b32decode(padded)
    except Exception as exc:
        raise VaultError("that Secret Key contains characters it cannot") from exc
    if len(raw) != SECRET_KEY_BYTES:
        raise VaultError("that Secret Key decodes to the wrong length")
    return raw


def read_secret_key(vault_path):
    """This vault's Secret Key, or "" when none is available here.

    SPM_SECRET_KEY wins over the file. A vault carried to a second machine has
    no file there yet, and the environment is how the key reaches a headless
    run or a test without being written to a disk it does not belong on.
    """
    override = (os.environ.get("SPM_SECRET_KEY") or "").strip()
    if override:
        secret_key_bytes(override)
        return override
    target = secret_key_path(vault_path)
    if not os.path.exists(target):
        return ""
    try:
        with open(target, "r", encoding="utf-8") as handle:
            stored = handle.read().strip()
    except OSError as exc:
        raise VaultError("the Secret Key file for this vault is unreadable") from exc
    if not stored:
        # An empty file is damage, not absence. Reporting it as "no Secret Key"
        # would send a bound vault down the password-only path and report a
        # correct password as wrong.
        raise VaultError("the Secret Key file for this vault is empty")
    secret_key_bytes(stored)
    return stored


def write_secret_key(vault_path, text):
    """Store this vault's Secret Key durably, 0600, in the data directory."""
    secret_key_bytes(text)
    target = secret_key_path(vault_path)
    directory = os.path.dirname(os.path.abspath(target)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, staged = tempfile.mkstemp(
        prefix="." + os.path.basename(target) + ".stage.", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text.strip() + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.chmod(staged, 0o600)
        os.replace(staged, target)
        staged = ""
        _fsync_dir(directory)
    finally:
        if staged and os.path.exists(staged):
            os.remove(staged)
    return target


def remove_secret_key(vault_path):
    """Forget the stored copy. Returns True when there was one."""
    target = secret_key_path(vault_path)
    if not os.path.exists(target):
        return False
    os.remove(target)
    _fsync_dir(os.path.dirname(os.path.abspath(target)) or ".")
    return True


def vault_wants_secret_key(vault_path):
    """True when this vault's header says it is bound to a Secret Key.

    False for anything that is not an AEAD container, which is the honest
    answer: the older formats have nowhere to record the binding, so they
    cannot have one.
    """
    try:
        with open(vault_path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return False
    modern = parse_container_aead(raw) if is_container(raw) else None
    return bool(modern and modern[0]["sk"])


def secret_key_for_write(vault_path):
    """The Secret Key a rewrite of this vault has to keep it bound to.

    Every write goes through here rather than through "was one passed in",
    because the failure mode of getting this wrong is silent: a save that
    forgot the binding would produce a vault that still opens on this machine
    and has quietly lost the protection its owner turned on.
    """
    if not vault_wants_secret_key(vault_path):
        return ""
    return require_secret_key(vault_path, {"sk": True})


def require_secret_key(vault_path, kdf):
    """The Secret Key this vault needs, or a refusal naming what is missing."""
    if not kdf.get("sk"):
        return ""
    secret = read_secret_key(vault_path)
    if not secret:
        record_event("secret-key", "fail", "reason=missing", vault_path)
        raise VaultSecretKeyError(
            "this vault is bound to a Secret Key and none is stored for this "
            "path; supply it with SPM_SECRET_KEY or run 'secret-key import'")
    return secret


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


# Which hosts count as sensitive is the user's list, kept in the vault. SPM
# ships no opinion about it and no examples: a built-in list would be a
# maintenance burden, would be wrong for somebody, and would put in the source
# and in every clone of the repository exactly the words this feature exists to
# keep off a screen. The list lives in META_HIDDEN_HOSTS because it is itself
# sensitive -- a plaintext config file naming them would leak the very thing
# being protected.
HIDDEN_HOSTS_TAG = "META_HIDDEN_HOSTS"
HIDDEN_HOSTS_MAX = 200


def hidden_hosts(plaintext):
    """The host words this vault treats as sensitive, lowercased and unique."""
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        if parts[0] == HIDDEN_HOSTS_TAG and len(parts) > 1:
            return _split_hosts(parts[1])
    return []


def _split_hosts(raw):
    seen, out = set(), []
    for token in re.split(r"[^A-Za-z0-9.-]+", (raw or "").lower()):
        token = token.strip(".-")
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
        if len(out) >= HIDDEN_HOSTS_MAX:
            break
    return out


def set_hidden_hosts(plaintext, raw):
    """Store the list, replacing any previous one. Returns the new plaintext."""
    hosts = _split_hosts(raw)
    rows = [line for line in (plaintext or "").splitlines()
            if line.split("\t")[0] != HIDDEN_HOSTS_TAG]
    if hosts:
        rows.append("%s\t%s\t-\t-\t-\t-" % (HIDDEN_HOSTS_TAG, " ".join(hosts)))
    return "\n".join(rows) + "\n"


def looks_sensitive(label, url, hosts):
    """Whether an entry matches the vault's own list.

    A suggestion, and only ever that: the stored per-entry flag is what
    governs, and nothing here changes it.

    Matching is on whole hosts, not on the pieces of one. Splitting a listed
    host into its labels and looking for any of them proposed hiding every
    entry that merely shared a suffix -- one list of ".invalid" hosts had SPM
    offering to hide an unrelated admin account, because both ended in
    "invalid". A URL matches the host itself or a subdomain of it; a label
    matches only when it is the whole host or its leading name.
    """
    if not hosts:
        return False
    host = ""
    try:
        host = (urllib.parse.urlsplit(url or "").hostname or "").lower()
    except ValueError:
        host = ""
    key = re.sub(r"[^a-z0-9]", "", (label or "").lower())
    for listed in hosts:
        if host and (host == listed or host.endswith("." + listed)):
            return True
        if not key:
            continue
        if key == re.sub(r"[^a-z0-9]", "", listed):
            return True
        # The leading name on its own, so a bare label matches a listed host.
        # Long enough not to collide with a common word by accident.
        leading = listed.split(".")[0]
        if len(leading) >= 4 and key == leading:
            return True
    return False


# --- Browser bindings: which records a page may see, and on what terms ------
#
# One implementation. The CLI's `bridge-list` and `bridge-get` each carried
# their own copy of this, built inline in a shell heredoc, and the two had
# already begun to disagree in shape if not yet in behaviour. A matcher that
# decides whether a page may see a credential is the last place to keep two of.

BRIDGE_URL_RE = re.compile(r"https?://[^\s]+")
BRIDGE_SCHEME_RE = re.compile(r"(?i)^https?://")


def _binding_host(token):
    """The host a bound URL names, wildcard preserved. '' if it names none."""
    try:
        return (urllib.parse.urlsplit(token).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def wildcard_scope(pattern):
    """The parent host an opt-in '*.' scope covers, or '' if it is not one.

    A wildcard is only ever written by hand into a record's URL field. It is
    never inferred from a bare hostname: without a public suffix list, treating
    'foo.co.uk' as also covering '.co.uk' would bind a record to every site in
    the United Kingdom, and bundling a PSL is a data dependency this project
    does not have.

    The one guard that does not need a PSL is a floor on how much can be
    claimed: '*.com' is refused because no record legitimately covers a whole
    top-level domain. It is a floor and not a substitute -- '*.co.uk' still
    parses, because SPM cannot tell it from '*.example.com'. That is the cost
    of having no PSL, and the reason this is opt in per record rather than
    inferred for every record.
    """
    if not pattern.startswith("*."):
        return ""
    parent = pattern[2:].strip(".")
    if not parent or "*" in parent:
        return ""
    if len(parent.split(".")) < 2:
        return ""
    return parent


def host_in_scope(requested, pattern):
    """Whether a page's host is covered by one binding pattern."""
    requested = (requested or "").lower().strip(".")
    pattern = (pattern or "").lower().strip(".")
    if not requested or not pattern:
        return False
    parent = wildcard_scope(pattern)
    if parent:
        # The parent itself and anything under it. The dot is what keeps
        # '*.example.com' off 'notexample.com', which a bare suffix test
        # would match.
        return requested == parent or requested.endswith("." + parent)
    return requested == pattern


def record_bindings(label, notes, url):
    """Every host pattern a record is bound to, with the scheme each requires.

    Returns a list of (pattern, scheme) pairs. The scheme is 'https' only when
    the binding was written as an https URL; a label-derived binding has no
    scheme of its own and does not demand one.
    """
    bindings, seen = [], set()

    def add(pattern, scheme):
        pattern = (pattern or "").lower().strip(".")
        if not pattern or (pattern, scheme) in seen:
            return
        seen.add((pattern, scheme))
        bindings.append((pattern, scheme))

    add((label or "").lower().strip("."), "")
    # The url field is the intended binding source. Notes are still scanned so
    # that vaults written before 2.12.0 -- where a URL could only live in the
    # notes -- keep matching exactly as they did, with no rewrite on upgrade.
    tokens = ([url] if url else []) + BRIDGE_URL_RE.findall(notes or "")
    for token in tokens:
        if not BRIDGE_SCHEME_RE.match(token):
            continue
        host = _binding_host(token)
        if host:
            add(host, "https" if token.lower().startswith("https://") else "http")
    return bindings


# Refusals the bridge can produce. Named here because the native host projects
# every error onto a fixed set, and a refusal the host has not been told about
# reaches the extension as a generic one.
BRIDGE_NOT_BOUND = "record is not bound to this hostname"
BRIDGE_INSECURE = "record requires a secure page"


def bridge_match(requested, scheme, label, notes, url):
    """Whether this page may see this record, and why not when it may not.

    Returns (True, "") or (False, reason).

    Downgrade protection is the second half and it fails closed. A record bound
    to an https URL is refused on an http page, and refused again when the
    caller did not say what the page's scheme was -- an unknown scheme cannot
    be shown to be https, and a credential fill is not the place to assume the
    safe answer. A caller that predates the scheme argument therefore stops
    filling https-bound records rather than quietly keeping the old behaviour.
    """
    scheme = (scheme or "").lower().strip(":")
    matched = [(pattern, bound) for pattern, bound in record_bindings(label, notes, url)
               if host_in_scope(requested, pattern)]
    if not matched:
        return False, BRIDGE_NOT_BOUND
    # Any binding that permits this page is enough; a record bound to both
    # http and https on the same host is not downgraded by the https one.
    for _pattern, bound in matched:
        if bound != "https" or scheme == "https":
            return True, ""
    return False, BRIDGE_INSECURE


def tidy_proposals(plaintext):
    """What a tidy would change, as data. Changes nothing.

    Each proposal names the record, what is proposed for it, and the before and
    after of every field involved, so a caller can render it for review without
    knowing any of the rules above.
    """
    proposals = []
    hosts = hidden_hosts(plaintext)
    for line in (plaintext or "").splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].isdigit() or len(parts) < 6:
            continue
        record_id, label = parts[0], parts[1]
        notes = parts[4] if len(parts) > 4 else ""
        attrs = parts[7] if len(parts) > 7 else ""
        folder, fields, hidden = decode_attrs(attrs)

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

        # Proposed, never applied here, and only for an entry that is not
        # already hidden -- re-proposing a decision someone has made is how a
        # review becomes noise people click through.
        url = parts[6] if len(parts) > 6 else ""
        if not hidden and looks_sensitive(label, url, hosts):
            changes["hidden"] = {"from": False, "to": True}

        if changes:
            proposals.append({"id": record_id, "label": label,
                              "changes": changes})
    return proposals


TIDY_LABEL_MAX = 200


def apply_tidy(plaintext, selections):
    """Apply reviewed changes. `selections` maps id -> {"label": str,
    "hidden": bool}.

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

        # Both attribute changes go through one decode/encode. Two of them
        # would make the second overwrite whatever the first had just written,
        # because encode_attrs takes the whole column and not a patch.
        if "folder" in changes or "hidden" in changes:
            folder, fields, hidden = decode_attrs(parts[7])
            if "folder" in changes:
                folder = changes["folder"]["to"]
            if "hidden" in changes:
                # Only when the review said so. An unticked row keeps the
                # decision it already had.
                hidden = bool(chosen[record_id].get("hidden", True))
            parts[7] = encode_attrs(folder, fields, hidden)
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


def install_vault_file(source, dest, archive=True, expect_sha256=""):
    """Put `source` at `dest` durably, keeping what was there recoverable.

    The shell carried three separate copies of cp-chmod-mv for this -- bundle
    restore, history restore, sync install -- and none of them fsynced, so a
    crash immediately after any of them could leave the new name over blocks
    that were never written. Worse, bundle restore overwrote a live vault with
    no archive and no .bak at all, which is the one write in SPM that could not
    be undone.

    Ordering matches write_vault: the previous generation is archived and
    copied to .bak BEFORE the rename, because after it there is nothing left to
    copy. Returns True when something was replaced.

    `expect_sha256` is checked against the staged copy, before the rename and
    after the bytes have been written -- so a copy that silently lost or
    changed bytes is caught while the destination is still intact. Sync pull
    already did this by hand; every caller gets it by asking for it.
    """
    dest_dir = os.path.dirname(os.path.abspath(dest)) or "."
    dest_name = os.path.basename(dest)
    replaced = os.path.exists(dest)

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="." + dest_name + ".install.",
                                        dir=dest_dir)
    os.close(tmp_fd)
    try:
        shutil.copyfile(source, tmp_path)
        os.chmod(tmp_path, 0o600)
        if expect_sha256:
            digest = hashlib.sha256()
            with open(tmp_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            if not hmac.compare_digest(digest.hexdigest(), expect_sha256.lower()):
                raise VaultError(
                    "the staged copy does not match the digest it was promised; "
                    "%s was left untouched" % dest)
        if replaced:
            # .bak always, archiving only when asked. A recovery file has no
            # history directory of its own -- archiving one would file it under
            # a scope derived from its own path -- but it is still the only
            # wrapper around the previous vault key, so it gets a .bak like
            # everything else.
            if archive:
                archive_generation(dest)
            shutil.copy2(dest, dest + ".bak")
            os.chmod(dest + ".bak", 0o600)
        _fsync_path(tmp_path)
        os.replace(tmp_path, dest)
        tmp_path = ""
        os.chmod(dest, 0o600)
        _fsync_dir(dest_dir)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
    return replaced


def install_recovery(vault_path, staged):
    target = recovery_path(vault_path)
    os.replace(staged, target)
    os.chmod(target, 0o600)
    _fsync_dir(os.path.dirname(os.path.abspath(target)) or ".")


# ----- reading ---------------------------------------------------------------

def unwrap_key(vault_path, master):
    """The vault key alone, or None when the vault predates the container."""
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    modern = parse_container_aead(raw)
    if modern is not None:
        kdf, envelope, _ = modern
        key = unwrap_key_aead(kdf, envelope, master,
                              require_secret_key(vault_path, kdf))
    else:
        parts = parse_container(raw)
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
    modern = parse_container_aead(raw)
    if modern is not None:
        kdf, envelope, cipher = modern
        # Resolved before the attempt, and outside the handler below, because a
        # missing Secret Key is not a wrong password. Letting it fall into that
        # handler would log bad-master and tell the user to retype something
        # they typed correctly.
        secret = require_secret_key(vault_path, kdf)
        try:
            key = unwrap_key_aead(kdf, envelope, master, secret)
        except Exception:
            record_event("unlock", "fail", scope + ",reason=bad-master")
            raise
        if not key:
            record_event("unlock", "fail", scope + ",reason=bad-master")
            raise VaultError("vault key envelope decrypted to nothing")
        try:
            plaintext = unseal(key, cipher).decode("utf-8", errors="ignore")
        except VaultError:
            # The envelope opened, so the password was right and the data
            # block is damaged. gpg could never separate these two -- it
            # refused both identically, and the log had to say so -- and an
            # authenticated data block is what makes the distinction real.
            record_event("unlock", "fail", scope + ",reason=corrupt")
            raise VaultIntegrityError(
                "this vault's data failed authentication; the master password "
                "was right, so the file itself is damaged -- restore the .bak "
                "or a history snapshot beside it")
        record_event("unlock", "ok", scope)
        return plaintext, key
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
        # For a gpg-sealed vault a wrong master password and a damaged file
        # stay indistinguishable -- gpg refuses both the same way -- so the log
        # says the honest thing rather than guessing which it was.
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
    modern = parse_container_aead(raw)
    if modern is not None:
        return unseal(vault_key, modern[2]).decode("utf-8", errors="ignore")
    parts = parse_container(raw)
    if parts is None:
        return None
    return gpg_decrypt(vault_key, parts[1]).decode("utf-8", errors="ignore")


# ----- writing ---------------------------------------------------------------

def write_vault(vault_path, master, plaintext, vault_key=None):
    """Install `plaintext` as an AEAD vault. Returns the vault key used.

    A gpg-sealed vault becomes an openssl-sealed one here, on its next write,
    with no flag day and nothing for the user to run. The upgrade is invisible
    to everything downstream because the vault key does not change: the
    recovery file still names it, Shamir shares still reconstruct it, and a
    .bak from before the upgrade still opens under the same master password.
    That is the whole reason format 3 separated the key from the password.

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

    # `master is None` means "keep the key envelope exactly as it is". A caller
    # holding the vault key but not the password -- a session unlocked by a
    # security key -- has nothing to seal an envelope with, and the empty
    # string is not a safe stand-in: it would succeed, and quietly re-wrap the
    # vault under an empty password. Distinguishing None from "" is the whole
    # of that guard.
    keep_envelope = master is None
    if keep_envelope and vault_key is None:
        raise VaultError("a write without a master password needs the vault key")

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
        cipher = seal(vault_key, plaintext.encode("utf-8"))
        if keep_envelope:
            with open(vault_path, "rb") as handle:
                existing = parse_container_aead(handle.read())
            if existing is None:
                raise VaultError("this vault has no key envelope to keep")
            kdf, envelope, _ = existing
            container = build_container_aead(kdf["salt"], envelope, cipher,
                                             kdf["n"], kdf["r"], kdf["p"])
        else:
            kdf_salt = os.urandom(KDF_SALT_BYTES)
            secret = secret_key_for_write(vault_path)
            envelope = seal(derive_kek(master, kdf_salt, secret=secret),
                            vault_key.encode("utf-8"))
            container = build_container_aead(kdf_salt, envelope, cipher,
                                             secret_key=bool(secret))
        with open(tmp_path, "wb") as handle:
            handle.write(container)

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
    key = unwrap_key(vault_path, old_master)
    if key is None:
        raise VaultError("vault must be migrated before its key can be rewrapped")
    if not key:
        raise VaultError("vault key envelope decrypted to nothing")
    return rewrap_with_key(vault_path, key, new_master)


def rewrap_with_key(vault_path, vault_key, new_master, secret=None):
    """Change only the master-password envelope, given the vault key.

    `secret` is what the rewrapped vault should be bound to: None keeps
    whatever binding the vault already has, which is what an ordinary password
    change wants, and an explicit value -- a new Secret Key, or "" for none --
    is how enabling and disabling one are expressed. Both are a rewrap of the
    envelope and nothing else, so turning a Secret Key on costs the same as
    changing a password rather than re-encrypting the vault.

    The vault ciphertext stays byte-identical -- for a vault already on the
    current format -- and the recovery file is not touched at all, because
    both key off the vault key, which does not change.
    This is the reason for separating the vault key: a password change stops
    being a re-encryption of everything the user owns.

    Taking the key rather than the old password lets a caller that has just
    read the vault skip an entire gpg invocation, which is the dominant cost
    of any vault operation.
    """
    with open(vault_path, "rb") as handle:
        raw = handle.read()
    key = vault_key
    if secret is None:
        secret = secret_key_for_write(vault_path)
    elif secret:
        secret_key_bytes(secret)
    kdf_salt = os.urandom(KDF_SALT_BYTES)
    envelope = seal(derive_kek(new_master, kdf_salt, secret=secret),
                    key.encode("utf-8"))
    modern = parse_container_aead(raw)
    if modern is not None:
        updated = build_container_aead(kdf_salt, envelope, modern[2],
                                       secret_key=bool(secret))
    else:
        parts = parse_container(raw)
        if parts is None:
            raise VaultError(
                "vault must be migrated before its key can be rewrapped")
        # A gpg-sealed vault is upgraded here rather than rewrapped in place.
        # The two cannot both hold: the new envelope is openssl-sealed, so the
        # gpg data block beside it would be unreadable to the reader that
        # opens the envelope. Re-sealing the data costs one decryption, which
        # a password change was already paying for, and it means the last
        # vaults on the old backend leave it the next time anyone touches
        # them rather than lingering until a write happens to come along.
        updated = build_container_aead(
            kdf_salt, envelope,
            seal(key, gpg_decrypt(key, parts[1])),
            secret_key=bool(secret))

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

    What that file holds depends on when it was last written: formats 3 and 5
    store the vault key, the formats before them stored the master password,
    and a
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

    modern = parse_container_aead(raw)
    if modern is not None:
        kdf, envelope, cipher = modern
        try:
            plaintext = unseal(secret, cipher).decode("utf-8", errors="ignore")
            key, stale = secret, False
        except VaultError:
            # Not the vault key, so read it as the master password the older
            # recovery files hold. A failure here is genuinely "this file does
            # not open this vault" rather than a guess between the two.
            try:
                key = unwrap_key_aead(kdf, envelope, secret,
                                      require_secret_key(vault_path, kdf))
            except VaultError:
                raise VaultError("the recovery file does not open this vault")
            if not key:
                raise VaultError("vault key envelope decrypted to nothing")
            plaintext = unseal(key, cipher).decode("utf-8", errors="ignore")
            stale = True
        write_plaintext(out_path, plaintext)
        return key, stale

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


# ----- typed records across an export ----------------------------------------
# A record that cannot leave is a record you do not own, and this project has
# already paid for finding that out late: until 4.1.0 every one of the twenty
# export formats dropped folders and custom fields silently, because the CLI
# and the dashboard each had their own idea of the column order. So the
# crossing is defined once, here, and both surfaces call it.
#
# No new column. A typed record's fields ride the `fields` column that custom
# fields already use -- it is JSON name/value pairs, meant to be read in a
# spreadsheet -- and the `type` column, which every export has always carried,
# is what says whether to read them back as schema fields or as custom ones.
# Adding a thirteenth column would have broken every headerless and positional
# reader, which is exactly the class of defect EXPORT_FIELDNAMES exists to
# prevent.

def record_export_row(record_type, record_id, label, values, created,
                      folder="", custom=None, hidden=False):
    """One export row for a typed record.

    Schema fields and custom fields are merged into `fields` in that order.
    They can be told apart again on the way back because a schema field's name
    is in the schema and a custom one's is not, which is why build_record_row
    refuses a custom field that shadows a schema field name.
    """
    merged = [{"name": name, "value": values[name]}
              for name, _k, _w, _r in record_fields(record_type)
              if values.get(name)]
    merged += [{"name": n, "value": v} for n, v in (custom or [])]
    return {
        "type": record_type,
        "id": str(record_id),
        "label": label,
        "username": "",
        "secret": "",
        "notes": "",
        "created": created,
        "extra": "",
        "url": "",
        "folder": folder,
        "fields": json_line_safe(merged) if merged else "",
        "hidden": "1" if hidden else "",
    }


def record_from_export_row(row):
    """(type, values, custom) for an export row, or None if it is not typed.

    Tolerant in the same way attrs_from_export_row is, and for the same
    reason: an import is where rows arrive from software that never heard of
    this format. A value that does not belong to the schema becomes a custom
    field rather than being dropped, because a name this build does not know
    may be a field a newer SPM does.
    """
    record_type = str(row.get("type", "") or "").strip()
    if record_type not in RECORD_SCHEMAS:
        return None
    _folder, pairs, _hidden = decode_attrs(attrs_from_export_row(row))
    known = {name for name, _k, _w, _r in record_fields(record_type)}
    values, custom = {}, []
    for name, value in pairs:
        if name in known:
            values[name] = value
        else:
            custom.append((name, value))
    return record_type, values, custom


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
    typed = type_from_tag(tag)
    if typed:
        # The type comes from the tag, so a damaged typed record is still
        # described by what it is. Reading it out of the payload would mean
        # decoding field 3, which is the one field this function must not
        # touch.
        return (typed.upper(),
                parts[1] if len(parts) > 1 else "?",
                parts[2] if len(parts) > 2 else "")
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


def looks_like_vault(plaintext):
    """Whether decrypted bytes are plausibly a vault rather than any old file.

    "The command exited zero" is not the same as "this decrypted". gpg exits 0
    on inputs it never decrypted at all -- an unencrypted OpenPGP literal-data
    packet is parsed and emitted as-is -- and it does so for roughly 1.1% of
    random 512-byte blobs, because byte 0 is read as a packet header and a few
    tags are processed without a key. Every caller of this is about to replace
    a live vault with the file in question, so exit status alone is too weak a
    thing to stake that on.

    Deliberately generous: any META_ row or any record line. A vault SPM wrote
    always carries META_VAULT_VERSION, and this must not start refusing odd but
    genuine vaults -- it exists to reject files that are not vaults at all.
    """
    for line in plaintext.split("\n"):
        tag = line.split("\t", 1)[0]
        if (tag.startswith("META_") or tag in _RECORD_TAGS or tag.isdigit()
                or tag.startswith(RECORD_TAG_PREFIX)):
            return True
    return False


def vault_counts(plaintext):
    """Record counts, duplicate password ids and empty password fields."""
    counts = {"passwords": 0, "notes": 0, "passphrases": 0,
              "backup_codes": 0, "authenticators": 0, "records": 0}
    by_tag = {"NOTE": "notes", "PASSPHRASE": "passphrases",
              "BACKUP_CODE": "backup_codes", "AUTH": "authenticators"}
    # Per-type counts share the dict rather than becoming a fourth return
    # value, and every value in it stays an int. A caller that asked for
    # counts["passwords"] before still gets a number, and one that wants a
    # breakdown asks for counts["type:wifi"]. A nested dict here would have
    # made `counts` a mixed bag whose every consumer needs to know which keys
    # are numbers.
    for known in RECORD_TYPES:
        counts["type:" + known] = 0
    seen, duplicates, empty = {}, [], 0
    for line in plaintext.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag in by_tag:
            counts[by_tag[tag]] += 1
        elif tag.startswith(RECORD_TAG_PREFIX):
            counts["records"] += 1
            # Counted even when this build has no schema for it, because a
            # vault written by a newer SPM holding six records this one cannot
            # render still holds six records, and reporting five would be a
            # lie told by a diagnostic.
            key = "type:" + type_from_tag(tag)
            counts[key] = counts.get(key, 0) + 1
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

    # Which backend actually sealed this file, not which one this build would
    # write. A vault upgrades on its next write, so between installing a
    # release and saving anything the two genuinely differ, and a report that
    # showed the build's answer would be describing itself.
    try:
        backend, kdf = vault_seal_summary(vault_path)
    except (OSError, VaultError) as exc:
        backend, kdf = "unreadable", None
        checks.append(_check("vault_cipher", "fail", str(exc)))
    if backend == "openssl":
        checks.append(_check(
            "vault_cipher", "ok",
            "sealed with AES-256-CTR and HMAC-SHA256; key derivation %s "
            "n=%d r=%d p=%d" % (kdf["name"], kdf["n"], kdf["r"], kdf["p"]),
            backend=backend, kdf=kdf["name"],
            kdf_n=kdf["n"], kdf_r=kdf["r"], kdf_p=kdf["p"],
            secret_key=bool(kdf["sk"])))
        # Reported as a state, never as a fault. A vault without a Secret Key
        # is the supported default and saying "warn" about it would train the
        # reader to ignore the line. What does deserve a warning is a bound
        # vault whose key this machine cannot find, because that is a lockout
        # waiting for the next unlock rather than a preference.
        if kdf["sk"]:
            try:
                held = bool(read_secret_key(vault_path))
            except VaultError:
                held = False
            checks.append(_check(
                "vault_secret_key", "ok" if held else "warn",
                "bound to a Secret Key, and this machine holds it"
                if held else
                "bound to a Secret Key that this machine does not hold; "
                "unlocking here needs SPM_SECRET_KEY or 'secret-key import'",
                secret_key=True, held=held))
        else:
            checks.append(_check(
                "vault_secret_key", "ok",
                "no Secret Key; the master password alone opens this vault",
                secret_key=False, held=False))
    elif backend == "gpg":
        checks.append(_check(
            "vault_cipher", "warn",
            "sealed with gpg; the next write upgrades it to AES-256-CTR with "
            "a memory-hard key derivation, in place and without a new key",
            backend=backend))
    elif backend is None:
        checks.append(_check(
            "vault_cipher", "warn",
            "predates the key container; the next write upgrades it in place",
            backend="legacy"))

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


def _b64(text):
    """base64 of a value, for the line-based shell interface."""
    return base64.b64encode(("" if text is None else str(text))
                            .encode("utf-8")).decode("ascii")


def _flag_value(args, flag, default=""):
    """The argument after `flag`, or `default` when it is absent."""
    if flag in args:
        index = args.index(flag) + 1
        if index < len(args):
            return args[index]
    return default


def _record_values_in():
    """{field: value} from "field<TAB>base64(value)" lines on stdin.

    A malformed line is refused rather than skipped. Skipping would drop a
    field the user typed and report success, which for a record they will
    later rely on is the worst of the available outcomes.
    """
    values = {}
    for line in sys.stdin.read().split("\n"):
        if not line.strip():
            continue
        if "\t" not in line:
            raise VaultError("malformed field line: expected NAME<TAB>base64")
        name, encoded = line.split("\t", 1)
        try:
            values[name] = base64.b64decode(encoded.strip(),
                                            validate=True).decode("utf-8")
        except Exception:
            raise VaultError("field %r did not carry valid base64" % (name,))
    return values


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: spm_core.py <command> [args]\n")
        return 2
    command = argv[1]
    try:
        if command == "read":
            # read <vault> <out> [--require-vault]
            # stdin: master ; stdout: vault key (may be empty)
            #
            # --require-vault is for the callers that are about to overwrite a
            # live vault with this file. They need "this decrypted" and not
            # merely "the command exited zero"; see looks_like_vault.
            vault, out = argv[2], argv[3]
            (master,) = _secrets(1)
            plaintext, key = read_vault(vault, master)
            if "--require-vault" in argv[4:] and not looks_like_vault(plaintext):
                raise VaultError(
                    "%s decrypted to something that is not a vault" % vault)
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
        elif command == "record":
            # record <op> [args] -- how the shell reads a schema. The
            # dashboard imports this module and calls the functions directly,
            # so nothing here exists for its benefit.
            #
            # Output is tab-separated rather than JSON because the only caller
            # is a POSIX shell, and a shell that has to parse JSON grows
            # either a python dependency per field or a regex that is wrong
            # for some input. Field values travel base64-encoded for the same
            # reason the vault row does: a note legitimately holds newlines,
            # and this is a line-based interface.
            #
            # No field value is ever an argument. A payload holds the record's
            # secrets and argv is world-readable on Linux for the life of the
            # process -- the same reason `_key_fd` exists rather than handing
            # openssl a key with -K. Ids, labels and timestamps are not
            # secrets and travel normally.
            op = argv[2]
            if op == "types":
                for name in RECORD_TYPES:
                    sys.stdout.write("%s\t%s\t%s\n" % (
                        name, RECORD_SCHEMAS[name]["label"],
                        RECORD_SCHEMAS[name].get("icon", "")))
            elif op == "schema":
                for field, kind, widget, required in record_fields(argv[3]):
                    sys.stdout.write("%s\t%s\t%s\t%s\n" % (
                        field, kind, widget, "1" if required else "0"))
            elif op == "next-id":
                # next-id <plainfile> <type>
                #
                # The shell allocated this with its own awk over the same
                # rows. Two implementations of "which id is free" is how the
                # CLI and the dashboard come to hand the same id to two
                # records, so the rule lives with the rows it reads.
                with open(argv[3], "r", encoding="utf-8") as handle:
                    sys.stdout.write(record_next_id(handle.read(), argv[4]) + "\n")
            elif op == "row":
                # row <type> <id> <label> <created> [--folder F] [--hidden]
                # stdin: "field<TAB>base64(value)" lines
                # stdout: one vault row
                sys.stdout.write(build_record_row(
                    argv[3], argv[4], argv[5], _record_values_in(), argv[6],
                    folder=_flag_value(argv[7:], "--folder"),
                    hidden="--hidden" in argv[7:]) + "\n")
            elif op == "parse":
                # stdin: one vault row
                # stdout: "field<TAB>base64(value)" lines, preceded by the
                # meta lines .type/.id/.label/.created/.folder/.hidden. The
                # dot prefix cannot collide with a field name, because a
                # schema field name is an identifier.
                #
                # Nothing at all, and exit 0, when the line is not a typed
                # record this build can read: "not a typed record" is an
                # answer to the question, not a failure to answer it.
                parsed = parse_record_row(sys.stdin.read().rstrip("\n"))
                if parsed is None:
                    return 0
                rtype, rid, label, values, created, folder, _f, hidden = parsed
                for key, value in ((".type", rtype), (".id", rid),
                                   (".label", label), (".created", created),
                                   (".folder", folder),
                                   (".hidden", "1" if hidden else "0")):
                    sys.stdout.write("%s\t%s\n" % (key, _b64(value)))
                for field, _k, _w, _r in record_fields(rtype):
                    if values.get(field):
                        sys.stdout.write("%s\t%s\n" % (field, _b64(values[field])))
            elif op == "redact":
                # stdin: "field<TAB>base64(value)" lines ; stdout: the same,
                # masked. A surface that shows a record without revealing it
                # asks for this rather than deciding which of its fields are
                # sensitive -- that decision belongs to the schema, once.
                masked = redact_record(argv[3], _record_values_in())
                for field, _k, _w, _r in record_fields(argv[3]):
                    if masked.get(field):
                        sys.stdout.write("%s\t%s\n" % (field, _b64(masked[field])))
            else:
                raise VaultError("unknown record op %r" % (op,))
        elif command == "ssh":
            # ssh <op> [args] -- what the CLI asks about a stored SSH key.
            #
            # The key arrives on stdin, base64-encoded, for the same reason a
            # record's field values do: it is the record's secret, and argv is
            # world-readable on Linux for the life of the process. The comment
            # is not a secret and travels normally.
            op = argv[2]
            if op == "info":
                # info [comment]
                # stdin:  base64 of the key text
                # stdout: "name<TAB>base64(value)" lines
                key_text = base64.b64decode(
                    sys.stdin.read().strip() or "").decode("utf-8", "replace")
                info = ssh_key_info(key_text, comment=argv[3] if len(argv) > 3 else "")
                for name in ("format", "type", "bits", "fingerprint",
                             "public", "encrypted", "problem"):
                    value = info[name]
                    if isinstance(value, bool):
                        value = "1" if value else "0"
                    sys.stdout.write("%s\t%s\n" % (name, _b64(str(value))))
            else:
                raise VaultError("unknown ssh op %r" % (op,))
        elif command == "gpg":
            # gpg <op> -- what the CLI asks about a stored OpenPGP key. The
            # armored key arrives on stdin, base64-encoded, for the same
            # reason the SSH key above does.
            op = argv[2]
            if op == "info":
                # stdin:  base64 of the armored key text
                # stdout: "name<TAB>base64(value)" lines
                key_text = base64.b64decode(
                    sys.stdin.read().strip() or "").decode("utf-8", "replace")
                info = pgp_key_info(key_text)
                for name in ("fingerprint", "keyid", "algorithm", "bits",
                             "curve", "created", "uids", "subkeys",
                             "secret", "encrypted", "problem"):
                    value = info[name]
                    if isinstance(value, bool):
                        value = "1" if value else "0"
                    sys.stdout.write("%s\t%s\n" % (name, _b64(str(value))))
            else:
                raise VaultError("unknown gpg op %r" % (op,))
        elif command == "secret-key":
            # secret-key <op> <vault> ; ops below say what they read on stdin.
            #
            # Every op that changes the binding writes the key file BEFORE
            # rewrapping and removes it AFTER. Order matters and only in one
            # direction: a file naming a key the vault is not bound to is
            # ignored by every reader, while a vault bound to a key no file
            # names is a lockout.
            op, vault = argv[2], argv[3]
            if op == "path":
                sys.stdout.write(secret_key_path(vault) + "\n")
            elif op == "status":
                bound = vault_wants_secret_key(vault)
                override = bool((os.environ.get("SPM_SECRET_KEY") or "").strip())
                stored = os.path.exists(secret_key_path(vault))
                sys.stdout.write(json.dumps({
                    "bound": bound,
                    "stored": stored,
                    "source": "env" if override else ("file" if stored else "none"),
                    "path": secret_key_path(vault),
                }) + "\n")
            elif op == "show":
                # stdin: master. The password is verified against the vault
                # first: without that, anything able to run this command could
                # read the key straight off the disk it is meant to protect.
                (master,) = _secrets(1)
                read_vault(vault, master)
                secret = read_secret_key(vault)
                if not secret:
                    raise VaultError("no Secret Key is stored for this vault")
                sys.stdout.write(secret + "\n")
            elif op == "enable":
                # stdin: master ; stdout: the new Secret Key
                (master,) = _secrets(1)
                if vault_wants_secret_key(vault):
                    raise VaultError(
                        "this vault already has a Secret Key; use rotate to "
                        "replace it, or disable to remove it")
                _plaintext, key = read_vault(vault, master)
                if not key:
                    raise VaultError(
                        "this vault predates the key envelope and must be "
                        "migrated before a Secret Key can be added")
                fresh = new_secret_key()
                write_secret_key(vault, fresh)
                try:
                    rewrap_with_key(vault, key, master, secret=fresh)
                except Exception:
                    remove_secret_key(vault)
                    raise
                record_event("secret-key", "ok", "reason=enabled", vault)
                sys.stdout.write(fresh + "\n")
            elif op == "rotate":
                # stdin: master ; stdout: the replacement Secret Key
                (master,) = _secrets(1)
                if not vault_wants_secret_key(vault):
                    raise VaultError("this vault has no Secret Key to rotate")
                _plaintext, key = read_vault(vault, master)
                previous = read_secret_key(vault)
                fresh = new_secret_key()
                write_secret_key(vault, fresh)
                try:
                    rewrap_with_key(vault, key, master, secret=fresh)
                except Exception:
                    if previous:
                        write_secret_key(vault, previous)
                    else:
                        remove_secret_key(vault)
                    raise
                record_event("secret-key", "ok", "reason=rotated", vault)
                sys.stdout.write(fresh + "\n")
            elif op == "disable":
                # stdin: master
                (master,) = _secrets(1)
                if not vault_wants_secret_key(vault):
                    raise VaultError("this vault has no Secret Key")
                _plaintext, key = read_vault(vault, master)
                rewrap_with_key(vault, key, master, secret="")
                remove_secret_key(vault)
                record_event("secret-key", "ok", "reason=disabled", vault)
            elif op == "import":
                # stdin: master\nsecret key. Stores the key and nothing else --
                # the vault is already bound, this machine simply did not have
                # the key yet.
                master, supplied = _secrets(2)
                supplied = supplied.strip()
                if not supplied:
                    raise VaultError("a Secret Key is required")
                secret_key_bytes(supplied)
                if vault_wants_secret_key(vault):
                    # Proven against the vault, not merely checked for shape.
                    # A key that decodes but is not this vault's would store
                    # cleanly and turn every later unlock into "wrong master
                    # password" -- a diagnosis pointing at the wrong secret.
                    with open(vault, "rb") as handle:
                        probe = parse_container_aead(handle.read())
                    if probe is None:
                        raise VaultError("this vault has no key envelope")
                    kdf, envelope, _cipher = probe
                    try:
                        proven = unwrap_key_aead(kdf, envelope, master, supplied)
                    except VaultError:
                        proven = ""
                    if not proven:
                        record_event("secret-key", "fail", "reason=bad-secret",
                                     vault)
                        raise VaultError(
                            "that Secret Key and master password do not open "
                            "this vault")
                write_secret_key(vault, supplied)
                record_event("secret-key", "ok", "reason=imported", vault)
            elif op == "forget":
                # Removes this machine's stored copy. The vault stays bound --
                # this is for a machine that should no longer hold the key.
                if not remove_secret_key(vault):
                    raise VaultError("no Secret Key is stored for this vault")
                record_event("secret-key", "ok", "reason=forgotten", vault)
            else:
                raise VaultError("unknown secret-key operation: %s" % op)
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
                raw = handle.read()
            modern = parse_container_aead(raw)
            container = modern[1:] if modern else parse_container(raw)
            if container is None:
                raise VaultError("this vault predates the key container")
            try:
                if modern:
                    unseal(key, container[1])
                else:
                    gpg_decrypt(key, container[1])
            except (subprocess.CalledProcessError, VaultError):
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
            # Enough bytes for the longest magic, not for one of them. Sized to
            # CONTAINER_MAGIC alone, this read truncated an AEAD header mid-word
            # and reported every current vault as not a container.
            with open(argv[2], "rb") as handle:
                head = handle.read(
                    max(len(CONTAINER_MAGIC), len(CONTAINER_MAGIC_AEAD)) + 1)
            return 0 if is_container(head) else 1
        elif command == "seal-info":
            # seal-info <vault> ; stdout: backend<TAB>kdf<TAB>n<TAB>r<TAB>p<TAB>sk
            # No secret is read: this describes the header, not the contents,
            # so `doctor` can report it without holding the vault open. sk is
            # appended rather than inserted so a reader cutting fields 1-5
            # keeps working.
            backend, kdf = vault_seal_summary(argv[2])
            if kdf:
                sys.stdout.write("%s\t%s\t%d\t%d\t%d\t%d\n" % (
                    backend, kdf["name"], kdf["n"], kdf["r"], kdf["p"],
                    1 if kdf["sk"] else 0))
            else:
                sys.stdout.write("%s\t-\t-\t-\t-\t0\n" % (backend or "legacy"))
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
            sys.stdout.write(encode_attrs(argv[2] if len(argv) > 2 else "", rows,
                                          "--hidden" in argv[3:]))
        elif command == "attrs-decode":
            # attrs-decode <column> ; stdout: one JSON document
            folder, fields, hidden = decode_attrs(argv[2] if len(argv) > 2 else "")
            sys.stdout.write(json.dumps(
                {"folder": folder, "hidden": hidden,
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
        elif command == "install-file":
            # stdout: "replaced" or "created", so the caller can say which.
            # install-file <source> <dest> [--no-archive] [--sha256 <hex>]
            options = argv[4:]
            expect = ""
            if "--sha256" in options:
                expect = options[options.index("--sha256") + 1]
            replaced = install_vault_file(
                argv[2], argv[3], archive="--no-archive" not in options,
                expect_sha256=expect)
            sys.stdout.write("replaced\n" if replaced else "created\n")
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
        elif command == "bridge-list":
            # bridge-list <plainfile> <page host> <page scheme>
            # stdout: JSON. Secret-free by construction -- a match is a
            # summary, and the secret column is never read here.
            host = (argv[3] or "").lower().strip(".")
            scheme = argv[4] if len(argv) > 4 else ""
            if not host or any(ch.isspace() for ch in host):
                sys.stdout.write(json.dumps(
                    {"ok": False, "error": "invalid browser hostname"}) + "\n")
                return 2
            with open(argv[2], "r", encoding="utf-8", errors="replace") as handle:
                matches = []
                for line in handle:
                    parts = line.rstrip("\n").split("\t")
                    if not parts or not parts[0].isdigit() or len(parts) < 6:
                        continue
                    url = parts[6] if len(parts) > 6 else ""
                    ok, _reason = bridge_match(host, scheme, parts[1], parts[4], url)
                    if ok:
                        matches.append({"id": parts[0], "label": parts[1],
                                        "username": parts[2], "url": url})
            sys.stdout.write(json.dumps({"ok": True, "matches": matches}) + "\n")
        elif command == "bridge-get":
            # bridge-get <plainfile> <record id> <page host> <page scheme>
            rid, host = argv[3], (argv[4] or "").lower().strip(".")
            scheme = argv[5] if len(argv) > 5 else ""
            with open(argv[2], "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.rstrip("\n").split("\t")
                    if parts and parts[0] == rid and len(parts) >= 6:
                        url = parts[6] if len(parts) > 6 else ""
                        ok, reason = bridge_match(host, scheme, parts[1], parts[4], url)
                        if not ok:
                            sys.stdout.write(json.dumps(
                                {"ok": False, "error": reason}) + "\n")
                            return 2
                        sys.stdout.write(json.dumps(
                            {"ok": True, "username": parts[2],
                             "password": parts[3]}, ensure_ascii=False) + "\n")
                        break
                else:
                    sys.stdout.write(json.dumps(
                        {"ok": False, "error": "record not found"}) + "\n")
                    return 1
        elif command == "self-test":
            return 0
        else:
            sys.stderr.write("unknown command: %s\n" % command)
            return 2
    except VaultSecretKeyError as exc:
        # 3, not 1. Every caller that reports a failed unlock says "wrong
        # master password", and for this one failure that sentence is both
        # false and useless. A separate status is what lets them say the true
        # thing without parsing an error message.
        sys.stderr.write("%s\n" % exc)
        return 3
    except VaultError as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    except subprocess.CalledProcessError:
        sys.stderr.write("the cipher refused the supplied secret\n")
        return 1
    except (OSError, IndexError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

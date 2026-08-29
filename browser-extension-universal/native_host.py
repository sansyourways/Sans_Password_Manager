#!/usr/bin/env python3
"""Persistent native-messaging host. The master password never leaves memory."""
import json
import os
import re
import struct
import subprocess
import sys
import time

MAX_MESSAGE = 64 * 1024
IDLE_SECONDS = int(os.environ.get("SPM_BRIDGE_IDLE_SECONDS", "300"))
MAX_SECONDS = int(os.environ.get("SPM_BRIDGE_MAX_SECONDS", "43200"))
SPM_BIN = os.environ.get("SPM_BIN", "/usr/local/bin/spm")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)

master = None
unlocked_at = 0.0
last_used = 0.0

def read_message():
    raw = sys.stdin.buffer.read(4)
    if not raw:
        return None
    if len(raw) != 4:
        raise ValueError("truncated message header")
    length = struct.unpack("=I", raw)[0]
    if length > MAX_MESSAGE:
        raise ValueError("message too large")
    payload = sys.stdin.buffer.read(length)
    if len(payload) != length:
        raise ValueError("truncated message")
    return json.loads(payload.decode("utf-8"))

def write_message(message):
    data = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("=I", len(data)) + data)
    sys.stdout.buffer.flush()

def valid_host(value):
    value = str(value or "").lower().strip(".")
    if not HOST_RE.fullmatch(value):
        raise ValueError("invalid browser hostname")
    return value

# The boundary the extension cannot talk past.
#
# Two halves, and the second is the one that needed writing down. Inbound, an
# action the extension names must appear here or it is refused -- that was
# already true, as a chain of if-statements. Outbound, a response is PROJECTED
# onto the fields named here rather than forwarded: today `bridge-get` returns
# a username and a password, but if it ever returns a note, a URL or a TOTP
# seed, that field cannot reach the extension without someone editing this
# table. Forwarding whatever the CLI printed made the extension's view of the
# vault whatever the CLI happened to print, which is not a contract.
#
# MATCH_FIELDS does the same for each row of a list response, because a match
# is a record summary and record summaries are exactly where an extra field
# would appear.
ACTIONS = {
    "unlock": (),
    "lock": (),
    "list": ("matches",),
    "get": ("username", "password"),
}
MATCH_FIELDS = ("id", "label", "username", "url")

# Errors are chosen from this set, not echoed. Stringifying an unexpected error
# changes its type without closing the channel -- a message that embeds a path
# still carries the path across. Every error the CLI's bridge commands and this
# host can produce is named here; anything else becomes the generic refusal, so
# the outbound side of the contract is closed for failures as well as successes.
ALLOWED_ERRORS = frozenset((
    "invalid browser hostname",
    "record is not bound to this hostname",
    "record not found",
    "master password required",
    "numeric record ID required",
    "SPM is locked or the session expired",
    "unsupported native messaging action",
    "SPM bridge returned an invalid response",
    "SPM bridge refused the request",
))
GENERIC_ERROR = "SPM refused the request"


def project(action, response):
    """A response reduced to the fields this action is allowed to return."""
    if not isinstance(response, dict):
        return {"ok": False, "error": "SPM bridge returned an invalid response"}
    if not response.get("ok"):
        reason = response.get("error")
        if not isinstance(reason, str) or reason not in ALLOWED_ERRORS:
            reason = GENERIC_ERROR
        return {"ok": False, "error": reason}
    out = {"ok": True}
    for field in ACTIONS.get(action, ()):
        if field not in response:
            continue
        if field == "matches":
            rows = response[field]
            out[field] = [
                {k: row.get(k, "") for k in MATCH_FIELDS}
                for row in (rows if isinstance(rows, list) else [])
                if isinstance(row, dict)
            ]
        else:
            out[field] = response[field]
    return out


def run_spm(command, *args, password):
    result = subprocess.run([SPM_BIN, command, *args], input=password + "\n", text=True,
                            capture_output=True, timeout=30, env={**os.environ, "NO_COLOR":"1"})
    line = result.stdout.strip().splitlines()[-1:] or [""]
    try: response = json.loads(line[0])
    except json.JSONDecodeError: response = {"ok":False,"error":"SPM bridge returned an invalid response"}
    if result.returncode and response.get("ok") is not False:
        response = {"ok":False,"error":"SPM bridge refused the request"}
    return response

def is_unlocked():
    global master
    now = time.monotonic()
    if master is not None and now-last_used <= IDLE_SECONDS and now-unlocked_at <= MAX_SECONDS:
        return True
    master = None
    return False

def handle(message):
    global master, unlocked_at, last_used
    action = message.get("action")
    if action not in ACTIONS:
        return {"ok":False,"error":"unsupported native messaging action"}
    if action == "lock":
        master = None
        return {"ok":True}
    if action == "unlock":
        candidate = message.get("master")
        if not isinstance(candidate, str) or not candidate:
            return {"ok":False,"error":"master password required"}
        response = run_spm("bridge-list", valid_host(message.get("host")), password=candidate)
        if response.get("ok"):
            master = candidate; unlocked_at = last_used = time.monotonic()
        # unlock reports success or failure and nothing else: the list it used
        # to verify the password is not the caller's to receive here.
        return project("unlock", response)
    # The original one-shot extension, which is still in this repository and
    # still connects to this host: it sends the master password with each get
    # and holds no session. Kept because removing it breaks that extension
    # silently, and stated plainly rather than left as a quiet exception --
    # a caller supplying the password directly is not constrained by `lock` or
    # by either timeout, because it has no session for them to act on. That is
    # a property of a one-shot protocol, not a hole this table can close.
    if action == "get" and isinstance(message.get("master"), str):
        record = str(message.get("record", ""))
        if not record.isdigit(): return {"ok":False,"error":"numeric record ID required"}
        return project("get", run_spm("bridge-get", record,
                                      valid_host(message.get("host")),
                                      password=message["master"]))
    if action in ("list", "get"):
        if not is_unlocked():
            return {"ok":False,"error":"SPM is locked or the session expired"}
        host = valid_host(message.get("host"))
        if action == "list": response = run_spm("bridge-list", host, password=master)
        else:
            record = str(message.get("record", ""))
            if not record.isdigit(): return {"ok":False,"error":"numeric record ID required"}
            response = run_spm("bridge-get", record, host, password=master)
        if response.get("ok"): last_used = time.monotonic()
        return project(action, response)
    return {"ok":False,"error":"unsupported native messaging action"}

while True:
    try:
        request = read_message()
        if request is None: break
        request_id = request.get("id")
        response = handle(request)
        if request_id is not None: response["id"] = request_id
        write_message(response)
    except Exception as error:
        write_message({"ok":False,"error":str(error)})

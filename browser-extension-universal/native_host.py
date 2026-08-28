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
        return response
    # Compatibility with the original one-shot extension during migration.
    if action == "get" and isinstance(message.get("master"), str):
        record = str(message.get("record", ""))
        if not record.isdigit(): return {"ok":False,"error":"numeric record ID required"}
        return run_spm("bridge-get", record, valid_host(message.get("host")), password=message["master"])
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
        return response
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

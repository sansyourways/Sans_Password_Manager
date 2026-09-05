#!/usr/bin/env python3
import json, os, pathlib, struct, subprocess, sys, tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    fake = pathlib.Path(directory) / "spm"
    fake.write_text("""#!/bin/sh
read master
[ "$master" = test-master ] || { printf '{"ok":false,"error":"bad password"}\\n'; exit 1; }
case "$1" in
 bridge-list) printf '{"ok":true,"matches":[{"id":"7","label":"Example","username":"alice","url":"https://example.invalid"}]}\\n' ;;
 bridge-get) printf '{"ok":true,"username":"alice","password":"test-secret"}\\n' ;;
esac
""", encoding="utf-8")
    fake.chmod(0o700)
    env = {**os.environ, "SPM_BIN":str(fake), "SPM_BRIDGE_IDLE_SECONDS":"300",
           "SPM_BRIDGE_IDLE_CEILING":"3600"}
    process = subprocess.Popen([sys.executable, str(root/"browser-extension-universal/native_host.py")],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)

    def request(payload):
        data=json.dumps(payload).encode()
        process.stdin.write(struct.pack("=I",len(data))+data); process.stdin.flush()
        length=struct.unpack("=I",process.stdout.read(4))[0]
        return json.loads(process.stdout.read(length))

    assert request({"id":"1","action":"list","host":"example.invalid"})["ok"] is False
    unlocked=request({"id":"2","action":"unlock","host":"example.invalid","master":"test-master"})
    assert unlocked["ok"] is True and "password" not in json.dumps(unlocked)
    listed=request({"id":"3","action":"list","host":"example.invalid"})
    assert listed["matches"][0]["username"] == "alice" and "test-secret" not in json.dumps(listed)
    assert request({"id":"4","action":"get","host":"example.invalid","record":"7"})["password"] == "test-secret"
    # The idle window a caller asks for is clamped, not obeyed and not refused.
    # Refusing would let a caller map the configuration by probing it, and the
    # honest answer to "give me twelve hours" is the ceiling.
    status = request({"id":"5","action":"status"})
    assert status["unlocked"] is True, status
    assert status["idle"] == 300, status
    assert 0 < status["expires_in"] <= 300, status
    assert "password" not in json.dumps(status)
    request({"id":"6","action":"lock"})
    over = request({"id":"7","action":"unlock","host":"example.invalid",
                    "master":"test-master","idle":86400})
    assert over["ok"] is True
    assert request({"id":"8","action":"status"})["idle"] == 3600, "the ceiling did not clamp"
    request({"id":"9","action":"lock"})
    under = request({"id":"10","action":"unlock","host":"example.invalid",
                     "master":"test-master","idle":1})
    assert under["ok"] is True
    assert request({"id":"11","action":"status"})["idle"] == 30, "the floor did not clamp"
    request({"id":"12","action":"lock"})
    junk = request({"id":"13","action":"unlock","host":"example.invalid",
                    "master":"test-master","idle":"not-a-number"})
    assert junk["ok"] is True
    assert request({"id":"14","action":"status"})["idle"] == 300, "a junk idle did not fall back"
    # An unlock that FAILS must not move the window: the session it would have
    # applied to does not exist.
    request({"id":"15","action":"lock"})
    assert request({"id":"16","action":"unlock","host":"example.invalid",
                    "master":"wrong","idle":900})["ok"] is False
    locked = request({"id":"17","action":"status"})
    assert locked["unlocked"] is False and locked["expires_in"] == 0, locked
    # ...and it must not have rewritten the window either. A wrong password is
    # not a way to change the terms of the next session.
    assert locked["idle"] == 300, locked

    assert request({"id":"18","action":"lock"})["ok"] is True
    assert request({"id":"19","action":"get","host":"example.invalid","record":"7"})["ok"] is False
    process.stdin.close(); process.wait(timeout=5)
    assert process.returncode == 0
print("Native host regression: unlock, secret-free list, get, lock, "
      "and an idle window that is clamped rather than obeyed")

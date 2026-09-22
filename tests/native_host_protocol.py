#!/usr/bin/env python3
import json, os, pathlib, struct, subprocess, sys, tempfile

root = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    fake = pathlib.Path(directory) / "spm"
    fake.write_text("""#!/bin/sh
read master
[ "$master" = test-master ] || { printf '{"ok":false,"error":"bad password"}\\n'; exit 1; }
case "$1" in
 bridge-list)
   case "$2" in
    *paypa1*) printf '{"ok":true,"matches":[],"warning":{"suspected":"paypal.com","reason":"lookalike","leak":"drop-me"}}\\n' ;;
    *) printf '{"ok":true,"matches":[{"id":"7","label":"Example","username":"alice","url":"https://example.invalid"}]}\\n' ;;
   esac ;;
 bridge-get) printf '{"ok":true,"username":"alice","password":"test-secret"}\\n' ;;
 bridge-save) read newpw; printf '{"ok":true}\\n' ;;
 bridge-totp) printf '{"ok":true,"code":"123456","seconds":12,"secret":"JBSWY3DPEHPK3PXP"}\\n' ;;
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
    assert "warning" not in listed, listed
    # Roadmap 35: a look-alike host carries a two-string caution and nothing else
    # -- the extra "leak" field the core sent is dropped at the boundary.
    warned=request({"id":"3w","action":"list","host":"paypa1.invalid"})
    assert warned["matches"] == [] and warned["warning"] == {"suspected":"paypal.com","reason":"lookalike"}, warned
    assert "drop-me" not in json.dumps(warned), warned
    assert request({"id":"4","action":"get","host":"example.invalid","record":"7"})["password"] == "test-secret"
    # The idle window a caller asks for is clamped, not obeyed and not refused.
    # Refusing would let a caller map the configuration by probing it, and the
    # honest answer to "give me twelve hours" is the ceiling.
    status = request({"id":"5","action":"status"})
    assert status["unlocked"] is True, status
    assert status["idle"] == 300, status
    assert 0 < status["expires_in"] <= 300, status
    assert "password" not in json.dumps(status)
    # Roadmap 39: save-on-submit is the one write, allowed only from an open
    # session, and it returns ok -- never the credential it just stored.
    saved = request({"id":"5s","action":"save","host":"example.invalid",
                     "username":"alice","password":"a-new-secret"})
    assert saved["ok"] is True and "a-new-secret" not in json.dumps(saved), saved
    # A save with no password is refused before anything is written.
    assert request({"id":"5t","action":"save","host":"example.invalid",
                    "username":"alice","password":""})["ok"] is False
    # Roadmap 51: a one-time code for an OTP field, from an open session only,
    # projected to the digits and their lifetime -- never the seed.
    otp = request({"id":"5u","action":"totp","host":"example.invalid"})
    assert otp["ok"] is True and otp["code"] == "123456" and otp["seconds"] == 12, otp
    assert "JBSWY3DPEHPK3PXP" not in json.dumps(otp), otp
    # Roadmap 38: the extension's "Lock SPM" control. A lock from an open session
    # must clear it outright -- status locked, nothing left to expire.
    assert request({"id":"6","action":"lock"})["ok"] is True
    after_lock = request({"id":"6b","action":"status"})
    assert after_lock["unlocked"] is False and after_lock["expires_in"] == 0, after_lock
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
    # A locked session cannot write either.
    assert request({"id":"19s","action":"save","host":"example.invalid",
                    "username":"alice","password":"nope"})["ok"] is False
    # ...and a locked session yields no one-time code either.
    assert request({"id":"19t","action":"totp","host":"example.invalid"})["ok"] is False
    process.stdin.close(); process.wait(timeout=5)
    assert process.returncode == 0
print("Native host regression: unlock, secret-free list, get, lock, "
      "and an idle window that is clamped rather than obeyed")

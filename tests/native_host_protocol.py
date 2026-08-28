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
    env = {**os.environ, "SPM_BIN":str(fake), "SPM_BRIDGE_IDLE_SECONDS":"300"}
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
    assert request({"id":"5","action":"lock"})["ok"] is True
    assert request({"id":"6","action":"get","host":"example.invalid","record":"7"})["ok"] is False
    process.stdin.close(); process.wait(timeout=5)
    assert process.returncode == 0
print("Native host regression: unlock, secret-free list, get and lock")

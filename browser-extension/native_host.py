#!/usr/bin/env python3
"""Minimal Chrome/Chromium native-messaging bridge for SPM."""
import json, os, struct, subprocess, sys

def read_message():
    raw=sys.stdin.buffer.read(4)
    if len(raw)!=4:return None
    size=struct.unpack("<I",raw)[0]
    if size>65536:raise ValueError("message too large")
    return json.loads(sys.stdin.buffer.read(size))

def send_message(value):
    raw=json.dumps(value,separators=(",",":")).encode()
    sys.stdout.buffer.write(struct.pack("<I",len(raw))+raw);sys.stdout.buffer.flush()

while True:
    try:
        msg=read_message()
        if msg is None:break
        if msg.get("action")!="get":send_message({"ok":False,"error":"unsupported action"});continue
        record=str(msg.get("record", ""));host=str(msg.get("host", ""));master=str(msg.get("master", ""))
        if not record.isdigit() or not host or not master:send_message({"ok":False,"error":"invalid request"});continue
        proc=subprocess.run([os.environ.get("SPM_BIN","/usr/local/bin/spm"),"bridge-get",record,host],input=(master+"\n").encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
        master=""
        try:response=json.loads(proc.stdout.decode())
        except Exception:response={"ok":False,"error":"SPM bridge failed"}
        send_message(response)
    except Exception as exc:
        send_message({"ok":False,"error":str(exc)[:160]})

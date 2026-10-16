# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

import subprocess, socket, time, os, signal, json

env = dict(os.environ, GDB="0")
cmd = ["./qemu/run.sh", "-qmp", "tcp:127.0.0.1:4445,server,nowait"]
log = open("/tmp/opencode/gh.log", "w")
p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env)
time.sleep(14)

def qmp(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())
    time.sleep(0.5)
    return sock.recv(4000000).decode(errors="replace")

try:
    s = socket.create_connection(("127.0.0.1", 4445), timeout=10)
    s.recv(65536)
    print(qmp(s, {"execute": "qmp_capabilities"})[:200])
    out = qmp(s, {"execute": "human-monitor-command",
                  "arguments": {"command-line": "info tlb"}})
    s.close()
    # unwrap json
    try:
        txt = json.loads(out.split("\n", 1)[1])["return"]
    except Exception:
        txt = out
    lines = txt.splitlines()
    print("total translation lines:", len(lines))
    for ln in lines:
        if "fffffe0007" in ln or "fffffe0006" in ln or " 0000000080" in ln:
            print(ln)
    print("--- sample ---")
    for ln in lines[:12]:
        print(ln)
except Exception as e:
    print("qmp err:", e)

p.send_signal(signal.SIGINT); time.sleep(1); p.kill()

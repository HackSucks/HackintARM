#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 HackintARM contributors

"""
console.py -- a guest serial console that keeps a log and takes typed input.

run.sh normally puts the guest's serial port on QEMU's stdio, which is fine for
a boot that is only watched: output is redirected to a file and there is
nothing to type into.  It is not enough once there is something on the other
end -- a single-user shell (gatehouse/src/patch.c hands PID 1 another program
when the ESP carries \\gatehouse\\init), a recovery environment, an installer.

    SERIAL=/tmp/opencode/ser.sock qemu/run.sh -monitor unix:/tmp/opencode/mon.sock,server,nowait &
    qemu/console.py /tmp/opencode/ser.sock -l build/boot42.log -i /tmp/opencode/ser.in

Every byte from the guest is appended to the log (so the file is still the
boot log) and echoed to stdout; every byte written to the input pipe is sent to
the guest, which makes a shell scriptable:

    printf 'ls /\\nmount\\n' > /tmp/opencode/ser.in

SERIAL waits for this client to connect before QEMU starts the guest, so
nothing is lost at the beginning of a boot.
"""

import argparse
import os
import select
import socket
import sys


def main():
    ap = argparse.ArgumentParser(description="guest serial console")
    ap.add_argument("socket", help="unix socket run.sh was given as SERIAL")
    ap.add_argument("-l", "--log", help="append everything the guest writes")
    ap.add_argument("-i", "--input",
                    help="forward bytes written to this pipe or file")
    ap.add_argument("-s", "--send", action="append", default=[],
                    help="send this once connected (may be repeated)")
    args = ap.parse_args()

    log = open(args.log, "ab", buffering=0) if args.log else None
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.connect(args.socket)

    fifo = os.open(args.input, os.O_RDWR | os.O_NONBLOCK) if args.input else None
    out = sys.stdout.buffer

    for line in args.send:
        conn.sendall(line.encode() + b"\n")

    while True:
        rfds = [conn] + ([fifo] if fifo is not None else [])
        ready, _, _ = select.select(rfds, [], [])
        # The guest first, so a reply is printed before the next command.
        for fd in ready:
            if fd is conn:
                data = conn.recv(1 << 16)
                if not data:
                    return 0            # guest went away
                if log:
                    log.write(data)
                out.write(data)
                out.flush()
            else:
                data = os.read(fifo, 1 << 12)
                if data:
                    conn.sendall(data)


if __name__ == "__main__":
    sys.exit(main())

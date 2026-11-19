"""Drive the packaged repair command through a real terminal, leaving proof stdout separate."""
import errno
import os
import pty
import select
import subprocess
import sys
import time

master, slave = pty.openpty()
child = subprocess.Popen(sys.argv[1:], stdin=slave, stderr=slave, stdout=subprocess.PIPE)
os.close(slave)
try:
    transcript = bytearray()
    answered = False
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if not select.select([master], [], [], 0.1)[0]:
            continue
        try:
            chunk = os.read(master, 8192)
        except OSError as exc:
            if exc.errno == errno.EIO:  # Terminal closed by child.
                break
            raise
        if not chunk:
            break
        transcript.extend(chunk)
        if len(transcript) > 32768:
            raise RuntimeError("unexpectedly large repair review")
        if not answered and b"Type approve to request owner presence" in transcript:
            os.write(master, b"\n")
            answered = True
    if child.wait(timeout=1) != 1 or not answered or child.stdout.read():
        raise RuntimeError("the installed repair review did not discard with empty proof output")
    sys.stdout.buffer.write(transcript)
finally:
    os.close(master)
    if child.poll() is None:
        child.kill()
        child.wait()

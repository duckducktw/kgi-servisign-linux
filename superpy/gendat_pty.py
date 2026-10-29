#!/usr/bin/env python3
# 用 pty 餵 KGI_CGCrypt genDat（它的 getpass 要求 stdin 是 tty，pipe 會變空密碼→5005）
import os, pty, sys, time, select
pfx, uid, pw = sys.argv[1], sys.argv[2], os.environ.pop("PW")
tool = os.environ.get("KGI_CGCRYPT", "./KGI_CGCrypt")
pid, fd = pty.fork()
if pid == 0:
    os.execv(tool, [tool, "genDat"])
buf = b""
def until(tok, t=15):
    global buf
    end = time.time() + t
    while tok not in buf and time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try: buf += os.read(fd, 4096)
            except OSError: break
for prompt, val in ((b"pfx path", pfx), (b"user id", uid), (b"password", pw)):
    until(prompt); time.sleep(0.2); os.write(fd, (val + "\n").encode())
until(b"]", 30)
_, st = os.waitpid(pid, 0)
out = buf.decode(errors="replace")
line = [l for l in out.splitlines() if "CGSetCertConfig" in l]
print(line[-1].strip() if line else out.strip()[-200:].replace(pfx, "<pfx>"))

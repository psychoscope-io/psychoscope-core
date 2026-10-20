#!/usr/bin/env python3
"""Smoke da TUI num pseudo-terminal real: abre o psychoscope-cli sem argumentos, espera os
textos esperados aparecerem na tela, envia 'q' e exige saida com codigo 0.
Uso: tui_pty.py <psychoscope-cli> <ctl.sock> <texto-esperado>..."""
import fcntl, os, pty, re, select, struct, sys, termios, time

cli, sock, expected = sys.argv[1], sys.argv[2], sys.argv[3:]
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()][A-Za-z0-9]")

pid, fd = pty.fork()
if pid == 0:
    os.execv(cli, [cli, "--ctl-socket", sock])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 130, 0, 0))

buf = b""
deadline = time.time() + 15
missing = list(expected)
while missing and time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        buf += data
    text = ANSI.sub(b"", buf).decode("utf-8", "replace")
    missing = [e for e in expected if e not in text]

os.write(fd, b"q")
status = None
end = time.time() + 5
while time.time() < end:
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        status = st
        break
    try:
        if select.select([fd], [], [], 0.1)[0]:
            os.read(fd, 65536)
    except OSError:
        pass
if status is None:
    os.kill(pid, 9)
    print("FALHOU: a TUI nao saiu apos 'q'")
    sys.exit(1)
if missing:
    print("FALHOU: textos ausentes na tela:", missing)
    print(ANSI.sub(b"", buf).decode("utf-8", "replace")[-1500:])
    sys.exit(1)
if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
    print("FALHOU: saida da TUI com status", status)
    sys.exit(1)
print("ok: TUI renderizou", expected, "e saiu com 'q'")

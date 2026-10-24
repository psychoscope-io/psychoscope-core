#!/usr/bin/env python3
"""Cenario da tela de configuracoes da TUI num pseudo-terminal real, contra um Core de verdade.
Deve rodar como root (por exemplo dentro de `unshare -Urn`): so o root grava a configuracao.

Uso: tui_config_pty.py <psychoscope-cli> <ctl.sock> <overrides.json>

Passos: abre a tela (:config), edita um campo com :set e com Enter, confere o rascunho, recusa
:q com alteracao pendente, grava (:w), confere a origem "ajuste" e o arquivo 0600, restaura (d),
descarta (:q!) e sai da TUI (:q) com codigo 0. O Bubble Tea redesenha so as linhas que mudam,
entao cada conferencia forca um repaint completo (muda e restaura o tamanho da janela)."""
import fcntl, os, pty, re, select, stat, struct, sys, termios, time

cli, sock, overrides = sys.argv[1:4]
ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]")
ROWS, COLS = 36, 130


def winsize(rows):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, COLS, 0, 0))


pid, fd = pty.fork()
if pid == 0:
    os.execv(cli, [cli, "--ctl-socket", sock])
winsize(ROWS)
buf = b""


def pump(sec):
    global buf
    end = time.time() + sec
    while time.time() < end:
        if select.select([fd], [], [], 0.05)[0]:
            try:
                buf += os.read(fd, 65536)
            except OSError:
                return


def send(data, wait=0.5):
    os.write(fd, data)
    pump(wait)


def screen():
    """Tela inteira atual: forca um repaint completo e devolve so o que foi desenhado depois."""
    global buf
    winsize(ROWS + 1)
    pump(0.3)
    buf = b""
    winsize(ROWS)
    pump(0.6)
    return ANSI.sub(b"", buf).decode("utf-8", "replace")


def check(what, ok, scr=""):
    print(("ok: " if ok else "FALHOU: ") + what)
    if not ok:
        print(scr[-2500:])
        os.kill(pid, 9)
        sys.exit(1)


# A TUI consulta a cor de fundo (OSC 11) e espera a resposta: espere a tela aparecer.
t0 = time.time()
while "PSYCHOSCOPE" not in ANSI.sub(b"", buf).decode("utf-8", "replace") and time.time() - t0 < 25:
    pump(0.3)

send(b":config\r", 1.0)
s = screen()
check("tela de configuracoes aberta, com secoes, campos, padrao e origem", all(x in s for x in
      ["Configurações", "Motor de detecção", "Janela do motor", "padrão"]), s)
check("root nao ve o aviso de somente leitura", "somente leitura" not in s, s)

send(b":set detection.scan.vertical_ports=30\r")
s = screen()
check("rascunho marcado e contado no titulo", "30 *" in s and "1 alteração(ões) não gravada(s)" in s, s)

send(b":q\r")
s = screen()
check(":q com alteracao pendente nao fecha a tela", "Configurações" in s and "não gravada" in s, s)

# Enter edita o campo selecionado (o primeiro, detection.window: "Janela do motor")
send(b"g")
send(b"\r")
s = screen()
check("Enter abre o editor do campo", "editando Janela do motor" in s, s)
send(b"\x1b")  # Esc cancela a edicao
s = screen()
check("Esc cancela so a edicao", "Configurações" in s and "editando" not in s, s)

send(b":w\r", 1.2)
send(b":set detection.scan.vertical_ports\r")  # :set sem valor leva a selecao ao campo
s = screen()
check("gravar aplica e limpa o rascunho", "não gravada" not in s and "ajuste" in s, s)
check("o valor gravado aparece na linha do campo", re.search(r"Portas distintas \(vertical\)\s+30\s+15\s+ajuste", s) is not None, s)
check("arquivo de ajustes com modo 0600", os.path.exists(overrides) and stat.S_IMODE(os.stat(overrides).st_mode) == 0o600)

send(b":set detection.scan.vertical_ports&\r")
s = screen()
check("restaurar marca o campo", "(restaurar ao valor base) *" in s, s)
send(b":w\r", 1.2)
check("restaurar gravado remove o arquivo de ajustes", not os.path.exists(overrides))

send(b":set detection.scan.vertical_ports=40\r")
send(b":q!\r")
s = screen()
check(":q! descarta e volta a tela principal", "Configurações" not in s and "PSYCHOSCOPE" in s, s)

# Esc volta da tela de configuracoes, sem precisar de comando
send(b":config\r", 1.0)
check("a tela de configuracoes reabre", "Configurações" in screen(), screen())
send(b"\x1b")
s = screen()
check("Esc volta para a tela principal", "Configurações" not in s and "PSYCHOSCOPE" in s, s)

os.write(fd, b":q\r")
end, status = time.time() + 6, None
while time.time() < end:
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        status = st
        break
    pump(0.1)
check(":q na tela principal sai com codigo 0", status is not None and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
print("TUI CONFIG OK")

#!/usr/bin/env bash
# Instala o Psychoscope (core + CLI, e opcionalmente o sensor) como servico systemd.
#
#   sudo ./deploy/install.sh [--sensor /caminho/mod-net-sensor] [--prefix /usr/local]
#                            [--bin-dir DIR] [--no-setcap] [--dry-run] [--destdir DIR]
#
# - Sem --destdir exige root. Com --destdir instala em um diretorio de staging (empacotamento
#   e testes): nao cria usuario, nao aplica setcap e nao toca no systemd.
# - Nunca sobrescreve /etc/psychoscope/psychoscope.json existente.
# - --dry-run apenas mostra o que seria feito.
set -euo pipefail

PREFIX=/usr/local
DESTDIR=""
SENSOR=""
BIN_DIR=""
SETCAP=1
DRY=0

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)   [ $# -ge 2 ] || die "--prefix exige um valor"; PREFIX="$2"; shift 2 ;;
    --destdir)  [ $# -ge 2 ] || die "--destdir exige um valor"; DESTDIR="$2"; shift 2 ;;
    --sensor)   [ $# -ge 2 ] || die "--sensor exige um caminho"; SENSOR="$2"; shift 2 ;;
    --bin-dir)  [ $# -ge 2 ] || die "--bin-dir exige um diretorio"; BIN_DIR="$2"; shift 2 ;;
    --no-setcap) SETCAP=0; shift ;;
    --dry-run)  DRY=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) usage >&2; die "argumento desconhecido: $1" ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN_DIR="${BIN_DIR:-$ROOT}"
if [ ! -x "$BIN_DIR/psychoscope" ] || [ ! -x "$BIN_DIR/psychoscope-cli" ]; then
  die "binarios psychoscope e psychoscope-cli nao encontrados em $BIN_DIR (rode a partir do tarball de release ou use --bin-dir)"
fi
[ -z "$SENSOR" ] || [ -x "$SENSOR" ] || die "sensor nao encontrado ou nao executavel: $SENSOR"
if [ ! -f "$HERE/systemd/psychoscope.service" ] || [ ! -f "$HERE/psychoscope.json.example" ]; then
  die "arquivos de deploy ausentes em $HERE"
fi

if [ -z "$DESTDIR" ] && [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
  die "execute como root (sudo), ou use --destdir/--dry-run"
fi

run() {
  if [ "$DRY" = 1 ]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}
D() { printf '%s%s' "$DESTDIR" "$1"; }   # caminho dentro do destdir

BINDIR="$PREFIX/bin"
CONF=/etc/psychoscope
UNIT_DIR=/etc/systemd/system

# 1. usuario de sistema
if [ -z "$DESTDIR" ]; then
  if ! getent passwd psychoscope >/dev/null; then
    run useradd --system --user-group --no-create-home --home-dir /var/lib/psychoscope --shell /usr/sbin/nologin psychoscope
  fi
fi

# 2. binarios
run install -d -m 0755 "$(D "$BINDIR")"
run install -m 0755 "$BIN_DIR/psychoscope" "$(D "$BINDIR")/psychoscope"
run install -m 0755 "$BIN_DIR/psychoscope-cli" "$(D "$BINDIR")/psychoscope-cli"
if [ -n "$SENSOR" ]; then
  run install -m 0755 "$SENSOR" "$(D "$BINDIR")/mod-net-sensor"
  if [ "$SETCAP" = 1 ] && [ -z "$DESTDIR" ]; then
    command -v setcap >/dev/null || [ "$DRY" = 1 ] || die "setcap nao encontrado (pacote libcap2-bin); use --no-setcap para aplicar depois"
    run setcap cap_net_raw,cap_net_admin=eip "$BINDIR/mod-net-sensor"
  else
    echo "aviso: setcap nao aplicado. Rode: setcap cap_net_raw,cap_net_admin=eip $BINDIR/mod-net-sensor" >&2
  fi
fi
# O atualizador fica instalado: `psychoscope-update` baixa, confere e instala a proxima versao.
if [ -f "$HERE/get.sh" ]; then
  run install -d -m 0755 "$(D "$PREFIX/sbin")"
  run install -m 0755 "$HERE/get.sh" "$(D "$PREFIX/sbin")/psychoscope-update"
fi

# 3. configuracao (nunca sobrescreve)
run install -d -m 0750 "$(D "$CONF")"
if [ -e "$(D "$CONF")/psychoscope.json" ]; then
  echo "mantendo $CONF/psychoscope.json existente"
else
  run install -m 0640 "$HERE/psychoscope.json.example" "$(D "$CONF")/psychoscope.json"
fi
if [ -z "$DESTDIR" ]; then
  run chgrp psychoscope "$CONF" "$CONF/psychoscope.json" 2>/dev/null || true
fi

# 4. unit do systemd (ajusta o caminho do binario ao prefixo escolhido)
run install -d -m 0755 "$(D "$UNIT_DIR")"
if [ "$DRY" = 1 ]; then
  echo "[dry-run] gerar $UNIT_DIR/psychoscope.service (ExecStart=$BINDIR/psychoscope)"
else
  sed "s#^ExecStart=.*#ExecStart=$BINDIR/psychoscope --config $CONF/psychoscope.json#" "$HERE/systemd/psychoscope.service" > "$(D "$UNIT_DIR")/psychoscope.service"
  chmod 0644 "$(D "$UNIT_DIR")/psychoscope.service"
fi

cat <<MSG

Instalacao concluida${DESTDIR:+ em $DESTDIR}.
Proximos passos:
  1. edite $CONF/psychoscope.json (interface do sensor em "args", por exemplo ["-i", "eth0"];
     veja os nomes com: mod-net-sensor --list-interfaces)
  2. sudo systemctl daemon-reload && sudo systemctl enable --now psychoscope
  3. sudo psychoscope-cli list        # ou: sudo psychoscope-cli (TUI)
Para atualizar depois: psychoscope-update --check  e  psychoscope-update
Veja docs/INSTALL.md para permissoes, metricas e solucao de problemas.
MSG

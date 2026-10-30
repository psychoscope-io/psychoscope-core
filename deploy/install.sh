#!/usr/bin/env bash
# Instala o Psychoscope (core + CLI, e opcionalmente o sensor) como servico systemd.
#
#   sudo ./deploy/install.sh [--sensor /caminho/mod-net-sensor] [--prefix /usr/local]
#                            [--bin-dir DIR] [--dry-run] [--destdir DIR]
#
# - Sem --destdir exige root. Com --destdir instala em um diretorio de staging (empacotamento
#   e testes): nao cria usuarios e nao toca no systemd.
# - Duas units: psychoscope.service (Core, sem capabilities) e psychoscope-sensor.service (sensor,
#   usuario proprio psychoscope-sensor, capabilities de captura pelo systemd; nao ha setcap).
# - Nunca sobrescreve /etc/psychoscope/psychoscope.json nem sensor.env existentes. Ao atualizar uma
#   configuracao antiga (sensor lancado pelo Core), converte so o modulo do sensor, com copia.
# - --dry-run apenas mostra o que seria feito.
set -euo pipefail

PREFIX=/usr/local
DESTDIR=""
SENSOR=""
BIN_DIR=""
DRY=0

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)   [ $# -ge 2 ] || die "--prefix exige um valor"; PREFIX="$2"; shift 2 ;;
    --destdir)  [ $# -ge 2 ] || die "--destdir exige um valor"; DESTDIR="$2"; shift 2 ;;
    --sensor)   [ $# -ge 2 ] || die "--sensor exige um caminho"; SENSOR="$2"; shift 2 ;;
    --bin-dir)  [ $# -ge 2 ] || die "--bin-dir exige um diretorio"; BIN_DIR="$2"; shift 2 ;;
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
if [ ! -f "$HERE/systemd/psychoscope.service" ] || [ ! -f "$HERE/systemd/psychoscope-sensor.service" ] ||
  [ ! -f "$HERE/psychoscope.json.example" ] || [ ! -f "$HERE/sensor.env.example" ]; then
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

# Atualizacao ou instalacao nova? A unit e legivel sem root (a configuracao fica em um diretorio 0750).
UPDATING=0
[ ! -e "$(D "$UNIT_DIR")/psychoscope.service" ] || UPDATING=1

# 0. configuracao de uma versao antiga (sensor lancado pelo Core) -> modulo externo. Aqui so se VALIDA
# (--check nao escreve nada, nem em --dry-run): se a conversao nao for fiel, ela recusa e nada foi
# instalado nem alterado. A migracao em si acontece depois dos binarios (passo 2b), para que uma falha
# na instalacao nunca deixe a configuracao nova com binarios antigos.
MIGRATE_ARGS=()
if [ -e "$(D "$CONF")/psychoscope.json" ]; then
  MIGRATE_ARGS=(migrate-config --config "$(D "$CONF")/psychoscope.json" --sensor-env "$(D "$CONF")/sensor.env")
  "$BIN_DIR/psychoscope-cli" "${MIGRATE_ARGS[@]}" --check ||
    die "a configuracao existente nao pode ser migrada sozinha; veja a mensagem acima e docs/INSTALL.md (Atualizando de 0.11 ou anterior)"
fi

# 1. usuarios de sistema: o Core e o sensor nao compartilham usuario
if [ -z "$DESTDIR" ]; then
  if ! getent passwd psychoscope >/dev/null; then
    run useradd --system --user-group --no-create-home --home-dir /var/lib/psychoscope --shell /usr/sbin/nologin psychoscope
  fi
  if ! getent passwd psychoscope-sensor >/dev/null; then
    run useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin psychoscope-sensor
  fi
fi

# 2. binarios
run install -d -m 0755 "$(D "$BINDIR")"
run install -m 0755 "$BIN_DIR/psychoscope" "$(D "$BINDIR")/psychoscope"
run install -m 0755 "$BIN_DIR/psychoscope-cli" "$(D "$BINDIR")/psychoscope-cli"
if [ -n "$SENSOR" ]; then
  run install -m 0755 "$SENSOR" "$(D "$BINDIR")/mod-net-sensor"
fi
# O atualizador fica instalado: `psychoscope-update` baixa, confere e instala a proxima versao.
if [ -f "$HERE/get.sh" ]; then
  run install -d -m 0755 "$(D "$PREFIX/sbin")"
  run install -m 0755 "$HERE/get.sh" "$(D "$PREFIX/sbin")/psychoscope-update"
fi

# 2b. migra a configuracao antiga (ja validada no passo 0), com os binarios novos no lugar
if [ "${#MIGRATE_ARGS[@]}" -gt 0 ]; then
  run "$BIN_DIR/psychoscope-cli" "${MIGRATE_ARGS[@]}" ||
    die "a migracao da configuracao falhou depois de instalar os binarios; a original esta intacta ou em psychoscope.json.antes-da-migracao; veja docs/INSTALL.md (Atualizando de 0.11 ou anterior)"
fi

# 3. configuracao (nunca sobrescreve)
run install -d -m 0750 "$(D "$CONF")"
if [ -e "$(D "$CONF")/psychoscope.json" ]; then
  echo "mantendo $CONF/psychoscope.json existente"
else
  run install -m 0640 "$HERE/psychoscope.json.example" "$(D "$CONF")/psychoscope.json"
fi
if [ -e "$(D "$CONF")/sensor.env" ]; then
  echo "mantendo $CONF/sensor.env existente"
else
  run install -m 0640 "$HERE/sensor.env.example" "$(D "$CONF")/sensor.env"
fi
if [ -z "$DESTDIR" ]; then
  run chgrp psychoscope "$CONF" "$CONF/psychoscope.json" "$CONF/sensor.env" 2>/dev/null || true
fi

# 4. units do systemd (ajustam o caminho dos binarios ao prefixo escolhido)
run install -d -m 0755 "$(D "$UNIT_DIR")"
if [ "$DRY" = 1 ]; then
  echo "[dry-run] gerar $UNIT_DIR/psychoscope.service (ExecStart=$BINDIR/psychoscope)"
  echo "[dry-run] gerar $UNIT_DIR/psychoscope-sensor.service (ExecStart=$BINDIR/mod-net-sensor)"
else
  sed "s#^ExecStart=.*#ExecStart=$BINDIR/psychoscope --config $CONF/psychoscope.json#" "$HERE/systemd/psychoscope.service" > "$(D "$UNIT_DIR")/psychoscope.service"
  sed "s#^ExecStart=.*#ExecStart=$BINDIR/mod-net-sensor \$SENSOR_ARGS#" "$HERE/systemd/psychoscope-sensor.service" > "$(D "$UNIT_DIR")/psychoscope-sensor.service"
  chmod 0644 "$(D "$UNIT_DIR")/psychoscope.service" "$(D "$UNIT_DIR")/psychoscope-sensor.service"
fi

if [ "$UPDATING" = 1 ]; then
  cat <<MSG

Atualizacao concluida${DESTDIR:+ em $DESTDIR}. A configuracao existente foi mantida.
Para usar a versao nova: sudo systemctl daemon-reload && sudo systemctl restart psychoscope
(reiniciar o Core reinicia tambem o sensor, que tem unit propria: psychoscope-sensor)
(o psychoscope-update ja faz isso sozinho)
MSG
else
  cat <<MSG

Instalacao concluida${DESTDIR:+ em $DESTDIR}.
Proximos passos:
  1. edite $CONF/sensor.env (interface de captura em SENSOR_ARGS, por exemplo "-i eth0";
     veja os nomes com: mod-net-sensor --list-interfaces)
  2. sudo systemctl daemon-reload && sudo systemctl enable --now psychoscope
  3. sudo psychoscope-cli list        # ou: sudo psychoscope-cli (TUI)
Para atualizar depois: psychoscope-update --check  e  psychoscope-update
Veja docs/INSTALL.md para permissoes, metricas e solucao de problemas.
MSG
fi

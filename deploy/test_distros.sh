#!/usr/bin/env bash
# Teste MANUAL de instalacao, atualizacao e remocao em distribuicoes reais (Debian, Ubuntu, Fedora),
# com systemd de verdade, dentro de conteineres Docker. Precisa de Docker e de rede (baixa as
# releases PUBLICAS da versao de partida e o sensor); por isso nao roda no CI. Nao toca em nada fora
# do Docker: conteineres descartaveis e imagens de teste removidas no fim.
#
#   deploy/test_distros.sh                          # as tres distribuicoes
#   DISTROS="fedora:latest" deploy/test_distros.sh  # so uma
#   OLD_CORE=0.11.0 OLD_SENSOR=0.3.1 deploy/test_distros.sh   # versoes de partida da atualizacao
#   LOCAL_BUILD=0 deploy/test_distros.sh            # atualiza para a ULTIMA RELEASE publicada
#   KEEP=1 deploy/test_distros.sh                   # nao remove conteineres nem imagens de teste
#
# Por distribuicao: instala a versao de partida pelo get.sh publicado (usuario comum + sudo), sobe o
# servico, atualiza com o psychoscope-update ja instalado e confere o modelo novo (Core sem
# capabilities e com NoNewPrivs, sensor em unit propria, com usuario proprio e capabilities
# ambientes, sem acesso ao banco de alertas), que a configuracao foi migrada sem perder nada, que os
# ajustes e o historico sobreviveram, e a remocao com e sem --purge. Sai com 1 se algo falhar.
#
# Por padrao (LOCAL_BUILD=1) a versao NOVA e o Core compilado desta arvore, servido por um servidor
# HTTP no gateway do Docker (get.sh com PSYCHOSCOPE_RELEASE_BASE), e o sensor e o da ultima release;
# serve para testar ANTES de publicar. Com LOCAL_BUILD=0 testa o que esta publicado.
# shellcheck disable=SC2016 # os comandos entre aspas simples sao avaliados DENTRO do conteiner, de proposito
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CORE_DIR="$(cd "$HERE/.." && pwd)"
DISTROS="${DISTROS:-debian:12 ubuntu:24.04 fedora:latest}"
OLD_CORE="${OLD_CORE:-0.11.0}"
OLD_SENSOR="${OLD_SENSOR:-0.3.1}"
LOCAL_BUILD="${LOCAL_BUILD:-1}"
LOCAL_CORE_VERSION="${LOCAL_CORE_VERSION:-99.0.0}"
NEW_SENSOR="${NEW_SENSOR:-}"
KEEP="${KEEP:-0}"
GH=https://github.com/psychoscope-io
command -v docker >/dev/null || { echo "docker nao encontrado" >&2; exit 2; }

FAILS=0
LOG="$(mktemp -d)"
C=""
IMG=""
SRV=""
BASE=""
x()  { docker exec "$C" bash -c "$1"; }                  # como root
xu() { docker exec -u tester "$C" bash -c "$1"; }        # como usuario comum
check() { # descricao comando-no-container (como root)
  if out="$(x "$2" 2>&1)"; then echo "  ok: $1"; else echo "  FALHOU: $1"; printf '%s\n' "$out" | tail -4 | sed 's/^/      /'; FAILS=$((FAILS + 1)); return 1; fi
}
waitfor() { # descricao segundos comando-no-container
  local i
  for ((i = 0; i < $2; i++)); do x "$3" >/dev/null 2>&1 && { echo "  ok: $1"; return 0; }; sleep 1; done
  echo "  FALHOU: $1 (nao ocorreu em $2 s)"; FAILS=$((FAILS + 1)); return 1
}
# scan_until ALVO TEXTO: varre ate o historico trazer TEXTO. O cooldown do net.scan.syn e por ORIGEM (60 s no
# tempo dos eventos) e o estado do motor sobrevive ao reinicio, entao uma varredura logo apos outra pode ser
# suprimida de proposito: repete a cada 25 s, por ate 4 rodadas.
scan_until() {
  local i j
  for ((i = 0; i < 4; i++)); do
    scan "$1"
    for ((j = 0; j < 25; j++)); do
      x "/usr/local/bin/psychoscope-cli alerts --history | grep -q '$2'" >/dev/null 2>&1 && { echo "  ok: alerta net.scan.syn do modelo novo gravado (varredura a $1)"; return 0; }
      sleep 1
    done
  done
  echo "  FALHOU: alerta net.scan.syn do modelo novo gravado (4 varreduras a $1)"; FAILS=$((FAILS + 1)); return 1
}
scan() { # alvo: 40 portas em poucos segundos (dispara net.scan.syn); como usuario comum
  xu "for p in \$(seq 1 40); do timeout 0.3 bash -c \"echo > /dev/tcp/$1/\$p\" 2>/dev/null; done; true"
}

dockerfile() { # imagem-base
  case "$1" in
    fedora*)
      cat <<EOF
FROM $1
RUN dnf -y -q install systemd curl sudo libpcap libcap iproute procps-ng shadow-utils util-linux && dnf clean all
EOF
      ;;
    *)
      cat <<EOF
FROM $1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus curl ca-certificates sudo libpcap0.8 libcap2-bin iproute2 procps && rm -rf /var/lib/apt/lists/*
EOF
      ;;
  esac
  cat <<'EOF'
RUN useradd -m tester && echo 'tester ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/tester
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
}

cleanup() {
  [ "$KEEP" = 1 ] && return
  [ -n "$C" ] && docker rm -f "$C" >/dev/null 2>&1
  [ -n "$IMG" ] && docker rmi -f "$IMG" >/dev/null 2>&1
  C=""; IMG=""
}
trap 'cleanup; [ -z "$SRV" ] || kill "$SRV" 2>/dev/null; rm -rf "$LOG"' EXIT

# prepare_local compila o Core desta arvore, monta uma "release" falsa (Core local + sensor da ultima
# release publicada) e a serve no gateway do Docker, o unico endereco que os conteineres alcancam.
prepare_local() {
  command -v go >/dev/null || { echo "go nao encontrado (precisa dele para compilar o Core; ou use LOCAL_BUILD=0)" >&2; exit 2; }
  command -v python3 >/dev/null || { echo "python3 nao encontrado" >&2; exit 2; }
  [ "$(uname -m)" = x86_64 ] || { echo "LOCAL_BUILD so cobre amd64 (a maquina e $(uname -m))" >&2; exit 2; }
  local gw pkg="psychoscope-core_${LOCAL_CORE_VERSION}_linux_amd64" ldf rel="$LOG/srv"
  gw="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
  [ -n "$gw" ] || { echo "nao achei o gateway da rede bridge do Docker" >&2; exit 2; }
  NEW_SENSOR="${NEW_SENSOR:-$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$GH/mod-net-sensor/releases/latest" | sed 's#.*/tag/v##')}"
  [[ "$NEW_SENSOR" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "nao descobri a ultima versao do sensor (use NEW_SENSOR=X.Y.Z)" >&2; exit 2; }

  echo "compilando o Core desta arvore como $LOCAL_CORE_VERSION ..."
  ldf="-s -w -X github.com/psychoscope-io/psychoscope-core/internal/version.Version=$LOCAL_CORE_VERSION"
  mkdir -p "$LOG/build/$pkg/deploy" "$rel/psychoscope-core/releases/download/v$LOCAL_CORE_VERSION" "$rel/mod-net-sensor/releases/download/v$NEW_SENSOR"
  (cd "$CORE_DIR" && for b in psychoscope psychoscope-cli; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$ldf" -o "$LOG/build/$pkg/$b" "./cmd/$b" || exit 1
  done) || { echo "falha ao compilar o Core" >&2; exit 2; }
  cp -r "$HERE/install.sh" "$HERE/get.sh" "$HERE/systemd" "$HERE/psychoscope.json.example" "$HERE/sensor.env.example" "$LOG/build/$pkg/deploy/"
  tar -C "$LOG/build" -czf "$rel/psychoscope-core/releases/download/v$LOCAL_CORE_VERSION/$pkg.tar.gz" "$pkg"
  (cd "$rel/psychoscope-core/releases/download/v$LOCAL_CORE_VERSION" && sha256sum ./*.tar.gz > SHA256SUMS)

  echo "baixando o sensor $NEW_SENSOR (release publicada) ..."
  local sd="$rel/mod-net-sensor/releases/download/v$NEW_SENSOR"
  local tb="mod-net-sensor_${NEW_SENSOR}_linux_amd64.tar.gz"
  curl -fsSL -o "$sd/$tb" "$GH/mod-net-sensor/releases/download/v$NEW_SENSOR/$tb" || { echo "falha ao baixar o sensor $NEW_SENSOR" >&2; exit 2; }
  curl -fsSL -o "$sd/SHA256SUMS" "$GH/mod-net-sensor/releases/download/v$NEW_SENSOR/SHA256SUMS" || { echo "falha ao baixar o SHA256SUMS do sensor $NEW_SENSOR" >&2; exit 2; }
  (cd "$sd" && grep "mod-net-sensor_${NEW_SENSOR}_linux_amd64.tar.gz" SHA256SUMS | sha256sum -c --status) || { echo "checksum do sensor $NEW_SENSOR nao confere" >&2; exit 2; }

  python3 -I "$HERE/release_server.py" "$rel" "$LOG/port" "$gw" &
  SRV=$!
  for _ in $(seq 50); do [ -s "$LOG/port" ] && break; sleep 0.1; done
  [ -s "$LOG/port" ] || { echo "servidor de releases nao subiu" >&2; exit 2; }
  BASE="http://$gw:$(cat "$LOG/port")"
  echo "releases locais em $BASE (Core $LOCAL_CORE_VERSION desta arvore, sensor $NEW_SENSOR)"
}

# upgrade [--force]: roda o psychoscope-update ja INSTALADO (o da versao de partida) como usuario comum.
upgrade() {
  if [ -n "$BASE" ]; then
    xu "sudo env PSYCHOSCOPE_RELEASE_BASE=$BASE /usr/local/sbin/psychoscope-update $*"
  else
    xu "sudo /usr/local/sbin/psychoscope-update $*"
  fi
}

run_distro() {
  local base="$1" tag
  tag="$(echo "$base" | tr ':/' '--')"
  IMG="psychoscope-test-$tag"; C="psychoscope-test-$tag"
  echo
  echo "=== $base ==="
  docker rm -f "$C" >/dev/null 2>&1
  dockerfile "$base" | docker build -q -t "$IMG" - >/dev/null || { echo "  FALHOU: construir a imagem de teste"; FAILS=$((FAILS + 1)); return; }
  # systemd precisa de /run, /sys/fs/cgroup e de montar namespaces (as unidades usam ProtectSystem e PrivateTmp, que o
  # AppArmor e o seccomp padrao do Docker barram); o sensor, de NET_RAW e NET_ADMIN, que o systemd entrega como ambientes
  docker run -d --name "$C" --cap-add SYS_ADMIN --cap-add NET_ADMIN --cap-add NET_RAW \
    --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
    --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw --cgroupns=host \
    "$IMG" >/dev/null || { echo "  FALHOU: subir o conteiner"; FAILS=$((FAILS + 1)); return; }
  waitfor "systemd iniciou" 60 'systemctl is-system-running 2>/dev/null | grep -Eq "running|degraded"' || return
  echo "  systemd: $(x 'systemctl --version | head -1')"

  echo "- instalacao da versao de partida (core $OLD_CORE, sensor $OLD_SENSOR, release publicada)"
  docker cp "$HERE/get.sh" "$C:/get.sh" && x 'chmod 755 /get.sh'
  if ! xu "bash /get.sh --core-version $OLD_CORE --sensor-version $OLD_SENSOR" >"$LOG/get.txt" 2>&1; then
    echo "  FALHOU: get.sh"; tail -6 "$LOG/get.txt" | sed 's/^/      /'; FAILS=$((FAILS + 1)); return
  fi
  echo "  ok: get.sh"
  check "binarios instalados e executaveis" 'for b in psychoscope psychoscope-cli mod-net-sensor; do test -x /usr/local/bin/$b || exit 1; done; test -x /usr/local/sbin/psychoscope-update'
  check "libpcap resolvida (ldd sem 'not found')" '! ldd /usr/local/bin/mod-net-sensor | grep "not found"'
  check "sensor executa (--version)" '/usr/local/bin/mod-net-sensor --version'
  check "usuario psychoscope existe" 'getent passwd psychoscope'
  check "configuracao 640 e diretorio 750" '[ "$(stat -c %a /etc/psychoscope/psychoscope.json)" = 640 ] && [ "$(stat -c %a /etc/psychoscope)" = 750 ]'

  echo "- servico da versao de partida"
  x "sed -i 's/\"retention_days\": 30/\"retention_days\": 31/' /etc/psychoscope/psychoscope.json" # marca para provar que a atualizacao preserva
  check "systemctl enable --now" 'systemctl enable --now psychoscope'
  waitfor "servico ativo" 20 'systemctl is-active --quiet psychoscope'
  local had_history=0 i
  for ((i = 0; i < 20; i++)); do # informativo: o sensor da versao anterior captura? (nao em systemd antigo, como o do Debian 12)
    x '/usr/local/bin/psychoscope-cli list | grep -q CONECTADO' >/dev/null 2>&1 && { had_history=1; break; }
    sleep 1
  done
  if [ "$had_history" = 1 ]; then
    echo "  ok: sensor da versao anterior conectado"
    scan "$(x "ip route | awk '/default/{print \$3; exit}'")"
    waitfor "alerta net.scan.syn gravado pela versao anterior" 40 '/usr/local/bin/psychoscope-cli alerts --history | grep -q net.scan.syn' || had_history=0
  else
    echo "  info: o sensor da versao anterior nao captura nesta distro; o historico anterior a atualizacao nao e testado (vale o da reinstalacao)"
  fi
  x '/usr/local/bin/psychoscope-cli config set detection.beacon.ignore_ports=1234 >/dev/null && [ "$(stat -c %a /var/lib/psychoscope/overrides.json)" = 600 ]' && echo "  ok: ajuste em tempo de execucao (overrides.json 600)"
  x 'sha256sum /var/lib/psychoscope/overrides.json > /root/antes.sha; sha256sum /etc/psychoscope/psychoscope.json | cut -d" " -f1 > /root/config-antes.sha'

  echo "- atualizacao (psychoscope-update da versao de partida -> ${BASE:+Core local $LOCAL_CORE_VERSION e }ultima release do sensor)"
  if upgrade >"$LOG/upd.txt" 2>&1; then echo "  ok: psychoscope-update"; else
    echo "  FALHOU: psychoscope-update"; tail -8 "$LOG/upd.txt" | sed 's/^/      /'; FAILS=$((FAILS + 1)); fi
  check "ficou na ultima versao (--check sai 0)" "${BASE:+PSYCHOSCOPE_RELEASE_BASE=$BASE }/usr/local/sbin/psychoscope-update --check"
  check "configuracao antiga migrada (sensor externo) e copia original guardada" \
    'grep -q "\"external\": true" /etc/psychoscope/psychoscope.json && ! grep -q "\"path\"" /etc/psychoscope/psychoscope.json && [ "$(sha256sum /etc/psychoscope/psychoscope.json.antes-da-migracao | cut -d" " -f1)" = "$(cat /root/config-antes.sha)" ]'
  check "restante da configuracao preservado (retencao 31 dias)" 'grep -q "\"retention_days\": 31" /etc/psychoscope/psychoscope.json'
  check "sensor.env criado a partir dos argumentos antigos" 'grep -qx "SENSOR_ARGS=-i eth0" /etc/psychoscope/sensor.env'
  check "ajustes em tempo de execucao preservados byte a byte" 'sha256sum -c /root/antes.sha'

  echo "- modelo novo: Core e sensor em units separadas"
  waitfor "Core ativo" 30 'systemctl is-active --quiet psychoscope'
  waitfor "unit do sensor ativa" 30 'systemctl is-active --quiet psychoscope-sensor'
  waitfor "sensor conectado ao Core" 40 '/usr/local/bin/psychoscope-cli list | grep -q CONECTADO'
  check "Core com NoNewPrivs e sem nenhuma capability" 'p=$(systemctl show -p MainPID --value psychoscope); grep -Eq "^NoNewPrivs:[[:space:]]+1" /proc/$p/status && grep -Eq "^CapEff:[[:space:]]+0+$" /proc/$p/status && grep -Eq "^CapBnd:[[:space:]]+0+$" /proc/$p/status'
  check "sensor roda com usuario proprio (nao root, nao o do Core)" 'p=$(systemctl show -p MainPID --value psychoscope-sensor); [ "$(ps -o user= -p $p | tr -d " ")" = psychoscope-sensor ]'
  check "sensor com CAP_NET_RAW e CAP_NET_ADMIN (e so elas)" 'p=$(systemctl show -p MainPID --value psychoscope-sensor); e=$(awk "/^CapEff/{print \$2}" /proc/$p/status); [ "$((0x$e))" = "$((0x3000))" ]'
  check "binario do sensor sem file capabilities (nao ha setcap)" '[ -z "$(getcap /usr/local/bin/mod-net-sensor)" ]'
  check "sensor nao usa o canal de controle do Core (ctl.sock)" '! runuser -u psychoscope-sensor -- /usr/local/bin/psychoscope-cli list'
  check "sensor nao le o banco de alertas do Core" '! runuser -u psychoscope-sensor -- test -r /var/lib/psychoscope/alerts.db'
  [ "$had_history" = 1 ] && check "historico de alertas da versao anterior preservado" '/usr/local/bin/psychoscope-cli alerts --history | grep -q net.scan.syn'
  scan_until 192.0.2.1 'de 192.0.2.1' # destino de documentacao: distingue do alerta da versao anterior
  check "doctor sem falhas" '/usr/local/bin/psychoscope-cli doctor'

  echo "- reinstalacao (--force) preserva configuracao, ajustes e historico"
  x 'sha256sum /etc/psychoscope/psychoscope.json /etc/psychoscope/sensor.env /var/lib/psychoscope/overrides.json > /root/antes2.sha'
  if upgrade --force >"$LOG/upd2.txt" 2>&1; then echo "  ok: psychoscope-update --force"; else
    echo "  FALHOU: psychoscope-update --force"; tail -8 "$LOG/upd2.txt" | sed 's/^/      /'; FAILS=$((FAILS + 1)); fi
  check "arquivos do administrador intactos" 'sha256sum -c /root/antes2.sha'
  waitfor "sensor reconectado" 40 '/usr/local/bin/psychoscope-cli list | grep -q CONECTADO'
  check "historico preservado" '/usr/local/bin/psychoscope-cli alerts --history | grep -q "de 192.0.2.1"'

  echo "- remocao"
  check "uninstall mantem configuracao, sensor.env e banco" 'bash /get.sh --uninstall >/dev/null && test -f /etc/psychoscope/psychoscope.json && test -f /etc/psychoscope/sensor.env && test -f /var/lib/psychoscope/alerts.db && ! test -e /usr/local/bin/psychoscope && ! test -e /etc/systemd/system/psychoscope.service && ! test -e /etc/systemd/system/psychoscope-sensor.service'
  check "uninstall --purge apaga tudo e os dois usuarios" 'bash /get.sh --uninstall --purge --yes >/dev/null && ! test -e /etc/psychoscope && ! test -e /var/lib/psychoscope && ! getent passwd psychoscope && ! getent passwd psychoscope-sensor'
}

[ "$LOCAL_BUILD" = 0 ] || prepare_local
# cleanup depois de cada distribuicao: um return antecipado de run_distro nao pode deixar o conteiner vivo
for d in $DISTROS; do run_distro "$d"; cleanup; done
echo
if [ "$FAILS" -eq 0 ]; then echo "DISTROS OK"; else echo "DISTROS: $FAILS verificacao(oes) falharam"; exit 1; fi

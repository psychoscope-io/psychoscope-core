#!/usr/bin/env bash
# Testes do install.sh sem privilegios: usa --destdir/--dry-run e binarios falsos.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail() { echo "FALHOU: $*" >&2; exit 1; }

mkdir -p "$T/bin" "$T/stage"
for b in psychoscope mod-net-sensor; do printf '#!/bin/sh\necho %s\n' "$b" > "$T/bin/$b"; chmod +x "$T/bin/$b"; done
# O psychoscope-cli falso registra as chamadas de migrate-config. MIGRATE_FAIL faz a verificacao
# (--check) recusar; MIGRATE_APPLY_FAIL faz a migracao em si falhar, depois de uma verificacao ok.
cat > "$T/bin/psychoscope-cli" <<SH
#!/bin/sh
if [ "\$1" = migrate-config ]; then
  echo "\$@" >> "$T/migrate.log"
  case " \$* " in
    *" --check "*) [ ! -e "$T/MIGRATE_FAIL" ] || { echo "migracao recusada" >&2; exit 1; } ;;
    *) [ ! -e "$T/MIGRATE_APPLY_FAIL" ] || { echo "falha ao gravar" >&2; exit 1; } ;;
  esac
fi
echo psychoscope-cli
SH
chmod +x "$T/bin/psychoscope-cli"

# Invariantes de seguranca das units (sem root, sem systemd). O Core roda sem nenhuma capability e com
# NoNewPrivileges; as capabilities de captura so existem na unit do sensor, como ambientes. Sem
# setcap: o systemd antigo (252) converte varias opcoes de isolamento em NoNewPrivs e anula o setcap.
check_units() {
  local core="$1/psychoscope.service" sensor="$1/psychoscope-sensor.service"
  grep -q '^NoNewPrivileges=yes$' "$core" || fail "o Core deve rodar com NoNewPrivileges=yes"
  grep -q '^CapabilityBoundingSet=$' "$core" || fail "o Core nao pode ter capability alguma (CapabilityBoundingSet= vazio)"
  grep -q '^AmbientCapabilities=$' "$core" || fail "o Core nao pode receber capabilities ambientes"
  if grep -v '^#' "$core" | grep -Eq 'AF_PACKET|CAP_NET_RAW|CAP_NET_ADMIN'; then fail "o Core nao precisa de AF_PACKET nem de capabilities de rede"; fi
  if grep -q '^NoNewPrivileges=no' "$core" "$sensor"; then fail "NoNewPrivileges=no anula-se no systemd antigo; use ambientes"; fi
  grep -q '^Wants=psychoscope-sensor.service$' "$core" || fail "o Core deve puxar a unit do sensor (Wants=)"
  grep -q '^User=psychoscope$' "$core" || fail "usuario do Core"
  grep -q '^User=psychoscope-sensor$' "$sensor" || fail "o sensor deve ter usuario proprio"
  grep -q '^SupplementaryGroups=psychoscope$' "$sensor" || fail "o sensor precisa do grupo do socket do Core"
  grep -q '^NoNewPrivileges=yes$' "$sensor" || fail "o sensor deve rodar com NoNewPrivileges=yes"
  grep -q '^AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN$' "$sensor" || fail "o sensor recebe as capabilities de captura como ambientes"
  grep -q '^CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN$' "$sensor" || fail "limite de capabilities do sensor"
  grep -q '^EnvironmentFile=/etc/psychoscope/sensor.env$' "$sensor" || fail "EnvironmentFile do sensor"
  grep -q "^ExecStart=/usr/local/bin/mod-net-sensor \$SENSOR_ARGS$" "$sensor" || fail "ExecStart do sensor"
  grep -q '^PartOf=psychoscope.service$' "$sensor" || fail "o sensor acompanha o Core (PartOf=)"
  if grep -q '^\[Install\]' "$sensor"; then fail "o sensor e iniciado pelo Core: sem [Install]"; fi
}

# O molde de unit para modulos novos e so um exemplo: nao e instalado e nao pode ter privilegio algum.
check_module_template() {
  local u="$1"
  grep -q '^NoNewPrivileges=yes$' "$u" || fail "o molde de modulo deve rodar com NoNewPrivileges=yes"
  grep -q '^CapabilityBoundingSet=$' "$u" || fail "o molde de modulo nao pode ter capability alguma"
  grep -q '^AmbientCapabilities=$' "$u" || fail "o molde de modulo nao pode receber capabilities ambientes"
  if grep -q '^NoNewPrivileges=no' "$u"; then fail "NoNewPrivileges=no anula-se no systemd antigo"; fi
  if grep -v '^#' "$u" | grep -Eq 'CAP_[A-Z_]+|AF_PACKET'; then fail "o molde de modulo nao pede capability nem AF_PACKET"; fi
  grep -q '^User=psychoscope-MODULO$' "$u" || fail "o molde deve ter usuario proprio"
  grep -q '^SupplementaryGroups=psychoscope$' "$u" || fail "o molde precisa do grupo do socket do Core"
  grep -q '^RestrictAddressFamilies=AF_UNIX$' "$u" || fail "o molde so fala com o socket do Core"
}
check_module_template "$HERE/systemd/psychoscope-module.service.example"

# 1. instalacao em staging
"$HERE/install.sh" --bin-dir "$T/bin" --sensor "$T/bin/mod-net-sensor" --destdir "$T/stage" --prefix /usr/local >"$T/out.txt" 2>"$T/err.txt"
for f in usr/local/bin/psychoscope usr/local/bin/psychoscope-cli usr/local/bin/mod-net-sensor usr/local/sbin/psychoscope-update; do
  [ -x "$T/stage/$f" ] || fail "$f nao instalado/executavel"
done
[ "$(stat -c %a "$T/stage/etc/psychoscope/psychoscope.json")" = 640 ] || fail "modo da configuracao"
[ "$(stat -c %a "$T/stage/etc/psychoscope")" = 750 ] || fail "modo do diretorio de configuracao"
grep -q '^ExecStart=/usr/local/bin/psychoscope --config /etc/psychoscope/psychoscope.json$' "$T/stage/etc/systemd/system/psychoscope.service" || fail "ExecStart da unit"
[ ! -e "$T/migrate.log" ] || fail "sem configuracao previa nao ha o que migrar"
[ "$(stat -c %a "$T/stage/etc/psychoscope/sensor.env")" = 640 ] || fail "modo do sensor.env"
grep -q '^SENSOR_ARGS=' "$T/stage/etc/psychoscope/sensor.env" || fail "sensor.env deveria trazer SENSOR_ARGS"
check_units "$T/stage/etc/systemd/system"
if ls "$T"/stage/etc/systemd/system/psychoscope-module* >/dev/null 2>&1; then fail "o molde de modulo nao deve ser instalado"; fi
grep -q "systemctl enable --now psychoscope" "$T/out.txt" || fail "instrucoes finais"
grep -q "Instalacao concluida" "$T/out.txt" || fail "a primeira instalacao deveria dizer que e nova"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$T/stage/etc/psychoscope/psychoscope.json" || fail "config de exemplo nao e JSON valido"

# 2. nao sobrescreve a configuracao existente; reinstalar e idempotente
echo '{"socket_mode":"0600"}' > "$T/stage/etc/psychoscope/psychoscope.json"
echo 'SENSOR_ARGS=-i enp3s0' > "$T/stage/etc/psychoscope/sensor.env"
"$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage" >"$T/out2.txt" 2>&1
grep -q '"0600"' "$T/stage/etc/psychoscope/psychoscope.json" || fail "a configuracao existente foi sobrescrita"
grep -q "mantendo /etc/psychoscope/psychoscope.json existente" "$T/out2.txt" || fail "mensagem de preservacao"
grep -q '^SENSOR_ARGS=-i enp3s0$' "$T/stage/etc/psychoscope/sensor.env" || fail "o sensor.env do administrador foi sobrescrito"
grep -q "mantendo /etc/psychoscope/sensor.env existente" "$T/out2.txt" || fail "mensagem de preservacao do sensor.env"
M="migrate-config --config $T/stage/etc/psychoscope/psychoscope.json --sensor-env $T/stage/etc/psychoscope/sensor.env"
[ "$(sed -n 1p "$T/migrate.log")" = "$M --check" ] || fail "a configuracao existente deve ser validada (--check) antes de tudo"
[ "$(sed -n 2p "$T/migrate.log")" = "$M" ] || fail "depois de validada, a migracao deve ser feita com os caminhos dela"
[ "$(wc -l < "$T/migrate.log")" = 2 ] || fail "esperadas so a verificacao e a migracao"
grep -q "Atualizacao concluida" "$T/out2.txt" || fail "reinstalar deveria dizer que e uma atualizacao"
if grep -q "enable --now" "$T/out2.txt"; then fail "a atualizacao nao deveria repetir os passos da instalacao nova"; fi
grep -q "systemctl restart psychoscope" "$T/out2.txt" || fail "a atualizacao deveria dizer como reiniciar o servico"

# 2b. se a migracao da configuracao antiga for recusada, nada e instalado nem alterado
touch "$T/MIGRATE_FAIL"
echo '{"socket_mode":"0600"}' > "$T/stage4-conf.json"
mkdir -p "$T/stage4/etc/psychoscope"; cp "$T/stage4-conf.json" "$T/stage4/etc/psychoscope/psychoscope.json"
if "$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage4" >"$T/out4.txt" 2>"$T/err4.txt"; then fail "migracao recusada deveria abortar a instalacao"; fi
grep -q "nao pode ser migrada sozinha" "$T/err4.txt" || fail "mensagem de migracao recusada"
[ ! -e "$T/stage4/usr" ] || fail "nada deve ser instalado quando a migracao e recusada"
cmp -s "$T/stage4-conf.json" "$T/stage4/etc/psychoscope/psychoscope.json" || fail "a configuracao nao pode mudar"
rm "$T/MIGRATE_FAIL"

# 2c. se a migracao falhar depois de validada, a instalacao aborta com a mensagem certa e a
# configuracao fica como estava
touch "$T/MIGRATE_APPLY_FAIL"
mkdir -p "$T/stage5/etc/psychoscope"; cp "$T/stage4-conf.json" "$T/stage5/etc/psychoscope/psychoscope.json"
if "$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage5" >"$T/out5.txt" 2>"$T/err5.txt"; then fail "falha na migracao deveria abortar a instalacao"; fi
grep -q "migracao da configuracao falhou depois de instalar os binarios" "$T/err5.txt" || fail "mensagem de falha na migracao"
cmp -s "$T/stage4-conf.json" "$T/stage5/etc/psychoscope/psychoscope.json" || fail "a configuracao nao pode ser alterada quando a migracao falha"
rm "$T/MIGRATE_APPLY_FAIL"

# 3. prefixo customizado reflete na unit
"$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage2" --prefix /opt/psy >/dev/null 2>&1
grep -q '^ExecStart=/opt/psy/bin/psychoscope ' "$T/stage2/etc/systemd/system/psychoscope.service" || fail "prefixo na unit"
[ -x "$T/stage2/opt/psy/bin/psychoscope" ] || fail "binario no prefixo"
grep -q "^ExecStart=/opt/psy/bin/mod-net-sensor \$SENSOR_ARGS$" "$T/stage2/etc/systemd/system/psychoscope-sensor.service" || fail "prefixo na unit do sensor"

# 4. dry-run nao escreve nada
"$HERE/install.sh" --bin-dir "$T/bin" --sensor "$T/bin/mod-net-sensor" --destdir "$T/stage3" --dry-run >"$T/dry.txt" 2>&1
[ ! -e "$T/stage3" ] || fail "dry-run criou arquivos"
grep -q "^\[dry-run\] install" "$T/dry.txt" || fail "dry-run deveria listar as acoes"
grep -q "psychoscope-sensor.service" "$T/dry.txt" || fail "dry-run deveria listar a unit do sensor"

# 5. erros claros
if "$HERE/install.sh" --bogus 2>"$T/e1.txt"; then fail "flag desconhecida deveria falhar"; fi
grep -q "argumento desconhecido" "$T/e1.txt" || fail "mensagem de flag desconhecida"
if "$HERE/install.sh" --bin-dir "$T/vazio" --destdir "$T/x" 2>"$T/e2.txt"; then fail "sem binarios deveria falhar"; fi
grep -q "nao encontrados" "$T/e2.txt" || fail "mensagem de binarios ausentes"
if "$HERE/install.sh" --bin-dir "$T/bin" --sensor "$T/nao-existe" --destdir "$T/x" 2>"$T/e3.txt"; then fail "sensor inexistente deveria falhar"; fi
if [ "$(id -u)" != 0 ]; then
  if "$HERE/install.sh" --bin-dir "$T/bin" 2>"$T/e4.txt"; then fail "sem root e sem --destdir deveria falhar"; fi
  grep -q "execute como root" "$T/e4.txt" || fail "mensagem de root"
fi
echo "install.sh OK"

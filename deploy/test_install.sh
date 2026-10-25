#!/usr/bin/env bash
# Testes do install.sh sem privilegios: usa --destdir/--dry-run e binarios falsos.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail() { echo "FALHOU: $*" >&2; exit 1; }

mkdir -p "$T/bin" "$T/stage"
for b in psychoscope psychoscope-cli mod-net-sensor; do printf '#!/bin/sh\necho %s\n' "$b" > "$T/bin/$b"; chmod +x "$T/bin/$b"; done

# 1. instalacao em staging
"$HERE/install.sh" --bin-dir "$T/bin" --sensor "$T/bin/mod-net-sensor" --destdir "$T/stage" --prefix /usr/local >"$T/out.txt" 2>"$T/err.txt"
for f in usr/local/bin/psychoscope usr/local/bin/psychoscope-cli usr/local/bin/mod-net-sensor usr/local/sbin/psychoscope-update; do
  [ -x "$T/stage/$f" ] || fail "$f nao instalado/executavel"
done
[ "$(stat -c %a "$T/stage/etc/psychoscope/psychoscope.json")" = 640 ] || fail "modo da configuracao"
[ "$(stat -c %a "$T/stage/etc/psychoscope")" = 750 ] || fail "modo do diretorio de configuracao"
grep -q '^ExecStart=/usr/local/bin/psychoscope --config /etc/psychoscope/psychoscope.json$' "$T/stage/etc/systemd/system/psychoscope.service" || fail "ExecStart da unit"
grep -q '^KillMode=mixed$' "$T/stage/etc/systemd/system/psychoscope.service" || fail "KillMode=mixed na unit (o Core encerra o sensor de forma ordenada)"
grep -q "setcap nao aplicado" "$T/err.txt" || fail "deveria avisar que o setcap nao foi aplicado em staging"
grep -q "systemctl enable --now psychoscope" "$T/out.txt" || fail "instrucoes finais"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$T/stage/etc/psychoscope/psychoscope.json" || fail "config de exemplo nao e JSON valido"

# 2. nao sobrescreve a configuracao existente; reinstalar e idempotente
echo '{"socket_mode":"0600"}' > "$T/stage/etc/psychoscope/psychoscope.json"
"$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage" >"$T/out2.txt" 2>&1
grep -q '"0600"' "$T/stage/etc/psychoscope/psychoscope.json" || fail "a configuracao existente foi sobrescrita"
grep -q "mantendo /etc/psychoscope/psychoscope.json existente" "$T/out2.txt" || fail "mensagem de preservacao"

# 3. prefixo customizado reflete na unit
"$HERE/install.sh" --bin-dir "$T/bin" --destdir "$T/stage2" --prefix /opt/psy >/dev/null 2>&1
grep -q '^ExecStart=/opt/psy/bin/psychoscope ' "$T/stage2/etc/systemd/system/psychoscope.service" || fail "prefixo na unit"
[ -x "$T/stage2/opt/psy/bin/psychoscope" ] || fail "binario no prefixo"

# 4. dry-run nao escreve nada
"$HERE/install.sh" --bin-dir "$T/bin" --sensor "$T/bin/mod-net-sensor" --destdir "$T/stage3" --dry-run >"$T/dry.txt" 2>&1
[ ! -e "$T/stage3" ] || fail "dry-run criou arquivos"
grep -q "^\[dry-run\] install" "$T/dry.txt" || fail "dry-run deveria listar as acoes"

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

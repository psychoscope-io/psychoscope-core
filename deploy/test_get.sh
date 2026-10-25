#!/usr/bin/env bash
# Testes do get.sh sem rede externa e sem root: um servidor HTTP local imita as releases do GitHub
# (inclusive o redirect de /releases/latest), os tarballs levam o deploy/ de verdade e a
# instalacao vai para --destdir. Binarios falsos respondem a --version.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
SRV=""
trap '[ -z "$SRV" ] || kill "$SRV" 2>/dev/null || true; rm -rf "$T"' EXIT
fail() { echo "FALHOU: $*" >&2; exit 1; }

command -v python3 >/dev/null || { echo "get.sh: python3 ausente, teste ignorado"; exit 0; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "get.sh: sem release para $(uname -m), teste ignorado"; exit 0 ;;
esac

# publish NOME VERSAO BINARIO...: publica no servidor um tarball falso, no layout do release.yml.
publish() {
  local repo="$1" ver="$2" pkg d
  shift 2
  pkg="${repo}_${ver}_linux_$ARCH"
  d="$T/srv/$repo/releases/download/v$ver"
  mkdir -p "$d" "$T/build/$pkg"
  for b in "$@"; do
    printf '#!/bin/sh\necho "%s %s"\n' "$b" "$ver" > "$T/build/$pkg/$b"
    chmod +x "$T/build/$pkg/$b"
  done
  if [ "$repo" = psychoscope-core ]; then
    mkdir -p "$T/build/$pkg/deploy"
    cp -r "$HERE/install.sh" "$HERE/get.sh" "$HERE/systemd" "$HERE/psychoscope.json.example" "$T/build/$pkg/deploy/"
  fi
  tar -C "$T/build" -czf "$d/$pkg.tar.gz" "$pkg"
  (cd "$d" && sha256sum ./*.tar.gz > SHA256SUMS)
}

cat > "$T/server.py" <<'PY'
import functools, http.server, os, re, sys
root, portfile = sys.argv[1], sys.argv[2]

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _route(self, fallback):
        m = re.fullmatch(r"/([\w.-]+)/releases/latest", self.path)
        if m:
            d = os.path.join(root, m.group(1), "releases", "download")
            vers = sorted(os.listdir(d), key=lambda v: tuple(map(int, v[1:].split(".")))) if os.path.isdir(d) else []
            self.send_response(302)
            self.send_header("Location", "/%s/releases/%s" % (m.group(1), "tag/" + vers[-1] if vers else ""))
            self.end_headers()
        elif re.fullmatch(r"/[\w.-]+/releases(/tag/v[\d.]+)?", self.path):
            self.send_response(200)
            self.end_headers()
        else:
            fallback()

    def do_GET(self):
        self._route(super().do_GET)

    def do_HEAD(self):
        self._route(super().do_HEAD)

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=root))
open(portfile, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY
mkdir -p "$T/srv"
python3 "$T/server.py" "$T/srv" "$T/port" &
SRV=$!
for _ in $(seq 50); do [ -s "$T/port" ] && break; sleep 0.1; done
[ -s "$T/port" ] || fail "servidor de teste nao subiu"
PORT="$(cat "$T/port")"
export PSYCHOSCOPE_RELEASE_BASE="http://127.0.0.1:$PORT"

get() { "$HERE/get.sh" --no-attestation --no-setcap "$@"; }
version_of() { "$T/$1/usr/local/bin/$2" --version; }
S="$T/stage"

publish psychoscope-core 0.5.0 psychoscope psychoscope-cli
publish mod-net-sensor 0.3.0 mod-net-sensor

# 1. instalacao nova com a versao mais recente de cada repositorio
get --destdir "$S" >"$T/o1.txt" 2>"$T/e1.txt" || { cat "$T/e1.txt" >&2; fail "instalacao nova"; }
for f in usr/local/bin/psychoscope usr/local/bin/psychoscope-cli usr/local/bin/mod-net-sensor usr/local/sbin/psychoscope-update; do
  [ -x "$S/$f" ] || fail "$f nao instalado"
done
[ -f "$S/etc/psychoscope/psychoscope.json" ] || fail "configuracao nao criada"
[ "$(version_of stage psychoscope)" = "psychoscope 0.5.0" ] || fail "versao do Core instalada"
[ "$(version_of stage mod-net-sensor)" = "mod-net-sensor 0.3.0" ] || fail "versao do sensor instalada"

# 2. --check e uma segunda execucao nao fazem nada quando esta atualizado
get --check --destdir "$S" >"$T/o2.txt" || fail "--check deveria sair com 0 quando atualizado"
grep -q "tudo atualizado" "$T/o2.txt" || fail "mensagem do --check"
get --destdir "$S" >"$T/o2b.txt"
grep -q "nada a fazer" "$T/o2b.txt" || fail "segunda execucao deveria ser um no-op"
get --force --destdir "$S" >"$T/o2c.txt" 2>&1 || fail "--force"
grep -q "baixando" "$T/o2c.txt" || fail "--force deveria reinstalar"

# 3. atualizacao: versao nova publicada, configuracao do administrador preservada
publish psychoscope-core 0.6.0 psychoscope psychoscope-cli
publish mod-net-sensor 0.3.1 mod-net-sensor
echo '{"socket_mode":"0600"}' > "$S/etc/psychoscope/psychoscope.json"
if get --check --destdir "$S" >"$T/o3.txt"; then fail "--check deveria sair com 1 com atualizacao disponivel"; fi
grep -q "0.5.0.*0.6.0" "$T/o3.txt" || fail "--check deveria mostrar instalada e disponivel"
get --destdir "$S" >/dev/null 2>&1 || fail "atualizacao"
[ "$(version_of stage psychoscope)" = "psychoscope 0.6.0" ] || fail "Core nao atualizado"
[ "$(version_of stage mod-net-sensor)" = "mod-net-sensor 0.3.1" ] || fail "sensor nao atualizado"
grep -q '"0600"' "$S/etc/psychoscope/psychoscope.json" || fail "a configuracao foi sobrescrita"

# 4. versao fixada pode ser anterior (rebaixa)
get --core-version 0.5.0 --sensor-version 0.3.0 --destdir "$S" >/dev/null 2>&1 || fail "versao fixada"
[ "$(version_of stage psychoscope)" = "psychoscope 0.5.0" ] || fail "rebaixamento do Core"

# 5. sem versao fixada, um build instalado mais novo que a release nao e rebaixado
get --destdir "$T/dev" >/dev/null 2>&1 || fail "instalacao para o teste de build novo"
printf '#!/bin/sh\necho "psychoscope 9.9.9"\n' > "$T/dev/usr/local/bin/psychoscope"
get --destdir "$T/dev" >"$T/o5.txt" 2>&1
grep -q "nada a fazer" "$T/o5.txt" || fail "build mais novo deveria ser mantido"
[ "$(version_of dev psychoscope)" = "psychoscope 9.9.9" ] || fail "build mais novo foi rebaixado"

# 6. dry-run: mostra o reinicio do servico ativo e nao grava nada
mkdir -p "$T/fakebin"
printf '#!/bin/sh\nexit 0\n' > "$T/fakebin/systemctl"; chmod +x "$T/fakebin/systemctl"
PATH="$T/fakebin:$PATH" get --dry-run --prefix "$T/prefix" >"$T/o6.txt" 2>&1 || { cat "$T/o6.txt" >&2; fail "dry-run"; }
grep -q "^\[dry-run\] install" "$T/o6.txt" || fail "dry-run deveria listar as acoes do instalador"
grep -q "^\[dry-run\] systemctl restart psychoscope" "$T/o6.txt" || fail "dry-run deveria mostrar o reinicio do servico"
[ ! -e "$T/prefix" ] || fail "dry-run criou arquivos"

# 7. falhas: checksum, arquitetura, argumentos
publish psychoscope-core 0.7.0 psychoscope psychoscope-cli
printf x >> "$T/srv/psychoscope-core/releases/download/v0.7.0/psychoscope-core_0.7.0_linux_${ARCH}.tar.gz"
if get --core-version 0.7.0 --destdir "$T/bad" 2>"$T/e7.txt"; then fail "checksum errado deveria falhar"; fi
grep -q "checksum invalido" "$T/e7.txt" || fail "mensagem de checksum"
[ ! -e "$T/bad" ] || fail "checksum errado nao deveria instalar nada"
if get --core-version 9.9.9 --destdir "$T/bad" 2>"$T/e7b.txt"; then fail "versao inexistente deveria falhar"; fi
grep -q "falha ao baixar" "$T/e7b.txt" || fail "mensagem de versao inexistente"
REAL_UNAME="$(command -v uname)"
cat > "$T/fakebin/uname" <<SH
#!/bin/sh
if [ "\$1" = -m ]; then echo armv7l; else exec $REAL_UNAME "\$@"; fi
SH
chmod +x "$T/fakebin/uname"
if PATH="$T/fakebin:$PATH" get --destdir "$T/bad" 2>"$T/e7c.txt"; then fail "arquitetura nao suportada deveria falhar"; fi
grep -q "arquitetura nao suportada" "$T/e7c.txt" || fail "mensagem de arquitetura"
if get --core-version 1.x 2>"$T/e7d.txt"; then fail "versao invalida deveria falhar"; fi
grep -q "versao invalida" "$T/e7d.txt" || fail "mensagem de versao invalida"
if get --purge 2>"$T/e7e.txt"; then fail "--purge sem --uninstall deveria falhar"; fi

# 8. desinstalacao: mantem configuracao; --purge --yes apaga tudo
get --uninstall --destdir "$S" >"$T/o8.txt" 2>&1 || fail "uninstall"
for f in usr/local/bin/psychoscope usr/local/bin/psychoscope-cli usr/local/bin/mod-net-sensor usr/local/sbin/psychoscope-update etc/systemd/system/psychoscope.service; do
  [ ! -e "$S/$f" ] || fail "$f deveria ter sido removido"
done
[ -f "$S/etc/psychoscope/psychoscope.json" ] || fail "uninstall nao deveria apagar a configuracao"
get --uninstall --purge --yes --destdir "$S" >/dev/null 2>&1 || fail "uninstall --purge"
[ ! -e "$S/etc/psychoscope" ] || fail "--purge deveria apagar a configuracao"

echo "get.sh OK"

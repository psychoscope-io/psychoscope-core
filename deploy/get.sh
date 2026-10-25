#!/usr/bin/env bash
# Baixa, verifica e instala (ou atualiza) o Psychoscope: Core, CLI e sensor, a partir das releases do GitHub.
#
#   ./get.sh [--core-version X.Y.Z] [--sensor-version X.Y.Z] [--prefix /usr/local] [--force]
#            [--check] [--dry-run] [--no-setcap] [--no-attestation] [--destdir DIR]
#   ./get.sh --uninstall [--purge] [--yes] [--prefix /usr/local] [--dry-run] [--destdir DIR]
#
# - Rode como usuario comum: o download e a verificacao nao precisam de root, e o script chama
#   sudo so para instalar (ou rode tudo como root). Depois de instalado, o mesmo script fica em
#   PREFIX/sbin/psychoscope-update.
# - Sem versao, usa a mais recente de cada repositorio (Core e sensor tem versoes independentes).
# - Confere o SHA256SUMS e, com o `gh` instalado e logado, a atestacao de proveniencia.
# - Reaproveita o deploy/install.sh do tarball: nunca sobrescreve /etc/psychoscope/psychoscope.json.
# - Se o servico estiver ativo, faz daemon-reload e restart. Nada a fazer se ja estiver atualizado.
# - --check so compara as versoes instaladas com as disponiveis (sai com 1 se houver atualizacao).
# - --uninstall remove servico e binarios e mantem configuracao e alertas; --purge apaga tambem
#   /etc/psychoscope, /var/lib/psychoscope e o usuario psychoscope (irreversivel; pede confirmacao).
# - PSYCHOSCOPE_RELEASE_BASE troca a origem dos downloads (espelho interno ou teste).
set -euo pipefail

BASE="${PSYCHOSCOPE_RELEASE_BASE:-https://github.com/psychoscope-io}"
ORG=psychoscope-io
PREFIX=/usr/local
DESTDIR=""
CORE_VERSION=""
SENSOR_VERSION=""
CHECK=0
FORCE=0
DRY=0
SETCAP=1
ATTEST=1
UNINSTALL=0
PURGE=0
YES=0
SUDO=()
TMP=""

usage() { sed -n '2,/^set -euo/{/^set -euo/!p}' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "get.sh: $*" >&2; exit 1; }
need_value() { [ "$2" -ge 2 ] || die "$1 exige um valor"; }
valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# Executa o comando, ou so o mostra em --dry-run.
run() {
  if [ "$DRY" = 1 ]; then printf '[dry-run]'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}
as_root() { run "${SUDO[@]}" "$@"; }

# Versao mais recente (sem o "v") seguindo o redirect de /releases/latest: sem API nem limite de taxa.
latest_version() {
  local url
  url="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "$BASE/$1/releases/latest")" ||
    die "nao foi possivel consultar a ultima release de $1 em $BASE (sem rede, ou o repositorio ainda nao publicou uma release); use --${2}-version X.Y.Z para fixar"
  case "$url" in
    */tag/v*) echo "${url##*/tag/v}" ;;
    *) die "$1 ainda nao tem release publicada em $BASE" ;;
  esac
}

# Versao do binario instalado (vazio se nao houver): a ultima palavra da primeira linha de --version.
installed_version() {
  local bin="$DESTDIR$PREFIX/bin/$1"
  if [ -x "$bin" ]; then "$bin" --version 2>/dev/null | awk 'NR==1{print $NF}' || true; fi
}

# needs_update INSTALADA DESEJADA FIXADA(0|1): sem versao fixada, uma instalada mais nova que a
# ultima release (build de desenvolvimento) nao e rebaixada.
needs_update() {
  local have="$1" want="$2" pinned="$3"
  [ "$have" != "$want" ] || return 1
  [ -n "$have" ] || return 0
  [ "$pinned" = 0 ] || return 0
  [ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | tail -n1)" != "$have" ]
}

report() { printf '  %-18s instalada: %-12s disponivel: %s\n' "$1" "${2:-nenhuma}" "$3"; }

attest() { # repositorio tarball
  if [ "$ATTEST" = 0 ]; then
    echo "aviso: atestacao de proveniencia ignorada (--no-attestation)" >&2
  elif command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
    gh attestation verify "$2" --repo "$ORG/$1" >/dev/null ||
      die "a atestacao de proveniencia de $(basename "$2") nao confere; nada foi instalado"
    echo "ok: atestacao de proveniencia de $(basename "$2")"
  else
    echo "aviso: so o checksum de $(basename "$2") foi conferido; para verificar tambem a atestacao, instale o 'gh' e faca login (gh auth login)" >&2
  fi
}

# fetch_release REPOSITORIO PACOTE VERSAO: baixa, confere e extrai em $TMP.
fetch_release() {
  local repo="$1" name="$2" ver="$3" arch_pkg line
  arch_pkg="${name}_${ver}_linux_${ARCH}"
  local url="$BASE/$repo/releases/download/v$ver"
  echo "baixando $arch_pkg ..."
  curl -fsSL --retry 2 -o "$TMP/$arch_pkg.tar.gz" "$url/$arch_pkg.tar.gz" ||
    die "falha ao baixar $url/$arch_pkg.tar.gz (a versao $ver existe? ela tem build para $ARCH?)"
  curl -fsSL --retry 2 -o "$TMP/$name.SHA256SUMS" "$url/SHA256SUMS" ||
    die "falha ao baixar $url/SHA256SUMS"
  line="$(awk -v f="$arch_pkg.tar.gz" '{n=$2; sub(/^\.\//, "", n)} n==f{print $1 "  " n}' "$TMP/$name.SHA256SUMS")"
  [ -n "$line" ] || die "$arch_pkg.tar.gz nao consta no SHA256SUMS da release; nada foi instalado"
  (cd "$TMP" && echo "$line" | sha256sum -c --status) ||
    die "checksum invalido para $arch_pkg.tar.gz (download corrompido ou adulterado); nada foi instalado"
  attest "$repo" "$TMP/$arch_pkg.tar.gz"
  tar -xzf "$TMP/$arch_pkg.tar.gz" -C "$TMP" --no-same-owner
  [ -d "$TMP/$arch_pkg" ] || die "o tarball $arch_pkg.tar.gz nao tem o diretorio $arch_pkg"
}

# Pede confirmacao de uma acao irreversivel (ou a dispensa com --yes).
confirm() {
  [ "$YES" = 1 ] && return 0
  [ "$DRY" = 1 ] && return 0
  [ -r /dev/tty ] || die "confirmacao necessaria e nao ha terminal; use --yes"
  local ans
  read -r -p "$1 Digite 'sim' para confirmar: " ans </dev/tty
  [ "$ans" = sim ] || die "cancelado"
}

uninstall() {
  if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null; then
    as_root systemctl disable --now psychoscope 2>/dev/null || true
  fi
  as_root rm -f "$DESTDIR/etc/systemd/system/psychoscope.service" \
    "$DESTDIR$PREFIX/bin/psychoscope" "$DESTDIR$PREFIX/bin/psychoscope-cli" "$DESTDIR$PREFIX/bin/mod-net-sensor" \
    "$DESTDIR$PREFIX/sbin/psychoscope-update"
  if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null; then as_root systemctl daemon-reload; fi
  if [ "$PURGE" = 1 ]; then
    confirm "Isto apaga /etc/psychoscope, /var/lib/psychoscope (config, alertas e ajustes) e o usuario psychoscope, sem volta."
    as_root rm -rf "$DESTDIR/etc/psychoscope" "$DESTDIR/var/lib/psychoscope"
    if [ -z "$DESTDIR" ] && getent passwd psychoscope >/dev/null; then as_root userdel psychoscope; fi
    echo "Psychoscope removido, inclusive configuracao, alertas e usuario."
  else
    echo "Psychoscope removido. Configuracao (/etc/psychoscope) e alertas (/var/lib/psychoscope) foram mantidos; use --purge para apagar."
  fi
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --core-version)   need_value "$1" $#; CORE_VERSION="${2#v}"; shift 2 ;;
      --sensor-version) need_value "$1" $#; SENSOR_VERSION="${2#v}"; shift 2 ;;
      --prefix)         need_value "$1" $#; PREFIX="$2"; shift 2 ;;
      --destdir)        need_value "$1" $#; DESTDIR="$2"; shift 2 ;;
      --check)          CHECK=1; shift ;;
      --force)          FORCE=1; shift ;;
      --dry-run)        DRY=1; shift ;;
      --no-setcap)      SETCAP=0; shift ;;
      --no-attestation) ATTEST=0; shift ;;
      --uninstall)      UNINSTALL=1; shift ;;
      --purge)          PURGE=1; shift ;;
      --yes)            YES=1; shift ;;
      -h|--help)        usage; exit 0 ;;
      *) usage >&2; die "argumento desconhecido: $1" ;;
    esac
  done
  for v in "$CORE_VERSION" "$SENSOR_VERSION"; do
    [ -z "$v" ] || valid_version "$v" || die "versao invalida: '$v' (use o formato X.Y.Z)"
  done
  [ "$PURGE" = 0 ] || [ "$UNINSTALL" = 1 ] || die "--purge so vale com --uninstall"

  # sudo so quando a instalacao real exige root.
  if [ "$CHECK" = 0 ] && [ -z "$DESTDIR" ] && [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null || die "execute como root (ou instale o sudo)"
    SUDO=(sudo)
  fi

  if [ "$UNINSTALL" = 1 ]; then uninstall; return; fi

  [ "$(uname -s)" = Linux ] || die "sistema nao suportado: $(uname -s) (as releases sao para Linux)"
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "arquitetura nao suportada: $(uname -m) (as releases sao para amd64 e arm64)" ;;
  esac
  command -v curl >/dev/null || die "curl nao encontrado (sudo apt install curl)"

  local core_pinned=0 sensor_pinned=0 core_want sensor_want core_have sensor_have update=0
  [ -z "$CORE_VERSION" ] || core_pinned=1
  [ -z "$SENSOR_VERSION" ] || sensor_pinned=1
  core_want="${CORE_VERSION:-$(latest_version psychoscope-core core)}"
  sensor_want="${SENSOR_VERSION:-$(latest_version mod-net-sensor sensor)}"
  core_have="$(installed_version psychoscope)"
  sensor_have="$(installed_version mod-net-sensor)"

  needs_update "$core_have" "$core_want" "$core_pinned" && update=1
  needs_update "$sensor_have" "$sensor_want" "$sensor_pinned" && update=1
  report psychoscope-core "$core_have" "$core_want"
  report mod-net-sensor "$sensor_have" "$sensor_want"

  if [ "$CHECK" = 1 ]; then
    if [ "$update" = 1 ]; then echo "ha atualizacao disponivel: rode ./get.sh (ou sudo psychoscope-update)"; return 1; fi
    echo "tudo atualizado"
    return 0
  fi
  if [ "$update" = 0 ] && [ "$FORCE" = 0 ]; then
    echo "nada a fazer: ja esta atualizado (use --force para reinstalar)"
    return 0
  fi

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  fetch_release psychoscope-core psychoscope-core "$core_want"
  fetch_release mod-net-sensor mod-net-sensor "$sensor_want"

  local core_dir="$TMP/psychoscope-core_${core_want}_linux_${ARCH}"
  local sensor_bin="$TMP/mod-net-sensor_${sensor_want}_linux_${ARCH}/mod-net-sensor"
  local args=(--sensor "$sensor_bin" --prefix "$PREFIX" --bin-dir "$core_dir")
  [ "$SETCAP" = 1 ] || args+=(--no-setcap)
  [ -z "$DESTDIR" ] || args+=(--destdir "$DESTDIR")
  [ "$DRY" = 0 ] || args+=(--dry-run)
  "${SUDO[@]}" bash "$core_dir/deploy/install.sh" "${args[@]}"

  if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null && systemctl is-active --quiet psychoscope 2>/dev/null; then
    echo "reiniciando o servico psychoscope para usar a versao nova ..."
    as_root systemctl daemon-reload
    as_root systemctl restart psychoscope
  fi
}

# Tudo dentro de main + exit: o bash nao le o arquivo adiante se psychoscope-update for
# substituido pelo install.sh no meio da execucao.
main "$@"
exit $?

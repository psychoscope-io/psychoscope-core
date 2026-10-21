# psychoscope-core

Orquestrador (hub) do Psychoscope MODR, com motor de detecção, persistência de alertas e CLI/TUI, em Go.

Instalação como serviço (systemd, usuário dedicado, privilégios mínimos): [docs/INSTALL.md](docs/INSTALL.md).

## O que faz

- **IPC dos módulos** (`internal/ipc`): `core.sock` (0660), framing length-prefixed, handshake `Hello`/`HelloResposta`,
  `SO_PEERCRED` (UID permitido + PID declarado == PID real do peer), telemetria/status com `id_modulo` validado,
  comandos com ACK/NACK síncronos e timeout, heartbeat (3 intervalos de silêncio derrubam a sessão).
- **Supervisor** (`internal/supervisor`): `os/exec` com grupo de processos próprio e ambiente mínimo, restart com backoff exponencial,
  watchdog de conexão, parada graciosa `ENCERRAR → SIGTERM → SIGKILL`; só o PID do filho lançado pode assumir o `id_modulo`.
- **Detecção** (`internal/detection`): janela deslizante em memória (tempo dos eventos, teto de eventos, índices por origem/destino),
  motor com fila não bloqueante, cooldown por chave e isolamento de panics de regras. Regras (`internal/detection/rules`):

  | Regra | Detecta (limiar padrão) | Severidade |
  |---|---|---|
  | `net.scan.syn` | varredura vertical (≥15 portas de um destino em 10s) e horizontal (≥20 hosts na mesma porta) por SYN puro | MÉDIA / ALTA |
  | `net.bruteforce.auth` | ≥10 conexões (portas de origem distintas) de uma origem ao mesmo destino:porta de autenticação (21, 22, 23, 445, 3389, 5900) em 30s | ALTA |
  | `net.icmp.sweep` | echo request (ICMPv4 tipo 8 / ICMPv6 128) para ≥20 destinos distintos em 10s | MÉDIA |
  | `net.dns.nxdomain_burst` | cliente com ≥10 respostas NXDOMAIN para ≥8 domínios distintos em 30s (DGA); consultas de DNS reverso (`in-addr.arpa`, `ip6.arpa`) não contam por padrão (`ignore_suffixes`) | MÉDIA |
  | `net.dns.tunnel` | ≥5 consultas distintas ao mesmo domínio base com rótulos longos (≥30) e de alta entropia (≥3.2 bits/char) em 60s | ALTA |
  | `net.dns.rate` | ≥200 consultas DNS de um cliente em 10s | MÉDIA |
  | `net.tls.suspicious` | ClientHello com SNI igual a um IP (MÉDIA), SNI com rótulo aleatório de ≥20 caracteres sem hífen (MÉDIA), versão máxima oferecida SSL3/TLS1.0/1.1 (BAIXA) ou ≥3 ClientHellos sem SNI em 60s (BAIXA) | MÉDIA / BAIXA |
  | `net.beacon` | contatos periódicos de um cliente ao mesmo `destino:porta` (SYN) ou domínio (DNS): ≥8 contatos, intervalo médio de 5s a 1h e variação (desvio/média) ≤20%; estado próprio, não depende da janela; destinos, portas e domínios conhecidos podem ser ignorados (`ignore_destinations`, `ignore_ports`, `ignore_domains`) | MÉDIA |

  Uma nova regra é um tipo que implementa `detection.Rule` (`Name`, `Eval(event, window) → alerta`); opcionalmente `detection.Gated`
  (`Key`, `Cooldown`) para pré-filtro barato e supressão de repetições.
- **Persistência** (`internal/store`): alertas gravados em SQLite (sem CGO, arquivo `0600`, WAL) por um gravador em lote fora do caminho
  quente; retenção por idade e por quantidade; na partida o histórico em memória é repovoado a partir do banco.
- **Canal de controle** (`internal/ctl`, `control.proto`): `ctl.sock` com listar módulos, enviar comando, assinar alertas (com histórico),
  consultar alertas persistidos (filtros de tempo, severidade, regra e módulo) e métricas.
- **Métricas** (`internal/metrics`): contadores/medidores do motor, do armazenamento e de cada módulo; pela CLI/TUI e, opcionalmente, em
  `/metrics` no formato Prometheus (somente loopback por padrão, sem autenticação).
- **CLI/TUI** (`cmd/psychoscope-cli`): sem argumentos abre a TUI (Bubbletea + Lipgloss) com painel de módulos, feed de alertas e linha de
  eventos/s, alertas e descartes. Teclas: `↑/↓` selecionar, `tab` alternar foco, `Enter` (no painel de alertas) abrir os detalhes do
  alerta (todos os campos, descrição e contexto com quebra de linha, `↑/↓`/`PgUp`/`PgDn` rolam, `Esc`/`Enter`/`q` fecham), `p` pausar,
  `r` retomar e `:` abrir a linha de comando. Sair e encerrar um módulo só existem como comandos, para não acontecerem por acidente:
  `:q` (ou `:quit`, `:sair`) + `Enter` sai, `:stop` + `Enter` encerra o módulo selecionado (o rodapé mostra o alvo enquanto você digita),
  `:pause` e `:resume`; `Tab` completa o comando e `Esc` cancela. `q`, `Esc` e `Ctrl+C` na tela principal só mostram a dica.
  Subcomandos: `list`, `cmd <modulo> pause|resume|reconfigure|stop [k=v]`, `alerts [--no-history] [-v]` (ao vivo),
  `alerts --history [-n 50] [--since 2h] [--min-severity alta] [--rule R] [--module M] [-v]` (persistido; `-v` mostra o contexto
  `chave=valor` de cada alerta, uma linha recuada por chave), `metrics`, `--version`.

## Uso rápido (desenvolvimento)

Para só experimentar, sem montar configuração, rode `scripts/demo.sh` do [mod-net-sensor](https://github.com/psychoscope-io/mod-net-sensor#testar-em-minutos-demo): ele compila tudo, reproduz um pcap malicioso e abre a TUI.

```
go build -o /tmp/psychoscope ./cmd/psychoscope && go build -o /tmp/psychoscope-cli ./cmd/psychoscope-cli
/tmp/psychoscope --config psychoscope.json        # ou --socket/--ctl-socket
/tmp/psychoscope-cli                              # TUI
```

`psychoscope.json` (tudo opcional exceto os módulos que você quer supervisionar; chaves desconhecidas são erro e a mensagem lista as válidas):

```json
{
  "socket_mode": "0660",
  "modules": [
    { "id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": ["-i", "eth0"], "stop_grace": "10s" }
  ],
  "storage": { "enabled": true, "path": "/var/lib/psychoscope/alerts.db", "retention_days": 30, "max_alerts": 100000 },
  "metrics": { "listen": "127.0.0.1:9464" },
  "detection": {
    "window": "60s",
    "disabled": [],
    "scan":       { "window": "10s", "vertical_ports": 15, "horizontal_hosts": 20, "cooldown": "60s" },
    "nxdomain":   { "window": "30s", "min_responses": 10, "min_distinct": 8, "cooldown": "2m", "ignore_suffixes": ["in-addr.arpa", "ip6.arpa"] },
    "tunnel":     { "window": "60s", "min_queries": 5, "min_label_len": 30, "min_entropy": 3.2, "allowed_bases": ["cdn.exemplo.com"], "cooldown": "2m" },
    "dns_rate":   { "window": "10s", "min_queries": 200, "cooldown": "2m" },
    "tls":        { "cooldown": "10m", "missing_sni_min": 3, "missing_sni_window": "60s", "min_label_len": 20, "min_entropy": 3.6, "allowed_bases": [] },
    "beacon":     { "min_samples": 8, "min_interval": "5s", "max_interval": "1h", "max_cv": 0.2, "max_keys": 50000, "cooldown": "30m", "ignore_domains": [], "ignore_ports": [], "ignore_destinations": ["203.0.113.0/24"] },
    "bruteforce": { "window": "30s", "min_attempts": 10, "ports": [21, 22, 23, 445, 3389, 5900], "cooldown": "5m", "ignore_sources": ["10.9.0.0/16"] },
    "icmp_sweep": { "window": "10s", "min_hosts": 20, "cooldown": "60s" }
  }
}
```

`detection.window` precisa cobrir a maior janela de regra (o `beacon` tem estado próprio e fica de fora). Sockets: `/var/run/psychoscope/`
se existir e for gravável (ex.: `RuntimeDirectory=` do systemd) ou root; senão `$XDG_RUNTIME_DIR/psychoscope/`. O banco de alertas segue a
mesma ideia: `/var/lib/psychoscope` (ex.: `StateDirectory=`), senão `$XDG_STATE_HOME/psychoscope` ou `~/.local/state/psychoscope`.
`--allow-unmanaged` (dev) aceita módulos não lançados pelo supervisor (só checa UID).

## Limitações conhecidas

- O alerta usa o relógio de detecção do Core como `timestamp`; o instante do evento vai em `contexto["evento_ts"]`.
- Falsos positivos esperados: `net.dns.tunnel` e `net.tls.suspicious` (entropia) em CDNs/serviços com rótulos longos aleatórios — use
  `allowed_bases`; `net.beacon` em tarefas periódicas legítimas (verificações de conectividade, polling) — use `ignore_destinations`/`ignore_domains`/`ignore_ports`;
  `net.bruteforce.auth` em automação — use `ignore_sources`.
- O estado do motor (janela, cooldowns, séries do beacon) é só em memória: reiniciar o Core o zera. Os alertas, não.
- A versão TLS informada é a maior **oferecida** no ClientHello, não a negociada.
- O endpoint de métricas não tem autenticação nem TLS.

## Notas de desenvolvimento

- Depende de `github.com/psychoscope-io/psychoscope-proto@v0.2.0`. Antes da publicação (ou offline): `source ../psychoscope-proto/scripts/local-deps.sh` resolve a dependência a partir do checkout local; para iterar no contrato sem criar tags, use um `go.work` (já ignorado pelo git).
- `testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.
- `internal/testmod` é um módulo falso para testes (o binário de teste se re-executa como filho).
- Testes do `install.sh`: `./deploy/test_install.sh`. Testes entre repositórios (daemon + sensor reais, persistência, TUI em pty):
  `mod-net-sensor/scripts/e2e.sh` e `scripts/live_smoke.sh`.
- Releases: ao publicar uma tag `vX.Y.Z`, `.github/workflows/release.yml` gera tarballs (amd64/arm64), `SHA256SUMS` e atestado de proveniência.

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).

# psychoscope-core

Orquestrador (hub) do Psychoscope MODR, com motor de detecção e CLI/TUI, em Go.

## O que faz

- **IPC dos módulos** (`internal/ipc`): `core.sock` (0660), framing length-prefixed, handshake `Hello`/`HelloResposta`,
  `SO_PEERCRED` (UID permitido + PID declarado == PID real do peer), telemetria/status com `id_modulo` validado,
  comandos com ACK/NACK síncronos e timeout, heartbeat (3 intervalos de silêncio derrubam a sessão).
- **Supervisor** (`internal/supervisor`): `os/exec` com grupo de processos próprio e ambiente mínimo, restart com backoff exponencial,
  watchdog de conexão, parada graciosa `ENCERRAR → SIGTERM → SIGKILL`; só o PID do filho lançado pode assumir o `id_modulo`.
- **Detecção** (`internal/detection`): janela deslizante em memória (tempo dos eventos, teto de eventos, índices por origem/destino),
  motor com fila não bloqueante, cooldown por chave e isolamento de panics de regras. Regras (`internal/detection/rules`):

  | Regra | Detecta | Severidade |
  |---|---|---|
  | `net.scan.syn` | varredura vertical (≥15 portas de um destino em 10s) e horizontal (≥20 hosts na mesma porta) por SYN puro | MÉDIA / ALTA |
  | `net.dns.nxdomain_burst` | cliente com ≥10 respostas NXDOMAIN para ≥8 domínios distintos em 30s (DGA) | MÉDIA |
  | `net.dns.tunnel` | ≥5 consultas distintas ao mesmo domínio base com rótulos longos (≥30) e de alta entropia (≥3.2 bits/char) em 60s | ALTA |

  Uma nova regra é um tipo que implementa `detection.Rule` (`Name`, `Eval(event, window) → alerta`); opcionalmente `detection.Gated`
  (`Key`, `Cooldown`) para pré-filtro barato e supressão de repetições.
- **Canal de controle** (`internal/ctl`, `control.proto`): `ctl.sock` com listar módulos, enviar comando e assinar alertas (com histórico dos últimos 256).
- **CLI/TUI** (`cmd/psychoscope-cli`): sem argumentos abre a TUI (Bubbletea + Lipgloss) com painel de módulos e feed de alertas;
  teclas: `↑/↓` selecionar, `tab` alternar foco, `p` pausar, `r` retomar, `x` encerrar (confirma com `y`), `q` sair.
  Subcomandos: `list`, `cmd <modulo> pause|resume|reconfigure|stop [k=v]`, `alerts [--no-history]`.

## Uso rápido

```
go build -o /tmp/psychoscope ./cmd/psychoscope && go build -o /tmp/psychoscope-cli ./cmd/psychoscope-cli
/tmp/psychoscope --config psychoscope.json        # ou --socket/--ctl-socket
/tmp/psychoscope-cli                              # TUI
```

`psychoscope.json` (tudo opcional exceto os módulos que você quer supervisionar):

```json
{
  "socket_mode": "0660",
  "modules": [
    { "id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": ["-i", "eth0"], "stop_grace": "10s" }
  ],
  "detection": {
    "window": "60s",
    "disabled": [],
    "scan":     { "window": "10s", "vertical_ports": 15, "horizontal_hosts": 20, "cooldown": "60s" },
    "nxdomain": { "window": "30s", "min_responses": 10, "min_distinct": 8, "cooldown": "2m" },
    "tunnel":   { "window": "60s", "min_queries": 5, "min_label_len": 30, "min_entropy": 3.2, "allowed_bases": ["cdn.exemplo.com"], "cooldown": "2m" }
  }
}
```

`detection.window` precisa cobrir a maior janela de regra. Sockets: `/var/run/psychoscope/` se existir e for gravável
(ex.: `RuntimeDirectory=` do systemd) ou root; senão `$XDG_RUNTIME_DIR/psychoscope/`. `--allow-unmanaged` (dev) aceita módulos não
lançados pelo supervisor (só checa UID).

## Limitações conhecidas

- O alerta usa o relógio de detecção do Core como `timestamp`; o instante do evento vai em `contexto["evento_ts"]`.
- `net.dns.tunnel` pode dar falso positivo em CDNs/serviços com rótulos longos aleatórios: use `allowed_bases`.
- Estado do motor é só em memória (reiniciar o Core zera janela e cooldowns); alertas não são persistidos.

## Notas de desenvolvimento

- Depende de `github.com/Bandeira27/psychoscope-proto@v0.1.0`. Antes da publicação (ou offline): `source ../psychoscope-proto/scripts/local-deps.sh` resolve a dependência a partir do checkout local; para iterar no contrato sem criar tags, use um `go.work` (já ignorado pelo git).
- `testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.
- `internal/testmod` é um módulo falso para testes (o binário de teste se re-executa como filho).
- Testes entre repositórios (daemon + sensor reais, TUI em pty): `mod-net-sensor/scripts/e2e.sh` e `scripts/live_smoke.sh`.

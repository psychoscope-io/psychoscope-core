# psychoscope-core

Orquestrador (hub) e CLI/TUI do Psychoscope MODR, em Go.

## Estado

Fase 3 concluída: daemon funcional com
- **IPC dos módulos** (`internal/ipc`): `core.sock` (0660), framing length-prefixed, handshake `Hello`/`HelloResposta`,
  `SO_PEERCRED` (UID permitido + PID declarado == PID real do peer), telemetria/status com `id_modulo` validado,
  comandos com ACK/NACK síncronos e timeout, heartbeat (3 intervalos de silêncio derrubam a sessão).
- **Supervisor** (`internal/supervisor`): `os/exec` com grupo de processos próprio e ambiente mínimo, restart com backoff exponencial,
  watchdog de conexão, parada graciosa `ENCERRAR → SIGTERM → SIGKILL`; só o PID do filho lançado pode assumir o `id_modulo`.
- **Canal de controle** (`internal/ctl`): `ctl.sock` com `control.proto` (listar módulos, enviar comando, assinar alertas); barramento de alertas em `internal/alerts`.
- **Daemon** `cmd/psychoscope` e **CLI** `cmd/psychoscope-cli` (`list`, `cmd <modulo> pause|resume|reconfigure|stop`, `alerts`).

Ainda não: motor de detecção/regras e TUI Bubbletea (Fase 5). O sensor real (`mod-net-sensor`) já conversa com este daemon: veja `scripts/e2e.sh` e `scripts/live_smoke.sh` naquele repositório.

## Uso rápido

```
go build -o /tmp/psychoscope ./cmd/psychoscope
/tmp/psychoscope --config psychoscope.json        # ou --socket/--ctl-socket
go run ./cmd/psychoscope-cli list
```

Exemplo de `psychoscope.json`:

```json
{
  "socket_mode": "0660",
  "modules": [
    { "id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": [], "stop_grace": "10s" }
  ]
}
```

Sockets: `/var/run/psychoscope/` se existir e for gravável (ex.: `RuntimeDirectory=` do systemd) ou root; senão `$XDG_RUNTIME_DIR/psychoscope/`.
`--allow-unmanaged` (dev) aceita módulos não lançados pelo supervisor (só checa UID).

## Notas

- `go.mod` usa `replace` para `../psychoscope-proto` durante o desenvolvimento; remover antes de publicar.
- `testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.
- `internal/testmod` é um módulo falso para testes (o binário de teste se re-executa como filho).

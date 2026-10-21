# AGENTS.md — psychoscope-core

Hub do Psychoscope MODR em Go: supervisiona módulos, recebe telemetria por IPC, detecta, persiste alertas e expõe CLI/TUI e métricas. Instalação: `docs/INSTALL.md`.

## Estrutura

- `cmd/psychoscope` (daemon) e `cmd/psychoscope-cli` (CLI e TUI; `alerts -v` mostra o contexto).
- `internal/ipc`: `core.sock`. `server.go` (aceita e lê), `handshake.go` (Hello, `SO_PEERCRED`, recusa), `handler.go` (interfaces `Authorizer`/`Handler`), `session.go` (comandos ACK/NACK), `framer.go`, `listen.go`.
- `internal/supervisor`: `supervisor.go` (API: Run/Stop/Command/List), `ipc_integration.go` (autorização por PID e estado da conexão), `lifecycle.go` (processo filho: backoff, watchdog, parada em escalada).
- `internal/detection` (+ `rules/`): janela deslizante, motor, regras. `internal/alerts`: barramento e histórico.
- `internal/store` (SQLite e gravador em lote), `internal/metrics`, `internal/ctl` (`ctl.sock`: um manipulador por pedido, e cliente), `internal/version`, `internal/testmod` (módulo falso para testes).
- `internal/tui`: `model.go` (estado, `Update` e despacho de teclas), `cmdline.go` (linha de comando `:q`/`:stop`/`:pause`/`:resume`), `detail.go` (detalhe do alerta com rolagem), `messages.go`, `commands.go` (chamadas assíncronas), `view.go` e `panels.go`.
- `internal/config`: `config.go` (`Load`/`Validate`), `env.go`, `file.go` (flags e esquema JSON), uma seção por arquivo (`modules`, `storage`, `metrics`, `detection`) e `overlay.go`.
- `internal/app`: ponto de composição (`app.go`: `build` → `listen` → `serve`, com encerramento ordenado), `sink.go` (telemetria → motor) e `metrics.go` (coletores).
- `deploy/` (unit do systemd, `install.sh`) e `docs/INSTALL.md`.

## Comandos

```bash
make hooks                  # uma vez por clone: ativa commit-msg, pre-commit e pre-push
make check                  # o que o CI roda: gofmt, vet, golangci-lint, shellcheck, actionlint, govulncheck, go test -race
make fmt                    # gofmt -w
./deploy/test_install.sh    # instalador, sem privilégios
```

Ferramentas (fora do `go.mod`): `golangci-lint` v2, `govulncheck`, `actionlint` (`go install`) e `shellcheck`. Achado de lint se corrige; só vira `//nolint:<linter> // motivo` quando o aviso é legítimo e o motivo cabe numa linha.

Dependência do proto antes de a tag existir no GitHub: `source ../psychoscope-proto/scripts/local-deps.sh` (ou um `go.work`, ignorado pelo git). Integração com o sensor real, persistência e TUI em pty: `../mod-net-sensor/scripts/e2e.sh` e `live_smoke.sh`.

## Regras e skills

Regras (`.claude/rules/`): as oito compartilhadas (`fluxo-de-trabalho`, `principios-de-design`, `organizacao-do-codigo`, `testes-e-verificacao`, `git-e-publicacao`, `seguranca`, `contrato-proto`, `estilo-e-idioma`) e `go`, `deteccao` (deste repositório).
Skills (`.claude/skills/`): `adicionar-regra-de-deteccao`, `verificar-core`, `refatorar-sem-quebrar`, `revisar-pr-dependabot`, `publicar-versao`.

## Armadilhas conhecidas

- Testes que montam `config.Config` à mão precisam de `Detection: config.DefaultDetection()` e de `Storage` explícito (valor zero = persistência desligada, com `Path` em diretório temporário).
- O `timestamp` do alerta é o instante da detecção; o instante do evento fica em `contexto["evento_ts"]`.
- Estado de regra e janela pertencem à goroutine do motor: sem travas, nunca acesse de fora.
- O encerramento é ordenado (módulos → servidores → motor → gravador → banco); não reordene em `internal/app`.

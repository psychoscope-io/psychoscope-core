# AGENTS.md — psychoscope-core

Hub do Psychoscope MODR em Go: supervisiona módulos, recebe telemetria por IPC, detecta, persiste alertas e expõe CLI/TUI e métricas. Instalação: `docs/INSTALL.md`.

## Estrutura

- `cmd/psychoscope` (daemon) e `cmd/psychoscope-cli` (CLI e TUI).
- `internal/ipc`: `core.sock`, framing, handshake `Hello`, `SO_PEERCRED`, sessões e comandos ACK/NACK.
- `internal/supervisor`: processos filhos (backoff, watchdog, parada graciosa) e autorização por PID.
- `internal/detection` (+ `rules/`): janela deslizante, motor, regras. `internal/alerts`: barramento e histórico.
- `internal/store` (SQLite), `internal/metrics`, `internal/ctl` (`ctl.sock` e cliente), `internal/tui`, `internal/config`, `internal/app` (montagem e shutdown ordenado), `internal/version`, `internal/testmod` (módulo falso para testes).
- `deploy/` (unit do systemd, `install.sh`) e `docs/INSTALL.md`.

## Comandos

```bash
gofmt -l .                  # deve sair vazio
go vet ./...
go test -race ./...
./deploy/test_install.sh    # instalador, sem privilégios
```

Dependência do proto antes de a tag existir no GitHub: `source ../psychoscope-proto/scripts/local-deps.sh` (ou um `go.work`, ignorado pelo git). Integração com o sensor real, persistência e TUI em pty: `../mod-net-sensor/scripts/e2e.sh` e `live_smoke.sh`.

## Regras e skills

Regras (`.claude/rules/`): as oito compartilhadas (`fluxo-de-trabalho`, `principios-de-design`, `organizacao-do-codigo`, `testes-e-verificacao`, `git-e-publicacao`, `seguranca`, `contrato-proto`, `estilo-e-idioma`) e `go`, `deteccao` (deste repositório).
Skills (`.claude/skills/`): `adicionar-regra-de-deteccao`, `verificar-core`, `refatorar-sem-quebrar`, `revisar-pr-dependabot`, `publicar-versao`.

## Armadilhas conhecidas

- Testes que montam `config.Config` à mão precisam de `Detection: config.DefaultDetection()` e de `Storage` explícito (valor zero = persistência desligada, com `Path` em diretório temporário).
- O `timestamp` do alerta é o instante da detecção; o instante do evento fica em `contexto["evento_ts"]`.
- Estado de regra e janela pertencem à goroutine do motor: sem travas, nunca acesse de fora.
- O encerramento é ordenado (módulos → servidores → motor → gravador → banco); não reordene em `internal/app`.

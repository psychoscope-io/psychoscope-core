---
name: verificar-core
description: Rodar a verificação completa do psychoscope-core antes de entregar uma mudança. Use ao terminar qualquer alteração no core.
---
# Verificar o core

```bash
gofmt -l .                      # vazio
go vet ./...
go test ./... -race -count=1
./deploy/test_install.sh
go test ./internal/ipc -run='^$' -fuzz=FuzzReadFrame -fuzztime=10s   # se tocou no framing
```

Sem `go.work` (como o CI vê): `GOWORK=off go test ./...`, com `source ../psychoscope-proto/scripts/local-deps.sh` se a tag do proto ainda não está no GitHub.

Integração, quando a mudança toca IPC, regras, persistência, métricas, CLI ou TUI:

```bash
cd ../mod-net-sensor && scripts/e2e.sh && scripts/live_smoke.sh
```

No relatório final, diga o que rodou e o que **não** pôde rodar (GitHub Actions, systemd real, capabilities ambientes).

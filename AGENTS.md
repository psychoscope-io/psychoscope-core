# AGENTS.md — psychoscope-core

Hub do Psychoscope MODR em Go: supervisiona módulos, recebe telemetria por IPC, detecta, persiste alertas e expõe CLI/TUI e métricas. Instalação: `docs/INSTALL.md`.

## Estrutura

- `cmd/psychoscope` (daemon) e `cmd/psychoscope-cli` (CLI e TUI; `alerts -v` mostra o contexto). `doctor` = `doctor.go` (orquestra e sai com 1 se houver falha), `doctor_checks.go` (decisões puras), `doctor_env.go` (único I/O de sistema, atrás de `doctorEnv`), `doctor_sensor.go` (`--check` do sensor) e `doctor_report.go` (texto e JSON). `analyze` = `analyze.go` (flags, motor vazio e `--set`; sai com 2 em `--fail-on-alert`), `analyze_env.go` (único I/O: roda o sensor sobre o pcap e recebe os eventos por um socket temporário, atrás de `eventSource`) e `analyze_report.go` (texto e JSON, instante do evento em UTC); não usa o Core, o `overrides.json` nem o estado do motor.
- `internal/ipc`: `core.sock`. `server.go` (aceita e lê), `handshake.go` (Hello, `SO_PEERCRED`, recusa), `handler.go` (interfaces `Authorizer`/`Handler`), `session.go` (comandos ACK/NACK), `framer.go`, `listen.go`, `counters.go` (limita `StatusModulo.contadores`: até 64 chaves de até 64 caracteres em `[a-z0-9._-]`; o resto é descartado antes de qualquer consumidor).
- `internal/supervisor`: `supervisor.go` (API: Run/Stop/Command/List), `ipc_integration.go` (autorização por PID e estado da conexão), `lifecycle.go` (processo filho: backoff, watchdog, parada em escalada), `external.go` (módulo `external`: mantido pelo systemd, sem processo filho; autorizado só pelo UID exato do `user`, estado pela conexão).
- `internal/detection` (+ `rules/`): janela deslizante, motor, regras. `rules/techniques.go` mapeia cada regra à técnica MITRE ATT&CK compatível (`ruleTechniques`; `contextTechniques` quando depende do contexto, como o `tipo` do `net.beacon`) ou diz por que não tem (`noTechnique`); um teste cobra a decisão por regra, e a página `docs/REGRAS.md` repete os IDs, os motivos e a versão do ATT&CK (`attackVersion`) conferida. É exibição (CLI `-v`, `analyze --json`, detalhe da TUI): não vai no proto nem no banco. `internal/alerts`: barramento e histórico.
- `internal/store` (SQLite e gravador em lote), `internal/metrics`, `internal/ctl` (`ctl.sock`: um manipulador por pedido, e cliente; `config.go` = leitura/escrita de configuração com a autorização por UID, `configvalue.go` = texto digitado ↔ JSON do contrato, `counters.go` = nomes legíveis dos contadores de módulo), `internal/version`, `internal/testmod` (módulo falso para testes).
- `internal/enginestate`: estado do motor em disco (`state.go` = `Store` Load/Save atômico 0600 com descarte de arquivo ilegível, grande demais ou "no futuro"; `saver.go` = snapshot periódico, pulado sem eventos novos). `detection/state.go` define `Snapshot`, `Stateful`, `Engine.Snapshot/State/Restore`; `rules/net_beacon_state.go` exporta e valida o estado do beacon. O gravador para antes do motor, e o estado final é lido depois dele (em `app/enginestate.go`).
- `internal/settings`: configuração em tempo de execução. `catalog.go` (campos editáveis por reflexão sobre `rules.Config`: valor, padrão, origem, nome da tag `label` e descrição da tag `doc`) e `manager.go` (`Apply`: valida em conjunto, grava `overrides.json` de forma atômica 0600, aplica ao vivo por `Live`, audita). A escrita é só do root (conferida no `ctl`).
- `internal/tui`: `model.go` (estado, `Update` e despacho de teclas), `cmdline.go` (linha de comando `:`; tabela `commands`: `q`, `q!`, `quit`, `stop`, `config`, `set`, `w`, `wq`) e `lineeditor.go` (editor de linha), `detail.go` (detalhe do alerta com rolagem e as teclas `i` e `u`, que acrescentam e removem a exceção sugerida), `settings.go` e `settings_view.go` (tela de configurações: rascunho, `:set`, `:w`), `messages.go`, `commands.go` (chamadas assíncronas), `view.go` e `panels.go`.
- `internal/config`: `config.go` (`Load`/`Validate`), `env.go`, `file.go` (flags e esquema JSON), uma seção por arquivo (`modules`, `storage`, `metrics`, `detection`), `overlay.go` e `overrides.go` (`Overrides`: ajustes por caminho; `Layer` os aplica sobre a base sem alterá-la) e `migrate.go` (função pura que converte o sensor lançado pelo Core, da configuração ≤0.11, no módulo `external`; o I/O é do `psychoscope-cli migrate-config`, `cmd/psychoscope-cli/migrate.go`).
- `internal/app`: ponto de composição (`app.go`: `build` → `listen` → `serve`, com encerramento ordenado), `modules.go` (usuário de módulo `external` → UID, falha na partida se não existir), `sink.go` (telemetria → motor), `metrics.go` (coletores) e `settings.go` (liga `internal/settings` ao motor e ao gravador).
- `deploy/` (`systemd/psychoscope.service` = Core sem capabilities e com `NoNewPrivileges=yes`; `systemd/psychoscope-sensor.service` = sensor com usuário `psychoscope-sensor` e as capabilities de captura como `AmbientCapabilities`; `sensor.env.example`; `install.sh`; `get.sh`: baixa, atualiza e desinstala, instalado como `psychoscope-update`; testes `test_install.sh` e `test_get.sh`, que usam `release_server.py`; `test_distros.sh`: manual, Docker + systemd em Debian/Ubuntu/Fedora), `docs/INSTALL.md`, `docs/REGRAS.md` (referência por regra: o que detecta, como investigar, falsos positivos, ajuste) e `docs/FALSOS-POSITIVOS.md` (do falso positivo ao pcap de teste com `analyze`).

## Comandos

```bash
make hooks                  # uma vez por clone: ativa commit-msg, pre-commit e pre-push
make check                  # o que o CI roda: gofmt, vet, golangci-lint, shellcheck, actionlint, govulncheck, go test -race
make fmt                    # gofmt -w
make build                  # dist/psychoscope e dist/psychoscope-cli com a versão (a release usa o mesmo alvo)
make tag                    # scripts/tag.sh: tag anotada da próxima versão (local; o push é seu)
./deploy/test_install.sh    # instalador, sem privilégios
./deploy/test_get.sh        # get.sh (servidor HTTP local, --destdir), sem rede nem root
./deploy/test_distros.sh    # MANUAL, fora do CI: Docker + systemd + rede; instala, atualiza e remove em Debian, Ubuntu e Fedora (Core compilado desta árvore; LOCAL_BUILD=0 testa o publicado)
```

Ferramentas (fora do `go.mod`): `golangci-lint` v2, `govulncheck`, `actionlint` (`go install`) e `shellcheck`. Achado de lint se corrige; só vira `//nolint:<linter> // motivo` quando o aviso é legítimo e o motivo cabe numa linha.

Dependência do proto antes de a tag existir no GitHub: `source ../psychoscope-proto/scripts/local-deps.sh` (ou um `go.work`, ignorado pelo git). Integração com o sensor real, persistência e TUI em pty: `../mod-net-sensor/scripts/e2e.sh` e `live_smoke.sh` (este roda `scripts/tui_config_pty.py`, a tela de configurações num pty real, como root de um `unshare -Urn`).

## Regras e skills

Regras (`.claude/rules/`): as oito compartilhadas (`fluxo-de-trabalho`, `principios-de-design`, `organizacao-do-codigo`, `testes-e-verificacao`, `git-e-publicacao`, `seguranca`, `contrato-proto`, `estilo-e-idioma`) e `go`, `deteccao` (deste repositório).
Skills (`.claude/skills/`): `adicionar-regra-de-deteccao`, `verificar-core`, `refatorar-sem-quebrar`, `revisar-pr-dependabot`, `publicar-versao`.

## Armadilhas conhecidas

- **Nunca dependa de `setcap` nem de `NoNewPrivileges=no` na unit do Core.** O systemd 252 (Debian 12) liga `NoNewPrivs=1` sozinho com `User=` e qualquer opção de isolamento baseada em seccomp ou `Protect*` de kernel, e isso anula as file capabilities; o 255+ (Ubuntu 24.04, Fedora) não. Por isso o sensor tem unit própria com `AmbientCapabilities`, e o `test_install.sh` cobra as invariantes das duas units.
- Testes que montam `config.Config` à mão precisam de `Detection: config.DefaultDetection()` e de `Storage` explícito (valor zero = persistência desligada, com `Path` em diretório temporário).
- O `timestamp` do alerta é o instante da detecção; o instante do evento fica em `contexto["evento_ts"]`.
- Estado de regra e janela pertencem à goroutine do motor: sem travas, nunca acesse de fora. Para trocar regras ou janela ao vivo, use `Engine.Reconfigure`: o cooldown e o estado das regras que continuam passam para as instâncias novas, exceto o das regras `detection.StateKeyed` cuja `StateKey` mudou (limiar ou janela ajustados), que recomeçam; `Restore` aplica a mesma regra na partida. `StateKey` ignora os campos com a tag `keepstate` em `rules.Config` (cooldown, tetos e listas de exceção: campo novo de lista ou de teto leva a tag; limiar não). Regra com estado próprio implementa `detection.Stateful` (`ExportState`/`ImportState`), e um teste cobra que toda regra tenha `StateKey`.
- A configuração em tempo de execução só escreve campos do catálogo (`internal/settings`); `modules`, sockets e caminhos nunca entram. O `overrides.json` é lido com chaves estritas. Campo novo de regra exige as tags `json`, `label` **e** `doc` (um teste cobra); regra nova também entra em `rules/labels.go` (nome legível e chaves de contexto).
- Os testes de integração fixam `overrides_path` num diretório temporário: sem isso, o arquivo de ajustes cairia no diretório de estado real (e, como root, em `/var/lib/psychoscope`).
- Testes que montam `config.Config` à mão deixam `EngineStatePath` vazio (desliga o estado do motor); os de integração do estado fixam o caminho em diretório temporário, como o `overrides_path`.
- A fila da assinatura do gravador de alertas (`store.subscriptionBuffer`, 16 384) e a de entrada do motor (`queue_size`, 4096) descartam e contam em vez de bloquear; `Bus.Publish` e `Engine.Submit` nunca podem bloquear. Mexeu no caminho do evento ou do alerta: rode os `go test -bench` de `ipc`, `detection/rules` e `store` e o `bench_replay.sh` do sensor, e registre o número no commit.
- O encerramento é ordenado (módulos → servidores → gravador do estado → motor → estado final → gravador de alertas → banco); não reordene em `internal/app`. O `Saver` pede cópias ao motor, então para antes dele; `Engine.State()` só vale com o motor parado.

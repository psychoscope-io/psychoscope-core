# psychoscope-core

Orquestrador (hub) do Psychoscope MODR, com motor de detecção, persistência de alertas e CLI/TUI, em Go.

Instalação como serviço (systemd, usuário dedicado, privilégios mínimos): [docs/INSTALL.md](docs/INSTALL.md).

O que cada regra detecta, como investigar um alerta e como ajustar os falsos positivos: [docs/REGRAS.md](docs/REGRAS.md).

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
  ler e aplicar configuração (a escrita só para o root; veja [Configuração em tempo de execução](#configuração-em-tempo-de-execução)),
  consultar alertas persistidos (filtros de tempo, severidade, regra e módulo) e métricas.
- **Métricas** (`internal/metrics`): contadores/medidores do motor, do armazenamento e de cada módulo; pela CLI/TUI e, opcionalmente, em
  `/metrics` no formato Prometheus (somente loopback por padrão, sem autenticação).
- **CLI/TUI** (`cmd/psychoscope-cli`): sem argumentos abre a TUI (Bubbletea + Lipgloss) com painel de módulos, feed de alertas e linha de
  eventos/s, alertas e descartes. Teclas: `↑/↓` selecionar, `tab` alternar foco, `Enter` (no painel de alertas) abrir os detalhes do
  alerta (todos os campos, descrição e contexto com quebra de linha, `↑/↓`/`PgUp`/`PgDn` rolam, `Esc`/`Enter`/`q`/`:q` fecham; `i` acrescenta a
  exceção sugerida do alerta à configuração, veja abaixo), `p` pausar, `r` retomar e `:` abrir a linha de comando (`:config` abre a tela de
  configurações). Sair e encerrar um módulo só existem como comandos, para não acontecerem por acidente:
  `:q` (ou `:quit`) + `Enter` fecha a visão atual, como no vim (no detalhe do alerta fecha só o detalhe; na tela principal sai da TUI),
  e `:stop` + `Enter` encerra o módulo selecionado (o rodapé mostra o alvo enquanto você digita). `p` pausa e `r` retoma o módulo selecionado
  (`r` também reinicia um módulo encerrado por `:stop`). `Tab` completa o comando e `Esc` cancela. `q`, `Esc` e `Ctrl+C` na tela principal só
  mostram a dica. **Mudança na v0.4.0:** `:sair`, `:pause` e `:resume` foram removidos (repetiam `q`/`:q`, `p` e `r`); os comandos seguem o vocabulário do vim, em inglês.
  Subcomandos: `list`, `cmd <modulo> pause|resume|reconfigure|stop [k=v]`, `config [-v] [prefixo]` / `config set campo=valor ...` /
  `config reset campo ...`, `alerts [--no-history] [-v]` (ao vivo),
  `alerts --history [-n 50] [--since 2h] [--min-severity alta] [--rule R] [--module M] [-v]` (persistido; `-v` mostra o contexto
  `chave=valor` de cada alerta, uma linha recuada por chave), `metrics`, `doctor` (veja abaixo), `--version`.

## Diagnóstico (`psychoscope-cli doctor`)

Verifica a instalação de uma vez e diz o que corrigir. É somente leitura: não altera nada na máquina.

```bash
psychoscope-cli doctor [--sensor] [--json] [--config /etc/psychoscope/psychoscope.json]
```

Saída no mesmo formato do `mod-net-sensor --check` (`[ok]`, `[aviso]`, `[falha]` e a linha `como corrigir:`), terminando com `resultado: N falha(s), M aviso(s)`.
O código de saída é **1 se houver alguma falha** e 0 caso contrário (avisos não contam), o que serve a scripts e a monitoramento.

| Verificação | O que olha |
|---|---|
| Socket de controle | abre o `ctl.sock` e, se não abrir, diz por quê: ausente (serviço parado ou caminho errado, inclusive o fallback de `$XDG_RUNTIME_DIR`), sem permissão (mostra modo e dono) ou UID não autorizado |
| Serviço systemd | `systemctl is-active psychoscope`; pulado se não houver `systemctl`. Unit parada com o Core respondendo vira aviso (Core iniciado fora do systemd) |
| Core | versão e tempo ligado |
| Módulos | estado, versão declarada, há quanto tempo estão conectados, PID e reinícios (com o último erro) |
| Perda de pacotes | por módulo, a partir dos contadores de perda: qualquer perda é aviso e **1 % ou mais dos pacotes é falha**, com a causa provável (captura, fila de eventos ou IPC). Os contadores são cumulativos desde que o módulo subiu |

- `--sensor`: também roda o `--check` do `mod-net-sensor` configurado (até 10 s) e repassa as falhas, avisos e correções dele. O arquivo de configuração costuma ser legível só pelo grupo `psychoscope`; sem acesso, o doctor avisa e segue. O `--check` roda com a identidade de quem chamou, e não com a do serviço; a saída traz o comando para reproduzir como o serviço (`sudo -u psychoscope ...`).
- `--json`: o mesmo relatório como JSON estável, `{"resultado": {"falhas", "avisos"}, "achados": [{"nivel", "item", "detalhe", "como_corrigir"}]}`, com `nivel` em `ok`, `aviso`, `falha` ou `pulado`.
- Se o Core não responde, o que depende dele aparece como `[pulado]`, sem repetir o mesmo erro.

## Configuração em tempo de execução

Limiares, exceções e regras desligadas se ajustam sem editar JSON nem reiniciar o serviço, pela tela de configurações da TUI ou pela CLI.
O arquivo do administrador (`/etc/psychoscope/psychoscope.json`) **nunca é tocado**: os ajustes ficam num arquivo próprio, `overrides.json`,
no diretório de estado (`/var/lib/psychoscope/`, modo `0600`; `overrides_path` no arquivo de configuração escolhe outro caminho), por cima
dele. Ordem de precedência: padrão do Core < arquivo do administrador < ajuste. "Restaurar" um campo remove o ajuste e volta ao valor do arquivo
(ou ao padrão); sem nenhum ajuste, o arquivo é removido.

- **Só o root escreve.** A decisão usa o UID que o kernel informa no canal de controle (`SO_PEERCRED`), nunca algo declarado pelo cliente;
  os demais usuários permitidos no canal leem em modo somente leitura. Cada mudança vai para o log (`journalctl -u psychoscope`) com UID, PID,
  campo, valor antes e valor depois (`configuracao alterada`).
- **O que é editável:** `detection.window`, `detection.disabled`, todos os campos de cada regra (`detection.<regra>.<campo>`, com descrição na
  tela) e `storage.retention_days` e `storage.max_alerts`. **Nunca** pelo canal: `modules` (caminho e argumentos de um módulo seriam execução de
  código), sockets, `socket_mode`, `allowed_uids`, `metrics.listen`, `storage.path` e `detection.queue_size` e `max_events` (exigem reinício).
  O arquivo de ajustes é lido com chaves estritas: qualquer outra chave impede a partida, com uma mensagem que cita o arquivo.
- **Aplicação ao vivo.** As regras e a janela do motor são trocadas sem perder os eventos retidos. Os cooldowns e o estado interno (como as séries do
  beacon) **das regras que você não ajustou continuam**; só as regras cuja configuração mudou recomeçam, de modo que ao alterar um limiar o alerta
  volta a aparecer na hora, e mexer numa regra não repete os alertas das outras. Os limites de retenção valem na hora (poda imediata).
- **Listas são substituídas, não somadas.** Um campo de lista (como `ignore_destinations`) com ajuste **substitui** a lista do arquivo do
  administrador, não se soma a ela. Ao ajustar (`i`, `:set`, `config set`), a lista que vale naquele momento, com os itens do arquivo, é copiada
  para o ajuste; depois disso, mudar essa lista no arquivo do administrador não tem efeito até você restaurar o campo (`d`, `:set campo&`,
  `config reset`), que volta a usar a lista do arquivo.
- **Validação conjunta.** Um pedido vale por inteiro ou não vale: por exemplo, `detection.scan.window` maior que `detection.window` só passa
  junto com a janela do motor.

**Tela de configurações (`:config`).** Lista os campos por seção com valor atual, padrão e origem (`padrão`, `arquivo` ou `ajuste`). Campos e
seções aparecem com nome legível (por exemplo "Destinos ignorados", em "Beacon (conexões periódicas)"); o identificador técnico, que é o que o
arquivo de configuração, o `:set` e a CLI usam, fica na linha de descrição do campo selecionado (`chave: detection.beacon.ignore_destinations`)
e ao lado do título da seção. Sob a lista aparecem a descrição e o formato do campo selecionado. `Enter` edita o campo (listas separadas por vírgula, durações como `30s`) e
`:set campo=valor` faz o mesmo; `d` ou `:set campo&` restauram ao valor base e `:set campo` mostra o valor (o `:set` leva a seleção ao campo;
`Tab` completa o caminho). As alterações ficam num **rascunho** (marcado com `*` e contado no título) e só `:w` as envia, de uma vez.
`Esc` volta para a tela principal (como `:q`, recusa se houver alterações pendentes; durante a edição de um campo, cancela só a edição), `:q!` descarta as alterações e `:wq` grava e fecha. Sem permissão de escrita, a tela é somente leitura.

**Ações `i` e `u` no detalhe do alerta.** Para os alertas de `net.beacon` (o IP de destino ou o domínio), `net.bruteforce.auth` (a origem) e
`net.dns.tunnel` (o domínio base), `i` acrescenta o valor à lista de exceções da regra (`beacon.ignore_destinations`, `beacon.ignore_domains`,
`bruteforce.ignore_sources`, `tunnel.allowed_bases`), sem duplicar e sem perder o que já estava na lista, e `u` o remove da lista (a regra
volta a monitorá-lo). O detalhe lê a lista atual e mostra, na seção "Ação", o estado e o que cada tecla fará: oferece `i` se o valor ainda não
está ignorado, `u` se está, e, se um item da lista já o abrange (uma rede CIDR que contém o IP, um domínio pai), diz qual e manda editar a
lista em `:config`, porque nem `i` nem `u` mudariam nada. Só o root grava. Outras regras (como a varredura) não têm exceção sugerida.

**Nomes na interface.** A TUI mostra o nome legível das regras ("Túnel DNS", não `net.dns.tunnel`) e das chaves de contexto ("Domínio base",
não `dominio_base`), com o identificador entre parênteses no detalhe do alerta. A CLI (`alerts`, `config`, `metrics`) mantém os
identificadores, por ser a interface de scripts. Campo novo de regra exige a tag `label` além de `json` e `doc` (um teste cobra).

**CLI.** `psychoscope-cli config [-v] [prefixo]` lista; `config set campo=valor ...` ajusta (mostra antes e depois); `config reset campo ...`
restaura. Exemplo: `sudo psychoscope-cli config set detection.beacon.ignore_destinations=149.154.160.0/20,2001:67c:4e8::/48`.

## Estado do motor entre reinícios

Sem isso, cada reinício do Core traria de volta os alertas já vistos e faria o `net.beacon`, que precisa de vários contatos regulares, recomeçar do zero.
O Core grava o estado do motor (os cooldowns de todas as regras e as séries e cooldowns do beacon) em `engine-state.json`, no diretório de estado
(`/var/lib/psychoscope/`, modo `0600`, diretório `0750`), no encerramento e a cada 60 s; na partida, lê o arquivo de volta.

- **Chaves** (arquivo de configuração, não editáveis pelo canal de controle): `engine_state_path` (padrão `<estado>/engine-state.json`) e
  `engine_state_interval` (padrão `60s`; `0s` grava só no encerramento).
- **É só uma otimização.** Arquivo ilegível, de versão desconhecida, com mais de 6 h ou salvo "no futuro" (o relógio voltou atrás: restaurar deixaria o
  beacon cego) é descartado com um aviso no log, e o Core sobe com o motor vazio; o próximo salvamento o substitui. Para zerar o estado de propósito,
  apague o arquivo e reinicie.
- **Queda abrupta** (`kill -9`, falta de energia) perde no máximo os últimos 60 s: o pior caso é um alerta repetido, nunca um alerta perdido.
- **Mudança de configuração:** o estado das séries do beacon só vale com o mesmo `min_interval`; se ele mudou, as séries são descartadas e só os cooldowns ficam.
- **Privacidade:** o arquivo contém IPs e domínios do tráfego observado, como o `alerts.db`; as permissões são as mesmas. Inclua-o (ou exclua-o) do backup conforme sua política.
- **Métricas:** `psychoscope_engine_state_saves_total` e `psychoscope_engine_state_save_errors_total`.

## Uso rápido (desenvolvimento)

Para só experimentar, sem montar configuração, rode `scripts/demo.sh` do [mod-net-sensor](https://github.com/psychoscope-io/mod-net-sensor#testar-em-minutos-demo): ele compila tudo, reproduz um pcap malicioso e abre a TUI.

```
make build                                        # dist/psychoscope e dist/psychoscope-cli, com a versao (git describe)
dist/psychoscope --config psychoscope.json        # ou --socket/--ctl-socket
dist/psychoscope-cli                              # TUI
```

Para montar o ambiente inteiro (clonar proto, core e sensor, atualizar e compilar tudo em `dist/`), use `scripts/dev.sh` do repositório [.github](https://github.com/psychoscope-io/.github) (`doctor`, `setup`, `update`, `build`, `clean`).

`psychoscope.json` (tudo opcional exceto os módulos que você quer supervisionar; chaves desconhecidas são erro e a mensagem lista as válidas):

```json
{
  "socket_mode": "0660",
  "modules": [
    { "id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": ["-i", "eth0"], "stop_grace": "10s" }
  ],
  "storage": { "enabled": true, "path": "/var/lib/psychoscope/alerts.db", "retention_days": 30, "max_alerts": 100000 },
  "engine_state_path": "/var/lib/psychoscope/engine-state.json",
  "engine_state_interval": "60s",
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
- A janela deslizante é só em memória: reiniciar o Core a esvazia (ela se refaz em 10 a 60 s). Os cooldowns e as séries do beacon sobrevivem ao
  reinício (veja [Estado do motor](#estado-do-motor-entre-reinícios)).
- A versão TLS informada é a maior **oferecida** no ClientHello, não a negociada.
- O endpoint de métricas não tem autenticação nem TLS.

## Notas de desenvolvimento

- Depende de `github.com/psychoscope-io/psychoscope-proto@v0.2.0`. Antes da publicação (ou offline): `source ../psychoscope-proto/scripts/local-deps.sh` resolve a dependência a partir do checkout local; para iterar no contrato sem criar tags, use um `go.work` (já ignorado pelo git).
- `testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.
- `internal/testmod` é um módulo falso para testes (o binário de teste se re-executa como filho).
- Testes do `install.sh` e do `get.sh` (instala, atualiza e desinstala; sem rede nem root): `./deploy/test_install.sh` e `./deploy/test_get.sh`. Testes entre repositórios (daemon + sensor reais, persistência, TUI em pty):
  `mod-net-sensor/scripts/e2e.sh` e `scripts/live_smoke.sh`.
- Releases: `make tag` (`scripts/tag.sh`) cria a tag anotada da próxima versão, só localmente; ao publicar a tag `vX.Y.Z`, `.github/workflows/release.yml` gera tarballs (amd64/arm64), o `get.sh`, `SHA256SUMS` e atestado de proveniência.

## Licença

Apache License 2.0 — veja [LICENSE](LICENSE).

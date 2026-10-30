# Instalação

Linux (x86_64 ou arm64) com systemd. O Core é um binário estático em Go; o sensor de rede (`mod-net-sensor`)
precisa da biblioteca `libpcap` instalada (`sudo apt install libpcap0.8`).

## Instalação rápida (recomendada)

O `get.sh` baixa a última release do Core e do sensor, confere o `SHA256SUMS` (e a atestação de proveniência, se o
`gh` estiver instalado e logado), instala com o `install.sh` e reinicia o serviço se ele já estiver rodando. Baixe,
leia e rode como usuário comum (ele usa `sudo` só para instalar):

```bash
curl -fsSLO https://github.com/psychoscope-io/psychoscope-core/releases/latest/download/get.sh
less get.sh
bash get.sh
```

Opções: `--core-version X.Y.Z` e `--sensor-version X.Y.Z` fixam versões (as duas são independentes), `--check` só
compara a versão instalada com a última release (sai com 1 se houver atualização), `--dry-run` mostra o que seria
instalado. Depois da primeira instalação o mesmo script fica em
`/usr/local/sbin/psychoscope-update`. Siga para o passo 3 (configurar). Os passos 1 e 2 abaixo são o caminho manual,
útil sem acesso à internet na máquina de destino ou para auditar cada etapa.

## 1. Baixar e verificar (manual)

Baixe os tarballs do Core e do sensor na página de *Releases* de cada repositório
(`psychoscope-core` e `mod-net-sensor`) e verifique antes de instalar:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify psychoscope-core_<versao>_linux_amd64.tar.gz --repo psychoscope-io/psychoscope-core
gh attestation verify mod-net-sensor_<versao>_linux_amd64.tar.gz   --repo psychoscope-io/mod-net-sensor
```

A atestação de proveniência prova que o binário foi gerado pelo workflow de release do repositório,
a partir da tag correspondente.

## 2. Instalar (manual)

```bash
tar xzf psychoscope-core_<versao>_linux_amd64.tar.gz
tar xzf mod-net-sensor_<versao>_linux_amd64.tar.gz
cd psychoscope-core_<versao>_linux_amd64
sudo ./deploy/install.sh --sensor ../mod-net-sensor_<versao>_linux_amd64/mod-net-sensor
```

O script cria os usuários de sistema `psychoscope` (Core) e `psychoscope-sensor` (sensor), instala os binários em
`/usr/local/bin`, grava `/etc/psychoscope/psychoscope.json` e `/etc/psychoscope/sensor.env` (se ainda não existirem) e as
units `psychoscope.service` e `psychoscope-sensor.service` em `/etc/systemd/system`. Não há `setcap`: o systemd entrega as
capabilities de captura só ao sensor. Use `--dry-run` para ver o que seria feito e `--prefix` para outro diretório.

## 3. Configurar

O mínimo é a interface do sensor, em `/etc/psychoscope/sensor.env` (`SENSOR_ARGS=-i eth0`; outros argumentos do sensor, como
`--bpf`, entram na mesma linha, separados por espaço e sem aspas). O exemplo usa `eth0`, que em muitas máquinas se chama
`enp3s0`, `wlp2s0` etc.: veja os nomes reais e confira o ambiente (sem `sudo`, só para ler) antes de subir o serviço. Depois
de editar o `sensor.env`: `sudo systemctl restart psychoscope-sensor`. Se o `id` do módulo ou o `socket` do Core forem diferentes dos
padrões (`mod-net-sensor` e `/run/psychoscope/core.sock`), o sensor precisa saber: ponha `PSYCHOSCOPE_MODULE_ID=...` e
`PSYCHOSCOPE_SOCKET=...` no mesmo arquivo (a migração automática já faz isso).

```
/usr/local/bin/mod-net-sensor --list-interfaces
/usr/local/bin/mod-net-sensor --check -i <interface>
```

O `psychoscope.json` declara o sensor como módulo **externo**: o systemd o mantém, e o Core só o autentica pelo usuário
(`SO_PEERCRED`). O usuário precisa existir na partida do Core.

```json
{
  "modules": [
    { "id": "mod-net-sensor", "external": true, "user": "psychoscope-sensor" }
  ]
}
```

Seções opcionais (valores padrão entre parênteses):

| Seção | Chaves principais |
|---|---|
| `storage` | `enabled` (true), `path` (`/var/lib/psychoscope/alerts.db`), `retention_days` (30), `max_alerts` (100000) |
| `metrics` | `listen` (desligado; ex.: `"127.0.0.1:9464"`), `allow_non_loopback` (false) |
| `detection` | `window` (60s), `disabled` (lista de regras), e uma seção por regra: `scan`, `nxdomain`, `tunnel`, `dns_rate`, `tls`, `beacon`, `bruteforce`, `icmp_sweep` — veja o README para as chaves de cada uma |
| raiz | `allowed_uids` (UIDs extras com acesso ao canal de controle), `socket_mode` (`0660` ou `0600`), `status_interval`, `log_level`, `overrides_path` (arquivo dos ajustes feitos pela TUI/CLI; padrão `/var/lib/psychoscope/overrides.json`), `engine_state_path` (estado do motor, padrão `/var/lib/psychoscope/engine-state.json`) e `engine_state_interval` (padrão `60s`; `0s` grava só no encerramento) |

Chaves desconhecidas são rejeitadas na partida com a lista das válidas.

## 4. Iniciar e verificar

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now psychoscope
sudo systemctl status psychoscope psychoscope-sensor   # habilitar o Core basta: ele puxa a unit do sensor
sudo journalctl -u psychoscope -u psychoscope-sensor -f

sudo psychoscope-cli list          # módulos e estado
sudo psychoscope-cli               # TUI (módulos, alertas ao vivo, p/r/x)
sudo psychoscope-cli alerts --history --since 24h --min-severity media
sudo psychoscope-cli metrics
```

### Ajustes feitos pela TUI e pela CLI

`sudo psychoscope-cli` (tela `:config`) e `sudo psychoscope-cli config set ...` gravam os ajustes em `/var/lib/psychoscope/overrides.json`
(modo `0600`, dono `psychoscope`), por cima do arquivo do administrador, que nunca é alterado. Só o root escreve, e cada mudança fica no
journal (`journalctl -u psychoscope | grep "configuracao alterada"`). Para **desfazer tudo**, remova o arquivo e reinicie o serviço
(`sudo rm /var/lib/psychoscope/overrides.json && sudo systemctl restart psychoscope`) ou restaure campo a campo na tela. Inclua-o no backup, junto com
`/etc/psychoscope/`: sem ele, uma restauração perde as exceções que você criou pela tela. Se o arquivo ficar inválido (edição manual), o Core não parte e a mensagem diz qual arquivo corrigir ou remover.

Um campo de lista com ajuste **substitui** a lista do arquivo do administrador (não se soma a ela): se você editar essa lista em
`/etc/psychoscope/psychoscope.json` depois de ajustá-la pela TUI, a edição só vale quando o campo for restaurado (`d` na tela,
`psychoscope-cli config reset <campo>`).

### Quem pode usar a CLI

O socket de controle (`/run/psychoscope/ctl.sock`) é `0660` do grupo `psychoscope`, e o Core ainda confere o
UID de quem conecta (via `SO_PEERCRED`): aceita `root`, o próprio usuário `psychoscope` e os UIDs listados em
`allowed_uids`. Para um administrador sem `sudo`, descubra o UID (`id -u fulano`), coloque-o em `allowed_uids`
e adicione-o ao grupo (`sudo usermod -aG psychoscope fulano`).

### Métricas (Prometheus)

Com `"metrics": {"listen": "127.0.0.1:9464"}`, o endpoint `http://127.0.0.1:9464/metrics` expõe o formato
texto do Prometheus. Ele **não tem autenticação**: por isso só aceita endereços de loopback, a menos que
`allow_non_loopback` seja ligado (nesse caso, proteja com firewall ou um proxy).

## Modelo de privilégios

- O Core roda como `psychoscope`, **sem nenhuma capability** (`CapabilityBoundingSet=` vazio) e com `NoNewPrivileges=yes`, mais
  `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, filtro de syscalls, `RestrictAddressFamilies` (sem
  `AF_PACKET`) e `MemoryDenyWriteExecute`.
- O sensor roda em unit própria (`psychoscope-sensor.service`), como `psychoscope-sensor`, **não como `root` nem como o usuário do
  Core**. Só ele recebe `CAP_NET_RAW` e `CAP_NET_ADMIN`, entregues pelo systemd como capabilities *ambientes* (o binário não tem
  `setcap`), com o mesmo tipo de isolamento do Core e acesso ao socket pelo grupo `psychoscope`. Os arquivos `0600` do Core
  (banco de alertas, ajustes e estado do motor) ficam fora do alcance dele; a configuração (`0640`, sem segredos) é legível pelo grupo.
- O Core só aceita o módulo `mod-net-sensor` vindo do UID exato do `user` configurado (conferido pelo kernel); nem `root` nem o
  UID do próprio Core assumem esse módulo.
- Por que não `setcap`: no systemd 252 (Debian 12), qualquer opção de isolamento baseada em seccomp faz o kernel marcar o processo
  com `NoNewPrivs`, o que anula as file capabilities do binário; no 255 ou mais novo (Ubuntu 24.04, Fedora) isso não ocorre. As
  capabilities ambientes funcionam nos dois.
- `psychoscope-cli stop mod-net-sensor` (ou `stop` na TUI) pede o encerramento por IPC; quem reinicia o sensor é o systemd
  (`Restart=on-failure`: uma saída limpa fica parada) e `resume` só orienta `systemctl start psychoscope-sensor`.

## Atualizar, desinstalar, backup

- **Atualizar:** `psychoscope-update --check` mostra se há versão nova e `psychoscope-update` baixa, confere, instala e
  reinicia o serviço (inclui o `daemon-reload`, necessário porque a atualização pode trocar a unit). A configuração e o
  banco de alertas são preservados (veja "Atualizando de 0.11 ou anterior"). Sem o atualizador, repita o passo 2 com os novos tarballs e rode
  `sudo systemctl daemon-reload && sudo systemctl restart psychoscope`.
- **Atualizando de 0.11 ou anterior:** nessas versões o Core lançava o sensor (`path` e `args` na configuração). O `install.sh`
  converte só esse módulo para a forma externa: guarda a cópia original em `/etc/psychoscope/psychoscope.json.antes-da-migracao`,
  passa `args` e `env` para `/etc/psychoscope/sensor.env` (que nunca é sobrescrito) e mantém o resto da configuração. Se a conversão
  não for fiel (mais de um sensor, argumento com espaço ou aspas), ele recusa **antes de instalar qualquer coisa** e diz o que fazer
  à mão. Para migrar manualmente: `sudo psychoscope-cli migrate-config`, ou troque o módulo por
  `{ "id": "mod-net-sensor", "external": true, "user": "psychoscope-sensor" }` e ponha os argumentos em `SENSOR_ARGS`.
  Para **voltar** a uma versão anterior à migração (`psychoscope-update --core-version 0.11.x`), restaure antes
  `/etc/psychoscope/psychoscope.json.antes-da-migracao` sobre `psychoscope.json`: o Core antigo rejeita `external` na configuração.
- **Backup:** copie `/etc/psychoscope/` (inclui o `sensor.env`) e `/var/lib/psychoscope/alerts.db` (o `engine-state.json`, ao lado dele, é descartável: guarda IPs e domínios do tráfego, e perdê-lo só faz o beacon recomeçar) (SQLite em modo WAL; use
  `sqlite3 alerts.db ".backup alerts.bak"` com o serviço rodando).
- **Desinstalar:** `psychoscope-update --uninstall` para o serviço e remove a unit e os binários, mantendo configuração e
  alertas; com `--purge` apaga também `/etc/psychoscope`, `/var/lib/psychoscope` e os usuários `psychoscope` e
  `psychoscope-sensor` (pede confirmação; `--yes` dispensa). Passo a passo manual equivalente:

  ```bash
  sudo systemctl disable --now psychoscope
  sudo systemctl stop psychoscope-sensor
  sudo rm /etc/systemd/system/psychoscope.service /etc/systemd/system/psychoscope-sensor.service
  sudo rm /usr/local/bin/psychoscope /usr/local/bin/psychoscope-cli /usr/local/bin/mod-net-sensor
  sudo systemctl daemon-reload
  ```

  Isso mantém a configuração e o histórico de alertas. Para apagar também esses dados e o usuário de sistema
  (irreversível; faça o backup antes se quiser guardar os alertas):

  ```bash
  sudo rm -r /etc/psychoscope /var/lib/psychoscope
  sudo userdel psychoscope-sensor
  sudo userdel psychoscope
  ```

## Experimentar sem instalar o serviço

Para avaliar a ferramenta, reproduzir um alerta ou testar um ajuste de limiar a partir de um pcap, basta o `psychoscope-cli` e o `mod-net-sensor`
no `PATH` (ou `--sensor caminho`), sem root nem systemd:

```bash
psychoscope-cli analyze captura.pcap
```

Detalhes e opções no README (seção "Análise offline de um pcap").

## Solução de problemas

Comece por `psychoscope-cli doctor` (com `--sensor` para incluir o `--check` do sensor): ele distingue serviço parado, socket ausente, falta de permissão e UID não autorizado, mostra o estado de cada módulo e a perda de pacotes, e imprime o comando de correção. O código de saída é 1 se houver falha.

| Sintoma | Causa provável |
|---|---|
| `nao foi possivel iniciar a captura ... Operation not permitted` no log do sensor | o sensor não está rodando pela unit `psychoscope-sensor.service` (`AmbientCapabilities`): configuração antiga em que o Core o lança (`psychoscope-cli migrate-config`), ou unit antiga (reinstale) |
| módulo `mod-net-sensor` em `INICIANDO` e o Core sem conexão | `systemctl status psychoscope-sensor` e `journalctl -u psychoscope-sensor`; se aparecer "nao autorizado" no log do Core, o `user` da configuração não é o usuário da unit |
| `usuario "psychoscope-sensor" nao encontrado` na partida do Core | crie o usuário (o `install.sh` faz) ou ajuste o `user` do módulo |
| `nao foi possivel iniciar a captura ... No such device` / `a interface 'eth0' nao existe` | o nome da interface em `args` não existe nesta máquina: rode `mod-net-sensor --list-interfaces` e ajuste `["-i", "<nome>"]` |
| o sensor sobe, mas o Core não mostra eventos | rode `mod-net-sensor --check -i <interface>`: ele confere permissão, filtro BPF e se o Core está escutando, e diz o que corrigir; `--print` mostra os eventos sem o Core |
| `analyze`: `nao encontrei o mod-net-sensor` | instale o sensor no `PATH` ou em `/usr/local/bin`, ou use `--sensor /caminho/mod-net-sensor` |
| `error while loading shared libraries: libpcap.so.0.8` | instale `libpcap0.8` |
| `armazenamento de alertas em ...: ... (defina storage.enabled=false ...)` | o usuário `psychoscope` não consegue escrever em `storage.path`; use o padrão (`StateDirectory`) ou ajuste permissões |
| `psychoscope-cli`: `permission denied`, `no such file or directory` ou conexão encerrada sem resposta | `psychoscope-cli doctor` diz qual: serviço parado, caminho do socket errado, usuário fora do grupo `psychoscope` ou UID fora de `allowed_uids` (ou use `sudo`) |
| módulo em `REINICIANDO` com erro `nao conectou ao socket` | caminho/permissões do binário do módulo, ou `connect_timeout` curto demais |

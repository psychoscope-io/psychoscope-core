# Instalação

Linux (x86_64 ou arm64) com systemd. O Core é um binário estático em Go; o sensor de rede (`mod-net-sensor`)
precisa da biblioteca `libpcap` instalada (`sudo apt install libpcap0.8`).

## 1. Baixar e verificar

Baixe os tarballs do Core e do sensor na página de *Releases* de cada repositório
(`psychoscope-core` e `mod-net-sensor`) e verifique antes de instalar:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify psychoscope-core_<versao>_linux_amd64.tar.gz --repo psychoscope-io/psychoscope-core
gh attestation verify mod-net-sensor_<versao>_linux_amd64.tar.gz   --repo psychoscope-io/mod-net-sensor
```

A atestação de proveniência prova que o binário foi gerado pelo workflow de release do repositório,
a partir da tag correspondente.

## 2. Instalar

```bash
tar xzf psychoscope-core_<versao>_linux_amd64.tar.gz
tar xzf mod-net-sensor_<versao>_linux_amd64.tar.gz
cd psychoscope-core_<versao>_linux_amd64
sudo ./deploy/install.sh --sensor ../mod-net-sensor_<versao>_linux_amd64/mod-net-sensor
```

O script cria o usuário de sistema `psychoscope`, instala os binários em `/usr/local/bin`, aplica
`setcap cap_net_raw,cap_net_admin=eip` **somente** no sensor, grava `/etc/psychoscope/psychoscope.json`
(se ainda não existir) e a unit `/etc/systemd/system/psychoscope.service`. Use `--dry-run` para ver o que
seria feito, `--prefix` para outro diretório e `--no-setcap` se preferir aplicar a capability depois.

## 3. Configurar

Edite `/etc/psychoscope/psychoscope.json`. O mínimo é a interface do sensor:

```json
{
  "modules": [
    { "id": "mod-net-sensor", "path": "/usr/local/bin/mod-net-sensor", "args": ["-i", "eth0"] }
  ]
}
```

Seções opcionais (valores padrão entre parênteses):

| Seção | Chaves principais |
|---|---|
| `storage` | `enabled` (true), `path` (`/var/lib/psychoscope/alerts.db`), `retention_days` (30), `max_alerts` (100000) |
| `metrics` | `listen` (desligado; ex.: `"127.0.0.1:9464"`), `allow_non_loopback` (false) |
| `detection` | `window` (60s), `disabled` (lista de regras), e uma seção por regra: `scan`, `nxdomain`, `tunnel`, `dns_rate`, `tls`, `beacon`, `bruteforce`, `icmp_sweep` — veja o README para as chaves de cada uma |
| raiz | `allowed_uids` (UIDs extras com acesso ao canal de controle), `socket_mode` (`0660` ou `0600`), `status_interval`, `log_level`, `overrides_path` (arquivo dos ajustes feitos pela TUI/CLI; padrão `/var/lib/psychoscope/overrides.json`) |

Chaves desconhecidas são rejeitadas na partida com a lista das válidas.

## 4. Iniciar e verificar

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now psychoscope
sudo systemctl status psychoscope
sudo journalctl -u psychoscope -f

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

- O Core roda como `psychoscope`, **sem capabilities**. O bounding set da unit limita o máximo a
  `CAP_NET_RAW`/`CAP_NET_ADMIN`.
- O sensor é um processo filho e ganha essas duas capabilities pelas *file capabilities* do binário
  (`setcap`). Por isso a unit mantém `NoNewPrivileges=no`: com `yes`, o kernel ignora file capabilities no
  `execve` e a captura falharia. O isolamento restante (`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  filtro de syscalls, `RestrictAddressFamilies`, `MemoryDenyWriteExecute` etc.) continua aplicado; o exposure
  level do `systemd-analyze security` da unit é 2.3 (OK).
- Se você preferir `NoNewPrivileges=yes`, remova o `setcap` do sensor e conceda as capabilities ao Core com
  `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` — o que dá essas capabilities ao Core e a todos os módulos.
- Ao atualizar o binário do sensor, reaplique o `setcap` (o `install.sh` faz isso).

## Atualizar, desinstalar, backup

- **Atualizar:** repita o passo 2 com os novos tarballs e rode `sudo systemctl daemon-reload && sudo systemctl restart psychoscope`
  (o `daemon-reload` é necessário porque a atualização pode trocar a unit). A configuração e o banco de alertas são preservados.
- **Backup:** copie `/etc/psychoscope/` e `/var/lib/psychoscope/alerts.db` (SQLite em modo WAL; use
  `sqlite3 alerts.db ".backup alerts.bak"` com o serviço rodando).
- **Desinstalar:** pare e desabilite o serviço, remova a unit e os binários e recarregue o systemd:

  ```bash
  sudo systemctl disable --now psychoscope
  sudo rm /etc/systemd/system/psychoscope.service
  sudo rm /usr/local/bin/psychoscope /usr/local/bin/psychoscope-cli /usr/local/bin/mod-net-sensor
  sudo systemctl daemon-reload
  ```

  Isso mantém a configuração e o histórico de alertas. Para apagar também esses dados e o usuário de sistema
  (irreversível; faça o backup antes se quiser guardar os alertas):

  ```bash
  sudo rm -r /etc/psychoscope /var/lib/psychoscope
  sudo userdel psychoscope
  ```

## Solução de problemas

| Sintoma | Causa provável |
|---|---|
| `nao foi possivel iniciar a captura ... Operation not permitted` no log do sensor | `setcap` ausente, ou `NoNewPrivileges=yes` na unit |
| `error while loading shared libraries: libpcap.so.0.8` | instale `libpcap0.8` |
| `armazenamento de alertas em ...: ... (defina storage.enabled=false ...)` | o usuário `psychoscope` não consegue escrever em `storage.path`; use o padrão (`StateDirectory`) ou ajuste permissões |
| `psychoscope-cli`: `permission denied` ou conexão encerrada sem resposta | UID não permitido: use `sudo` ou `allowed_uids` (e o grupo `psychoscope`) |
| módulo em `REINICIANDO` com erro `nao conectou ao socket` | caminho/permissões do binário do módulo, ou `connect_timeout` curto demais |

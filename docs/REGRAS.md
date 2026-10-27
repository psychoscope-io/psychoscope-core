# Referência das regras de detecção

Uma seção por regra: o que ela detecta, por que importa, o que olhar quando dispara, o que costuma ser falso positivo e como ajustar. Os valores padrão são os de `rules.Default()`; todos se alteram sem reiniciar o serviço (veja [Ajustar uma regra](#ajustar-uma-regra)).

Sobre os falsos positivos: cada seção separa o que **já foi visto em máquina real** do que é **esperado pela natureza da heurística** e ainda não foi confirmado. Só o `net.beacon` tem ocorrência observada até agora. As demais listas são hipóteses fundamentadas e serão confirmadas ou corrigidas pelo catálogo de falsos positivos do roadmap (Marco 1).

## Como ler um alerta

- **Severidade:** BAIXA (vale registrar), MÉDIA (vale olhar), ALTA (olhe agora).
- **Cooldown:** depois de disparar, a regra fica calada para a mesma chave (por exemplo, o mesmo cliente) durante o "Intervalo entre alertas". Isso evita repetir o mesmo alerta, mas significa que a **contagem de alertas não é a contagem de eventos**.
- **Contexto:** `psychoscope-cli alerts -v` (ou `Enter` no alerta, na TUI) mostra as chaves que explicam o disparo. Cada seção abaixo lista as suas.
- **Tempo:** todas as janelas são medidas no instante dos eventos de rede, não no relógio da máquina.

## Ajustar uma regra

| Quero... | Como |
|---|---|
| Ignorar o que causou este alerta | `i` na tela de detalhe (só para regras com lista de exceção: `net.beacon`, `net.bruteforce.auth` e `net.dns.tunnel`); `u` desfaz |
| Mudar um limiar | `:config` na TUI, ou `psychoscope-cli config set detection.<seção>.<campo>=<valor>` (como root) |
| Voltar ao valor anterior | `d` na tela de configurações, ou `psychoscope-cli config reset detection.<seção>.<campo>` |
| Desligar uma regra | `psychoscope-cli config set detection.disabled=net.dns.rate` (lista de nomes de regra) |
| Ver o que vale hoje | `psychoscope-cli config -v detection.<seção>` |

Os ajustes ficam em `overrides.json`, por cima do arquivo do administrador. Detalhes e limites em [Configuração em tempo de execução](../README.md#configuração-em-tempo-de-execução). Ao ajustar, os cooldowns e o estado interno das regras recomeçam.

---

## `net.scan.syn`: varredura de portas

**Severidade:** MÉDIA (vertical), ALTA (horizontal). **Seção:** `detection.scan`.

**O que detecta.** Uma origem que envia pacotes SYN puros (início de conexão TCP, sem ACK) para muitas portas de um destino (**vertical**) ou para a mesma porta em muitos destinos (**horizontal**), dentro da janela.

**Por que importa.** Varredura é o reconhecimento que antecede quase todo ataque: o atacante descobre quais serviços existem antes de escolher o alvo. A horizontal, que procura uma porta específica pela rede, costuma indicar worm ou busca por um serviço vulnerável, por isso a severidade maior.

**Padrões.** Janela 10 s; ≥15 portas distintas num destino (vertical); ≥20 destinos distintos na mesma porta (horizontal); cooldown 1 min; examina até 5000 eventos da origem por avaliação.

**Contexto do alerta.** `tipo` (vertical/horizontal), `origem`, `destino` (vertical) ou `porta` (horizontal), `portas_distintas` ou `hosts_distintos`, `janela`, `portas_exemplo`.

**O que investigar.** Quem é a origem? Se for interna, é uma máquina sua ou desconhecida? Se for a própria máquina, qual programa está abrindo conexões (`ss -tpn`)? Se for externa, os destinos são serviços expostos?

**Falsos positivos esperados (ainda não observados).**
- Scanners de vulnerabilidade e de inventário que você mesmo roda (nmap, Nessus, OpenVAS).
- Ferramentas de descoberta de rede e ferramentas de monitoramento que testam muitas portas.
- Clientes P2P ou aplicativos que abrem conexões a muitos pares na mesma porta.

**Como ajustar.** Esta regra não tem lista de exceções. Suba `vertical_ports` ou `horizontal_hosts` se a rede tiver tráfego legítimo assim, ou desligue a regra. Para um scanner próprio, o caminho é combinar limiar mais alto com a janela menor.

---

## `net.bruteforce.auth`: força bruta de autenticação

**Severidade:** ALTA. **Seção:** `detection.bruteforce`.

**O que detecta.** Uma origem que abre muitas conexões (portas de origem distintas) para o mesmo destino e porta de um serviço de autenticação, dentro da janela. Conta só SYN puro.

**Por que importa.** É o padrão de tentativa de adivinhar senha em SSH, RDP, SMB, FTP, Telnet e VNC, e o ataque mais comum contra qualquer máquina exposta.

**Padrões.** Janela 30 s; ≥10 conexões; portas 21, 22, 23, 445, 3389 e 5900; cooldown 5 min.

**Contexto do alerta.** `origem`, `destino`, `porta`, `conexoes`, `janela`.

**O que investigar.** A origem é externa e o serviço está exposto? Veja o log do serviço (`journalctl -u ssh`) para tentativas falhas. Se o serviço aceita senha, considere chave pública.

**Falsos positivos esperados (ainda não observados).**
- Automação legítima que abre muitas sessões SSH seguidas (backups, orquestração, integração contínua, transferências com várias conexões).
- Ferramentas de monitoramento que testam a porta com frequência.

**Como ajustar.** `ignore_sources` aceita IPs e CIDRs de origem isentos, e a tecla `i` do alerta já sugere a origem. Também dá para subir `min_attempts` ou editar `ports`.

---

## `net.icmp.sweep`: varredura ICMP

**Severidade:** MÉDIA. **Seção:** `detection.icmp_sweep`.

**O que detecta.** Uma origem que envia ping (echo request, ICMPv4 tipo 8 ou ICMPv6 tipo 128) a muitos destinos distintos na janela.

**Por que importa.** Ping em massa é a forma mais barata de descobrir quais máquinas estão ligadas numa rede.

**Padrões.** Janela 10 s; ≥20 destinos distintos; cooldown 1 min.

**Contexto do alerta.** `origem`, `hosts_distintos`, `janela`.

**O que investigar.** A origem é uma ferramenta sua de monitoramento? Se não for, trate como o reconhecimento de uma varredura de portas.

**Falsos positivos esperados (ainda não observados).**
- Ferramentas de monitoramento e inventário de rede (fping, Nagios, Zabbix) que fazem ping periódico a muitos hosts.

**Como ajustar.** Sem lista de exceções. Suba `min_hosts` ou desligue a regra se a máquina fizer esse trabalho de propósito.

---

## `net.dns.nxdomain_burst`: rajada de NXDOMAIN

**Severidade:** MÉDIA. **Seção:** `detection.nxdomain`.

**O que detecta.** Um cliente que recebe muitas respostas "o domínio não existe" (NXDOMAIN) para domínios distintos em pouco tempo.

**Por que importa.** Malware com algoritmo de geração de domínios (DGA) testa centenas de nomes gerados até achar o que o atacante registrou como servidor de comando e controle. A maioria não existe e responde NXDOMAIN.

**Padrões.** Janela 30 s; ≥10 respostas e ≥8 domínios distintos; cooldown 2 min; sufixos ignorados `in-addr.arpa` e `ip6.arpa`.

**Contexto do alerta.** `cliente`, `resolvedor`, `respostas_nxdomain`, `dominios_distintos`, `janela`, `dominios_exemplo`.

**O que investigar.** Os domínios de exemplo parecem aleatórios (`x7f3kq9a.com`) ou são nomes legíveis? Qual programa os consulta?

**Falsos positivos.**
- *Tratado por padrão:* consultas de DNS reverso (`in-addr.arpa`, `ip6.arpa`), que dão NXDOMAIN o tempo todo em redes privadas.
- *Esperados (ainda não observados):* nomes de busca (search domains) mal configurados, que tentam vários sufixos; navegadores e clientes de e-mail sondando nomes inexistentes; ferramentas de rede de descoberta (mDNS, WPAD).

**Como ajustar.** `ignore_suffixes` ignora um domínio e seus subdomínios; sem tecla `i` para esta regra, edite pela tela de configurações. Também dá para subir `min_responses` e `min_distinct`.

---

## `net.dns.tunnel`: túnel DNS

**Severidade:** ALTA. **Seção:** `detection.tunnel`.

**O que detecta.** Um cliente que faz várias consultas distintas ao mesmo domínio base com subdomínios longos e de alta entropia (aparência de dados codificados).

**Por que importa.** O DNS atravessa quase todo firewall, então serve para esconder comunicação de controle ou tirar dados da máquina, codificados dentro dos nomes consultados.

**Padrões.** Janela 60 s; ≥5 consultas distintas; rótulo de ≥30 caracteres com entropia de Shannon ≥3,2 bits por caractere; cooldown 2 min. Domínios `.arpa` e `.local` não contam.

**Contexto do alerta.** `cliente`, `dominio_base`, `consultas_distintas`, `janela`, `consulta_exemplo`.

**O que investigar.** O domínio base é conhecido? Os subdomínios parecem dados em base32/base64? Qual processo consulta?

**Falsos positivos esperados (ainda não observados).**
- CDNs, serviços de nuvem, antivírus e telemetria que usam subdomínios longos e aleatórios por design.
- Verificação de reputação por DNS (listas de bloqueio, DNSBL).

**Como ajustar.** `allowed_bases` isenta um domínio base, e a tecla `i` do alerta já sugere o `dominio_base`. Também dá para subir `min_label_len`, `min_entropy` ou `min_queries`.

---

## `net.dns.rate`: pico de consultas DNS

**Severidade:** MÉDIA. **Seção:** `detection.dns_rate`.

**O que detecta.** Um cliente que faz um número muito alto de consultas DNS na janela.

**Por que importa.** Um volume anormal de consultas pode ser malware sondando nomes, exfiltração por DNS ou uma falha que consulta em laço, que também vale corrigir.

**Padrões.** Janela 10 s; ≥200 consultas; cooldown 2 min.

**Contexto do alerta.** `cliente`, `consultas`, `dominios_distintos`, `janela`.

**O que investigar.** Muitas consultas ao mesmo domínio (laço de aplicação) ou a muitos domínios distintos (varredura)?

**Falsos positivos esperados (ainda não observados).**
- Máquina que funciona como resolvedor local ou encaminhador para outras (o "cliente" é a rede toda).
- Aplicativos que resolvem centenas de nomes de uma vez (navegador carregando uma página pesada, atualização de pacotes, pré-busca de links).

**Como ajustar.** Sem lista de exceções. Suba `min_queries` ou a janela, ou desligue a regra se a máquina for um resolvedor.

---

## `net.tls.suspicious`: TLS suspeito

**Severidade:** MÉDIA ou BAIXA, conforme o motivo. **Seção:** `detection.tls`.

**O que detecta.** Características suspeitas no início de uma conexão TLS (ClientHello), em ordem de prioridade:

| Motivo | Severidade | Critério |
|---|---|---|
| SNI igual a um IP | MÉDIA | o nome do servidor é um endereço IP |
| SNI aleatório | MÉDIA | algum rótulo do SNI (exceto o TLD, e sem hífen) tem ≥20 caracteres e entropia ≥3,6 |
| Versão obsoleta | BAIXA | o cliente oferece no máximo SSL3, TLS 1.0 ou TLS 1.1 |
| Sem SNI | BAIXA | ≥3 ClientHellos sem SNI do mesmo cliente em 60 s |

**Por que importa.** Software legítimo quase sempre informa o nome do servidor e usa versões atuais. Malware costuma conectar direto a um IP, usar nomes gerados ou bibliotecas antigas.

**Padrões.** Cooldown 10 min por cliente e motivo; demais valores como na tabela acima.

**Contexto do alerta.** `motivo`, `cliente`, `destino`, `sni`, `versao_tls`; para "sem SNI", também `ocorrencias` e `janela`.

**O que investigar.** Qual programa abriu a conexão? O destino é conhecido?

**Falsos positivos esperados (ainda não observados).**
- Aplicativos internos ou de IoT que conectam por IP.
- Dispositivos e softwares antigos que só falam TLS 1.0/1.1.
- Clientes de linha de comando, bibliotecas e alguns jogos que não enviam SNI.
- Serviços com identificadores longos e gerados no nome (`id` de sessão no subdomínio).

**Como ajustar.** `allowed_bases` isenta um domínio base **só da checagem de entropia**; os demais motivos não têm exceção. Dá para subir `missing_sni_min`, `min_label_len` ou `min_entropy`.

---

## `net.beacon`: conexões periódicas

**Severidade:** MÉDIA. **Seção:** `detection.beacon`.

**O que detecta.** Um cliente que contata o mesmo destino:porta (por SYN) ou consulta o mesmo domínio (por DNS) em intervalos regulares. A regra acompanha a série de contatos e alerta quando há contatos suficientes, o intervalo médio está na faixa e a variação é baixa.

**Por que importa.** Programas maliciosos instalados "ligam para casa" em intervalos fixos para receber ordens. A regularidade é o traço que os distingue de tráfego humano, que é irregular.

**Padrões.** ≥8 contatos regulares; intervalo médio de 5 s a 1 h; variação (desvio dividido pela média) ≤0,2; cooldown 30 min; acompanha até 50.000 séries. Contatos mais próximos que o intervalo mínimo (5 s) contam como um só. Um silêncio maior que três vezes o intervalo médio reinicia a série.

**Contexto do alerta.** `tipo` (tcp/dns), `origem`, `alvo`, `chave`, `intervalo_medio`, `amostras`, `variacao_pct`.

**O que investigar.** Qual programa contata o alvo? Identifique pelo destino (`ss -tpn`, `lsof -i`) e pelo intervalo: um valor redondo (60 s, 5 min) é típico de software, tanto legítimo quanto malicioso.

**Falsos positivos.**
- *Observado em máquina real:* aplicativos de mensagens e outros que mantêm conexão viva com *keepalive* (por exemplo, destinos que parecem de mensageiros, com cerca de 91 s e 0 % de variação).
- *Esperados (ainda não observados):* verificação de atualização periódica, sincronização de relógio, agentes de monitoramento, clientes de e-mail e de sincronização em nuvem.

**Como ajustar.** É a regra com mais opções: `ignore_destinations` (IPs ou CIDRs de destino TCP), `ignore_domains` (nome exato ou sufixo), `ignore_ports`. A tecla `i` do alerta sugere o destino ou o domínio. Para tornar a regra mais exigente: subir `min_samples` ou baixar `max_cv`.

**Limitação conhecida.** O estado da regra (as séries e os cooldowns) vive na memória do Core. Ao reiniciar ou reconfigurar, ele recomeça e um beacon já visto pode alertar de novo.

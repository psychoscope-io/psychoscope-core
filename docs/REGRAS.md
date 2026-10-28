# Referência das regras de detecção

Uma seção por regra: o que ela detecta, por que importa, o que olhar quando dispara, o que costuma ser falso positivo e como ajustar. Os valores padrão são os de `rules.Default()`; todos se alteram sem reiniciar o serviço (veja [Ajustar uma regra](#ajustar-uma-regra)).

Sobre os falsos positivos: cada seção separa o que **já foi visto em máquina real** do que é **esperado pela natureza da heurística** e ainda não foi confirmado. Só o `net.beacon` tem ocorrência observada até agora. As demais listas são hipóteses fundamentadas e serão confirmadas ou corrigidas pelo catálogo de falsos positivos do roadmap (Marco 1). Quando um falso positivo não tem como ser separado do ataque pelo sinal que a regra usa, a decisão registrada é manter o padrão e documentar a exceção, não afrouxar o limiar.

## Como ler um alerta

- **Severidade:** BAIXA (vale registrar), MÉDIA (vale olhar), ALTA (olhe agora).
- **Cooldown:** depois de disparar, a regra fica calada para a mesma chave (por exemplo, o mesmo cliente) durante o "Intervalo entre alertas". Isso evita repetir o mesmo alerta, mas significa que a **contagem de alertas não é a contagem de eventos**.
- **Técnica ATT&CK:** cada regra indica, quando existe, a técnica do [MITRE ATT&CK](https://attack.mitre.org) compatível com o que detectou (`alerts -v`, o detalhe da TUI e o `analyze --json` mostram `ID nome`). É para enquadrar o que foi visto, não um diagnóstico: o alerta é um indício, e as regras (ou variantes) sem técnica equivalente dizem isso na própria seção. Os IDs e nomes foram conferidos em attack.mitre.org contra o ATT&CK Enterprise v20, em 2026-10-28; ao revisar a tabela (`rules/techniques.go`), confira de novo e atualize `attackVersion`.
- **Contexto:** `psychoscope-cli alerts -v` (ou `Enter` no alerta, na TUI) mostra as chaves que explicam o disparo. Cada seção abaixo lista as suas.
- **Tempo:** todas as janelas são medidas no instante dos eventos de rede, não no relógio da máquina.

## Ajustar uma regra

| Quero... | Como |
|---|---|
| Ignorar o que causou este alerta | `i` na tela de detalhe (só para regras com lista de exceção: `net.beacon`, `net.bruteforce.auth`, `net.dns.tunnel` e `net.tls.suspicious` por entropia do SNI); `u` desfaz |
| Mudar um limiar | `:config` na TUI, ou `psychoscope-cli config set detection.<seção>.<campo>=<valor>` (como root) |
| Voltar ao valor anterior | `d` na tela de configurações, ou `psychoscope-cli config reset detection.<seção>.<campo>` |
| Desligar uma regra | `psychoscope-cli config set detection.disabled=net.dns.rate` (lista de nomes de regra) |
| Ver o que vale hoje | `psychoscope-cli config -v detection.<seção>` |

Os ajustes ficam em `overrides.json`, por cima do arquivo do administrador. Detalhes e limites em [Configuração em tempo de execução](../README.md#configuração-em-tempo-de-execução). Ao mudar um limiar ou uma janela de uma regra, só os cooldowns e o estado interno **dela** recomeçam (para o alerta voltar a aparecer na hora); os das outras regras continuam. Mudar só o `cooldown`, um teto ou uma lista de exceção (o que a tecla `i` faz) não zera nada.

---

## `net.scan.syn`: varredura de portas

**Severidade:** MÉDIA (vertical), ALTA (horizontal). **Seção:** `detection.scan`.

**O que detecta.** Uma origem que envia pacotes SYN puros (início de conexão TCP, sem ACK) para muitas portas de um destino (**vertical**) ou para a mesma porta em muitos destinos (**horizontal**), dentro da janela.

**Por que importa.** Varredura é o reconhecimento que antecede quase todo ataque: o atacante descobre quais serviços existem antes de escolher o alvo. A horizontal, que procura uma porta específica pela rede, costuma indicar worm ou busca por um serviço vulnerável, por isso a severidade maior.

**Padrões.** Janela 10 s; ≥15 portas distintas num destino (vertical); ≥20 destinos distintos **sem resposta** na mesma porta (horizontal); cooldown 1 min; examina até 5000 eventos da origem por avaliação. Na horizontal, um destino que respondeu SYN-ACK à sonda não conta (um navegador completa o handshake de dezenas de hosts ao carregar uma página; uma varredura mira hosts que não respondem ou respondem RST), e uma sonda só vale depois de 1 s, tempo de a resposta chegar (por isso uma varredura que termina menos de 1 s depois da última sonda só aparece quando a mesma origem mandar outro SYN dentro da janela). Se o sensor só enxerga um sentido do tráfego (captura assimétrica), nada responde e a regra conta tudo, como antes. Consequência: varrer só hosts que respondem tudo (um rastreamento de servidores web ativos) não é visto como varredura horizontal.

**Técnica MITRE ATT&CK.** [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/): Varredura de portas é descoberta de serviços de rede. É uma técnica *compatível* com o indício, não confirmada.

**Contexto do alerta.** `tipo` (vertical/horizontal), `origem`, `destino` (vertical) ou `porta` (horizontal), `portas_distintas` (vertical) ou `hosts_distintos` e `sem_resposta` (horizontal: hosts sondados e quantos não responderam), `janela`, `portas_exemplo`.

**O que investigar.** Quem é a origem? Se for interna, é uma máquina sua ou desconhecida? Se for a própria máquina, qual programa está abrindo conexões (`ss -tpn`)? Se for externa, os destinos são serviços expostos?

**Falsos positivos.**
- *Observado em máquina real (corrigido):* um navegador carregando páginas pesadas abria conexões a 20 ou mais hosts na porta 443 em 10 s e gerava 58 alertas ALTA numa semana. Agora o critério de resposta (acima) os exclui; o caso `scan-web-navegador` do catálogo prova isso, e o `scan-horizontal-443` prova que uma varredura real da 443 continua alertando.
- *Verdadeiro positivo observado:* um nmap rodado de propósito (13 alertas verticais, até ~5 mil portas) foi detectado; é o caso `scan-nmap-vertical`.
- *Esperados (ainda não observados):* scanners de vulnerabilidade e de inventário que você mesmo roda (nmap, Nessus, OpenVAS), ferramentas de descoberta de rede e de monitoramento que testam muitas portas, e clientes P2P que abrem conexões a muitos pares na mesma porta.

**Como ajustar.** Esta regra não tem lista de exceções. Suba `vertical_ports` ou `horizontal_hosts` se a rede tiver tráfego legítimo assim, ou desligue a regra. Para um scanner próprio, o caminho é combinar limiar mais alto com a janela menor.

---

## `net.bruteforce.auth`: força bruta de autenticação

**Severidade:** ALTA. **Seção:** `detection.bruteforce`.

**O que detecta.** Uma origem que abre muitas conexões (portas de origem distintas) para o mesmo destino e porta de um serviço de autenticação, dentro da janela. Conta só SYN puro.

**Por que importa.** É o padrão de tentativa de adivinhar senha em SSH, RDP, SMB, FTP, Telnet e VNC, e o ataque mais comum contra qualquer máquina exposta.

**Padrões.** Janela 30 s; ≥10 conexões; portas 21, 22, 23, 445, 3389 e 5900; cooldown 5 min.

**Técnica MITRE ATT&CK.** [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/): Muitas tentativas de conexão a um serviço de autenticação. É uma técnica *compatível* com o indício, não confirmada.

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

**Técnica MITRE ATT&CK.** [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/): Varrer ping em muitos hosts é descoberta de sistemas remotos. É uma técnica *compatível* com o indício, não confirmada.

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

**Padrões.** Janela 30 s; ≥10 respostas e ≥8 domínios distintos; cooldown 2 min; sufixos ignorados `in-addr.arpa` e `ip6.arpa`. Nomes cujo primeiro rótulo começa com `_` (descoberta de serviço, como `_https._tcp.host`) não contam: um DGA gera nomes comuns, mas quem usar esse prefixo para esconder o DGA passaria por esta regra.

**Técnica MITRE ATT&CK.** [T1568.002 Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002/): A rajada de NXDOMAIN é o rastro de um malware testando domínios gerados por algoritmo. É uma técnica *compatível* com o indício, não confirmada.

**Contexto do alerta.** `cliente`, `resolvedor`, `respostas_nxdomain`, `dominios_distintos`, `janela`, `dominios_exemplo`.

**O que investigar.** Os domínios de exemplo parecem aleatórios (`x7f3kq9a.com`) ou são nomes legíveis? Qual programa os consulta?

**Falsos positivos.**
- *Tratado por padrão:* consultas de DNS reverso (`in-addr.arpa`, `ip6.arpa`), que dão NXDOMAIN o tempo todo em redes privadas.
- *Observado em máquina real (corrigido):* consultas SRV `_https._tcp.<host>` do apt e de outros clientes (5 alertas numa semana), que voltam NXDOMAIN. Agora não contam; o caso `nxdomain-srv-apt` do catálogo prova isso, e o `nxdomain-dga-com-srv` prova que um DGA misturado a SRV continua alertando.
- *Esperados (ainda não observados):* nomes de busca (search domains) mal configurados, que tentam vários sufixos; navegadores e clientes de e-mail sondando nomes inexistentes; ferramentas de rede de descoberta (mDNS, WPAD).

**Como ajustar.** `ignore_suffixes` ignora um domínio e seus subdomínios; sem tecla `i` para esta regra, edite pela tela de configurações. Também dá para subir `min_responses` e `min_distinct`.

---

## `net.dns.tunnel`: túnel DNS

**Severidade:** ALTA. **Seção:** `detection.tunnel`.

**O que detecta.** Um cliente que faz várias consultas distintas ao mesmo domínio base com subdomínios longos e de alta entropia (aparência de dados codificados).

**Por que importa.** O DNS atravessa quase todo firewall, então serve para esconder comunicação de controle ou tirar dados da máquina, codificados dentro dos nomes consultados.

**Padrões.** Janela 60 s; ≥5 consultas distintas; rótulo de ≥30 caracteres com entropia de Shannon ≥3,2 bits por caractere; cooldown 2 min. Domínios `.arpa` e `.local` não contam.

**Técnica MITRE ATT&CK.** [T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/): Dados escondidos em consultas DNS usam o DNS como canal de comando e controle. É uma técnica *compatível* com o indício, não confirmada.

**Contexto do alerta.** `cliente`, `dominio_base`, `consultas_distintas`, `janela`, `consulta_exemplo`.

**O que investigar.** O domínio base é conhecido? Os subdomínios parecem dados em base32/base64? Qual processo consulta?

**Falsos positivos.**
- *Observado em máquina real:* 1 alerta numa semana, para um nome de balanceador de carga da nuvem (`...elb.amazonaws.com`) com rótulos longos. Trate com `allowed_bases` (a tecla `i` sugere o `dominio_base`).
- *Esperados (ainda não observados):* CDNs, antivírus e telemetria que usam subdomínios longos e aleatórios por design, e verificação de reputação por DNS (listas de bloqueio, DNSBL).

**Como ajustar.** `allowed_bases` isenta um domínio base, e a tecla `i` do alerta já sugere o `dominio_base`. Também dá para subir `min_label_len`, `min_entropy` ou `min_queries`.

---

## `net.dns.rate`: pico de consultas DNS

**Severidade:** MÉDIA. **Seção:** `detection.dns_rate`.

**O que detecta.** Um cliente que faz um número muito alto de consultas DNS na janela.

**Por que importa.** Um volume anormal de consultas pode ser malware sondando nomes, exfiltração por DNS ou uma falha que consulta em laço, que também vale corrigir.

**Padrões.** Janela 10 s; ≥200 consultas; cooldown 2 min.

**Técnica MITRE ATT&CK.** Sem técnica equivalente: um pico de consultas DNS é volume, não o comportamento de uma técnica específica.

**Contexto do alerta.** `cliente`, `consultas`, `dominios_distintos`, `janela`.

**O que investigar.** Muitas consultas ao mesmo domínio (laço de aplicação) ou a muitos domínios distintos (varredura)?

**Falsos positivos.**
- *Observado em máquina real:* 3 alertas numa semana, de 200 consultas a ~75 domínios distintos em 10 s, compatível com um navegador carregando uma página pesada. Poucos o bastante para manter o padrão; suba `min_queries` se incomodar.
- *Esperados (ainda não observados):* máquina que funciona como resolvedor local ou encaminhador para outras (o "cliente" é a rede toda), atualização de pacotes e pré-busca de links.

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

**Técnica MITRE ATT&CK.** Sem técnica equivalente: SNI com IP literal e versão antiga de TLS são anomalias de configuração, sem técnica que as descreva.

**Contexto do alerta.** `motivo`, `cliente`, `destino`, `sni`, `versao_tls`; para "sem SNI", também `ocorrencias` e `janela`.

**O que investigar.** Qual programa abriu a conexão? O destino é conhecido?

**Falsos positivos.**
- *Observado em máquina real:* SNI de alta entropia em nomes legítimos (8 alertas numa semana): rótulos numerados de armazenamento de nuvem (por exemplo `productionresultssa8.blob.core.windows.net`, com 20 letras e entropia 3,68, perto do limite de 3,6) e identificadores por sessão de serviços antifraude (um rótulo de 59 caracteres sob `online-metrix.net`). A entropia **não separa** isso do ataque, então o limiar não mudou: libere o sufixo com `allowed_bases` (a tecla `i` do alerta sugere o SNI sem o primeiro rótulo). O caso `tls-sni-azure-blob` do catálogo prova o alerta e o ajuste.
- *Esperados (ainda não observados):* aplicativos internos ou de IoT que conectam por IP; dispositivos e softwares antigos que só falam TLS 1.0/1.1; clientes de linha de comando, bibliotecas e alguns jogos que não enviam SNI.

**Como ajustar.** `allowed_bases` isenta um domínio **e seus subdomínios** (comparação por sufixo: `windows.net` libera tudo sob ele, `blob.core.windows.net` só o armazenamento; em plataformas compartilhadas isso cobre outros inquilinos, então prefira o sufixo mais estreito) **só da checagem de entropia**; os demais motivos não têm exceção. Cada entrada precisa ter pelo menos dois rótulos (`net` ou `com` sozinhos são recusados, pois isentariam o TLD inteiro). Dá para subir `missing_sni_min`, `min_label_len` ou `min_entropy`.

---

## `net.beacon`: conexões periódicas

**Severidade:** MÉDIA. **Seção:** `detection.beacon`.

**O que detecta.** Um cliente que contata o mesmo destino:porta (por SYN) ou consulta o mesmo domínio (por DNS) em intervalos regulares. A regra acompanha a série de contatos e alerta quando há contatos suficientes, o intervalo médio está na faixa e a variação é baixa.

**Por que importa.** Programas maliciosos instalados "ligam para casa" em intervalos fixos para receber ordens. A regularidade é o traço que os distingue de tráfego humano, que é irregular.

**Padrões.** ≥8 contatos regulares; intervalo médio de 5 s a 1 h; variação (desvio dividido pela média) ≤0,2; cooldown 30 min; acompanha até 50.000 séries. Contatos mais próximos que o intervalo mínimo (5 s) contam como um só. Um silêncio maior que três vezes o intervalo médio reinicia a série.

**Técnica MITRE ATT&CK.** No beacon por DNS (`tipo=dns`): [T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/), comando e controle sobre DNS. No beacon por SYN (`tipo=tcp`) não há técnica: a regra só vê conexões regulares, sem protocolo de aplicação, e afirmar uma daria precisão que a evidência não tem. É uma técnica *compatível* com o indício, não confirmada.

**Contexto do alerta.** `tipo` (tcp/dns), `origem`, `alvo`, `chave`, `intervalo_medio`, `amostras`, `variacao_pct`.

**O que investigar.** Qual programa contata o alvo? Identifique pelo destino (`ss -tpn`, `lsof -i`) e pelo intervalo: um valor redondo (60 s, 5 min) é típico de software, tanto legítimo quanto malicioso.

**Falsos positivos.**
- *Observado em máquina real:* aplicativos de mensagens e outros que reabrem a conexão em intervalo fixo (por exemplo, destinos que parecem de mensageiros, com cerca de 91 s e 0 % de variação). Numa semana, 285 dos 374 alertas vieram de aplicativos conhecidos (Telegram, Firefox/Mozilla, Cursor, ChatGPT, GitHub, verificações de conectividade), em intervalos de ~14 s a ~30 min. Também apareceram consultas de DNS reverso (`in-addr.arpa`, `ip6.arpa`) periódicas, que não são beacon: ignore-as com `ignore_domains`. **Os limiares padrão não mudam por causa disso**: pelo tempo dos contatos, esse tráfego e um beacon real são indistinguíveis (a regularidade é justamente o sinal), e afrouxar o padrão esconderia o beacon verdadeiro em todas as máquinas. A saída é a exceção por destino, que é local e explícita. O caso está no catálogo (`beacon-keepalive`, no `mod-net-sensor`): com os padrões a regra dispara, e `--set detection.beacon.ignore_destinations=<ip>` no `psychoscope-cli analyze` o silencia; o teste do catálogo garante as duas coisas.
- *Esperados (ainda não observados):* verificação de atualização periódica, sincronização de relógio, agentes de monitoramento, clientes de e-mail e de sincronização em nuvem.

**Como ajustar.** É a regra com mais opções: `ignore_destinations` (IPs ou CIDRs de destino TCP), `ignore_domains` (nome exato ou sufixo), `ignore_ports`. A tecla `i` do alerta sugere o destino ou o domínio. Prefira o nome (`ignore_domains`) ao IP: IPs de nuvem e CDN são compartilhados, e ignorar um deles libera tudo o que estiver ali; use `ignore_destinations` com o IP isolado (/32) só quando não houver nome. Para tornar a regra mais exigente: subir `min_samples` ou baixar `max_cv`.

**Estado entre reinícios.** As séries e os cooldowns do beacon são gravados em `engine-state.json` (veja [Estado do motor](../README.md#estado-do-motor-entre-reinícios)) e restaurados na partida, então reiniciar o Core não faz um beacon já visto alertar de novo nem o faz recomeçar a contagem dos 8 contatos. As séries só são restauradas se o `min_interval` não mudou, e a regra recomeça vazia se um limiar dela foi editado entre duas partidas. O estado guarda no máximo as 30 mil séries mais recentes. Uma queda abrupta perde no máximo os últimos 60 s de estado.

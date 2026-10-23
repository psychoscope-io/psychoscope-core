---
name: adicionar-regra-de-deteccao
description: Criar uma nova regra de detecção no motor do Core (internal/detection/rules). Use ao implementar uma nova detecção de rede ou ajustar limiares de uma existente.
---
# Adicionar uma regra de detecção

1. **Defina o sinal** com o dono: que evento do sensor a regra consome (o sensor só emite DNS, TLS ClientHello, TCP SYN/RST e ICMP por padrão), o limiar, a janela e a severidade. Se faltar dado no evento, é mudança de contrato (skill `evoluir-contrato` no proto).
2. **Código** em `internal/detection/rules/net_<tema>.go`, seguindo `.claude/rules/deteccao.md`. Use `net_scan.go` (regra simples com `Gated`) ou `net_beacon.go` (estado próprio) como modelo.
3. **Configuração:** struct com tags `json` e `doc` em `rules.go` (a tela de configurações e a CLI `config` passam a listar os campos sozinhas, pela reflexão sobre `Sections()`), `Default()`, `Validate()`, `AllNames()`, `Sections()`, `LongestWindow()`, `Build()`. Se um campo novo tiver um tipo que o catálogo não conhece, `internal/settings/catalog.go` (`describeField`) falha com uma mensagem dizendo o que fazer; veja a skill `adicionar-campo-de-configuracao`.
4. **Testes** em `rules_*_test.go` com o helper `run(t, cfg, eventos...)`: positivo, falsos positivos (tráfego regular, retransmissões, abaixo do limiar, fora da janela, clientes distintos), cooldown e rearme. Prove que o teste morde: altere o limiar padrão e veja falhar.
5. Se a regra tem lista de exceções (`ignore_*`, `allowed_*`), ensine `rules.Exception` a sugeri-la (tecla `i` no detalhe do alerta).
6. **Documente** no README (tabela de regras, chaves de configuração, falsos positivos esperados) e em `docs/INSTALL.md` se criar chaves novas.
7. **Integração:** se o tráfego couber no pcap sintético, estenda `../mod-net-sensor/scripts/gen_pcap.py` e o conjunto exato de alertas do `e2e.sh` (ele falha com alerta a mais ou a menos).
8. Rode a skill `verificar-core`.

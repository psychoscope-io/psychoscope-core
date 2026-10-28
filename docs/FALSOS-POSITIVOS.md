# Do falso positivo ao pcap de teste

Um alerta que não devia ter disparado vira um caso de teste em quatro passos. O `psychoscope-cli analyze` reproduz o alerta sem o serviço e diz
se um ajuste o resolve; o pcap fica no repositório para a regra nunca voltar a disparar nele.

1. **Capture só o necessário** (com a permissão de captura, fora do `analyze`), filtrando pelo par de máquinas e pela porta do alerta (`contexto` do `alerts -v`):

   ```bash
   sudo tcpdump -i eth0 -w fp-beacon.pcap 'host 192.0.2.10 and host 198.51.100.7 and port 443'
   ```

   Capture o tempo que a regra precisa para disparar (veja a janela e os mínimos dela em `docs/REGRAS.md`; o `net.beacon`, por exemplo, precisa de várias amostras).

2. **Confirme que o alerta reproduz**, só com a regra em questão:

   ```bash
   psychoscope-cli analyze --rule net.beacon fp-beacon.pcap
   ```

3. **Teste o ajuste** (ou a exceção) que o resolveria, sem editar arquivo:

   ```bash
   psychoscope-cli analyze --rule net.beacon --set detection.beacon.max_cv=0.1 fp-beacon.pcap
   ```

4. **Guarde como regressão.** O comando abaixo sai com 2 se a regra ainda disparar, então serve de teste automático:

   ```bash
   psychoscope-cli analyze --fail-on-alert --rule net.beacon fp-beacon.pcap
   ```

## Corrigir a regra ou documentar a exceção

Nem todo falso positivo se resolve mexendo no padrão. Se o sinal que a regra usa não separa o legítimo do ataque (o `net.beacon` em reconexão periódica é o caso), afrouxar o limiar só esconde o ataque real em todas as máquinas: mantenha o padrão, registre a exceção no `.ajuste` do caso e explique a decisão em `docs/REGRAS.md`. Só quando houver um sinal novo que distinga os dois, corrija a regra e esvazie o `.esperado` no mesmo commit.

## Também guarde o verdadeiro positivo

Antes de afrouxar uma regra ou mudar o critério dela, guarde um pcap do ataque que ela **tem** de continuar pegando (`testdata/verdadeiros-positivos/` do `mod-net-sensor`, com o `.esperado` listando a regra). Foi assim que o critério de resposta do scan horizontal da 443 pôde ser trocado sem perder a varredura real: o caso `scan-horizontal-443` falharia no mesmo teste.

## O que pode entrar num repositório público

Só pcap **sintético ou anonimizado**: sem endereços, nomes (SNI, consultas DNS) nem conteúdo de máquinas reais. Reescreva endereços para as faixas de
documentação (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) e nomes para `example.com`, ou reproduza o padrão com `scripts/gen_pcap.py` do
`mod-net-sensor`. Um pcap de captura real não deve ser commitado.

Os pcaps de falso positivo do projeto ficam em `testdata/falsos-positivos/` do `mod-net-sensor`, e o `scripts/analyze_fp.sh` dele roda este mesmo
`analyze --fail-on-alert` em cada um.

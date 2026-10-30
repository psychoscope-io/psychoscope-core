package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// ScanSYN detecta varreduras de portas por SYN puro (SYN sem ACK):
//   - vertical: uma origem sonda muitas portas distintas de um mesmo destino (MEDIA);
//   - horizontal: uma origem sonda a mesma porta em muitos destinos distintos (ALTA).
//
// Retransmissoes de SYN para o mesmo destino:porta contam uma vez.
//
// Na horizontal, so conta o destino que NAO respondeu SYN-ACK a sonda (um navegador completa os
// handshakes de dezenas de hosts ao carregar uma pagina, uma varredura mira hosts que nao
// respondem ou respondem RST). Uma sonda mais nova que answerGrace ainda pode estar a caminho da
// resposta, entao so entra na conta depois disso (e por isso uma varredura que termina menos de
// answerGrace depois da ultima sonda so e vista quando a origem mandar outro SYN na janela). Sem
// ver o sentido de volta (captura so de um lado) nada responde e a regra se comporta como antes.
type ScanSYN struct{ cfg ScanConfig }

// answerGrace e quanto uma sonda precisa envelhecer, no tempo dos eventos, para ser tida como
// sem resposta: cobre o tempo de ida e volta ate o servidor.
const answerGrace = time.Second

func NewScanSYN(cfg ScanConfig) *ScanSYN { return &ScanSYN{cfg} }

func (r *ScanSYN) Name() string            { return NameScanSYN }
func (r *ScanSYN) Kind() detection.Kind    { return detection.KindNet }
func (r *ScanSYN) Cooldown() time.Duration { return r.cfg.Cooldown }

func (r *ScanSYN) Key(ev *detection.Event) (string, bool) {
	if !ev.IsPureSYN() || ev.Net.IpOrigem == "" {
		return "", false
	}
	return ev.Net.IpOrigem, true
}

// probes resume as sondas SYN de uma origem na janela: portas por destino, destinos por porta e,
// destes, os candidatos a "sem resposta" (sondas com mais de answerGrace, ainda sem conferir
// se houve SYN-ACK).
type probes struct {
	portsByDst  map[string]map[uint32]struct{}
	hostsByPort map[uint32]map[string]struct{}
	agedByPort  map[uint32]map[string]struct{}
}

// endpoint e um destino:porta.
type endpoint struct {
	ip   string
	port uint32
}

// answered devolve os destino:porta que responderam SYN-ACK a origem de ev dentro da janela.
func (r *ScanSYN) answered(ev *detection.Event, w *detection.Window) map[endpoint]struct{} {
	out := map[endpoint]struct{}{}
	cutoff := ev.At.Add(-r.cfg.Window)
	evs := w.ToDst(ev.Net.IpOrigem)
	for i, scanned := len(evs)-1, 0; i >= 0 && scanned < r.cfg.MaxScan; i, scanned = i-1, scanned+1 {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if e.IsTCP() && e.Net.FlagsTcp&detection.FlagSYN != 0 && e.Net.FlagsTcp&detection.FlagACK != 0 {
			out[endpoint{e.Net.IpOrigem, e.Net.PortaOrigem}] = struct{}{}
		}
	}
	return out
}

func (r *ScanSYN) collect(ev *detection.Event, w *detection.Window) probes {
	p := probes{portsByDst: map[string]map[uint32]struct{}{}, hostsByPort: map[uint32]map[string]struct{}{}, agedByPort: map[uint32]map[string]struct{}{}}
	cutoff := ev.At.Add(-r.cfg.Window)
	evs := w.FromSrc(ev.Net.IpOrigem)
	for i, scanned := len(evs)-1, 0; i >= 0 && scanned < r.cfg.MaxScan; i, scanned = i-1, scanned+1 {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if !e.IsPureSYN() {
			continue
		}
		dst, port := e.Net.IpDestino, e.Net.PortaDestino
		if p.portsByDst[dst] == nil {
			p.portsByDst[dst] = map[uint32]struct{}{}
		}
		p.portsByDst[dst][port] = struct{}{}
		if p.hostsByPort[port] == nil {
			p.hostsByPort[port] = map[string]struct{}{}
		}
		p.hostsByPort[port][dst] = struct{}{}
		if ev.At.Sub(e.At) >= answerGrace {
			if p.agedByPort[port] == nil {
				p.agedByPort[port] = map[string]struct{}{}
			}
			p.agedByPort[port][dst] = struct{}{}
		}
	}
	return p
}

// busiestDst devolve o destino com mais portas distintas (empate: menor endereco).
func (p probes) busiestDst() (dst string, ports int) {
	for d, ps := range p.portsByDst {
		if len(ps) > ports || (len(ps) == ports && d < dst) {
			dst, ports = d, len(ps)
		}
	}
	return dst, ports
}

// busiestUnanswered devolve a porta com mais destinos sem resposta entre as que tem candidatos
// suficientes (empate: menor porta). So consulta as respostas (uma varredura da janela) se alguma
// porta tem pelo menos min candidatos: o caso comum, de uma maquina que faz poucas conexoes, sai
// antes.
func (r *ScanSYN) busiestUnanswered(ev *detection.Event, w *detection.Window, p probes, min int) (port uint32, hosts int) {
	var answered map[endpoint]struct{}
	for pt, aged := range p.agedByPort {
		if len(aged) < min {
			continue
		}
		if answered == nil {
			answered = r.answered(ev, w)
		}
		n := 0
		for dst := range aged {
			if _, ok := answered[endpoint{dst, pt}]; !ok {
				n++
			}
		}
		if n > hosts || (n == hosts && pt < port) {
			port, hosts = pt, n
		}
	}
	return port, hosts
}

func (r *ScanSYN) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	// corte barato: sem pelo menos tantos eventos da origem quanto o menor limiar, nenhuma das duas
	// varreduras pode ter ocorrido, e collect aloca tres mapas
	if len(w.FromSrc(ev.Net.IpOrigem)) < min(r.cfg.VerticalPorts, r.cfg.HorizontalHosts) {
		return nil
	}
	p := r.collect(ev, w)
	if dst, n := p.busiestDst(); n >= r.cfg.VerticalPorts {
		return r.verticalAlert(ev, dst, p.portsByDst[dst])
	}
	if port, n := r.busiestUnanswered(ev, w, p, r.cfg.HorizontalHosts); n >= r.cfg.HorizontalHosts {
		return r.horizontalAlert(ev, port, len(p.hostsByPort[port]), n)
	}
	return nil
}

func (r *ScanSYN) verticalAlert(ev *detection.Event, dst string, portSet map[uint32]struct{}) *psychoscopev1.Alerta {
	src := ev.Net.IpOrigem
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	return detection.NewAlert(NameScanSYN, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
		fmt.Sprintf("Varredura vertical de portas: %s sondou %d portas de %s em %s", src, len(ports), dst, r.cfg.Window),
		ev, map[string]string{
			"tipo": "vertical", "origem": src, "destino": dst,
			"portas_distintas": fmt.Sprint(len(ports)), "janela": r.cfg.Window.String(), "portas_exemplo": sample(ports, 10),
		})
}

func (r *ScanSYN) horizontalAlert(ev *detection.Event, port uint32, hosts, unanswered int) *psychoscopev1.Alerta {
	src := ev.Net.IpOrigem
	return detection.NewAlert(NameScanSYN, psychoscopev1.Severidade_SEVERIDADE_ALTA,
		fmt.Sprintf("Varredura horizontal: %s sondou a porta %d em %d hosts (%d sem resposta) em %s", src, port, hosts, unanswered, r.cfg.Window),
		ev, map[string]string{
			"tipo": "horizontal", "origem": src, "porta": fmt.Sprint(port),
			"hosts_distintos": fmt.Sprint(hosts), "sem_resposta": fmt.Sprint(unanswered), "janela": r.cfg.Window.String(),
		})
}

func sample(ports []int, n int) string {
	if len(ports) > n {
		ports = ports[:n]
	}
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = fmt.Sprint(p)
	}
	return strings.Join(s, ",")
}

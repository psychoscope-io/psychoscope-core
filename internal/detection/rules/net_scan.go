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
type ScanSYN struct{ cfg ScanConfig }

func NewScanSYN(cfg ScanConfig) *ScanSYN { return &ScanSYN{cfg} }

func (r *ScanSYN) Name() string            { return NameScanSYN }
func (r *ScanSYN) Cooldown() time.Duration { return r.cfg.Cooldown }

func (r *ScanSYN) Key(ev *detection.Event) (string, bool) {
	if !ev.IsPureSYN() || ev.Net.IpOrigem == "" {
		return "", false
	}
	return ev.Net.IpOrigem, true
}

// probes resume as sondas SYN de uma origem na janela: portas por destino e destinos por porta.
type probes struct {
	portsByDst  map[string]map[uint32]struct{}
	hostsByPort map[uint32]map[string]struct{}
}

func (r *ScanSYN) collect(ev *detection.Event, w *detection.Window) probes {
	p := probes{portsByDst: map[string]map[uint32]struct{}{}, hostsByPort: map[uint32]map[string]struct{}{}}
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

// busiestPort devolve a porta sondada em mais destinos distintos (empate: menor porta).
func (p probes) busiestPort() (port uint32, hosts int) {
	for pt, hs := range p.hostsByPort {
		if len(hs) > hosts || (len(hs) == hosts && pt < port) {
			port, hosts = pt, len(hs)
		}
	}
	return port, hosts
}

func (r *ScanSYN) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	p := r.collect(ev, w)
	if dst, n := p.busiestDst(); n >= r.cfg.VerticalPorts {
		return r.verticalAlert(ev, dst, p.portsByDst[dst])
	}
	if port, n := p.busiestPort(); n >= r.cfg.HorizontalHosts {
		return r.horizontalAlert(ev, port, n)
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

func (r *ScanSYN) horizontalAlert(ev *detection.Event, port uint32, hosts int) *psychoscopev1.Alerta {
	src := ev.Net.IpOrigem
	return detection.NewAlert(NameScanSYN, psychoscopev1.Severidade_SEVERIDADE_ALTA,
		fmt.Sprintf("Varredura horizontal: %s sondou a porta %d em %d hosts em %s", src, port, hosts, r.cfg.Window),
		ev, map[string]string{
			"tipo": "horizontal", "origem": src, "porta": fmt.Sprint(port),
			"hosts_distintos": fmt.Sprint(hosts), "janela": r.cfg.Window.String(),
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

package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
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

func (r *ScanSYN) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	src := ev.Net.IpOrigem
	cutoff := ev.At.Add(-r.cfg.Window)
	evs := w.FromSrc(src)

	portsByDst := map[string]map[uint32]struct{}{}
	hostsByPort := map[uint32]map[string]struct{}{}
	for i, scanned := len(evs)-1, 0; i >= 0 && scanned < r.cfg.MaxScan; i, scanned = i-1, scanned+1 {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if !e.IsPureSYN() {
			continue
		}
		dst, port := e.Net.IpDestino, e.Net.PortaDestino
		if portsByDst[dst] == nil {
			portsByDst[dst] = map[uint32]struct{}{}
		}
		portsByDst[dst][port] = struct{}{}
		if hostsByPort[port] == nil {
			hostsByPort[port] = map[string]struct{}{}
		}
		hostsByPort[port][dst] = struct{}{}
	}

	var bestDst string
	bestPorts := 0
	for dst, ps := range portsByDst {
		if len(ps) > bestPorts || (len(ps) == bestPorts && dst < bestDst) {
			bestDst, bestPorts = dst, len(ps)
		}
	}
	if bestPorts >= r.cfg.VerticalPorts {
		ports := make([]int, 0, bestPorts)
		for p := range portsByDst[bestDst] {
			ports = append(ports, int(p))
		}
		sort.Ints(ports)
		return detection.NewAlert(NameScanSYN, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
			fmt.Sprintf("Varredura vertical de portas: %s sondou %d portas de %s em %s", src, bestPorts, bestDst, r.cfg.Window),
			ev, map[string]string{
				"tipo": "vertical", "origem": src, "destino": bestDst,
				"portas_distintas": fmt.Sprint(bestPorts), "janela": r.cfg.Window.String(), "portas_exemplo": sample(ports, 10),
			})
	}

	var bestPort uint32
	bestHosts := 0
	for port, hs := range hostsByPort {
		if len(hs) > bestHosts || (len(hs) == bestHosts && port < bestPort) {
			bestPort, bestHosts = port, len(hs)
		}
	}
	if bestHosts >= r.cfg.HorizontalHosts {
		return detection.NewAlert(NameScanSYN, psychoscopev1.Severidade_SEVERIDADE_ALTA,
			fmt.Sprintf("Varredura horizontal: %s sondou a porta %d em %d hosts em %s", src, bestPort, bestHosts, r.cfg.Window),
			ev, map[string]string{
				"tipo": "horizontal", "origem": src, "porta": fmt.Sprint(bestPort),
				"hosts_distintos": fmt.Sprint(bestHosts), "janela": r.cfg.Window.String(),
			})
	}
	return nil
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

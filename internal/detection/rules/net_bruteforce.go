package rules

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// BruteForce detecta forca bruta contra servicos de autenticacao: muitas conexoes novas
// (SYN puro) de uma origem ao MESMO destino:porta de autenticacao (SSH, RDP, SMB, VNC,
// Telnet, FTP) em pouco tempo (ALTA). Retransmissoes de SYN (mesma porta de origem) contam
// uma vez; varreduras de muitas portas sao da regra net.scan.syn.
type BruteForce struct {
	cfg    BruteForceConfig
	ports  map[uint32]bool
	ignore []*net.IPNet
}

func NewBruteForce(cfg BruteForceConfig) *BruteForce {
	b := &BruteForce{cfg: cfg, ports: map[uint32]bool{}}
	for _, p := range cfg.Ports {
		b.ports[uint32(p)] = true //nolint:gosec // porta validada em Config.Validate (1-65535)
	}
	b.ignore, _ = parseSources(cfg.IgnoreSources) // validado em Config.Validate
	return b
}

func (r *BruteForce) Name() string            { return NameBruteForce }
func (r *BruteForce) Cooldown() time.Duration { return r.cfg.Cooldown }

func (r *BruteForce) ignored(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range r.ignore {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func (r *BruteForce) Key(ev *detection.Event) (string, bool) {
	if !ev.IsPureSYN() || !r.ports[ev.Net.PortaDestino] || ev.Net.IpOrigem == "" || r.ignored(ev.Net.IpOrigem) {
		return "", false
	}
	return ev.Net.IpOrigem + "|" + ev.Net.IpDestino + ":" + strconv.Itoa(int(ev.Net.PortaDestino)), true
}

func (r *BruteForce) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	src, dst, port := ev.Net.IpOrigem, ev.Net.IpDestino, ev.Net.PortaDestino
	evs := w.FromSrc(src)
	if len(evs) < r.cfg.MinAttempts {
		return nil
	}
	cutoff := ev.At.Add(-r.cfg.Window)
	conns := map[uint32]struct{}{}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if e.IsPureSYN() && e.Net.IpDestino == dst && e.Net.PortaDestino == port {
			conns[e.Net.PortaOrigem] = struct{}{}
		}
	}
	if len(conns) < r.cfg.MinAttempts {
		return nil
	}
	return detection.NewAlert(NameBruteForce, psychoscopev1.Severidade_SEVERIDADE_ALTA,
		fmt.Sprintf("Possivel forca bruta: %s abriu %d conexoes para %s:%d em %s", src, len(conns), dst, port, r.cfg.Window),
		ev, map[string]string{
			"origem": src, "destino": dst, "porta": strconv.Itoa(int(port)),
			"conexoes": fmt.Sprint(len(conns)), "janela": r.cfg.Window.String(),
		})
}

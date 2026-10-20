package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const (
	icmpEchoRequestV4 = 8
	icmpEchoRequestV6 = 128
)

// ICMPSweep detecta varredura de hosts por ping (echo request para muitos destinos
// distintos em pouco tempo) (MEDIA).
type ICMPSweep struct{ cfg ICMPSweepConfig }

func NewICMPSweep(cfg ICMPSweepConfig) *ICMPSweep { return &ICMPSweep{cfg} }

func (r *ICMPSweep) Name() string            { return NameICMPSweep }
func (r *ICMPSweep) Cooldown() time.Duration { return r.cfg.Cooldown }

// isEchoRequest: tipo 8 (ICMPv4) ou 128 (ICMPv6; versao inferida pelo ':' no IP de origem).
func isEchoRequest(ev *detection.Event) bool {
	if ev.Net.GetProtocolo() != psychoscopev1.ProtocoloTransporte_PROTO_ICMP {
		return false
	}
	if strings.Contains(ev.Net.IpOrigem, ":") {
		return ev.Net.IcmpTipo == icmpEchoRequestV6
	}
	return ev.Net.IcmpTipo == icmpEchoRequestV4
}

func (r *ICMPSweep) Key(ev *detection.Event) (string, bool) {
	if !isEchoRequest(ev) || ev.Net.IpOrigem == "" {
		return "", false
	}
	return ev.Net.IpOrigem, true
}

func (r *ICMPSweep) Eval(ev *detection.Event, w *detection.Window) *psychoscopev1.Alerta {
	src := ev.Net.IpOrigem
	evs := w.FromSrc(src)
	if len(evs) < r.cfg.MinHosts {
		return nil
	}
	cutoff := ev.At.Add(-r.cfg.Window)
	hosts := map[string]struct{}{}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		if e.At.Before(cutoff) {
			break
		}
		if isEchoRequest(e) {
			hosts[e.Net.IpDestino] = struct{}{}
		}
	}
	if len(hosts) < r.cfg.MinHosts {
		return nil
	}
	return detection.NewAlert(NameICMPSweep, psychoscopev1.Severidade_SEVERIDADE_MEDIA,
		fmt.Sprintf("Varredura ICMP: %s enviou ping a %d hosts distintos em %s", src, len(hosts), r.cfg.Window),
		ev, map[string]string{"origem": src, "hosts_distintos": fmt.Sprint(len(hosts)), "janela": r.cfg.Window.String()})
}

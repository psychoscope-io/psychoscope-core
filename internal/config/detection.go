package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
)

// Detection configura a janela deslizante, a fila do motor e os limiares das regras.
type Detection struct {
	Window    time.Duration
	MaxEvents int
	QueueSize int
	Rules     rules.Config
}

// fileDetection guarda a secao "detection" bruta: os campos proprios sao tratados em
// loadDetection e cada secao de regra e sobreposta por overlayStruct (estrito).
type fileDetection struct{ raw map[string]json.RawMessage }

func (f *fileDetection) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &f.raw) }

// DefaultDetection devolve a configuracao padrao do motor de deteccao.
func DefaultDetection() Detection {
	return Detection{Window: time.Minute, MaxEvents: 200_000, QueueSize: 4096, Rules: rules.Default()}
}

// loadDetection sobrepoe a secao "detection" do arquivo aos defaults. Chaves desconhecidas
// sao erro; cada secao de regra aceita apenas os campos da sua struct (tags json).
func loadDetection(f fileDetection) (Detection, error) {
	return applyDetection(DefaultDetection(), f)
}

// applyDetection sobrepoe f a base (devolvida por valor; base nao e alterada: as listas sao
// sempre substituidas, nunca editadas no lugar).
func applyDetection(d Detection, f fileDetection) (Detection, error) {
	sections := d.Rules.Sections()
	keys := make([]string, 0, len(f.raw))
	for k := range f.raw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // erros deterministicos
	for _, k := range keys {
		raw := f.raw[k]
		var err error
		switch k {
		case "window":
			var s string
			if err = json.Unmarshal(raw, &s); err == nil {
				d.Window, err = parseDur("detection.window", s, d.Window)
			}
		case "max_events":
			err = json.Unmarshal(raw, &d.MaxEvents)
		case "queue_size":
			err = json.Unmarshal(raw, &d.QueueSize)
		case "disabled":
			d.Rules.Disabled = nil // fatia nova: nao reaproveita o vetor da base
			err = json.Unmarshal(raw, &d.Rules.Disabled)
		default:
			dst, ok := sections[k]
			if !ok {
				return d, fmt.Errorf("detection: campo desconhecido %q", k)
			}
			err = overlayStruct(raw, dst, "detection."+k)
		}
		if err != nil {
			return d, fmt.Errorf("detection.%s: %w", k, err)
		}
	}
	return d, nil
}

func (d Detection) validate() error {
	if d.MaxEvents <= 0 || d.QueueSize <= 0 {
		return errors.New("detection.max_events e detection.queue_size devem ser positivos")
	}
	if err := d.Rules.Validate(); err != nil {
		return err
	}
	if longest := d.Rules.LongestWindow(); d.Window < longest {
		return fmt.Errorf("detection.window (%v) deve cobrir a maior janela de regra (%v)", d.Window, longest)
	}
	return nil
}

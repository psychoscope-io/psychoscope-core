package app

import (
	"context"
	"fmt"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	"github.com/psychoscope-io/psychoscope-core/internal/settings"
)

// openSettings le os ajustes gravados (arquivo no diretorio de estado) e passa a usar a
// configuracao efetiva, que e a do administrador com os ajustes por cima. Sem OverridesPath
// a configuracao em tempo de execucao fica desligada.
func (d *daemon) openSettings() error {
	if d.cfg.OverridesPath == "" {
		return nil
	}
	m, err := settings.New(d.cfg, d.cfg.OverridesPath, liveSettings{d}, d.log.With("componente", "configuracao"))
	if err != nil {
		return err
	}
	d.settings = m
	d.cfg = m.Effective()
	return nil
}

func (d *daemon) overrideCount() int {
	if d.settings == nil {
		return 0
	}
	return d.settings.OverrideCount()
}

// liveSettings aplica uma configuracao efetiva nova nos componentes em execucao: troca as
// regras e a janela do motor (preservando o estado das regras cuja chave de estado nao mudou) e os limites
// de retencao do gravador de alertas.
type liveSettings struct{ d *daemon }

func (l liveSettings) Apply(ctx context.Context, c *config.Config) error {
	ruleSet, err := rules.Build(c.Detection.Rules)
	if err != nil {
		return err
	}
	if err := l.d.engine.Reconfigure(ctx, ruleSet, c.Detection.Window); err != nil {
		return fmt.Errorf("motor de deteccao: %w", err)
	}
	if l.d.persister != nil {
		l.d.persister.SetLimits(c.Storage.Retention(), c.Storage.MaxAlerts)
	}
	return nil
}

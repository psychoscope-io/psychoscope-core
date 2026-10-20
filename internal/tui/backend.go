// Package tui implementa a interface de terminal (Bubbletea + Lipgloss) do Psychoscope:
// painel de modulos com controle (pausar/retomar/encerrar) e feed de alertas ao vivo.
package tui

import (
	"context"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Stream e uma assinatura de alertas.
type Stream interface {
	Alerts() <-chan *psychoscopev1.Alerta
	Err() error
	Close()
}

// Backend e o que a TUI precisa do Core (satisfeito por ClientBackend).
type Backend interface {
	List(ctx context.Context) ([]*psychoscopev1.ModuloInfo, error)
	Command(ctx context.Context, module string, acao psychoscopev1.ComandoControle_TipoAcao) error
	StreamAlerts(ctx context.Context) (Stream, error)
	Metrics(ctx context.Context) ([]*psychoscopev1.Metrica, error)
}

// ClientBackend adapta ctl.Client ao Backend.
type ClientBackend struct{ Client *ctl.Client }

func (b ClientBackend) List(ctx context.Context) ([]*psychoscopev1.ModuloInfo, error) {
	return b.Client.List(ctx)
}

func (b ClientBackend) Command(ctx context.Context, module string, acao psychoscopev1.ComandoControle_TipoAcao) error {
	return b.Client.Command(ctx, module, acao, nil)
}

func (b ClientBackend) Metrics(ctx context.Context) ([]*psychoscopev1.Metrica, error) {
	return b.Client.Metrics(ctx)
}

type clientStream struct{ s *ctl.AlertStream }

func (c clientStream) Alerts() <-chan *psychoscopev1.Alerta { return c.s.C }
func (c clientStream) Err() error                           { return c.s.Err() }
func (c clientStream) Close()                               { c.s.Close() }

// StreamAlerts assina os alertas incluindo o historico recente do Core.
func (b ClientBackend) StreamAlerts(ctx context.Context) (Stream, error) {
	s, err := b.Client.StreamAlerts(ctx, true)
	if err != nil {
		return nil, err
	}
	return clientStream{s}, nil
}

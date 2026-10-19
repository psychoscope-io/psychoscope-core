// Package app monta e executa o daemon do Core: servidor IPC dos modulos,
// supervisor, canal de controle e (futuramente) o motor de deteccao.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/Bandeira27/psychoscope-core/internal/alerts"
	"github.com/Bandeira27/psychoscope-core/internal/config"
	"github.com/Bandeira27/psychoscope-core/internal/ctl"
	"github.com/Bandeira27/psychoscope-core/internal/ipc"
	"github.com/Bandeira27/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

// Version e a versao do Core (sobrescrita via -ldflags "-X .../app.Version=").
var Version = "0.1.0-dev"

// telemetrySink e o ponto de entrada da telemetria. Na Fase 5 encaminha para o
// motor de deteccao (janela deslizante); por ora apenas contabiliza.
type telemetrySink struct {
	ipc.NopHandler
	events atomic.Uint64
	log    *slog.Logger
}

func (t *telemetrySink) OnTelemetry(s *ipc.Session, _ *psychoscopev1.EventoTelemetria) {
	if n := t.events.Add(1); n%1000 == 1 {
		t.log.Debug("telemetria recebida", "modulo", s.ID, "total", n)
	}
}

// Run sobe todos os componentes e bloqueia ate ctx ser cancelado. O encerramento
// e ordenado: primeiro os modulos (que ainda precisam do IPC para receber
// ENCERRAR), depois o canal de controle e por fim o servidor IPC.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	uid := uint32(os.Geteuid())
	policy := ipc.NewUIDPolicy(uid, cfg.AllowedUIDs)
	bus := alerts.NewBus()

	sup := supervisor.New(supervisor.Options{
		Specs: cfg.Modules, SocketPath: cfg.SocketPath, UIDs: policy,
		AllowUnmanaged: cfg.AllowUnmanaged, Logger: log.With("componente", "supervisor"),
	})
	sink := &telemetrySink{log: log}

	srv, err := ipc.NewServer(ipc.ServerConfig{
		Path: cfg.SocketPath, Mode: cfg.SocketMode, CoreVersion: Version,
		StatusInterval: cfg.StatusInterval, CommandTimeout: cfg.CommandTimeout,
		Auth: sup, Handler: ipc.Handlers(sup, sink), Logger: log.With("componente", "ipc"),
	})
	if err != nil {
		return err
	}
	ctlSrv, err := ctl.NewServer(ctl.Config{
		Path: cfg.CtlSocketPath, Mode: cfg.SocketMode, Backend: sup, Alerts: bus,
		UIDs: policy, Logger: log.With("componente", "ctl"),
	})
	if err != nil {
		return err
	}

	if err := srv.Listen(); err != nil {
		return fmt.Errorf("socket dos modulos: %w", err)
	}
	if err := ctlSrv.Listen(); err != nil {
		srv.Shutdown()
		return fmt.Errorf("socket de controle: %w", err)
	}
	if cfg.AllowUnmanaged {
		log.Warn("allow_unmanaged ativo: modulos nao lancados pelo supervisor serao aceitos (apenas checagem de UID)")
	}
	log.Info("psychoscope-core iniciado", "versao", Version, "socket", cfg.SocketPath, "ctl", cfg.CtlSocketPath, "modulos", len(cfg.Modules), "uid", uid)

	netCtx, stopNet := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = srv.Serve(netCtx) }()
	go func() { defer wg.Done(); _ = ctlSrv.Serve(netCtx) }()

	sup.Run(ctx) // retorna apos ctx cancelado e todos os filhos encerrados

	stopNet()
	ctlSrv.Shutdown()
	srv.Shutdown()
	wg.Wait()
	log.Info("psychoscope-core encerrado")
	return nil
}

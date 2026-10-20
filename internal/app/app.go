// Package app monta e executa o daemon do Core: servidor IPC dos modulos,
// supervisor, canal de controle e (futuramente) o motor de deteccao.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/metrics"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// telemetrySink encaminha a telemetria dos modulos ao motor de deteccao. Roda na
// goroutine de leitura da sessao, portanto so enfileira (Submit nunca bloqueia).
type telemetrySink struct {
	ipc.NopHandler
	engine *detection.Engine
	events atomic.Uint64
	log    *slog.Logger
}

func (t *telemetrySink) OnTelemetry(s *ipc.Session, ev *psychoscopev1.EventoTelemetria) {
	if n := t.events.Add(1); n%1000 == 1 {
		t.log.Debug("telemetria recebida", "modulo", s.ID, "total", n)
	}
	if rede := ev.GetRede(); rede != nil {
		t.engine.Submit(s.ID, rede)
	}
}

// Run sobe todos os componentes e bloqueia ate ctx ser cancelado. O encerramento
// e ordenado: primeiro os modulos (que ainda precisam do IPC para receber
// ENCERRAR), depois os servidores, o motor (que esvazia a fila), o gravador de
// alertas (que faz a ultima gravacao) e por fim o banco.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	started := time.Now()
	uid := uint32(os.Geteuid())
	policy := ipc.NewUIDPolicy(uid, cfg.AllowedUIDs)
	bus := alerts.NewBus()

	var (
		st        *store.Store
		persister *store.Persister
	)
	if cfg.Storage.Enabled {
		var err error
		if st, err = store.Open(cfg.Storage.Path); err != nil {
			return fmt.Errorf("armazenamento de alertas em %s: %w (defina storage.enabled=false para desligar a persistencia)", cfg.Storage.Path, err)
		}
		defer st.Close()
		if past, err := st.Recent(ctx, alerts.DefaultHistory); err != nil {
			log.Warn("nao foi possivel recuperar o historico de alertas", "err", err)
		} else {
			bus.Seed(past)
		}
		persister = store.NewPersister(st, bus, store.PersisterConfig{
			Retention: cfg.Storage.Retention(), MaxAlerts: cfg.Storage.MaxAlerts, Logger: log.With("componente", "armazenamento"),
		})
	}

	sup := supervisor.New(supervisor.Options{
		Specs: cfg.Modules, SocketPath: cfg.SocketPath, UIDs: policy,
		AllowUnmanaged: cfg.AllowUnmanaged, Logger: log.With("componente", "supervisor"),
	})
	ruleSet, err := rules.Build(cfg.Detection.Rules)
	if err != nil {
		return err
	}
	engine := detection.NewEngine(detection.EngineConfig{
		Window: cfg.Detection.Window, MaxEvents: cfg.Detection.MaxEvents, QueueSize: cfg.Detection.QueueSize,
		Logger: log.With("componente", "deteccao"),
	}, ruleSet, bus)
	sink := &telemetrySink{engine: engine, log: log}
	gather := func() []*psychoscopev1.Metrica {
		return metrics.Gather(func() []*psychoscopev1.Metrica { return collect(started, engine, st, persister, sup) })
	}

	srv, err := ipc.NewServer(ipc.ServerConfig{
		Path: cfg.SocketPath, Mode: cfg.SocketMode, CoreVersion: version.Version,
		StatusInterval: cfg.StatusInterval, CommandTimeout: cfg.CommandTimeout,
		Auth: sup, Handler: ipc.Handlers(sup, sink), Logger: log.With("componente", "ipc"),
	})
	if err != nil {
		return err
	}
	ctlCfg := ctl.Config{
		Path: cfg.CtlSocketPath, Mode: cfg.SocketMode, Backend: sup, Alerts: bus,
		UIDs: policy, Metrics: gather, Logger: log.With("componente", "ctl"),
	}
	if st != nil {
		ctlCfg.Store = st // so atribui quando ha banco (evita interface nao-nula com ponteiro nulo)
	}
	ctlSrv, err := ctl.NewServer(ctlCfg)
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
	var metricsLn net.Listener
	if cfg.Metrics.Listen != "" {
		if metricsLn, err = metrics.Listen(cfg.Metrics.Listen); err != nil {
			ctlSrv.Shutdown()
			srv.Shutdown()
			return fmt.Errorf("endpoint de metricas: %w", err)
		}
		log.Info("endpoint de metricas ativo", "endereco", metricsLn.Addr().String())
		if !cfg.Metrics.AllowNonLoopback {
			log.Info("metricas acessiveis apenas por loopback")
		} else {
			log.Warn("metricas expostas fora de loopback sem autenticacao")
		}
	}
	if cfg.AllowUnmanaged {
		log.Warn("allow_unmanaged ativo: modulos nao lancados pelo supervisor serao aceitos (apenas checagem de UID)")
	}
	log.Info("psychoscope-core iniciado", "versao", version.Version, "regras", len(ruleSet), "socket", cfg.SocketPath, "ctl", cfg.CtlSocketPath,
		"modulos", len(cfg.Modules), "uid", uid, "persistencia", st != nil)

	netCtx, stopNet := context.WithCancel(context.Background())
	var wgNet, wgEngine, wgPersist sync.WaitGroup
	wgNet.Add(2)
	go func() { defer wgNet.Done(); _ = srv.Serve(netCtx) }()
	go func() { defer wgNet.Done(); _ = ctlSrv.Serve(netCtx) }()
	if metricsLn != nil {
		wgNet.Add(1)
		go func() { defer wgNet.Done(); _ = metrics.Serve(netCtx, metricsLn, metrics.Handler(gather)) }()
	}
	engCtx, stopEngine := context.WithCancel(context.Background())
	wgEngine.Add(1)
	go func() { defer wgEngine.Done(); engine.Run(engCtx) }()
	persistCtx, stopPersist := context.WithCancel(context.Background())
	if persister != nil {
		wgPersist.Add(1)
		go func() { defer wgPersist.Done(); persister.Run(persistCtx) }()
	}

	sup.Run(ctx) // retorna apos ctx cancelado e todos os filhos encerrados

	stopNet()
	ctlSrv.Shutdown()
	srv.Shutdown()
	wgNet.Wait()
	stopEngine() // o motor esvazia a fila antes de parar...
	wgEngine.Wait()
	stopPersist() // ...e so entao o gravador faz a ultima gravacao
	wgPersist.Wait()
	es := engine.Stats()
	log.Info("psychoscope-core encerrado", "eventos_processados", es.Processed, "eventos_descartados", es.Dropped, "alertas", es.Alerts)
	return nil
}

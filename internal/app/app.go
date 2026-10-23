// Package app e o ponto de composicao do daemon do Core: monta o servidor IPC dos
// modulos, o supervisor, o motor de deteccao, o armazenamento de alertas, o canal de
// controle e as metricas, e cuida da partida e do encerramento ordenado.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/metrics"
	"github.com/psychoscope-io/psychoscope-core/internal/settings"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// daemon agrupa os componentes construidos por Run, na ordem em que sao criados.
type daemon struct {
	cfg     *config.Config // efetiva: arquivo do administrador + ajustes
	log     *slog.Logger
	opts    options
	started time.Time

	settings  *settings.Manager // nulo sem OverridesPath
	bus       *alerts.Bus
	store     *store.Store // nulo com a persistencia desligada
	persister *store.Persister
	sup       *supervisor.Supervisor
	engine    *detection.Engine
	rules     int
	srv       *ipc.Server
	ctl       *ctl.Server
	metricsLn net.Listener // nulo com o endpoint de metricas desligado
}

// Run sobe todos os componentes e bloqueia ate ctx ser cancelado. O encerramento
// e ordenado: primeiro os modulos (que ainda precisam do IPC para receber
// ENCERRAR), depois os servidores, o motor (que esvazia a fila), o gravador de
// alertas (que faz a ultima gravacao) e por fim o banco.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return run(ctx, cfg, log, options{})
}

// options ajusta a montagem do daemon; so os testes usam algo alem do padrao.
type options struct {
	// admin decide quem pode alterar a configuracao pelo canal de controle (nil = somente root).
	admin func(uid uint32) bool
}

func run(ctx context.Context, cfg *config.Config, log *slog.Logger, opts options) error {
	d, err := build(ctx, cfg, log, opts)
	if err != nil {
		return err
	}
	defer d.closeStore()
	if err := d.listen(); err != nil {
		return err
	}
	d.logStarted()
	d.serve(ctx)
	return nil
}

// build cria os componentes sem abrir nenhum socket. Se falhar depois de abrir o
// banco, fecha o banco antes de devolver o erro.
func build(ctx context.Context, cfg *config.Config, log *slog.Logger, opts options) (*daemon, error) {
	d := &daemon{cfg: cfg, log: log, opts: opts, started: time.Now(), bus: alerts.NewBus()}
	if err := d.assemble(ctx); err != nil {
		d.closeStore()
		return nil, err
	}
	return d, nil
}

func (d *daemon) assemble(ctx context.Context) error {
	if err := d.openSettings(); err != nil { // antes de tudo: o resto usa a configuracao efetiva
		return err
	}
	if err := d.openStore(ctx); err != nil {
		return err
	}
	policy := ipc.NewUIDPolicy(uint32(os.Geteuid()), d.cfg.AllowedUIDs) //nolint:gosec // UID do kernel nao e negativo
	d.sup = supervisor.New(supervisor.Options{
		Specs: d.cfg.Modules, SocketPath: d.cfg.SocketPath, UIDs: policy,
		AllowUnmanaged: d.cfg.AllowUnmanaged, Logger: d.log.With("componente", "supervisor"),
	})
	if err := d.buildEngine(); err != nil {
		return err
	}
	return d.buildServers(policy)
}

func (d *daemon) closeStore() {
	if d.store != nil {
		_ = d.store.Close()
	}
}

// openStore abre o banco de alertas (se habilitado) e repovoa o historico em memoria.
func (d *daemon) openStore(ctx context.Context) error {
	if !d.cfg.Storage.Enabled {
		return nil
	}
	st, err := store.Open(d.cfg.Storage.Path)
	if err != nil {
		return fmt.Errorf("armazenamento de alertas em %s: %w (defina storage.enabled=false para desligar a persistencia)", d.cfg.Storage.Path, err)
	}
	d.store = st
	if past, err := st.Recent(ctx, alerts.DefaultHistory); err != nil {
		d.log.Warn("nao foi possivel recuperar o historico de alertas", "err", err)
	} else {
		d.bus.Seed(past)
	}
	d.persister = store.NewPersister(st, d.bus, store.PersisterConfig{
		Retention: d.cfg.Storage.Retention(), MaxAlerts: d.cfg.Storage.MaxAlerts, Logger: d.log.With("componente", "armazenamento"),
	})
	return nil
}

func (d *daemon) buildEngine() error {
	ruleSet, err := rules.Build(d.cfg.Detection.Rules)
	if err != nil {
		return err
	}
	d.rules = len(ruleSet)
	d.engine = detection.NewEngine(detection.EngineConfig{
		Window: d.cfg.Detection.Window, MaxEvents: d.cfg.Detection.MaxEvents, QueueSize: d.cfg.Detection.QueueSize,
		Logger: d.log.With("componente", "deteccao"),
	}, ruleSet, d.bus)
	return nil
}

// gather monta o instantaneo de metricas (usado pelo ctl e pelo endpoint HTTP).
func (d *daemon) gather() []*psychoscopev1.Metrica {
	return metrics.Gather(func() []*psychoscopev1.Metrica {
		return collect(d.started, d.engine, d.store, d.persister, d.sup)
	})
}

func (d *daemon) buildServers(policy ipc.UIDPolicy) (err error) {
	cfg := d.cfg
	sink := &telemetrySink{engine: d.engine, log: d.log}
	if d.srv, err = ipc.NewServer(ipc.ServerConfig{
		Path: cfg.SocketPath, Mode: cfg.SocketMode, CoreVersion: version.Version,
		StatusInterval: cfg.StatusInterval, CommandTimeout: cfg.CommandTimeout,
		Auth: d.sup, Handler: ipc.Handlers(d.sup, sink), Logger: d.log.With("componente", "ipc"),
	}); err != nil {
		return err
	}
	ctlCfg := ctl.Config{
		Path: cfg.CtlSocketPath, Mode: cfg.SocketMode, Backend: d.sup, Alerts: d.bus,
		UIDs: policy, Metrics: d.gather, Admin: d.opts.admin, Logger: d.log.With("componente", "ctl"),
	}
	if d.settings != nil {
		ctlCfg.Settings = d.settings // so atribui quando ha gerenciador (evita interface nao-nula com ponteiro nulo)
	}
	if d.store != nil {
		ctlCfg.Store = d.store // so atribui quando ha banco (evita interface nao-nula com ponteiro nulo)
	}
	d.ctl, err = ctl.NewServer(ctlCfg)
	return err
}

// listen abre os sockets (e o endpoint de metricas). Em caso de falha, fecha o que ja abriu.
func (d *daemon) listen() error {
	if err := d.srv.Listen(); err != nil {
		return fmt.Errorf("socket dos modulos: %w", err)
	}
	if err := d.ctl.Listen(); err != nil {
		d.srv.Shutdown()
		return fmt.Errorf("socket de controle: %w", err)
	}
	if d.cfg.Metrics.Listen == "" {
		return nil
	}
	ln, err := metrics.Listen(d.cfg.Metrics.Listen)
	if err != nil {
		d.ctl.Shutdown()
		d.srv.Shutdown()
		return fmt.Errorf("endpoint de metricas: %w", err)
	}
	d.metricsLn = ln
	d.log.Info("endpoint de metricas ativo", "endereco", ln.Addr().String())
	if d.cfg.Metrics.AllowNonLoopback {
		d.log.Warn("metricas expostas fora de loopback sem autenticacao")
	} else {
		d.log.Info("metricas acessiveis apenas por loopback")
	}
	return nil
}

func (d *daemon) logStarted() {
	if d.cfg.AllowUnmanaged {
		d.log.Warn("allow_unmanaged ativo: modulos nao lancados pelo supervisor serao aceitos (apenas checagem de UID)")
	}
	d.log.Info("psychoscope-core iniciado", "versao", version.Version, "regras", d.rules, "socket", d.cfg.SocketPath, "ctl", d.cfg.CtlSocketPath,
		"modulos", len(d.cfg.Modules), "uid", os.Geteuid(), "persistencia", d.store != nil, "ajustes", d.overrideCount())
}

// serve inicia as goroutines, espera ctx terminar e encerra tudo na ordem certa.
func (d *daemon) serve(ctx context.Context) {
	netCtx, stopNet := context.WithCancel(context.Background())
	var wgNet, wgEngine, wgPersist sync.WaitGroup
	wgNet.Add(2)
	go func() { defer wgNet.Done(); _ = d.srv.Serve(netCtx) }()
	go func() { defer wgNet.Done(); _ = d.ctl.Serve(netCtx) }()
	if d.metricsLn != nil {
		wgNet.Add(1)
		go func() { defer wgNet.Done(); _ = metrics.Serve(netCtx, d.metricsLn, metrics.Handler(d.gather)) }()
	}
	engCtx, stopEngine := context.WithCancel(context.Background())
	wgEngine.Add(1)
	go func() { defer wgEngine.Done(); d.engine.Run(engCtx) }()
	persistCtx, stopPersist := context.WithCancel(context.Background())
	if d.persister != nil {
		wgPersist.Add(1)
		go func() { defer wgPersist.Done(); d.persister.Run(persistCtx) }()
	}

	d.sup.Run(ctx) // retorna apos ctx cancelado e todos os filhos encerrados

	stopNet()
	d.ctl.Shutdown()
	d.srv.Shutdown()
	wgNet.Wait()
	stopEngine() // o motor esvazia a fila antes de parar...
	wgEngine.Wait()
	stopPersist() // ...e so entao o gravador faz a ultima gravacao
	wgPersist.Wait()
	es := d.engine.Stats()
	d.log.Info("psychoscope-core encerrado", "eventos_processados", es.Processed, "eventos_descartados", es.Dropped, "alertas", es.Alerts)
}

// Package ctl implementa o canal de controle CLI <-> Core (ctl.sock): mesmo
// framing do IPC dos modulos, mensagens RequisicaoControle/RespostaControle.
package ctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/store"
	"github.com/psychoscope-io/psychoscope-core/internal/supervisor"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AlertSource consulta alertas persistidos (satisfeito por *store.Store).
type AlertSource interface {
	Query(ctx context.Context, f store.Filter) ([]*psychoscopev1.Alerta, uint64, error)
}

// Backend e o que o canal de controle precisa do Core (satisfeito por *supervisor.Supervisor).
type Backend interface {
	List() []supervisor.Info
	Command(ctx context.Context, id string, acao psychoscopev1.ComandoControle_TipoAcao, params map[string]string) error
}

// Config parametriza o servidor de controle.
type Config struct {
	Path           string
	Mode           os.FileMode
	Backend        Backend
	Alerts         *alerts.Bus
	UIDs           ipc.UIDPolicy
	CommandTimeout time.Duration // prazo total de um EnviarComando (ENCERRAR pode levar StopGrace)
	// Store, se presente, atende PedidoListarAlertas com o historico persistido; sem ele,
	// responde com o historico em memoria do Bus.
	Store AlertSource
	// Metrics, se presente, atende PedidoMetricas; sem ele a lista vem vazia.
	Metrics func() []*psychoscopev1.Metrica
	// Settings, se presente, atende PedidoLerConfig e PedidoAplicarConfig; sem ele ambos
	// respondem que a configuracao por este canal esta indisponivel.
	Settings SettingsBackend
	// Admin diz se o UID pode alterar a configuracao (padrao: somente o root). A leitura vale
	// para qualquer UID ja permitido no canal.
	Admin    func(uid uint32) bool
	MaxConns int
	Logger   *slog.Logger
}

// Server atende clientes (CLI/TUI) em ctl.sock.
type Server struct {
	cfg Config
	log *slog.Logger
	ln  *net.UnixListener

	slots chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
	wg      sync.WaitGroup
}

// NewServer valida cfg e cria o servidor.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Path == "" || cfg.Backend == nil || cfg.Alerts == nil {
		return nil, errors.New("ctl: Path, Backend e Alerts sao obrigatorios")
	}
	if cfg.Mode == 0 {
		cfg.Mode = 0o660
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 16
	}
	if cfg.Admin == nil {
		cfg.Admin = func(uid uint32) bool { return uid == 0 }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, log: cfg.Logger, slots: make(chan struct{}, cfg.MaxConns), conns: map[net.Conn]struct{}{}}, nil
}

// Listen abre o socket.
func (s *Server) Listen() error {
	ln, err := ipc.ListenUnix(s.cfg.Path, s.cfg.Mode, s.log)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Serve aceita clientes ate ctx ser cancelado ou Shutdown ser chamado.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // encerramento pedido: nao e falha
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.log.Warn("ctl: conexoes demais; recusada")
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			<-s.slots
			_ = conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			s.handle(conn)
		}()
	}
}

// Shutdown para de aceitar, fecha os clientes e aguarda.
func (s *Server) Shutdown() {
	s.mu.Lock()
	s.closing = true
	if s.ln != nil {
		_ = s.ln.Close()
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

type clientConn struct {
	srv  *Server
	cred ipc.PeerCred // credenciais do kernel (SO_PEERCRED) de quem conectou
	conn net.Conn
	wmu  sync.Mutex
	sub  *alerts.Subscription
	done chan struct{}
}

func (c *clientConn) send(r *psychoscopev1.RespostaControle) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	b, err := marshal(r)
	if err != nil {
		return err
	}
	return ipc.WriteFrame(c.conn, b)
}

func (s *Server) handle(conn *net.UnixConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	cred, err := ipc.PeerCredOf(conn)
	if err != nil {
		s.log.Warn("ctl: credenciais do peer", "err", err)
		return
	}
	if !s.cfg.UIDs.Allows(cred.UID) {
		s.log.Warn("ctl: uid nao permitido", "uid", cred.UID, "pid", cred.PID)
		return
	}

	c := &clientConn{srv: s, cred: cred, conn: conn, done: make(chan struct{})}
	defer func() {
		close(c.done)
		if c.sub != nil {
			c.sub.Close()
		}
	}()

	for {
		b, err := ipc.ReadFrame(conn, 0)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Warn("ctl: leitura", "uid", cred.UID, "pid", cred.PID, "err", err)
			}
			return
		}
		req, err := unmarshalRequest(b)
		if err != nil {
			s.log.Warn("ctl: requisicao invalida", "err", err)
			return
		}
		if err := c.dispatch(req); err != nil {
			s.log.Warn("ctl: resposta", "err", err)
			return
		}
	}
}

func fail(id, msg string) *psychoscopev1.RespostaControle {
	return &psychoscopev1.RespostaControle{IdRequisicaoReferencia: id, Sucesso: false, MensagemErro: msg}
}

func (c *clientConn) dispatch(req *psychoscopev1.RequisicaoControle) error {
	id := req.IdRequisicao
	switch p := req.Pedido.(type) {
	case *psychoscopev1.RequisicaoControle_ListarModulos:
		return c.send(c.listModules(id))
	case *psychoscopev1.RequisicaoControle_EnviarComando:
		return c.send(c.sendCommand(id, p.EnviarComando))
	case *psychoscopev1.RequisicaoControle_AssinarAlertas:
		return c.subscribe(id, p.AssinarAlertas)
	case *psychoscopev1.RequisicaoControle_ListarAlertas:
		return c.send(c.listAlerts(id, p.ListarAlertas))
	case *psychoscopev1.RequisicaoControle_Metricas:
		return c.send(c.metrics(id))
	case *psychoscopev1.RequisicaoControle_LerConfig:
		return c.send(c.readConfig(id))
	case *psychoscopev1.RequisicaoControle_AplicarConfig:
		return c.send(c.applyConfig(id, p.AplicarConfig))
	default:
		return c.send(fail(id, "pedido vazio ou desconhecido"))
	}
}

func (c *clientConn) listModules(id string) *psychoscopev1.RespostaControle {
	lista := &psychoscopev1.ListaModulos{}
	for _, in := range c.srv.cfg.Backend.List() {
		lista.Modulos = append(lista.Modulos, InfoToProto(in))
	}
	return &psychoscopev1.RespostaControle{
		IdRequisicaoReferencia: id, Sucesso: true,
		Resultado: &psychoscopev1.RespostaControle_Modulos{Modulos: lista},
	}
}

func (c *clientConn) sendCommand(id string, e *psychoscopev1.PedidoEnviarComando) *psychoscopev1.RespostaControle {
	if e.IdModulo == "" || e.Acao == psychoscopev1.ComandoControle_ACAO_DESCONHECIDA {
		return fail(id, "id_modulo e acao sao obrigatorios")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.srv.cfg.CommandTimeout)
	defer cancel()
	if err := c.srv.cfg.Backend.Command(ctx, e.IdModulo, e.Acao, e.Parametros); err != nil {
		return fail(id, err.Error())
	}
	return &psychoscopev1.RespostaControle{IdRequisicaoReferencia: id, Sucesso: true}
}

// subscribe confirma a assinatura e passa a encaminhar alertas na mesma conexao.
func (c *clientConn) subscribe(id string, p *psychoscopev1.PedidoAssinarAlertas) error {
	if c.sub != nil {
		return c.send(fail(id, "assinatura de alertas ja ativa nesta conexao"))
	}
	if p.GetIncluirHistorico() {
		c.sub = c.srv.cfg.Alerts.SubscribeWithHistory(256)
	} else {
		c.sub = c.srv.cfg.Alerts.Subscribe(256)
	}
	if err := c.send(&psychoscopev1.RespostaControle{IdRequisicaoReferencia: id, Sucesso: true}); err != nil {
		return err
	}
	go c.forwardAlerts(id, c.sub)
	return nil
}

func (c *clientConn) metrics(id string) *psychoscopev1.RespostaControle {
	lista := &psychoscopev1.ListaMetricas{}
	if c.srv.cfg.Metrics != nil {
		lista.Metricas = c.srv.cfg.Metrics()
	}
	return &psychoscopev1.RespostaControle{
		IdRequisicaoReferencia: id, Sucesso: true,
		Resultado: &psychoscopev1.RespostaControle_Metricas{Metricas: lista},
	}
}

func (c *clientConn) forwardAlerts(id string, sub *alerts.Subscription) {
	for {
		select {
		case a, ok := <-sub.C:
			if !ok {
				return
			}
			if err := c.send(&psychoscopev1.RespostaControle{
				IdRequisicaoReferencia: id, Sucesso: true,
				Resultado: &psychoscopev1.RespostaControle_Alerta{Alerta: a},
			}); err != nil {
				_ = c.conn.Close() // cliente morto/lento: derruba a conexao
				return
			}
		case <-c.done:
			return
		}
	}
}

// InfoToProto converte o retrato do supervisor para a mensagem do canal de controle.
func InfoToProto(in supervisor.Info) *psychoscopev1.ModuloInfo {
	m := &psychoscopev1.ModuloInfo{
		IdModulo: in.ID, Estado: in.State, Pid: uint32(max(in.PID, 0)), //nolint:gosec // PID nao negativo (max com 0)
		Reinicios: in.Restarts, UltimoStatus: in.LastStatus, UltimoErro: in.LastError, VersaoModulo: in.ModuleVersion,
	}
	if !in.LastContact.IsZero() {
		m.UltimoContato = timestamppb.New(in.LastContact)
	}
	if !in.ConnectedSince.IsZero() {
		m.ConectadoDesde = timestamppb.New(in.ConnectedSince)
	}
	return m
}

var errBadRequest = fmt.Errorf("ctl: requisicao malformada")

// listAlerts atende PedidoListarAlertas: do banco quando ha, senao do historico em memoria.
func (c *clientConn) listAlerts(id string, p *psychoscopev1.PedidoListarAlertas) *psychoscopev1.RespostaControle {
	f := store.Filter{
		Limit: int(min(p.Limite, store.MaxLimit)), MinSeverity: p.SeveridadeMinima,
		Rule: p.Regra, Module: p.IdModulo,
	}
	if p.Desde != nil {
		f.Since = p.Desde.AsTime()
	}
	lista := &psychoscopev1.ListaAlertas{}
	if c.srv.cfg.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		as, total, err := c.srv.cfg.Store.Query(ctx, f)
		if err != nil {
			c.srv.log.Error("ctl: consulta de alertas", "err", err)
			return fail(id, "erro ao consultar o armazenamento de alertas")
		}
		lista.Alertas, lista.Total = as, total
	} else {
		recent := c.srv.cfg.Alerts.Recent() // do mais antigo ao mais novo
		limit := f.Limit
		if limit <= 0 {
			limit = store.DefaultLimit
		}
		for i := len(recent) - 1; i >= 0; i-- {
			if !f.Match(recent[i]) {
				continue
			}
			lista.Total++
			if len(lista.Alertas) < limit {
				lista.Alertas = append(lista.Alertas, recent[i])
			}
		}
	}
	return &psychoscopev1.RespostaControle{
		IdRequisicaoReferencia: id, Sucesso: true,
		Resultado: &psychoscopev1.RespostaControle_Alertas{Alertas: lista},
	}
}

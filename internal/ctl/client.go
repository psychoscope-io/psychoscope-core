package ctl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Client fala com o ctl.sock do Core. Chamadas de requisicao/resposta abrem uma
// conexao curta cada (simples e robusta contra reinicios do Core); o stream de
// alertas usa uma conexao propria.
type Client struct {
	Path        string
	DialTimeout time.Duration // padrao 3s
	CallTimeout time.Duration // padrao 35s (ENCERRAR pode levar o StopGrace do modulo)
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	to := c.DialTimeout
	if to == 0 {
		to = 3 * time.Second
	}
	d := net.Dialer{Timeout: to}
	return d.DialContext(ctx, "unix", c.Path)
}

func (c *Client) call(ctx context.Context, req *psychoscopev1.RequisicaoControle) (*psychoscopev1.RespostaControle, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	to := c.CallTimeout
	if to == 0 {
		to = 35 * time.Second
	}
	dl := time.Now().Add(to)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = conn.SetDeadline(dl)
	// Cancelamento do contexto interrompe a E/S pendente.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := WriteRequest(conn, req); err != nil {
		return nil, err
	}
	r, err := ReadResponse(conn)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !r.Sucesso {
		return r, errors.New(r.MensagemErro)
	}
	return r, nil
}

// List devolve o estado de todos os modulos.
func (c *Client) List(ctx context.Context) ([]*psychoscopev1.ModuloInfo, error) {
	r, err := c.call(ctx, &psychoscopev1.RequisicaoControle{IdRequisicao: "list",
		Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}})
	if err != nil {
		return nil, err
	}
	return r.GetModulos().GetModulos(), nil
}

// Command envia uma acao de controle a um modulo.
func (c *Client) Command(ctx context.Context, module string, acao psychoscopev1.ComandoControle_TipoAcao, params map[string]string) error {
	_, err := c.call(ctx, &psychoscopev1.RequisicaoControle{IdRequisicao: "cmd",
		Pedido: &psychoscopev1.RequisicaoControle_EnviarComando{EnviarComando: &psychoscopev1.PedidoEnviarComando{
			IdModulo: module, Acao: acao, Parametros: params}}})
	return err
}

// AlertStream e uma assinatura ativa de alertas.
type AlertStream struct {
	C <-chan *psychoscopev1.Alerta

	conn net.Conn
	once sync.Once
	mu   sync.Mutex
	err  error
}

// Err devolve o motivo do fim do stream (valido depois que C fecha).
func (s *AlertStream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close encerra a assinatura.
func (s *AlertStream) Close() { s.once.Do(func() { _ = s.conn.Close() }) }

// StreamAlerts assina os alertas; history=true reenvia primeiro os alertas recentes.
// O canal fecha quando ctx e cancelado, Close e chamado ou a conexao cai (veja Err).
func (c *Client) StreamAlerts(ctx context.Context, history bool) (*AlertStream, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := WriteRequest(conn, &psychoscopev1.RequisicaoControle{IdRequisicao: "alerts",
		Pedido: &psychoscopev1.RequisicaoControle_AssinarAlertas{AssinarAlertas: &psychoscopev1.PedidoAssinarAlertas{IncluirHistorico: history}}}); err != nil {
		conn.Close()
		return nil, err
	}
	ack, err := ReadResponse(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !ack.Sucesso {
		conn.Close()
		return nil, fmt.Errorf("assinatura recusada: %s", ack.MensagemErro)
	}
	_ = conn.SetDeadline(time.Time{})

	out := make(chan *psychoscopev1.Alerta, 64)
	s := &AlertStream{C: out, conn: conn}
	context.AfterFunc(ctx, s.Close)
	go func() {
		defer close(out)
		for {
			r, err := ReadResponse(conn)
			if err != nil {
				s.mu.Lock()
				s.err = err
				s.mu.Unlock()
				return
			}
			if a := r.GetAlerta(); a != nil {
				select {
				case out <- a:
				default: // consumidor lento: descarta o mais novo em vez de travar a leitura
				}
			}
		}
	}()
	return s, nil
}

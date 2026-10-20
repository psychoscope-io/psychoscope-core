package ipc

import (
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Authorizer decide se um modulo que passou no Hello basico pode ser aceito.
// Um erro rejeita a conexao (a mensagem vai ao modulo, portanto nao deve vazar detalhes internos).
type Authorizer interface {
	Authorize(h *psychoscopev1.HelloModulo, cred PeerCred) error
}

// Handler recebe os eventos das sessoes. Os metodos rodam na goroutine de leitura
// da sessao e NAO devem bloquear.
type Handler interface {
	OnConnect(s *Session)
	OnTelemetry(s *Session, ev *psychoscopev1.EventoTelemetria)
	OnStatus(s *Session, st *psychoscopev1.StatusModulo)
	OnDisconnect(s *Session, err error)
}

// NopHandler ignora todos os eventos.
type NopHandler struct{}

func (NopHandler) OnConnect(*Session)                                    {}
func (NopHandler) OnTelemetry(*Session, *psychoscopev1.EventoTelemetria) {}
func (NopHandler) OnStatus(*Session, *psychoscopev1.StatusModulo)        {}
func (NopHandler) OnDisconnect(*Session, error)                          {}

// Handlers compoe varios Handler; todos recebem cada evento, na ordem dada.
func Handlers(hs ...Handler) Handler { return multiHandler(hs) }

type multiHandler []Handler

func (m multiHandler) OnConnect(s *Session) {
	for _, h := range m {
		h.OnConnect(s)
	}
}
func (m multiHandler) OnTelemetry(s *Session, ev *psychoscopev1.EventoTelemetria) {
	for _, h := range m {
		h.OnTelemetry(s, ev)
	}
}
func (m multiHandler) OnStatus(s *Session, st *psychoscopev1.StatusModulo) {
	for _, h := range m {
		h.OnStatus(s, st)
	}
}
func (m multiHandler) OnDisconnect(s *Session, err error) {
	for _, h := range m {
		h.OnDisconnect(s, err)
	}
}

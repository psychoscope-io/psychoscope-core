package tui

import (
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const (
	refreshEvery   = time.Second
	reconnectAfter = 2 * time.Second
	maxAlerts      = 500
	callTimeout    = 3 * time.Second
	commandTimeout = 35 * time.Second // ENCERRAR pode levar o StopGrace do modulo
	statusTTL      = 5 * time.Second
)

type focus int

const (
	focusModules focus = iota
	focusAlerts
)

// ---- mensagens ----

type (
	tickMsg    time.Time
	modulesMsg struct {
		mods []*psychoscopev1.ModuloInfo
		err  error
	}
	streamOpenedMsg struct {
		s   Stream
		err error
	}
	metricsMsg struct {
		ms  []*psychoscopev1.Metrica
		err error
		at  time.Time
	}
	alertMsg        struct{ a *psychoscopev1.Alerta }
	streamClosedMsg struct{ err error }
	reopenMsg       struct{}
	commandDoneMsg  struct {
		label string
		err   error
	}
	clearStatusMsg struct{ seq int }
	// configMsg traz a configuracao lida; configAppliedMsg, o resultado de :w ou :wq.
	configMsg struct {
		list *psychoscopev1.ListaConfig
		err  error
	}
	// ignoreDoneMsg e o resultado da tecla i (acrescentar uma excecao a uma lista).
	ignoreDoneMsg struct {
		field, value string
		already      bool // o valor ja estava na lista: nada foi gravado
		err          error
	}
	configAppliedMsg struct {
		list       *psychoscopev1.ListaConfig
		err        error
		closeAfter bool
		changes    int // campos enviados (ajustes e restauracoes)
	}
)

// Model e o estado da TUI (tea.Model).

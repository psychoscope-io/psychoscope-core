package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Comandos assincronos do Bubble Tea: cada um fala com o Core fora do laco de
// atualizacao e devolve uma mensagem (messages.go).

func (m *Model) fetchModules() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		mods, err := be.List(ctx)
		return modulesMsg{mods, err}
	}
}

func (m *Model) fetchMetrics() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		ms, err := be.Metrics(ctx)
		return metricsMsg{ms, err, time.Now()}
	}
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(refreshEvery, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) openStream() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		// O contexto so cobre a conexao inicial; o stream vive ate Close.
		s, err := be.StreamAlerts(context.WithoutCancel(ctx))
		return streamOpenedMsg{s, err}
	}
}

func waitAlert(s Stream) tea.Cmd {
	return func() tea.Msg {
		a, ok := <-s.Alerts()
		if !ok {
			return streamClosedMsg{s.Err()}
		}
		return alertMsg{a}
	}
}

func (m *Model) send(module string, acao psychoscopev1.ComandoControle_TipoAcao, label string) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		return commandDoneMsg{label, be.Command(ctx, module, acao)}
	}
}

func (m *Model) fetchConfig() tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		l, err := be.Config(ctx)
		return configMsg{l, err}
	}
}

// applyConfig envia o rascunho ao Core; closeAfter fecha a tela se der certo (:wq).
func (m *Model) applyConfig(patch map[string]string, restore []string, closeAfter bool) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		l, err := be.ApplyConfig(ctx, patch, restore)
		return configAppliedMsg{list: l, err: err, closeAfter: closeAfter, changes: len(patch) + len(restore)}
	}
}

// ignoreCmd acrescenta value a lista field da configuracao: le a configuracao atual (para nao
// perder o que ja esta na lista), recusa em modo somente leitura e nao duplica.
func (m *Model) ignoreCmd(field, value string) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		done := func(err error) tea.Msg { return ignoreDoneMsg{field: field, value: value, err: err} }
		l, err := be.Config(ctx)
		if err != nil {
			return done(err)
		}
		if l.GetSomenteLeitura() {
			return done(errors.New(readOnlyMsg))
		}
		var items []string
		for _, f := range l.GetCampos() {
			if f.Caminho == field {
				if err := json.Unmarshal([]byte(f.ValorAtual), &items); err != nil {
					return done(fmt.Errorf("%s: valor atual inesperado: %w", field, err))
				}
			}
		}
		if slices.Contains(items, value) {
			return ignoreDoneMsg{field: field, value: value, already: true}
		}
		next, err := json.Marshal(append(items, value))
		if err != nil {
			return done(err)
		}
		_, err = be.ApplyConfig(ctx, map[string]string{field: string(next)}, nil)
		return done(err)
	}
}

func (m *Model) setStatus(text string, isErr bool) tea.Cmd {
	m.status, m.statusErr = text, isErr
	m.statusSeq++
	seq := m.statusSeq
	return tea.Tick(statusTTL, func(time.Time) tea.Msg { return clearStatusMsg{seq} })
}

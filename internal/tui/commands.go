package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
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
		return configAppliedMsg{list: l, err: err, closeAfter: closeAfter, patch: patch, restore: restore}
	}
}

// ignoreCmd acrescenta value a lista field da configuracao (ou o remove, com remove): le a
// configuracao atual (para nao perder o que ja esta na lista), recusa em modo somente leitura
// e nao grava quando nada muda.
func (m *Model) ignoreCmd(field, value string, remove bool) tea.Cmd {
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		defer cancel()
		res := ignoreDoneMsg{field: field, value: value, label: field, remove: remove}
		l, err := be.Config(ctx)
		if err != nil {
			res.err = err
			return res
		}
		if f := ctl.FindField(l, field); f != nil && f.Rotulo != "" {
			res.label = f.Rotulo
		}
		if l.GetSomenteLeitura() {
			res.err = errors.New(readOnlyMsg)
			return res
		}
		items, err := listItems(l, field)
		if err != nil {
			res.err = err
			return res
		}
		if slices.Contains(items, value) == !remove { // i com o valor ja presente, u com ele ausente
			res.noop = true
			return res
		}
		if remove {
			items = slices.DeleteFunc(slices.Clone(items), func(s string) bool { return s == value })
		} else {
			items = append(items, value)
		}
		next, err := json.Marshal(items)
		if err != nil {
			res.err = err
			return res
		}
		_, res.err = be.ApplyConfig(ctx, map[string]string{field: string(next)}, nil)
		return res
	}
}

// listItems le a lista de texto field da configuracao (vazia, nunca nil, se nao houver itens).
func listItems(l *psychoscopev1.ListaConfig, field string) ([]string, error) {
	items := []string{}
	if f := ctl.FindField(l, field); f != nil {
		if err := json.Unmarshal([]byte(f.ValorAtual), &items); err != nil {
			return nil, fmt.Errorf("%s: valor atual inesperado: %w", field, err)
		}
	}
	return items, nil
}

// fetchIgnoreInfo le a configuracao para saber se o valor sugerido para o alerta aberto ja
// esta ignorado; sem excecao sugerida, nao consulta nada.
func (m *Model) fetchIgnoreInfo() tea.Cmd {
	if m.detail == nil {
		return nil
	}
	a := m.detail.a
	if _, _, ok := rules.Exception(a); !ok {
		return nil
	}
	be := m.be
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		l, err := be.Config(ctx)
		return ignoreInfoMsg{a: a, list: l, err: err}
	}
}

func (m *Model) setStatus(text string, isErr bool) tea.Cmd {
	m.status, m.statusErr = text, isErr
	m.statusSeq++
	seq := m.statusSeq
	return tea.Tick(statusTTL, func(time.Time) tea.Msg { return clearStatusMsg{seq} })
}

package tui

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"google.golang.org/protobuf/types/known/timestamppb"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

type fakeStream struct {
	ch     chan *psychoscopev1.Alerta
	err    error
	closed bool
}

func (f *fakeStream) Alerts() <-chan *psychoscopev1.Alerta { return f.ch }
func (f *fakeStream) Err() error                           { return f.err }
func (f *fakeStream) Close()                               { f.closed = true }

type fakeBackend struct {
	mu      sync.Mutex
	mods    []*psychoscopev1.ModuloInfo
	listErr error
	cmdErr  error
	cmds    []string
	stream  *fakeStream
	metrics []*psychoscopev1.Metrica
	metErr  error

	cfg      *psychoscopev1.ListaConfig // configuracao devolvida por Config; ApplyConfig a atualiza
	cfgErr   error
	applyErr error
	applies  []applyCall
}

// applyCall registra um ApplyConfig recebido.
type applyCall struct {
	patch   map[string]string
	restore []string
}

func (f *fakeBackend) Config(context.Context) (*psychoscopev1.ListaConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, f.cfgErr
}

// ApplyConfig grava o pedido e reflete o resultado na configuracao: ajuste vira valor atual
// com origem AJUSTE; restaurar volta ao padrao com origem PADRAO.
func (f *fakeBackend) ApplyConfig(_ context.Context, patch map[string]string, restore []string) (*psychoscopev1.ListaConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies = append(f.applies, applyCall{patch, restore})
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	for _, c := range f.cfg.Campos {
		if v, ok := patch[c.Caminho]; ok {
			c.ValorAtual, c.Origem = v, psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE
		}
		if slices.Contains(restore, c.Caminho) {
			c.ValorAtual, c.Origem = c.ValorPadrao, psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO
		}
	}
	return f.cfg, nil
}

func (f *fakeBackend) List(context.Context) ([]*psychoscopev1.ModuloInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mods, f.listErr
}

func (f *fakeBackend) Command(_ context.Context, mod string, a psychoscopev1.ComandoControle_TipoAcao) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, mod+":"+a.String())
	return f.cmdErr
}

func (f *fakeBackend) Metrics(context.Context) ([]*psychoscopev1.Metrica, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metrics, f.metErr
}

func (f *fakeBackend) StreamAlerts(context.Context) (Stream, error) {
	if f.stream == nil {
		return nil, errors.New("sem stream")
	}
	return f.stream, nil
}

func mods() []*psychoscopev1.ModuloInfo {
	return []*psychoscopev1.ModuloInfo{
		{IdModulo: "mod-net-sensor", Estado: psychoscopev1.EstadoModulo_ESTADO_CONECTADO, Pid: 4242, Reinicios: 1,
			UltimoStatus:  &psychoscopev1.StatusModulo{EventosProcessados: 17, PacotesCapturados: 20, PacotesDescartados: 3},
			UltimoContato: timestamppb.Now()},
		{IdModulo: "mod-yara", Estado: psychoscopev1.EstadoModulo_ESTADO_FALHOU, UltimoErro: "exit status 3"},
	}
}

func alert(id, rule string, sev psychoscopev1.Severidade) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{IdAlerta: id, Regra: rule, Severidade: sev, Descricao: "descricao " + id,
		Timestamp: timestamppb.Now(), Contexto: map[string]string{"origem": "10.0.0.66", "chave": "k"}}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// exec executa o tea.Cmd (e os comandos de um Batch) devolvendo as mensagens que nao sao timers.
func exec(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-done:
	case <-time.After(300 * time.Millisecond):
		return nil // timers (tea.Tick) nao devem ser aguardados em testes
	}
	if batch, ok := msg.(tea.BatchMsg); ok {
		var out []tea.Msg
		for _, c := range batch {
			out = append(out, exec(c)...)
		}
		return out
	}
	return []tea.Msg{msg}
}

func feed(m *Model, msgs ...tea.Msg) {
	for _, msg := range msgs {
		m.Update(msg)
	}
}

func plain(m *Model) string { return ansi.Strip(m.View()) }

func TestModulesRenderedFromBackend(t *testing.T) {
	be := &fakeBackend{mods: mods()}
	m := NewModel(be)
	msgs := exec(m.fetchModules())
	feed(m, msgs...)
	v := plain(m)
	for _, want := range []string{"PSYCHOSCOPE", "● conectado", "mod-net-sensor", "CONECTADO", "4242", "17", "20", "mod-yara", "FALHOU", "Alertas (0)", "nenhum alerta"} {
		if !strings.Contains(v, want) {
			t.Errorf("view sem %q:\n%s", want, v)
		}
	}
}

func TestBackendErrorShowsDisconnected(t *testing.T) {
	m := NewModel(&fakeBackend{listErr: errors.New("connection refused")})
	feed(m, exec(m.fetchModules())...)
	v := plain(m)
	if !strings.Contains(v, "sem conexão com o core") || !strings.Contains(v, "connection refused") {
		t.Fatalf("view:\n%s", v)
	}
}

func TestSelectionAndPauseResumeCommands(t *testing.T) {
	be := &fakeBackend{mods: mods()}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)

	feed(m, exec2(m, key("down"))...)
	if m.selected != 1 {
		t.Fatalf("selected=%d", m.selected)
	}
	feed(m, exec2(m, key("down"))...) // clamp
	if m.selected != 1 {
		t.Fatalf("selecao deve parar no ultimo: %d", m.selected)
	}
	feed(m, exec2(m, key("up"))...)

	// p / r enviam o comando ao modulo selecionado e atualizam o status
	for _, tc := range []struct{ k, want string }{{"p", "mod-net-sensor:PAUSAR"}, {"r", "mod-net-sensor:RETOMAR"}} {
		_, cmd := m.Update(key(tc.k))
		msgs := exec(cmd)
		feed(m, msgs...)
		be.mu.Lock()
		got := be.cmds[len(be.cmds)-1]
		be.mu.Unlock()
		if got != tc.want {
			t.Fatalf("%s: comando %q, esperado %q", tc.k, got, tc.want)
		}
		if !strings.Contains(plain(m), ": ok") {
			t.Fatalf("status de sucesso ausente:\n%s", plain(m))
		}
	}
}

// exec2 aplica uma tecla e devolve as mensagens do comando resultante.
func exec2(m *Model, k tea.KeyMsg) []tea.Msg {
	_, cmd := m.Update(k)
	return exec(cmd)
}

func TestCommandErrorIsShown(t *testing.T) {
	be := &fakeBackend{mods: mods(), cmdErr: errors.New("modulo recusou")}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	feed(m, exec2(m, key("p"))...)
	if v := plain(m); !strings.Contains(v, "pausar mod-net-sensor: modulo recusou") {
		t.Fatalf("view:\n%s", v)
	}
}

func TestNoModuleSelectedRejectsCommands(t *testing.T) {
	be := &fakeBackend{}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	m.Update(key("p"))
	if len(be.cmds) != 0 || !strings.Contains(m.status, "nenhum módulo") {
		t.Fatalf("status=%q cmds=%v", m.status, be.cmds)
	}
}

func TestAlertsNewestFirstCappedAndSelectionStable(t *testing.T) {
	m := NewModel(&fakeBackend{})
	st := &fakeStream{ch: make(chan *psychoscopev1.Alerta)}
	feed(m, streamOpenedMsg{s: st})
	feed(m, alertMsg{alert("a1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA)},
		alertMsg{alert("a2", "net.dns.tunnel", psychoscopev1.Severidade_SEVERIDADE_ALTA)})
	if m.alerts[0].IdAlerta != "a2" || m.alerts[1].IdAlerta != "a1" {
		t.Fatalf("ordem: %v", m.alerts)
	}
	v := plain(m)
	if !strings.Contains(v, "Alertas (2)") || !strings.Contains(v, "net.dns.tunnel") || !strings.Contains(v, "ALTA") ||
		strings.Index(v, "descricao a2") > strings.Index(v, "descricao a1") {
		t.Fatalf("view:\n%s", v)
	}

	// foco nos alertas: selecao no a1 permanece nele quando chega alerta novo
	m.Update(key("tab"))
	m.Update(key("down"))
	if m.alerts[m.alertSel].IdAlerta != "a1" {
		t.Fatal("selecao")
	}
	feed(m, alertMsg{alert("a3", "r", psychoscopev1.Severidade_SEVERIDADE_BAIXA)})
	if m.alerts[m.alertSel].IdAlerta != "a1" {
		t.Fatalf("selecao deve acompanhar o alerta a1, esta em %s", m.alerts[m.alertSel].IdAlerta)
	}
	if !strings.Contains(plain(m), "origem=10.0.0.66") {
		t.Fatalf("detalhe do alerta selecionado ausente:\n%s", plain(m))
	}

	for i := 0; i < maxAlerts+50; i++ {
		feed(m, alertMsg{alert(fmt.Sprint("x", i), "r", psychoscopev1.Severidade_SEVERIDADE_CRITICA)})
	}
	if len(m.alerts) != maxAlerts {
		t.Fatalf("limite de alertas: %d", len(m.alerts))
	}
}

func TestStreamLifecycleAndReconnect(t *testing.T) {
	be := &fakeBackend{}
	m := NewModel(be)
	// abertura falha -> agenda nova tentativa
	_, cmd := m.Update(streamOpenedMsg{err: errors.New("x")})
	if cmd == nil || m.streamOK {
		t.Fatal("deveria agendar reconexao")
	}
	if !strings.Contains(plain(m), "alertas: reconectando") {
		t.Fatal("estado de reconexao ausente")
	}
	// abre com sucesso
	st := &fakeStream{ch: make(chan *psychoscopev1.Alerta, 1)}
	_, cmd = m.Update(streamOpenedMsg{s: st})
	if !m.streamOK || cmd == nil || !strings.Contains(plain(m), "alertas: ao vivo") {
		t.Fatal("stream aberto")
	}
	// alerta chega pelo canal via waitAlert
	st.ch <- alert("z", "r", psychoscopev1.Severidade_SEVERIDADE_ALTA)
	msgs := exec(cmd)
	if len(msgs) != 1 {
		t.Fatalf("msgs=%v", msgs)
	}
	feed(m, msgs...)
	if len(m.alerts) != 1 {
		t.Fatal("alerta nao entregue")
	}
	// canal fecha -> streamClosedMsg -> fecha e agenda reabertura
	close(st.ch)
	closed := exec(waitAlert(st))
	if _, ok := closed[0].(streamClosedMsg); !ok {
		t.Fatalf("esperado streamClosedMsg: %T", closed[0])
	}
	_, cmd = m.Update(closed[0])
	if m.streamOK || !st.closed || cmd == nil {
		t.Fatal("deve fechar e agendar reabertura")
	}
}

func TestStatusExpiry(t *testing.T) {
	m := NewModel(&fakeBackend{})
	m.setStatus("a", false)
	seq1 := m.statusSeq
	m.setStatus("b", false)
	m.Update(clearStatusMsg{seq1}) // timer antigo nao apaga o status novo
	if m.status != "b" {
		t.Fatalf("status=%q", m.status)
	}
	m.Update(clearStatusMsg{m.statusSeq})
	if m.status != "" {
		t.Fatal("status deveria expirar")
	}
}

func TestViewFitsEveryTerminalSize(t *testing.T) {
	be := &fakeBackend{mods: mods()}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	feed(m, streamOpenedMsg{s: &fakeStream{ch: make(chan *psychoscopev1.Alerta)}})
	for i := 0; i < 40; i++ {
		feed(m, alertMsg{alert(fmt.Sprint(i), "net.dns.nxdomain_burst", psychoscopev1.Severidade_SEVERIDADE_MEDIA)})
	}
	for _, f := range []focus{focusModules, focusAlerts} {
		m.focus = f
		for _, size := range [][2]int{{40, 12}, {60, 20}, {80, 24}, {120, 40}, {200, 60}, {10, 5}} {
			m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			v := m.View()
			lines := strings.Split(v, "\n")
			wantW := max(size[0], 40)
			wantH := max(size[1], 12)
			if len(lines) != wantH {
				t.Errorf("%v foco=%d: %d linhas, esperado %d", size, f, len(lines), wantH)
			}
			for i, l := range lines {
				if w := lipgloss.Width(l); w > wantW {
					t.Errorf("%v foco=%d linha %d com %d colunas (> %d): %q", size, f, i, w, wantW, ansi.Strip(l))
				}
			}
		}
	}
}

func TestCommandLineFitsEveryTerminalSize(t *testing.T) {
	m, _, _ := newTestModel(t)
	m.Update(key(":"))
	typeLine(m, "stop "+strings.Repeat("x", 300))
	for _, size := range [][2]int{{40, 12}, {80, 24}, {200, 60}, {10, 5}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		lines := strings.Split(m.View(), "\n")
		if len(lines) != max(size[1], 12) {
			t.Errorf("%v: %d linhas", size, len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > max(size[0], 40) {
				t.Errorf("%v linha %d com %d colunas: %q", size, i, w, ansi.Strip(l))
			}
		}
	}
}

func metric(name string, v float64) *psychoscopev1.Metrica {
	return &psychoscopev1.Metrica{Nome: name, Valor: v}
}

func TestMetricsLineRatesAndResets(t *testing.T) {
	be := &fakeBackend{}
	m := NewModel(be)
	at := time.Unix(1_700_000_000, 0)
	snap := func(ev, drop, alerts float64) []*psychoscopev1.Metrica {
		return []*psychoscopev1.Metrica{
			metric("psychoscope_engine_events_processed_total", ev),
			metric("psychoscope_engine_events_dropped_total", drop),
			{Nome: "psychoscope_module_packets_dropped_total", Valor: 4, Rotulos: map[string]string{"module": "a"}},
			{Nome: "psychoscope_module_packets_dropped_total", Valor: 6, Rotulos: map[string]string{"module": "b"}},
			metric("psychoscope_engine_alerts_total", alerts),
		}
	}
	if strings.Contains(plain(m), "ev/s") {
		t.Fatal("sem metricas nao deve exibir a linha")
	}
	m.Update(metricsMsg{ms: snap(100, 1, 2), at: at})
	if !strings.Contains(plain(m), "0 ev/s") || !strings.Contains(plain(m), "11 descartes") || !strings.Contains(plain(m), "2 alertas") {
		t.Fatalf("primeira amostra (sem taxa):\n%s", plain(m))
	}
	m.Update(metricsMsg{ms: snap(400, 1, 3), at: at.Add(2 * time.Second)})
	if !strings.Contains(plain(m), "150 ev/s") || !strings.Contains(plain(m), "3 alertas") {
		t.Fatalf("taxa = delta/dt:\n%s", plain(m))
	}
	m.Update(metricsMsg{ms: snap(10, 0, 0), at: at.Add(4 * time.Second)}) // Core reiniciou
	if !strings.Contains(plain(m), " 0 ev/s") {
		t.Fatalf("contador que diminuiu nao gera taxa negativa:\n%s", plain(m))
	}
	m.Update(metricsMsg{err: errors.New("fora do ar")})
	if strings.Contains(plain(m), "ev/s") {
		t.Fatal("erro de metricas esconde a linha")
	}
}

func TestMetricsFetchedOnInitAndTick(t *testing.T) {
	be := &fakeBackend{metrics: []*psychoscopev1.Metrica{metric("psychoscope_engine_alerts_total", 5)}}
	m := NewModel(be)
	var sawMetrics bool
	for _, msg := range exec(m.fetchMetrics()) {
		if mm, ok := msg.(metricsMsg); ok && mm.err == nil && len(mm.ms) == 1 {
			sawMetrics = true
			m.Update(mm)
		}
	}
	if !sawMetrics || !strings.Contains(plain(m), "5 alertas") {
		t.Fatalf("metricas via backend:\n%s", plain(m))
	}
}

package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/settings"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// sampleLabels sao os nomes que o Core enviaria (tag label) para os campos de sampleConfig;
// um campo fora da tabela chega sem rotulo, como de um Core mais antigo.
var sampleLabels = map[string]string{
	"detection.window":                     "Janela do motor",
	"detection.beacon.ignore_destinations": "Destinos ignorados",
	"detection.beacon.ignore_ports":        "Portas ignoradas",
	"detection.scan.vertical_ports":        "Portas distintas (vertical)",
	"detection.scan.window":                "Janela de observação",
	"detection.bruteforce.ignore_sources":  "Origens ignoradas",
	"detection.tunnel.allowed_bases":       "Domínios base permitidos",
}

func cfgField(path string, t psychoscopev1.TipoCampo, value, def string, o psychoscopev1.OrigemCampo, doc string) *psychoscopev1.CampoConfig {
	return &psychoscopev1.CampoConfig{Caminho: path, Tipo: t, ValorAtual: value, ValorPadrao: def, Origem: o, Descricao: doc, Rotulo: sampleLabels[path]}
}

const (
	tInt   = psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO
	tDur   = psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO
	tTexts = psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO
	tInts  = psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO
	oDef   = psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO
	oFile  = psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO
	oSet   = psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE
)

func sampleConfig(readOnly bool) *psychoscopev1.ListaConfig {
	return &psychoscopev1.ListaConfig{
		SomenteLeitura: readOnly, ArquivoAjustes: "/var/lib/psychoscope/overrides.json",
		Campos: []*psychoscopev1.CampoConfig{
			cfgField("detection.window", tDur, `"1m"`, `"1m"`, oDef, "Janela deslizante do motor."),
			cfgField("detection.beacon.ignore_destinations", tTexts, `["10.0.0.0/8"]`, `[]`, oFile, "IPs ou CIDRs de destino ignorados."),
			cfgField("detection.beacon.ignore_ports", tInts, `[123]`, `[]`, oSet, "Portas de destino TCP ignoradas."),
			cfgField("detection.beacon.ignore_domains", tTexts, `[]`, `[]`, oDef, "Dominios ignorados nos beacons de DNS."),
			cfgField("detection.bruteforce.ignore_sources", tTexts, `["10.9.0.1"]`, `[]`, oFile, "Origens isentas da forca bruta."),
			cfgField("detection.tunnel.allowed_bases", tTexts, `[]`, `[]`, oDef, "Dominios base isentos do tunel DNS."),
			cfgField("detection.scan.vertical_ports", tInt, "15", "15", oDef, "Portas distintas que caracterizam varredura vertical."),
			cfgField("detection.scan.window", tDur, `"10s"`, `"10s"`, oDef, "Janela de observacao das sondas SYN."),
			cfgField("storage.max_alerts", tInt, "100000", "100000", oDef, "Maximo de alertas persistidos."),
		},
	}
}

func settingsModel(t *testing.T, readOnly bool) (*Model, *fakeBackend) {
	t.Helper()
	be := &fakeBackend{mods: mods(), cfg: sampleConfig(readOnly)}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	return m, be
}

// run digita ":linha" e Enter e entrega ao modelo as mensagens do comando resultante.
func run(m *Model, line string) {
	m.Update(key(":"))
	typeLine(m, line)
	_, cmd := m.Update(key("enter"))
	feed(m, exec(cmd)...)
}

func openCfg(t *testing.T, readOnly bool) (*Model, *fakeBackend) {
	t.Helper()
	m, be := settingsModel(t, readOnly)
	run(m, "config")
	if m.cfg == nil || m.cfg.list == nil {
		t.Fatalf("a tela deveria estar aberta e carregada: %+v", m.cfg)
	}
	return m, be
}

func selectField(t *testing.T, m *Model, path string) {
	t.Helper()
	for i, f := range m.cfg.fields() {
		if f.Caminho == path {
			m.cfg.sel = i
			return
		}
	}
	t.Fatalf("campo %s ausente", path)
}

func TestConfigCommandOpensTheScreenWithSectionsFieldsAndDescription(t *testing.T) {
	m, _ := openCfg(t, false)
	v := plain(m)
	for _, want := range []string{"Configurações", "Motor de detecção", "detection.beacon", "detection.scan", "Armazenamento de alertas",
		"Janela do motor", "Destinos ignorados", "Portas distintas (vertical)", "max_alerts", "1m", "10.0.0.0/8", "123", "15", "100000",
		"padrão", "arquivo", "ajuste", ":set campo=valor"} {
		if !strings.Contains(v, want) {
			t.Errorf("tela sem %q:\n%s", want, v)
		}
	}
	// a descricao e o tipo do campo selecionado (o primeiro: detection.window)
	if !strings.Contains(v, "Janela deslizante do motor.") || !strings.Contains(v, "duração (por exemplo 30s, 2m, 1h)") {
		t.Fatalf("descricao e tipo do campo selecionado:\n%s", v)
	}
	if strings.Contains(v, "somente leitura") {
		t.Fatalf("root nao ve o aviso:\n%s", v)
	}
}

func TestConfigNavigation(t *testing.T) {
	m, _ := openCfg(t, false)
	n := len(m.cfg.fields())
	m.Update(key("down"))
	m.Update(key("j"))
	if m.cfg.sel != 2 {
		t.Fatalf("sel=%d", m.cfg.sel)
	}
	m.Update(key("up"))
	m.Update(key("k"))
	m.Update(key("k")) // ja no topo
	if m.cfg.sel != 0 {
		t.Fatalf("sel=%d", m.cfg.sel)
	}
	m.Update(key("G"))
	if m.cfg.sel != n-1 || !strings.Contains(plain(m), "Maximo de alertas persistidos.") {
		t.Fatalf("G vai ao fim e a descricao acompanha: sel=%d\n%s", m.cfg.sel, plain(m))
	}
	m.Update(key("down")) // ja no fim
	m.Update(key("g"))
	if m.cfg.sel != 0 {
		t.Fatalf("g vai ao inicio: %d", m.cfg.sel)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	if m.cfg.sel == 0 {
		t.Fatal("PgDn deve descer")
	}
}

func TestConfigEditWithEnterStagesADraft(t *testing.T) {
	m, be := openCfg(t, false)
	selectField(t, m, "detection.scan.vertical_ports")
	m.Update(key("enter"))
	if m.cfg.edit == nil || m.cfg.edit.buf != "15" {
		t.Fatalf("o editor abre com o valor atual: %+v", m.cfg.edit)
	}
	if !strings.Contains(plain(m), "editando Portas distintas (vertical): 15█") {
		t.Fatalf("rodape de edicao:\n%s", plain(m))
	}
	m.Update(key("backspace"))
	m.Update(key("backspace"))
	typeLine(m, "30")
	m.Update(key("enter"))
	if m.cfg.edit != nil || m.cfg.draft["detection.scan.vertical_ports"] != "30" {
		t.Fatalf("rascunho: %+v", m.cfg.draft)
	}
	v := plain(m)
	if !strings.Contains(v, "30 *") || !strings.Contains(v, "1 alteração(ões) não gravada(s)") {
		t.Fatalf("o rascunho aparece marcado e contado no titulo:\n%s", v)
	}
	if len(be.applies) != 0 {
		t.Fatal("editar nao envia nada ao Core: so :w grava")
	}

	// lista: o editor mostra o valor como se digita; um valor igual ao atual desfaz o rascunho
	selectField(t, m, "detection.beacon.ignore_ports")
	m.Update(key("enter"))
	if m.cfg.edit.buf != "123" {
		t.Fatalf("lista como texto: %q", m.cfg.edit.buf)
	}
	typeLine(m, ", 443")
	m.Update(key("enter"))
	if m.cfg.draft["detection.beacon.ignore_ports"] != "[123,443]" {
		t.Fatalf("lista no rascunho: %v", m.cfg.draft)
	}
	m.Update(key("enter")) // reabre com "123, 443"
	for i := 0; i < len(", 443"); i++ {
		m.Update(key("backspace")) // volta a "123", o valor atual
	}
	m.Update(key("enter"))
	if _, ok := m.cfg.draft["detection.beacon.ignore_ports"]; ok {
		t.Fatalf("valor igual ao atual desfaz o rascunho: %v", m.cfg.draft)
	}
}

func TestConfigEditErrorsKeepEditingAndEscCancels(t *testing.T) {
	m, _ := openCfg(t, false)
	selectField(t, m, "detection.scan.vertical_ports")
	m.Update(key("enter"))
	typeLine(m, "x")
	m.Update(key("enter"))
	if m.cfg.edit == nil || !strings.Contains(m.status, "numero inteiro") || !m.statusErr || len(m.cfg.draft) != 0 {
		t.Fatalf("texto invalido nao vira rascunho e a edicao continua: status=%q", m.status)
	}
	if !strings.Contains(plain(m), "editando Portas distintas (vertical): 15x█") || !strings.Contains(plain(m), "esperado um numero inteiro") {
		t.Fatalf("o erro aparece junto da linha de edicao:\n%s", plain(m))
	}
	m.Update(key("esc"))
	if m.cfg == nil || m.cfg.edit != nil || len(m.cfg.draft) != 0 {
		t.Fatal("Esc cancela so a edicao, sem fechar a tela")
	}
}

func TestSetCommandStagesRestoresAndShows(t *testing.T) {
	m, _ := openCfg(t, false)
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "set detection.beacon.ignore_destinations=149.154.160.0/20, 2001:67c:4e8::/48")
	if m.cfg.draft["detection.scan.vertical_ports"] != "30" ||
		m.cfg.draft["detection.beacon.ignore_destinations"] != `["149.154.160.0/20","2001:67c:4e8::/48"]` {
		t.Fatalf("rascunho: %v", m.cfg.draft)
	}
	// o :set leva a selecao ao campo alterado, para a mudanca ficar a vista
	if got := m.cfg.selected().Caminho; got != "detection.beacon.ignore_destinations" {
		t.Fatalf("a selecao acompanha o ultimo :set: %s", got)
	}
	// mostrar o valor
	run(m, "set detection.scan.vertical_ports")
	if !strings.Contains(m.status, "detection.scan.vertical_ports = 30") || !strings.Contains(m.status, "padrão: 15") {
		t.Fatalf("status=%q", m.status)
	}
	// restaurar um campo com ajuste gravado (ignore_ports) marca restore; sem ajuste, avisa
	run(m, "set detection.beacon.ignore_ports&")
	if !m.cfg.restore["detection.beacon.ignore_ports"] {
		t.Fatalf("restore: %v", m.cfg.restore)
	}
	run(m, "set detection.scan.window&")
	if m.cfg.restore["detection.scan.window"] || !strings.Contains(m.status, "ja esta no valor base") {
		t.Fatalf("campo sem ajuste nao tem o que restaurar: %v %q", m.cfg.restore, m.status)
	}
	// a tecla d faz o mesmo que :set campo&
	selectField(t, m, "detection.beacon.ignore_ports")
	delete(m.cfg.restore, "detection.beacon.ignore_ports")
	m.Update(key("d"))
	if !m.cfg.restore["detection.beacon.ignore_ports"] {
		t.Fatal("d marca o campo para restaurar")
	}
	if !strings.Contains(plain(m), "(restaurar ao valor base) *") {
		t.Fatalf("restaurar aparece marcado:\n%s", plain(m))
	}
	// erros
	for line, want := range map[string]string{
		"set":                                  "uso:",
		"set nao.existe=1":                     "desconhecido ou não editável",
		"set detection.scan.vertical_ports=ab": "numero inteiro",
		"set detection.window=dez":             "duracao",
	} {
		run(m, line)
		if !strings.Contains(m.status, want) || !m.statusErr {
			t.Errorf(":%s: status=%q, esperado %q", line, m.status, want)
		}
	}
}

func TestWriteSendsTheDraftAndClearsItOnSuccess(t *testing.T) {
	m, be := openCfg(t, false)
	run(m, "w")
	if !strings.Contains(m.status, "nada a gravar") || len(be.applies) != 0 {
		t.Fatalf("sem alteracoes: %q", m.status)
	}
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "set detection.beacon.ignore_ports&")
	run(m, "w")
	if len(be.applies) != 1 {
		t.Fatalf("applies=%v", be.applies)
	}
	a := be.applies[0]
	if len(a.patch) != 1 || a.patch["detection.scan.vertical_ports"] != "30" || len(a.restore) != 1 || a.restore[0] != "detection.beacon.ignore_ports" {
		t.Fatalf("pedido: %+v", a)
	}
	if m.cfg == nil || m.cfg.pending() != 0 || !strings.Contains(m.status, "configuração aplicada (2 campo(s))") {
		t.Fatalf("apos gravar: pending=%d status=%q", m.cfg.pending(), m.status)
	}
	if v := plain(m); !strings.Contains(v, "30") || strings.Contains(v, "não gravada") {
		t.Fatalf("a tela mostra o valor gravado e sem pendencias:\n%s", v)
	}
}

func TestWriteErrorKeepsTheDraftAndShowsTheCoreMessage(t *testing.T) {
	m, be := openCfg(t, false)
	be.applyErr = errors.New("detection.scan.window: maior que detection.window")
	run(m, "set detection.scan.window=5m")
	run(m, "w")
	if !strings.Contains(m.status, "detection.scan.window: maior que detection.window") || !m.statusErr {
		t.Fatalf("status=%q", m.status)
	}
	if m.cfg.pending() != 1 || m.cfg.draft["detection.scan.window"] != `"5m"` {
		t.Fatalf("o rascunho fica para ser corrigido: %v", m.cfg.draft)
	}
	// corrigir os dois campos juntos e gravar de novo
	be.applyErr = nil
	run(m, "set detection.window=10m")
	run(m, "w")
	if len(be.applies) != 2 || len(be.applies[1].patch) != 2 || m.cfg.pending() != 0 {
		t.Fatalf("segunda tentativa: %v pending=%d", be.applies, m.cfg.pending())
	}
}

func TestQuitCommandsWithPendingChanges(t *testing.T) {
	m, be := openCfg(t, false)
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "q")
	if m.cfg == nil || !strings.Contains(m.status, "1 alteração(ões) não gravada(s)") || !m.statusErr {
		t.Fatalf(":q com pendencia recusa: status=%q", m.status)
	}
	run(m, "quit")
	if m.cfg == nil {
		t.Fatal(":quit tambem recusa")
	}
	run(m, "q!")
	if m.cfg != nil || len(be.applies) != 0 {
		t.Fatal(":q! descarta e fecha, sem gravar")
	}
	// reabrir nao traz o rascunho antigo; :q sem pendencias fecha a tela, nao a TUI
	run(m, "config")
	if m.cfg.pending() != 0 {
		t.Fatal("rascunho descartado")
	}
	m.Update(key(":"))
	typeLine(m, "q")
	_, cmd := m.Update(key("enter"))
	if m.cfg != nil || isQuit(cmd) {
		t.Fatal(":q sem pendencias fecha so a tela")
	}
	// :wq grava e fecha
	run(m, "config")
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "wq")
	if m.cfg != nil || len(be.applies) != 1 {
		t.Fatalf(":wq grava e fecha: applies=%d", len(be.applies))
	}
	// :wq com erro nao fecha
	run(m, "config")
	be.applyErr = errors.New("recusado")
	run(m, "set detection.scan.vertical_ports=31")
	run(m, "wq")
	if m.cfg == nil || m.cfg.pending() != 1 {
		t.Fatal(":wq com erro mantem a tela e o rascunho")
	}
}

func TestReadOnlyMode(t *testing.T) {
	m, be := openCfg(t, true)
	if v := plain(m); !strings.Contains(v, "somente leitura") {
		t.Fatalf("aviso no titulo e no rodape:\n%s", v)
	}
	selectField(t, m, "detection.scan.vertical_ports")
	m.Update(key("enter"))
	if m.cfg.edit != nil || !strings.Contains(m.status, "somente leitura") || !m.statusErr {
		t.Fatalf("Enter nao edita: %q", m.status)
	}
	for _, line := range []string{"set detection.scan.vertical_ports=30", "set detection.beacon.ignore_ports&", "w", "wq"} {
		run(m, line)
		if !strings.Contains(m.status, "somente leitura") || !m.statusErr {
			t.Errorf(":%s: status=%q", line, m.status)
		}
	}
	m.Update(key("d"))
	if m.cfg.pending() != 0 || len(be.applies) != 0 {
		t.Fatal("nada e alterado em modo somente leitura")
	}
	run(m, "set detection.scan.vertical_ports") // mostrar continua permitido
	if !strings.Contains(m.status, "detection.scan.vertical_ports = 15") {
		t.Fatalf("status=%q", m.status)
	}
}

func TestCommandsThatNeedTheSettingsScreen(t *testing.T) {
	m, _ := settingsModel(t, false)
	for _, line := range []string{"set a=1", "w", "wq"} {
		run(m, line)
		if !strings.Contains(m.status, "vale na tela de configurações") || !m.statusErr {
			t.Errorf(":%s fora da tela: %q", line, m.status)
		}
	}
	// e :stop nao age escondido atras da tela de configuracoes
	run(m, "config")
	run(m, "stop")
	if !strings.Contains(m.status, "feche a tela de configurações") {
		t.Fatalf(":stop com a tela aberta: %q", m.status)
	}
}

func TestConfigLoadErrors(t *testing.T) {
	m, be := settingsModel(t, false)
	be.cfgErr = errors.New("sem conexao")
	run(m, "config")
	if m.cfg != nil || !strings.Contains(m.status, "sem conexao") || !m.statusErr {
		t.Fatalf("falha ao abrir volta a tela principal: cfg=%v status=%q", m.cfg, m.status)
	}
	// recarregar com a tela aberta mantem o rascunho
	be.cfgErr = nil
	run(m, "config")
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "config")
	if m.cfg == nil || m.cfg.draft["detection.scan.vertical_ports"] != "30" {
		t.Fatal(":config com a tela aberta recarrega e mantem o rascunho")
	}
}

func TestTabCompletesFieldPathsAfterSet(t *testing.T) {
	m, _ := openCfg(t, false)
	for _, tc := range []struct{ typed, want string }{
		{"set detection.scan.v", "set detection.scan.vertical_ports"}, // unico
		{"set detection.scan.", "set detection.scan."},                // vertical_ports e window: maior prefixo comum
		{"set st", "set storage.max_alerts"},
		{"set detection.beacon.ignore_", "set detection.beacon.ignore_"},
		{"set zz", "set zz"},
		{"set detection.window=1", "set detection.window=1"}, // depois do = nao completa
	} {
		m.Update(key(":"))
		typeLine(m, tc.typed)
		m.Update(key("tab"))
		if m.cmdline.buf != tc.want {
			t.Errorf("Tab apos %q: %q, esperado %q", tc.typed, m.cmdline.buf, tc.want)
		}
		m.Update(key("esc"))
	}
	// o nome do comando continua completando
	m.Update(key(":"))
	typeLine(m, "con")
	m.Update(key("tab"))
	if m.cmdline.buf != "config" {
		t.Fatalf("con -> %q", m.cmdline.buf)
	}
}

func TestSettingsScreenFitsEveryTerminalSize(t *testing.T) {
	m, be := openCfg(t, false)
	for i := 0; i < 40; i++ { // muitos campos para exigir rolagem
		be.cfg.Campos = append(be.cfg.Campos, cfgField(fmt.Sprintf("detection.regra%02d.campo", i), tInt, "1", "1", oDef, strings.Repeat("descricao longa ", 20)))
	}
	run(m, "config")
	be.cfg.Campos[1].ValorAtual = `["` + strings.Repeat("x", 300) + `"]`
	run(m, "config")
	run(m, "set detection.scan.vertical_ports=30")
	for _, edit := range []bool{false, true} {
		m.cfg.edit = nil
		if edit {
			selectField(t, m, "detection.beacon.ignore_destinations")
			m.Update(key("enter"))
		}
		for _, size := range [][2]int{{40, 12}, {60, 20}, {80, 24}, {120, 40}, {200, 60}, {10, 5}} {
			m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			for _, nav := range []string{"G", "g"} { // pior caso: ao fim e ao inicio
				if !edit {
					m.Update(key(nav))
				}
				lines := strings.Split(m.View(), "\n")
				if len(lines) != max(size[1], 12) {
					t.Errorf("%v edit=%v: %d linhas, esperado %d", size, edit, len(lines), max(size[1], 12))
				}
				for i, l := range lines {
					if w := lipgloss.Width(l); w > max(size[0], 40) {
						t.Errorf("%v edit=%v linha %d com %d colunas: %q", size, edit, i, w, ansi.Strip(l))
					}
				}
			}
		}
	}
}

func TestSelectedFieldStaysVisibleWhileScrolling(t *testing.T) {
	m, be := openCfg(t, false)
	for i := 0; i < 60; i++ {
		be.cfg.Campos = append(be.cfg.Campos, cfgField(fmt.Sprintf("detection.zz%02d.campo", i), tInt, "1", "1", oDef, "d"))
	}
	run(m, "config")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 16})
	for i := 0; i < len(m.cfg.fields())-1; i++ {
		m.Update(key("down"))
		sel := m.cfg.selected()
		if !strings.Contains(plain(m), keyOf(sel.Caminho)) || !strings.Contains(plain(m), " "+sel.Descricao) {
			t.Fatalf("o campo selecionado %s deve estar na tela:\n%s", sel.Caminho, plain(m))
		}
	}
	for i := 0; i < len(m.cfg.fields())-1; i++ {
		m.Update(key("up"))
	}
	if m.cfg.sel != 0 || !strings.Contains(plain(m), "detection\n") && !strings.Contains(plain(m), " detection ") {
		t.Fatalf("de volta ao topo:\n%s", plain(m))
	}
}

// Com muitos campos, o :set num campo fora da primeira pagina precisa rolar ate ele.
func TestSetScrollsTheChangedFieldIntoView(t *testing.T) {
	m, be := openCfg(t, false)
	for i := 0; i < 60; i++ {
		be.cfg.Campos = append(be.cfg.Campos, cfgField(fmt.Sprintf("detection.zz%02d.campo", i), tInt, "1", "1", oDef, "d"))
	}
	run(m, "config")
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 16})
	run(m, "set detection.zz55.campo=7")
	v := plain(m)
	if !strings.Contains(v, "7 *") || !strings.Contains(v, "detection.zz55") {
		t.Fatalf("o campo alterado fora da primeira pagina deve aparecer na tela:\n%s", v)
	}
}

// O :w envia uma copia do rascunho; edicoes feitas enquanto o pedido esta em andamento nao
// podem ser apagadas pela resposta de sucesso.
func TestWriteKeepsEditsMadeWhileTheRequestWasInFlight(t *testing.T) {
	m, be := openCfg(t, false)
	run(m, "set detection.scan.vertical_ports=30")
	run(m, "set detection.beacon.ignore_ports&")
	m.Update(key(":"))
	typeLine(m, "w")
	_, cmd := m.Update(key("enter"))
	inFlight := exec(cmd) // o pedido foi ao Core, a resposta ainda nao chegou ao modelo

	run(m, "set detection.window=2m")              // campo novo
	run(m, "set detection.scan.vertical_ports=45") // mesmo campo, valor novo
	feed(m, inFlight...)

	if len(be.applies) != 1 || be.applies[0].patch["detection.scan.vertical_ports"] != "30" {
		t.Fatalf("o pedido enviado tinha o valor antigo: %+v", be.applies)
	}
	if got := m.cfg.draft; len(got) != 2 || got["detection.window"] != `"2m"` || got["detection.scan.vertical_ports"] != "45" {
		t.Fatalf("as duas edicoes novas continuam pendentes: %v", got)
	}
	if m.cfg.restore["detection.beacon.ignore_ports"] {
		t.Fatal("o que foi enviado e aceito sai do rascunho")
	}
	if !strings.Contains(plain(m), "2 alteração(ões) não gravada(s)") {
		t.Fatalf("o titulo conta as pendencias:\n%s", plain(m))
	}
}

func TestWriteQuitDoesNotDiscardEditsMadeDuringTheRequest(t *testing.T) {
	m, be := openCfg(t, false)
	run(m, "set detection.scan.vertical_ports=30")
	m.Update(key(":"))
	typeLine(m, "wq")
	_, cmd := m.Update(key("enter"))
	inFlight := exec(cmd)
	run(m, "set detection.window=2m")
	feed(m, inFlight...)
	if m.cfg == nil {
		t.Fatal(":wq nao pode fechar a tela com uma edicao nova pendente")
	}
	if !strings.Contains(m.status, "1 alteração(ões) nova(s) ainda não gravada(s)") || !m.statusErr || len(be.applies) != 1 {
		t.Fatalf("status=%q applies=%d", m.status, len(be.applies))
	}
	run(m, "wq") // agora grava o que sobrou e fecha
	if m.cfg != nil || len(be.applies) != 2 {
		t.Fatalf("segundo :wq: cfg=%v applies=%d", m.cfg, len(be.applies))
	}
}

// View so desenha: chama-la (uma ou varias vezes, e com a selecao mexida por fora de Update)
// nao pode alterar a rolagem. Quem a ajusta e o Update.
func TestViewDoesNotChangeTheScrollAndUpdateKeepsTheSelectionVisible(t *testing.T) {
	m, be := openCfg(t, false)
	for i := 0; i < 60; i++ {
		be.cfg.Campos = append(be.cfg.Campos, cfgField(fmt.Sprintf("detection.zz%02d.campo", i), tInt, "1", "1", oDef, "d"))
	}
	run(m, "config")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 16})

	m.cfg.sel = len(m.cfg.fields()) - 1 // selecao movida sem passar por Update
	before := m.cfg.scroll
	for i := 0; i < 3; i++ {
		_ = m.View()
	}
	if m.cfg.scroll != before {
		t.Fatalf("View alterou a rolagem: %d -> %d", before, m.cfg.scroll)
	}

	m.Update(key("g")) // uma mensagem de verdade volta a sincronizar
	m.Update(key("G"))
	if m.cfg.scroll == 0 || !strings.Contains(plain(m), "campo") {
		t.Fatalf("Update mantem a selecao visivel: scroll=%d", m.cfg.scroll)
	}
	// redimensionar tambem sincroniza, sem tecla nenhuma
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	sel := m.cfg.selected()
	if !strings.Contains(plain(m), keyOf(sel.Caminho)) {
		t.Fatalf("apos redimensionar a selecao continua visivel:\n%s", plain(m))
	}
}

func TestConfigListShowsReadableNamesAndKeepsTheKeyInTheDescription(t *testing.T) {
	m, _ := openCfg(t, false)
	v := plain(m)
	for _, want := range []string{"Motor de detecção", "Armazenamento de alertas", "Beacon (conexões periódicas)",
		"Destinos ignorados", "Portas ignoradas", "Origens ignoradas"} {
		if !strings.Contains(v, want) {
			t.Errorf("a lista deveria mostrar %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "ignore_destinations ") || strings.Contains(v, " ignore_ports ") {
		t.Errorf("a coluna de nomes nao mostra a chave tecnica:\n%s", v)
	}
	selectField(t, m, "detection.beacon.ignore_destinations")
	if v := plain(m); !strings.Contains(v, "chave: detection.beacon.ignore_destinations") {
		t.Errorf("a descricao do campo selecionado traz a chave para o :set:\n%s", v)
	}
	// o texto vazio de uma lista nao e "[]"
	selectField(t, m, "detection.beacon.ignore_domains")
	if v := plain(m); !strings.Contains(v, "(vazia)") || strings.Contains(v, "[]") {
		t.Errorf("lista vazia aparece como (vazia):\n%s", v)
	}
}

func TestConfigListFallsBackToTheKeyWithoutLabel(t *testing.T) {
	m, _ := openCfg(t, false)
	// storage.max_alerts nao esta em sampleLabels: Core mais antigo, sem rotulo
	if v := plain(m); !strings.Contains(v, "max_alerts") {
		t.Errorf("sem rotulo, a lista mostra a chave:\n%s", v)
	}
	selectField(t, m, "storage.max_alerts")
	m.Update(key("enter"))
	if v := plain(m); !strings.Contains(v, "editando storage.max_alerts: 100000█") {
		t.Errorf("sem rotulo, o rodape de edicao mostra o caminho:\n%s", v)
	}
}

// O Core real descreve os campos pelo catalogo: toda secao dele precisa de titulo e todo campo
// de rotulo, senao a tela volta a mostrar caminhos tecnicos.
func TestEveryCatalogSectionHasATitleAndEveryFieldALabel(t *testing.T) {
	cfg := &config.Config{Detection: config.DefaultDetection(), Storage: config.Storage{RetentionDays: 30, MaxAlerts: 100}}
	fields, err := settings.Catalog(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fields {
		if sec := sectionOf(f.Path); sectionTitle(sec) == sec {
			t.Errorf("secao %q sem titulo legivel em sectionTitle", sec)
		}
		if f.Label == "" {
			t.Errorf("campo %s sem rotulo", f.Path)
		}
	}
}

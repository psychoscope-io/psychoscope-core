package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// typeLine digita text na linha de comando aberta (um caractere por tecla, como no terminal).
func typeLine(m *Model, text string) {
	for _, r := range text {
		if r == ' ' {
			m.Update(key("space"))
		} else {
			m.Update(key(string(r)))
		}
	}
}

// isQuit informa se alguma mensagem produzida por cmd e tea.QuitMsg.
func isQuit(cmd tea.Cmd) bool {
	for _, msg := range exec(cmd) {
		if _, ok := msg.(tea.QuitMsg); ok {
			return true
		}
	}
	return false
}

func newTestModel(t *testing.T) (*Model, *fakeBackend, *fakeStream) {
	t.Helper()
	be := &fakeBackend{mods: mods()}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	st := &fakeStream{ch: make(chan *psychoscopev1.Alerta)}
	m.Update(streamOpenedMsg{s: st})
	return m, be, st
}

func TestSingleKeysNeverQuit(t *testing.T) {
	for _, k := range []string{"q", "esc", "ctrl+c", "x"} {
		m, be, st := newTestModel(t)
		_, cmd := m.Update(key(k))
		if isQuit(cmd) || st.closed {
			t.Fatalf("%s nao deve sair", k)
		}
		if len(be.cmds) != 0 {
			t.Fatalf("%s nao deve enviar comando: %v", k, be.cmds)
		}
	}
	m, _, _ := newTestModel(t)
	m.Update(key("q"))
	if !strings.Contains(plain(m), ":q e Enter") {
		t.Fatalf("dica de saida ausente:\n%s", plain(m))
	}
	m.Update(key("x"))
	if !strings.Contains(plain(m), ":stop e Enter") {
		t.Fatalf("dica de encerramento ausente:\n%s", plain(m))
	}
}

func TestQuitCommands(t *testing.T) {
	for _, name := range []string{"q", "quit", "q!"} {
		m, _, st := newTestModel(t)
		m.Update(key(":"))
		typeLine(m, name)
		_, cmd := m.Update(key("enter"))
		if !isQuit(cmd) || !st.closed {
			t.Fatalf(":%s deveria sair e fechar o stream (closed=%v)", name, st.closed)
		}
	}
}

func TestCommandLineCancelAndEdit(t *testing.T) {
	m, _, st := newTestModel(t)
	m.Update(key(":"))
	typeLine(m, "qx")
	m.Update(key("backspace"))
	if m.cmdline == nil || m.cmdline.buf != "q" {
		t.Fatalf("buf=%v", m.cmdline)
	}
	if !strings.Contains(plain(m), ":q█") {
		t.Fatalf("rodape com a linha de comando ausente:\n%s", plain(m))
	}
	for _, cancel := range []string{"esc", "ctrl+c"} {
		m.Update(key(":"))
		typeLine(m, "q")
		_, cmd := m.Update(key(cancel))
		if m.cmdline != nil || isQuit(cmd) || st.closed {
			t.Fatalf("%s deve apenas cancelar a linha", cancel)
		}
	}
	// Enter com a linha vazia nao faz nada.
	m.Update(key(":"))
	_, cmd := m.Update(key("enter"))
	if m.cmdline != nil || isQuit(cmd) {
		t.Fatal("linha vazia nao sai")
	}
}

func TestStopCommandActsOnSelectedModule(t *testing.T) {
	m, be, _ := newTestModel(t)
	m.Update(key(":"))
	typeLine(m, "stop")
	if !strings.Contains(plain(m), "→ mod-net-sensor") {
		t.Fatalf("rodape deve mostrar o alvo:\n%s", plain(m))
	}
	_, cmd := m.Update(key("enter"))
	feed(m, exec(cmd)...)
	if len(be.cmds) != 1 || be.cmds[0] != "mod-net-sensor:ENCERRAR" {
		t.Fatalf("cmds=%v", be.cmds)
	}

	// o alvo acompanha a selecao
	m.Update(key("down"))
	m.Update(key(":"))
	typeLine(m, "stop")
	if !strings.Contains(plain(m), "→ mod-yara") {
		t.Fatalf("alvo deveria ser o modulo selecionado:\n%s", plain(m))
	}
	_, cmd = m.Update(key("enter"))
	feed(m, exec(cmd)...)
	if got := be.cmds[len(be.cmds)-1]; got != "mod-yara:ENCERRAR" {
		t.Fatalf("cmds=%v", be.cmds)
	}
}

func TestStopWithoutModuleIsRejected(t *testing.T) {
	be := &fakeBackend{}
	m := NewModel(be)
	feed(m, exec(m.fetchModules())...)
	m.Update(key(":"))
	typeLine(m, "stop")
	if !strings.Contains(plain(m), "nenhum módulo selecionado") {
		t.Fatalf("rodape deve avisar da falta de alvo:\n%s", plain(m))
	}
	m.Update(key("enter"))
	if len(be.cmds) != 0 || !strings.Contains(m.status, "nenhum módulo") || !m.statusErr {
		t.Fatalf("status=%q cmds=%v", m.status, be.cmds)
	}
}

func TestUnknownCommandAndArgumentsAreRejected(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"foo", "comando desconhecido: foo (use :q, :q!, :quit, :stop)"},
		{"stop mod-net-sensor", "o comando stop não aceita argumentos"},
		{"q agora", "o comando q não aceita argumentos"},
		{"q! agora", "o comando q não aceita argumentos"},
		// comandos removidos na v0.4.0: duplicavam as teclas p e r, ou eram apelido nao-vim
		{"sair", "comando desconhecido: sair"},
		{"pause", "comando desconhecido: pause"},
		{"resume", "comando desconhecido: resume"},
	} {
		m, be, st := newTestModel(t)
		m.Update(key(":"))
		typeLine(m, tc.line)
		_, cmd := m.Update(key("enter"))
		if isQuit(cmd) || st.closed || len(be.cmds) != 0 {
			t.Fatalf(":%s nao deve ter efeito (cmds=%v)", tc.line, be.cmds)
		}
		if !strings.Contains(m.status, tc.want) || !m.statusErr {
			t.Fatalf(":%s: status=%q, esperado %q", tc.line, m.status, tc.want)
		}
	}
}

func TestTabCompletion(t *testing.T) {
	for _, tc := range []struct{ typed, want string }{
		{"s", "stop"}, // unico candidato
		{"st", "stop"},
		{"qu", "quit"},
		{"q", "q"}, // "q", "q!" e "quit": o maior prefixo comum e o proprio "q"
		{"zz", "zz"},
	} {
		m, _, _ := newTestModel(t)
		m.Update(key(":"))
		typeLine(m, tc.typed)
		m.Update(key("tab"))
		if m.cmdline.buf != tc.want {
			t.Errorf("tab apos %q: buf=%q, esperado %q", tc.typed, m.cmdline.buf, tc.want)
		}
	}
}

func TestPauseResumeKeysStillWork(t *testing.T) {
	m, be, _ := newTestModel(t)
	feed(m, exec2(m, key("p"))...)
	feed(m, exec2(m, key("r"))...)
	if len(be.cmds) != 2 || be.cmds[0] != "mod-net-sensor:PAUSAR" || be.cmds[1] != "mod-net-sensor:RETOMAR" {
		t.Fatalf("cmds=%v", be.cmds)
	}
}

// O terminal real entrega ":q" digitado rapido como UMA tecla com duas runas.
func TestBurstOfRunesIsSplitIntoKeys(t *testing.T) {
	m, _, st := newTestModel(t)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(":q")})
	if m.cmdline == nil || m.cmdline.buf != "q" {
		t.Fatalf("a rajada deveria abrir a linha e digitar q: %+v", m.cmdline)
	}
	if isQuit(cmd) || st.closed {
		t.Fatal("sem Enter nao sai")
	}
	_, cmd = m.Update(key("enter"))
	if !isQuit(cmd) || !st.closed {
		t.Fatal("Enter deveria sair")
	}

	// rajada que inclui a quebra de linha: sai direto
	m, _, st = newTestModel(t)
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(":quit")})
	_, cmd = m.Update(key("enter"))
	if !isQuit(cmd) || !st.closed {
		t.Fatal(":quit em rajada deveria sair")
	}

	// uma rajada de teclas comuns nao sai nem quebra: "qqq" so mostra a dica
	m, _, st = newTestModel(t)
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("qqq")})
	if isQuit(cmd) || st.closed {
		t.Fatal("qqq nao deve sair")
	}
}

func TestPastedTextOnlyGoesToTheCommandLine(t *testing.T) {
	m, be, st := newTestModel(t)
	// colado fora da linha de comando: ignorado (nao vira comando)
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(":q"), Paste: true})
	if m.cmdline != nil || isQuit(cmd) || st.closed || len(be.cmds) != 0 {
		t.Fatal("texto colado na tela principal deve ser ignorado")
	}
	// colado dentro da linha: entra, sem caracteres de controle, e ainda exige Enter
	m.Update(key(":"))
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("stop\n"), Paste: true})
	if m.cmdline.buf != "stop" || len(be.cmds) != 0 {
		t.Fatalf("buf=%q cmds=%v", m.cmdline.buf, be.cmds)
	}
}

// :q fecha a visao atual, como no vim: com o detalhe do alerta aberto ele so fecha o detalhe.
func TestQuitCommandClosesTheDetailBeforeQuittingTheApp(t *testing.T) {
	m := modelWithAlerts(t, 100, 30, burstAlert())
	m.Update(key("enter"))
	if m.detail == nil {
		t.Fatal("o detalhe deveria estar aberto")
	}
	m.Update(key(":")) // o detalhe aceita a linha de comando
	if m.cmdline == nil {
		t.Fatal(":' no detalhe abre a linha de comando")
	}
	typeLine(m, "q")
	_, cmd := m.Update(key("enter"))
	if m.detail != nil || isQuit(cmd) {
		t.Fatal(":q com o detalhe aberto fecha so o detalhe")
	}
	// agora na tela principal, o mesmo comando sai
	m.Update(key(":"))
	typeLine(m, "q")
	_, cmd = m.Update(key("enter"))
	if !isQuit(cmd) {
		t.Fatal(":q na tela principal sai")
	}
}

func TestStopFromTheDetailScreenStillTargetsTheSelectedModule(t *testing.T) {
	m := modelWithAlerts(t, 100, 30, burstAlert())
	be := m.be.(*fakeBackend)
	m.Update(key("enter"))
	m.Update(key(":"))
	typeLine(m, "stop")
	if !strings.Contains(plain(m), "→ mod-net-sensor") {
		t.Fatalf("o alvo aparece no rodape tambem no detalhe:\n%s", plain(m))
	}
	_, cmd := m.Update(key("enter"))
	feed(m, exec(cmd)...)
	if len(be.cmds) != 1 || be.cmds[0] != "mod-net-sensor:ENCERRAR" {
		t.Fatalf("cmds=%v", be.cmds)
	}
}

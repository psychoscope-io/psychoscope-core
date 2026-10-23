package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// Linha de comando estilo vim: ':' abre, Enter executa, Esc cancela. Sair e encerrar um
// modulo exigem digitar um comando, nunca uma tecla unica que possa ser apertada por acidente.

const (
	hintQuit = "para sair: digite :q e Enter"
	hintStop = "para encerrar o módulo: digite :stop e Enter"
)

// commandFunc executa um comando; args sao os termos digitados depois do nome.
type commandFunc func(m *Model, args []string) tea.Cmd

// commands sao os comandos aceitos: uma forma principal por acao, e so os apelidos do proprio
// vim (q e quit). Teclas diretas ficam para navegar e para acoes reversiveis (p, r); comando
// com ':' e para o que sai de uma tela ou e destrutivo.
var commands = map[string]commandFunc{
	"q":    (*Model).cmdQuit,
	"q!":   (*Model).cmdQuit,
	"quit": (*Model).cmdQuit,
	"stop": (*Model).cmdStop,
}

// commandNames lista os nomes dos comandos em ordem alfabetica (completude com Tab e ajuda).
func commandNames() []string {
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// cmdline e o texto digitado depois do ':'.
type cmdline struct{ lineEditor }

// name devolve o primeiro termo digitado, sem espacos.
func (c *cmdline) name() string {
	f := strings.Fields(c.buf)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// actsOnModule informa se o comando digitado age no modulo selecionado.
func (c *cmdline) actsOnModule() bool { return c.name() == "stop" }

// complete completa o nome do comando com o unico candidato, ou com o maior prefixo comum.
func (c *cmdline) complete() {
	if strings.ContainsAny(c.buf, " \t") {
		return
	}
	var matches []string
	for _, n := range commandNames() {
		if strings.HasPrefix(n, c.buf) {
			matches = append(matches, n)
		}
	}
	if len(matches) == 0 {
		return
	}
	prefix := matches[0]
	for _, n := range matches[1:] {
		for !strings.HasPrefix(n, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	c.buf = prefix
}

func (m *Model) onKeyCmdline(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := m.cmdline
	switch k.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.cmdline = nil
	case tea.KeyEnter:
		m.cmdline = nil
		return m, m.runCommand(c.buf)
	case tea.KeyTab:
		c.complete()
	default:
		c.edit(k)
	}
	return m, nil
}

// runCommand executa a linha digitada. Comando desconhecido nao faz nada alem de avisar.
func (m *Model) runCommand(line string) tea.Cmd {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil
	}
	fn, ok := commands[f[0]]
	if !ok {
		valid := make([]string, 0, len(commands))
		for _, n := range commandNames() {
			valid = append(valid, ":"+n)
		}
		return m.setStatus(fmt.Sprintf("comando desconhecido: %s (use %s)", f[0], strings.Join(valid, ", ")), true)
	}
	return fn(m, f[1:])
}

// argsError recusa argumentos num comando que nao os aceita.
func (m *Model) argsError(name string) tea.Cmd {
	return m.setStatus(fmt.Sprintf("o comando %s não aceita argumentos", name), true)
}

// cmdQuit fecha a visao atual: o detalhe do alerta, se aberto, ou a propria TUI (como o :q do vim).
func (m *Model) cmdQuit(args []string) tea.Cmd {
	if len(args) > 0 {
		return m.argsError("q")
	}
	if m.detail != nil {
		m.detail = nil
		return nil
	}
	return m.quit()
}

// cmdStop encerra o modulo selecionado.
func (m *Model) cmdStop(args []string) tea.Cmd {
	if len(args) > 0 {
		return m.argsError("stop")
	}
	mod := m.selectedModule()
	if mod == nil {
		return m.setStatus("nenhum módulo selecionado", true)
	}
	return tea.Batch(m.send(mod.IdModulo, psychoscopev1.ComandoControle_ENCERRAR, "encerrar "+mod.IdModulo),
		m.setStatus("encerrando "+mod.IdModulo+"…", false))
}

// moduleCommand envia acao ao modulo selecionado.
func (m *Model) moduleCommand(acao psychoscopev1.ComandoControle_TipoAcao, verb string) tea.Cmd {
	mod := m.selectedModule()
	if mod == nil {
		return m.setStatus("nenhum módulo selecionado", true)
	}
	return m.send(mod.IdModulo, acao, verb+mod.IdModulo)
}

// quit fecha o stream de alertas e encerra a TUI.
func (m *Model) quit() tea.Cmd {
	if m.stream != nil {
		m.stream.Close()
	}
	return tea.Quit
}

// cmdlineFooter e o texto do rodape enquanto o comando e digitado; mostra o modulo-alvo
// dos comandos que agem no modulo selecionado.
func (m *Model) cmdlineFooter() string {
	line := ":" + m.cmdline.buf + "█"
	if m.cmdline.actsOnModule() {
		if mod := m.selectedModule(); mod != nil {
			return line + dimStyle.Render("   → "+mod.IdModulo)
		}
		return line + errStyle.Render("   nenhum módulo selecionado")
	}
	return line
}

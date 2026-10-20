package tui

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// Run abre a TUI em tela cheia e bloqueia ate o usuario sair.
func Run(b Backend) error {
	p := tea.NewProgram(NewModel(b), tea.WithAltScreen(), tea.WithOutput(os.Stdout))
	_, err := p.Run()
	return err
}

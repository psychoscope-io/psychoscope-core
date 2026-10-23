package tui

import (
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

// lineEditor e um editor de uma linha de texto: digitar, espaco, Backspace e colar. Quem o
// usa (a linha de comando, e a edicao de um valor de configuracao) trata as demais teclas
// (Enter, Esc, Tab).
type lineEditor struct{ buf string }

// edit aplica a tecla se for de edicao e informa se foi. Caracteres de controle (a quebra de
// linha de um texto colado, por exemplo) sao descartados.
func (e *lineEditor) edit(k tea.KeyMsg) bool {
	switch k.Type {
	case tea.KeyBackspace:
		if r := []rune(e.buf); len(r) > 0 {
			e.buf = string(r[:len(r)-1])
		}
	case tea.KeySpace:
		e.buf += " "
	case tea.KeyRunes:
		e.buf += printable(k.Runes)
	default:
		return false
	}
	return true
}

// printable descarta caracteres de controle.
func printable(rs []rune) string {
	var b strings.Builder
	for _, r := range rs {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

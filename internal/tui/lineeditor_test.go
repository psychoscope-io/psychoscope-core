package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestLineEditorEditsAndIgnoresOtherKeys(t *testing.T) {
	var e lineEditor
	for _, k := range []tea.KeyMsg{key("a"), key("b"), key("space"), {Type: tea.KeyRunes, Runes: []rune("cd")}} {
		if !e.edit(k) {
			t.Fatalf("%v e tecla de edicao", k)
		}
	}
	if e.buf != "ab cd" {
		t.Fatalf("buf=%q", e.buf)
	}
	e.edit(key("backspace"))
	if e.buf != "ab c" {
		t.Fatalf("backspace: %q", e.buf)
	}
	for _, k := range []tea.KeyMsg{key("enter"), key("esc"), key("tab"), key("up"), key("ctrl+c")} {
		if e.edit(k) {
			t.Errorf("%v nao e tecla de edicao", k)
		}
	}
	if e.buf != "ab c" {
		t.Fatalf("teclas que nao sao de edicao nao alteram o texto: %q", e.buf)
	}
}

func TestLineEditorHandlesUnicodeAndPastedControlCharacters(t *testing.T) {
	var e lineEditor
	e.edit(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ação")})
	e.edit(key("backspace")) // apaga uma runa, nao um byte
	if e.buf != "açã" {
		t.Fatalf("backspace em UTF-8: %q", e.buf)
	}
	e.edit(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a\nb\tc\x1b"), Paste: true})
	if e.buf != "açãabc" {
		t.Fatalf("controle descartado: %q", e.buf)
	}
	var empty lineEditor
	empty.edit(key("backspace")) // sem efeito e sem panico
	if empty.buf != "" {
		t.Fatalf("backspace no vazio: %q", empty.buf)
	}
}

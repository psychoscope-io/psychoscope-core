package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"google.golang.org/protobuf/types/known/timestamppb"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func burstAlert() *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{
		IdAlerta: "id-123", Regra: "net.dns.nxdomain_burst", Severidade: psychoscopev1.Severidade_SEVERIDADE_MEDIA,
		Descricao:      "Rajada de NXDOMAIN (possivel DGA): 192.168.0.8 recebeu 10 respostas para 10 dominios distintos em 30s",
		Timestamp:      timestamppb.New(time.Date(2026, 10, 20, 22, 3, 56, 0, time.UTC)),
		IdModuloOrigem: "mod-net-sensor",
		Contexto: map[string]string{
			"cliente":          "192.168.0.8",
			"dominios_exemplo": "1.0.17.172.in-addr.arpa,1.0.18.172.in-addr.arpa,1.0.19.172.in-addr.arpa,1.0.20.172.in-addr.arpa,1.0.21.172.in-addr.arpa",
			"evento_ts":        "2026-10-20T22:03:55.5Z",
		},
	}
}

func modelWithAlerts(t *testing.T, w, h int, alerts ...*psychoscopev1.Alerta) *Model {
	t.Helper()
	m, _, _ := newTestModel(t)
	m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	for i := len(alerts) - 1; i >= 0; i-- { // o mais novo entra por ultimo e fica no topo
		m.Update(alertMsg{alerts[i]})
	}
	m.Update(key("tab"))
	return m
}

func TestEnterOpensDetailOnlyOnAlertsPanel(t *testing.T) {
	m := modelWithAlerts(t, 100, 30, burstAlert())
	m.Update(key("tab")) // volta ao painel de modulos
	m.Update(key("enter"))
	if m.detail != nil {
		t.Fatal("Enter no painel de modulos nao abre detalhe")
	}
	m.Update(key("tab"))
	m.Update(key("enter"))
	if m.detail == nil || m.detail.a.IdAlerta != "id-123" {
		t.Fatalf("detail=%+v", m.detail)
	}

	empty, _, _ := newTestModel(t)
	empty.Update(key("tab"))
	empty.Update(key("enter"))
	if empty.detail != nil {
		t.Fatal("sem alertas nao ha o que abrir")
	}
}

func TestDetailShowsEveryField(t *testing.T) {
	m := modelWithAlerts(t, 100, 30, burstAlert())
	m.Update(key("enter"))
	v := plain(m)
	for _, want := range []string{
		"Alerta · Rajada de NXDOMAIN",
		"Regra", "Rajada de NXDOMAIN (net.dns.nxdomain_burst)",
		"ATT&CK", "T1568.002 Dynamic Resolution: Domain Generation Algorithms",
		"Severidade", "MEDIA",
		"Detectado", "2026-10-20T22:03:56Z",
		"Evento", "2026-10-20T22:03:55Z",
		"Módulo", "mod-net-sensor",
		"ID", "id-123",
		"Descrição",
		"Contexto", "Cliente", "192.168.0.8",
		"Domínios de exemplo", "1.0.17.172.in-addr.arpa,", "1.0.21.172.in-addr.arpa",
		"Esc, Enter, q ou :q fecham",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("detalhe sem %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "evento_ts") {
		t.Errorf("o instante do evento ja aparece como campo proprio:\n%s", v)
	}
	// a descricao e longa e quebra em varias linhas; remontada, tem de ser identica ao original
	if got := descriptionOnScreen(v); got != burstAlert().Descricao {
		t.Errorf("descricao remontada = %q, esperado %q", got, burstAlert().Descricao)
	}
}

// descriptionOnScreen junta as linhas entre os titulos "Descrição" e "Contexto".
func descriptionOnScreen(view string) string {
	var parts []string
	in := false
	for _, l := range strings.Split(view, "\n") {
		l = strings.TrimSpace(strings.Trim(strings.TrimSpace(l), "│"))
		switch {
		case l == "Descrição":
			in = true
		case l == "Contexto":
			in = false
		case in && l != "":
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, " ")
}

func TestDetailOmitsAttackWhenTheRuleHasNone(t *testing.T) {
	a := burstAlert()
	a.Regra = "net.dns.rate"
	m := modelWithAlerts(t, 100, 30, a)
	m.Update(key("enter"))
	if v := plain(m); strings.Contains(v, "ATT&CK") {
		t.Errorf("net.dns.rate nao tem tecnica equivalente:\n%s", v)
	}
}

func TestDetailKeepsInvalidEventTimeInContext(t *testing.T) {
	a := burstAlert()
	a.Contexto["evento_ts"] = "ontem"
	m := modelWithAlerts(t, 100, 30, a)
	m.Update(key("enter"))
	v := plain(m)
	if !strings.Contains(v, "evento_ts") || !strings.Contains(v, "ontem") || strings.Contains(v, "Evento ") {
		t.Fatalf("valor invalido deve continuar na tabela de contexto:\n%s", v)
	}
}

func TestDetailCloseKeysDoNotQuit(t *testing.T) {
	for _, k := range []string{"esc", "enter", "q"} {
		m := modelWithAlerts(t, 100, 30, burstAlert())
		m.Update(key("enter"))
		_, cmd := m.Update(key(k))
		if m.detail != nil || isQuit(cmd) {
			t.Fatalf("%s deve fechar o detalhe sem sair da TUI", k)
		}
		if !strings.Contains(plain(m), "Alertas (1)") {
			t.Fatalf("depois de fechar, a tela principal deve voltar:\n%s", plain(m))
		}
	}
}

func TestDetailScrollsAndClamps(t *testing.T) {
	a := burstAlert()
	for i := 0; i < 30; i++ {
		a.Contexto[fmt.Sprintf("campo%02d", i)] = fmt.Sprint("valor", i)
	}
	m := modelWithAlerts(t, 100, 14, a) // pouco espaco: precisa rolar
	m.Update(key("enter"))
	if strings.Contains(plain(m), "campo29") {
		t.Fatal("o fim nao deveria estar visivel antes de rolar")
	}
	if !strings.Contains(plain(m), "linhas 1-") {
		t.Fatalf("titulo deve indicar o trecho:\n%s", plain(m))
	}
	m.Update(key("up")) // ja no topo
	if m.detail.scroll != 0 {
		t.Fatalf("scroll=%d", m.detail.scroll)
	}
	m.Update(key("G"))
	if !strings.Contains(plain(m), "campo29") || m.detail.scroll != m.detailMaxScroll() {
		t.Fatalf("G deve ir ao fim:\n%s", plain(m))
	}
	m.Update(key("down")) // ja no fim
	if m.detail.scroll != m.detailMaxScroll() {
		t.Fatal("rolagem nao pode passar do fim")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	if m.detail.scroll >= m.detailMaxScroll() {
		t.Fatal("PgUp deve subir")
	}
	m.Update(key("g"))
	if m.detail.scroll != 0 {
		t.Fatal("g deve ir ao topo")
	}
}

func TestDetailStaysOnTheSameAlertWhenNewOnesArrive(t *testing.T) {
	m := modelWithAlerts(t, 100, 30, burstAlert())
	m.Update(key("enter"))
	for i := 0; i < 5; i++ {
		m.Update(alertMsg{alert(fmt.Sprint("novo", i), "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_ALTA)})
	}
	if m.detail == nil || m.detail.a.IdAlerta != "id-123" || !strings.Contains(plain(m), "id-123") {
		t.Fatalf("o detalhe deve continuar no alerta aberto:\n%s", plain(m))
	}
}

func TestDetailFitsEveryTerminalSize(t *testing.T) {
	a := burstAlert()
	a.Contexto["longo"] = strings.Repeat("x", 500)
	m := modelWithAlerts(t, 100, 30, a)
	m.Update(key("enter"))
	for _, size := range [][2]int{{40, 12}, {60, 20}, {80, 24}, {120, 40}, {200, 60}, {10, 5}} {
		m.Update(tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m.Update(key("G")) // pior caso: rolado ao fim
		lines := strings.Split(m.View(), "\n")
		if len(lines) != max(size[1], 12) {
			t.Errorf("%v: %d linhas, esperado %d", size, len(lines), max(size[1], 12))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > max(size[0], 40) {
				t.Errorf("%v linha %d com %d colunas: %q", size, i, w, ansi.Strip(l))
			}
		}
	}
}

func TestWrapText(t *testing.T) {
	for _, tc := range []struct {
		in   string
		w    int
		want []string
	}{
		{"", 10, []string{""}},
		{"curto", 10, []string{"curto"}},
		{"uma frase que passa da largura", 12, []string{"uma frase", "que passa da", "largura"}},
		{"aaa.com,bbb.com,ccc.com", 12, []string{"aaa.com,", "bbb.com,", "ccc.com"}}, // um item por trecho, sem cortar nomes
		{"abcdefghij", 4, []string{"abcd", "efgh", "ij"}},                            // token maior que a linha
		{"ab cdefghij", 4, []string{"ab", "cdef", "ghij"}},
	} {
		got := wrapText(tc.in, tc.w)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("wrapText(%q, %d) = %q, esperado %q", tc.in, tc.w, got, tc.want)
		}
		for _, l := range got {
			if len([]rune(l)) > tc.w {
				t.Errorf("linha %q passa de %d colunas", l, tc.w)
			}
		}
	}
	if got := wrapText("qualquer coisa", 0); len(got) == 0 {
		t.Fatal("largura invalida ainda devolve linhas")
	}
}

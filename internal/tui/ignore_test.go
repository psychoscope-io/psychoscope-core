package tui

import (
	"cmp"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func beaconTCPAlert(target string) *psychoscopev1.Alerta {
	a := alert("b1", "net.beacon", psychoscopev1.Severidade_SEVERIDADE_MEDIA)
	a.Contexto = map[string]string{"tipo": "tcp", "alvo": target, "origem": "192.168.0.8"}
	return a
}

// detailOf abre o detalhe do alerta num modelo com a configuracao de teste.
func detailOf(t *testing.T, readOnly bool, a *psychoscopev1.Alerta) (*Model, *fakeBackend) {
	t.Helper()
	m, be := settingsModel(t, readOnly)
	m.Update(streamOpenedMsg{s: &fakeStream{ch: make(chan *psychoscopev1.Alerta)}})
	m.Update(alertMsg{a})
	m.Update(key("tab"))
	m.Update(key("enter"))
	if m.detail == nil {
		t.Fatal("o detalhe deveria estar aberto")
	}
	return m, be
}

// settle entrega ao modelo as mensagens dos comandos e, em cascata, as dos comandos que elas
// geram (a atualizacao do detalhe depois de gravar, por exemplo).
func settle(m *Model, cmd tea.Cmd) {
	for i := 0; i < 4 && cmd != nil; i++ {
		var next []tea.Cmd
		for _, msg := range exec(cmd) {
			_, c := m.Update(msg)
			next = append(next, c)
		}
		cmd = tea.Batch(next...)
	}
}

func pressI(m *Model) {
	_, cmd := m.Update(key("i"))
	settle(m, cmd)
}

func TestIgnoreKeyAppendsTheSuggestedExceptionWithoutDroppingTheList(t *testing.T) {
	for name, tc := range map[string]struct {
		alert     *psychoscopev1.Alerta
		field     string
		wantList  string
		wantValue string
	}{
		"beacon tcp: IP, mantendo o que ja estava": {beaconTCPAlert("149.154.166.110:443"), "detection.beacon.ignore_destinations",
			`["10.0.0.0/8","149.154.166.110"]`, "149.154.166.110"},
		"beacon tcp IPv6": {beaconTCPAlert("2001:67c:4e8:f004::9:443"), "detection.beacon.ignore_destinations",
			`["10.0.0.0/8","2001:67c:4e8:f004::9"]`, "2001:67c:4e8:f004::9"},
		"beacon dns": {func() *psychoscopev1.Alerta {
			a := alert("b2", "net.beacon", psychoscopev1.Severidade_SEVERIDADE_MEDIA)
			a.Contexto = map[string]string{"tipo": "dns", "alvo": "c2.evil.example"}
			return a
		}(), "detection.beacon.ignore_domains", `["c2.evil.example"]`, "c2.evil.example"},
		"bruteforce": {func() *psychoscopev1.Alerta {
			a := alert("f1", "net.bruteforce.auth", psychoscopev1.Severidade_SEVERIDADE_ALTA)
			a.Contexto = map[string]string{"origem": "10.0.0.66", "destino": "10.0.0.2", "porta": "22"}
			return a
		}(), "detection.bruteforce.ignore_sources", `["10.9.0.1","10.0.0.66"]`, "10.0.0.66"},
		"tunel DNS": {func() *psychoscopev1.Alerta {
			a := alert("t1", "net.dns.tunnel", psychoscopev1.Severidade_SEVERIDADE_ALTA)
			a.Contexto = map[string]string{"dominio_base": "evil-tunnel.com"}
			return a
		}(), "detection.tunnel.allowed_bases", `["evil-tunnel.com"]`, "evil-tunnel.com"},
	} {
		m, be := detailOf(t, false, tc.alert)
		pressI(m)
		if len(be.applies) != 1 || len(be.applies[0].patch) != 1 || be.applies[0].patch[tc.field] != tc.wantList || len(be.applies[0].restore) != 0 {
			t.Errorf("%s: pedido %+v, esperado %s=%s", name, be.applies, tc.field, tc.wantList)
			continue
		}
		if !strings.Contains(m.status, tc.wantValue+" acrescentado a «"+cmp.Or(sampleLabels[tc.field], tc.field)+"»") || m.statusErr {
			t.Errorf("%s: status=%q", name, m.status)
		}
		if m.detail == nil {
			t.Errorf("%s: o detalhe continua aberto", name)
		}
	}
}

func TestIgnoreKeyDoesNotDuplicate(t *testing.T) {
	m, be := detailOf(t, false, beaconTCPAlert("10.0.0.0:443")) // 10.0.0.0 NAO e o "10.0.0.0/8" da lista
	pressI(m)
	m2, be2 := detailOf(t, false, func() *psychoscopev1.Alerta {
		a := alert("f1", "net.bruteforce.auth", psychoscopev1.Severidade_SEVERIDADE_ALTA)
		a.Contexto = map[string]string{"origem": "10.9.0.1"} // ja esta em ignore_sources
		return a
	}())
	pressI(m2)
	if len(be2.applies) != 0 || !strings.Contains(m2.status, "10.9.0.1 já está em «Origens ignoradas»") || m2.statusErr {
		t.Fatalf("valor ja presente: nada gravado: applies=%d status=%q", len(be2.applies), m2.status)
	}
	if len(be.applies) != 1 { // o primeiro caso grava normalmente
		t.Fatalf("applies=%d", len(be.applies))
	}
}

func TestIgnoreKeyRefusesWithoutWritePermissionOrSuggestion(t *testing.T) {
	m, be := detailOf(t, true, beaconTCPAlert("149.154.166.110:443"))
	pressI(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "somente leitura") || !m.statusErr {
		t.Fatalf("somente leitura: applies=%d status=%q", len(be.applies), m.status)
	}

	// regra sem excecao sugerida (varredura): nem consulta a configuracao
	scan := alert("s1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA)
	m, be = detailOf(t, false, scan)
	be.cfgErr = errors.New("nao deveria ser consultada")
	pressI(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "não tem exceção sugerida") || m.statusErr {
		t.Fatalf("sem sugestao: applies=%d status=%q", len(be.applies), m.status)
	}
}

func TestIgnoreKeyShowsBackendErrors(t *testing.T) {
	m, be := detailOf(t, false, beaconTCPAlert("149.154.166.110:443"))
	be.applyErr = errors.New("detection.beacon.ignore_destinations: valor invalido")
	pressI(m)
	if !strings.Contains(m.status, "valor invalido") || !m.statusErr {
		t.Fatalf("erro do Core: %q", m.status)
	}
	m, be = detailOf(t, false, beaconTCPAlert("149.154.166.110:443"))
	be.cfgErr = errors.New("sem conexao")
	pressI(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "sem conexao") || !m.statusErr {
		t.Fatalf("falha ao ler a configuracao: %q", m.status)
	}
}

func TestDetailShowsWhatTheIKeyWillDo(t *testing.T) {
	m, _ := detailOf(t, false, beaconTCPAlert("2001:67c:4e8:f004::9:443"))
	v := plain(m)
	for _, want := range []string{"Ação", "tecla i: ignorar 2001:67c:4e8:f004::9, acrescentando-o a «detection.beacon.ignore_destinations»", "i ignorar"} {
		if !strings.Contains(v, want) {
			t.Errorf("detalhe sem %q:\n%s", want, v)
		}
	}
	// alerta de regra sem excecao: nao ha secao Acao
	m, _ = detailOf(t, false, alert("s1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA))
	if strings.Contains(plain(m), "tecla i: ignorar") {
		t.Fatalf("sem sugestao nao ha secao Ação:\n%s", plain(m))
	}
}

// detailLoaded abre o detalhe como a pessoa faria (Enter) e entrega ao modelo o estado da
// excecao lido da configuracao.
func detailLoaded(t *testing.T, readOnly bool, a *psychoscopev1.Alerta) (*Model, *fakeBackend) {
	t.Helper()
	m, be := settingsModel(t, readOnly)
	m.Update(streamOpenedMsg{s: &fakeStream{ch: make(chan *psychoscopev1.Alerta)}})
	m.Update(alertMsg{a})
	m.Update(key("tab"))
	_, cmd := m.Update(key("enter"))
	feed(m, exec(cmd)...)
	if m.detail == nil || !m.detail.ignore.known {
		t.Fatalf("o detalhe deveria ter lido o estado da excecao: %+v", m.detail)
	}
	return m, be
}

func pressU(m *Model) {
	_, cmd := m.Update(key("u"))
	settle(m, cmd)
}

func bruteforceAlert(src string) *psychoscopev1.Alerta {
	a := alert("f9", "net.bruteforce.auth", psychoscopev1.Severidade_SEVERIDADE_ALTA)
	a.Contexto = map[string]string{"origem": src, "destino": "10.0.0.2", "porta": "22"}
	return a
}

func TestDetailShowsWhetherTheValueIsAlreadyIgnored(t *testing.T) {
	// 10.9.0.1 esta em ignore_sources: ja ignorado, a tecla u desfaz
	m, _ := detailLoaded(t, false, bruteforceAlert("10.9.0.1"))
	v := plain(m)
	for _, want := range []string{"10.9.0.1 já está ignorado em «Origens ignoradas»", "Tecla u: voltar a monitorar"} {
		if !strings.Contains(v, want) {
			t.Errorf("detalhe sem %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "tecla i: ignorar") {
		t.Errorf("ja ignorado: nao oferece ignorar de novo:\n%s", v)
	}
	// 10.0.0.66 nao esta: oferece ignorar, com o nome legivel da lista
	m, _ = detailLoaded(t, false, bruteforceAlert("10.0.0.66"))
	if v := plain(m); !strings.Contains(v, "tecla i: ignorar 10.0.0.66, acrescentando-o a «Origens ignoradas»") {
		t.Errorf("detalhe sem a oferta de ignorar:\n%s", v)
	}
	// somente leitura: o aviso vem no texto
	m, _ = detailLoaded(t, true, bruteforceAlert("10.0.0.66"))
	if v := plain(m); !strings.Contains(v, "Somente leitura: só o root altera") {
		t.Errorf("detalhe sem o aviso de somente leitura:\n%s", v)
	}
}

func TestUKeyRemovesTheValueFromTheListAndTheDetailUpdates(t *testing.T) {
	m, be := detailLoaded(t, false, bruteforceAlert("10.9.0.1"))
	pressU(m)
	if len(be.applies) != 1 || be.applies[0].patch["detection.bruteforce.ignore_sources"] != "[]" || len(be.applies[0].restore) != 0 {
		t.Fatalf("pedido: %+v", be.applies)
	}
	if !strings.Contains(m.status, "10.9.0.1 removido de «Origens ignoradas»: volta a ser monitorado") || m.statusErr {
		t.Fatalf("status=%q", m.status)
	}
	if m.detail == nil || m.detail.ignore.exact {
		t.Fatalf("o detalhe deveria refletir a remocao: %+v", m.detail)
	}
	if v := plain(m); !strings.Contains(v, "tecla i: ignorar 10.9.0.1") {
		t.Errorf("depois de remover, oferece ignorar de novo:\n%s", v)
	}
	// o ciclo fecha: i volta a acrescentar
	pressI(m)
	if got := be.applies[len(be.applies)-1].patch["detection.bruteforce.ignore_sources"]; got != `["10.9.0.1"]` {
		t.Fatalf("i depois de u: %s", got)
	}
}

func TestUKeyKeepsTheOtherItemsOfTheList(t *testing.T) {
	m, be := detailLoaded(t, false, beaconTCPAlert("1.2.3.4:443"))
	pressI(m) // lista passa a ["10.0.0.0/8","1.2.3.4"]
	pressU(m)
	if got := be.applies[len(be.applies)-1].patch["detection.beacon.ignore_destinations"]; got != `["10.0.0.0/8"]` {
		t.Fatalf("u remove so o valor do alerta: %s", got)
	}
}

func TestUKeyWhenTheValueIsNotInTheListWritesNothing(t *testing.T) {
	m, be := detailLoaded(t, false, bruteforceAlert("10.0.0.66"))
	pressU(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "10.0.0.66 não está em «Origens ignoradas»") || m.statusErr {
		t.Fatalf("applies=%d status=%q", len(be.applies), m.status)
	}
}

func TestCoveredByANetworkNeitherAddsNorRemoves(t *testing.T) {
	// 10.0.0.0/8 esta em ignore_destinations: 10.9.9.9 ja e ignorado por ele
	m, be := detailLoaded(t, false, beaconTCPAlert("10.9.9.9:443"))
	v := plain(m)
	if !strings.Contains(v, "10.9.9.9 já é ignorado por «10.0.0.0/8» em «Destinos ignorados»") || !strings.Contains(v, ":config") {
		t.Fatalf("detalhe do valor coberto:\n%s", v)
	}
	pressI(m)
	pressU(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "já é ignorado por «10.0.0.0/8»") {
		t.Fatalf("coberto por CIDR: nada a gravar: applies=%d status=%q", len(be.applies), m.status)
	}
}

func TestUKeyRefusesWithoutWritePermissionAndWithoutSuggestion(t *testing.T) {
	m, be := detailLoaded(t, true, bruteforceAlert("10.9.0.1"))
	pressU(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "somente leitura") || !m.statusErr {
		t.Fatalf("somente leitura: applies=%d status=%q", len(be.applies), m.status)
	}
	m, be = detailOf(t, false, alert("s1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA))
	pressU(m)
	if len(be.applies) != 0 || !strings.Contains(m.status, "não tem exceção sugerida") {
		t.Fatalf("sem sugestao: applies=%d status=%q", len(be.applies), m.status)
	}
}

func TestDetailWithoutAnAnswerFromTheCoreKeepsTheGenericAction(t *testing.T) {
	m, be := settingsModel(t, false)
	be.cfgErr = errors.New("sem conexao")
	m.Update(streamOpenedMsg{s: &fakeStream{ch: make(chan *psychoscopev1.Alerta)}})
	m.Update(alertMsg{bruteforceAlert("10.9.0.1")})
	m.Update(key("tab"))
	_, cmd := m.Update(key("enter"))
	feed(m, exec(cmd)...)
	if m.detail == nil || m.detail.ignore.known {
		t.Fatalf("sem resposta do Core o estado fica desconhecido: %+v", m.detail)
	}
	if v := plain(m); !strings.Contains(v, "tecla i: ignorar 10.9.0.1") {
		t.Errorf("o texto generico continua:\n%s", v)
	}
}

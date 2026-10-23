package tui

import (
	"errors"
	"strings"
	"testing"

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

func pressI(m *Model) {
	_, cmd := m.Update(key("i"))
	feed(m, exec(cmd)...)
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
		if !strings.Contains(m.status, tc.wantValue+" acrescentado a "+tc.field) || m.statusErr {
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
	if len(be2.applies) != 0 || !strings.Contains(m2.status, "10.9.0.1 já está em detection.bruteforce.ignore_sources") || m2.statusErr {
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
	for _, want := range []string{"Ação", "tecla i: acrescenta 2001:67c:4e8:f004::9 a detection.beacon.ignore_destinations", "i ignorar"} {
		if !strings.Contains(v, want) {
			t.Errorf("detalhe sem %q:\n%s", want, v)
		}
	}
	// alerta de regra sem excecao: nao ha secao Acao
	m, _ = detailOf(t, false, alert("s1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_MEDIA))
	if strings.Contains(plain(m), "tecla i: acrescenta") {
		t.Fatalf("sem sugestao nao ha secao Ação:\n%s", plain(m))
	}
}

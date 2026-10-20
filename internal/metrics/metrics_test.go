package metrics

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestWriteTextFormat(t *testing.T) {
	ms := Gather(func() []*psychoscopev1.Metrica {
		return []*psychoscopev1.Metrica{
			Gauge("psychoscope_module_up", "Modulo conectado (1/0).", 1, "module", "mod-b"),
			Counter("psychoscope_events_total", "Eventos \\ processados\nem total.", 42),
			Gauge("psychoscope_module_up", "Modulo conectado (1/0).", 0, "module", "mod-a"),
			Gauge("psychoscope_weird", "", math.Inf(1), "k", "a\"b\\c\nd"),
			Gauge("nome com espaco!", "x", math.NaN()),
		}
	})
	var b bytes.Buffer
	if err := WriteText(&b, ms); err != nil {
		t.Fatal(err)
	}
	want := `# HELP nome_com_espaco_ x
# TYPE nome_com_espaco_ gauge
nome_com_espaco_ NaN
# HELP psychoscope_events_total Eventos \\ processados\nem total.
# TYPE psychoscope_events_total counter
psychoscope_events_total 42
# HELP psychoscope_module_up Modulo conectado (1/0).
# TYPE psychoscope_module_up gauge
psychoscope_module_up{module="mod-a"} 0
psychoscope_module_up{module="mod-b"} 1
# TYPE psychoscope_weird gauge
psychoscope_weird{k="a\"b\\c\nd"} +Inf
`
	if b.String() != want {
		t.Fatalf("saida diferente.\n--- obtido\n%s--- esperado\n%s", b.String(), want)
	}
}

func TestGatherIsDeterministic(t *testing.T) {
	g := func() []*psychoscopev1.Metrica {
		return []*psychoscopev1.Metrica{Gauge("b", "", 1), Gauge("a", "", 2, "x", "2"), Gauge("a", "", 3, "x", "1")}
	}
	got := Gather(g, nil)
	if got[0].Nome != "a" || got[0].Rotulos["x"] != "1" || got[2].Nome != "b" {
		t.Fatalf("ordem: %v", got)
	}
}

func TestHTTPEndpoint(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, Handler(func() []*psychoscopev1.Metrica { return []*psychoscopev1.Metrica{Counter("x_total", "h", 7)} }))
	}()
	base := "http://" + ln.Addr().String()

	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") ||
		!strings.Contains(string(body), "x_total 7") {
		t.Fatalf("GET /metrics: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if resp, _ := http.Post(base+"/metrics", "text/plain", strings.NewReader("x")); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST deve ser 405: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(base + "/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/ deve ser 404: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(base + "/metrics/../secret"); resp.StatusCode == 200 {
		t.Errorf("caminho inesperado nao pode servir metricas")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve nao terminou")
	}
	if _, err := http.Get(base + "/metrics"); err == nil {
		t.Fatal("servidor deveria estar fechado")
	}
}

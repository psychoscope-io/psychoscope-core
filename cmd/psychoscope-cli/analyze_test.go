package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestMain deixa o binario de teste fazer o papel de sensor falso (PSY_FAKE_SENSOR=modo): o
// padrao do internal/testmod, aqui com os argumentos reais do sensor (--socket=...).
func TestMain(m *testing.M) {
	if mode := os.Getenv("PSY_FAKE_SENSOR"); mode != "" {
		fakeSensor(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const scanSource = "10.0.0.66"

// scanEvents devolve n SYNs de uma origem a portas distintas, 100 ms entre eles (tempo de 2023).
func scanEvents(n int) []*psychoscopev1.EventoFluxoRede {
	base := time.Unix(1_700_000_000, 0)
	out := make([]*psychoscopev1.EventoFluxoRede, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, &psychoscopev1.EventoFluxoRede{
			IpOrigem: scanSource, IpDestino: "10.0.0.2", PortaOrigem: 40000, PortaDestino: uint32(i), //nolint:gosec // i pequeno
			Protocolo: psychoscopev1.ProtocoloTransporte_PROTO_TCP, FlagsTcp: 0x02, TamanhoBytes: 60,
			TimestampCaptura: timestamppb.New(base.Add(time.Duration(i) * 100 * time.Millisecond)),
		})
	}
	return out
}

func fakeSensor(mode string) {
	var sock string
	for _, a := range os.Args[1:] {
		if v, ok := strings.CutPrefix(a, "--socket="); ok {
			sock = v
		}
	}
	switch mode {
	case "fail":
		os.Stderr.WriteString("o arquivo nao e um pcap valido\n")
		os.Exit(3)
	case "hang":
		time.Sleep(time.Minute)
		return
	}
	if mode == "reconnect" { // cai no meio do replay e volta (como o backoff do sensor real), mandando o resto
		fakeSession(sock, scanEvents(30)[:10])
		time.Sleep(150 * time.Millisecond) // o Core precisa ter encerrado a sessao anterior
		fakeSession(sock, scanEvents(30)[10:])
		return
	}
	if mode == "empty" {
		fakeSession(sock, nil)
		return
	}
	fakeSession(sock, scanEvents(30))
}

// fakeSession conecta, faz o Hello, envia os eventos e fecha a conexao.
func fakeSession(sock string, events []*psychoscopev1.EventoFluxoRede) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		os.Exit(10)
	}
	defer conn.Close()
	id := os.Getenv("PSYCHOSCOPE_MODULE_ID")
	_ = ipc.WriteMessage(conn, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Hello{Hello: &psychoscopev1.HelloModulo{
		IdModulo: id, VersaoProtocolo: ipc.ProtocolVersion, VersaoModulo: "fake", Pid: uint32(os.Getpid()), //nolint:gosec // pid positivo
	}}})
	if m, err := ipc.ReadMessage(conn, 0); err != nil || !m.GetHelloResposta().GetAceito() {
		os.Exit(11)
	}
	for _, ev := range events {
		_ = ipc.WriteMessage(conn, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Telemetria{Telemetria: &psychoscopev1.EventoTelemetria{
			IdModulo: id, Dado: &psychoscopev1.EventoTelemetria_Rede{Rede: ev},
		}}})
	}
}

// fakeSource entrega eventos prontos (ou falha depois deles), sem processo nem socket.
type fakeSource struct {
	events []*psychoscopev1.EventoFluxoRede
	err    error
}

func (f fakeSource) Stream(_ context.Context, _ string, emit func(string, *psychoscopev1.EventoFluxoRede) error) error {
	for _, ev := range f.events {
		if err := emit("mod-net-sensor", ev); err != nil {
			return err
		}
	}
	return f.err
}

// isolate aponta HOME e os diretorios XDG para um temporario e planta um overrides.json que, se
// fosse lido, desligaria a regra de varredura. Devolve o diretorio de estado do servico.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	state := filepath.Join(home, "state")
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", state)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	psy := filepath.Join(state, "psychoscope")
	if err := os.MkdirAll(psy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(psy, "overrides.json"), []byte(`{"detection": {"scan": {"vertical_ports": 1000}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return state
}

func writePcap(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.pcap")
	if err := os.WriteFile(p, []byte("conteudo qualquer: quem valida e o sensor"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runAnalyze(t *testing.T, src eventSource, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	r := analyzeRun{source: func(string) (eventSource, error) { return src, nil }}
	err := r.run(context.Background(), args, &out)
	return out.String(), err
}

func TestAnalyzeReportsAlertsWithEventTime(t *testing.T) {
	isolate(t)
	out, err := runAnalyze(t, fakeSource{events: scanEvents(30)}, writePcap(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"2023-11-14 22:13:21Z [MEDIA] net.scan.syn:", // instante do 15o SYN, nao o relogio
		"    portas_distintas=15",
		"eventos analisados: 30 (de 2023-11-14 22:13:20 a 2023-11-14 22:13:23, UTC)",
		"alertas: 1 (net.scan.syn=1)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q na saida:\n%s", want, out)
		}
	}
}

func TestAnalyzeIsDeterministicAndIgnoresServiceOverrides(t *testing.T) {
	state := isolate(t) // o overrides.json plantado exigiria 1000 portas: se fosse lido, nao haveria alerta
	pcap := writePcap(t)
	first, err := runAnalyze(t, fakeSource{events: scanEvents(30)}, pcap)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := runAnalyze(t, fakeSource{events: scanEvents(30)}, pcap)
	if first != second {
		t.Errorf("duas execucoes deram saidas diferentes (o motor deve comecar vazio):\n%s\n---\n%s", first, second)
	}
	if !strings.Contains(first, "net.scan.syn") {
		t.Errorf("o overrides.json do servico influenciou a analise:\n%s", first)
	}
	entries, _ := filepath.Glob(filepath.Join(state, "psychoscope", "*"))
	if len(entries) != 1 {
		t.Errorf("a analise criou arquivos no estado do servico: %v", entries)
	}
}

func TestAnalyzeSetBites(t *testing.T) {
	isolate(t)
	pcap := writePcap(t)
	events := fakeSource{events: scanEvents(30)}

	out, err := runAnalyze(t, events, "--set", "detection.scan.vertical_ports=31", pcap)
	if err != nil || !strings.Contains(out, "alertas: nenhum") {
		t.Fatalf("limiar acima das 30 portas devia silenciar o alerta: %v\n%s", err, out)
	}
	out, err = runAnalyze(t, events, pcap, "--set", "detection.scan.vertical_ports=30") // flag depois do arquivo
	if err != nil || !strings.Contains(out, "net.scan.syn=1") {
		t.Fatalf("limiar de 30 portas devia manter o alerta: %v\n%s", err, out)
	}
}

func TestAnalyzeSetErrors(t *testing.T) {
	isolate(t)
	pcap := writePcap(t)
	for _, tc := range []struct{ set, want string }{
		{"detection.scan.vertical_portas=1", "desconhecido"},
		{"vertical_ports=1", "desconhecido"},
		{"storage.max_alerts=5", "desconhecido"},
		{"detection.scan.vertical_ports=muitas", "numero inteiro"},
		{"detection.scan.vertical_ports", "campo=valor"},
		{"detection.scan.vertical_ports=-3", "vertical_ports"},
	} {
		_, err := runAnalyze(t, fakeSource{}, "--set", tc.set, pcap)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("--set %q: erro %v, esperava citar %q", tc.set, err, tc.want)
		}
	}
}

func TestAnalyzeRuleFilterJSONAndExitCode(t *testing.T) {
	isolate(t)
	pcap := writePcap(t)

	out, err := runAnalyze(t, fakeSource{events: scanEvents(30)}, "--json", "--rule", "net.beacon", pcap)
	if err != nil {
		t.Fatal(err)
	}
	var j jsonAnalysis
	if err := json.Unmarshal([]byte(out), &j); err != nil {
		t.Fatalf("saida nao e JSON: %v\n%s", err, out)
	}
	if j.Eventos != 30 || len(j.Alertas) != 0 || j.Filtro != "net.beacon" || j.Incompleta {
		t.Errorf("JSON inesperado: %+v", j)
	}

	out, err = runAnalyze(t, fakeSource{events: scanEvents(30)}, "--json", pcap)
	if err != nil {
		t.Fatalf("sem --fail-on-alert, alertas nao sao erro: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || len(j.Alertas) != 1 || j.Alertas[0].Contexto["origem"] != scanSource {
		t.Errorf("JSON sem o alerta: %v %+v", err, j)
	}

	if _, err := runAnalyze(t, fakeSource{events: scanEvents(30)}, "--fail-on-alert", pcap); !errors.Is(err, errAnalyzeAlerts) {
		t.Errorf("--fail-on-alert com alertas devia dar errAnalyzeAlerts, deu %v", err)
	}
	if _, err := runAnalyze(t, fakeSource{events: scanEvents(5)}, "--fail-on-alert", pcap); err != nil {
		t.Errorf("--fail-on-alert sem alertas devia passar: %v", err)
	}
}

func TestAnalyzeMaxAlerts(t *testing.T) {
	isolate(t)
	// duas origens distintas disparam dois alertas; o limite de 1 descarta e conta o outro
	events := scanEvents(30)
	other := scanEvents(30)
	for _, ev := range other {
		ev.IpOrigem = "10.0.0.67"
	}
	out, err := runAnalyze(t, fakeSource{events: append(events, other...)}, "--max-alerts", "1", writePcap(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "alertas: 1 ") || !strings.Contains(out, "1 alertas a mais foram descartados") {
		t.Errorf("limite de alertas nao aplicado:\n%s", out)
	}
}

func TestAnalyzeIncompleteReportsAlertsAndFails(t *testing.T) {
	isolate(t)
	out, err := runAnalyze(t, fakeSource{events: scanEvents(30), err: errors.New("o sensor falhou: arquivo truncado")}, writePcap(t))
	if err == nil || !strings.Contains(err.Error(), "arquivo truncado") {
		t.Fatalf("esperava erro do sensor, veio %v", err)
	}
	if !strings.Contains(out, "net.scan.syn") || !strings.Contains(out, "analise INCOMPLETA") {
		t.Errorf("o relatorio parcial devia sair marcado como incompleto:\n%s", out)
	}
}

func TestAnalyzeArgsAndFile(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "vazio.pcap")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "falta o arquivo"},
		{[]string{"a.pcap", "b.pcap"}, "um arquivo por vez"},
		{[]string{"--timeout", "0s", empty}, "--timeout"},
		{[]string{"--max-alerts", "0", empty}, "--max-alerts"},
		{[]string{"--rule", "net.nada", empty}, "desconhecida"},
		{[]string{"--nao-existe", empty}, "uso: analyze"},
		{[]string{filepath.Join(dir, "ausente.pcap")}, "nao consegui abrir"},
		{[]string{dir}, "nao e um arquivo comum"},
		{[]string{empty}, "esta vazio"},
	} {
		_, err := runAnalyze(t, fakeSource{}, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %v: erro %v, esperava citar %q", tc.args, err, tc.want)
		}
	}
}

// fakeSensorBin cria um "sensor" que re-executa este binario de teste no modo pedido.
func fakeSensorBin(t *testing.T, mode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "mod-net-sensor")
	script := "#!/bin/sh\nGORACE=atexit_sleep_ms=0 PSY_FAKE_SENSOR=" + mode + " exec '" + exe + "' \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // script de teste, precisa ser executavel
		t.Fatal(err)
	}
	return p
}

func sensorRun(bin string) analyzeRun {
	return analyzeRun{source: func(string) (eventSource, error) {
		return sensorSource{bin: bin, grace: 200 * time.Millisecond}, nil
	}}
}

func TestSensorSourceEndToEnd(t *testing.T) {
	isolate(t)
	var out bytes.Buffer
	if err := sensorRun(fakeSensorBin(t, "ok")).run(context.Background(), []string{writePcap(t)}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "eventos analisados: 30") || !strings.Contains(out.String(), "net.scan.syn=1") {
		t.Errorf("os 30 eventos do sensor falso nao chegaram ao motor:\n%s", out.String())
	}
}

func TestSensorSourceFailures(t *testing.T) {
	isolate(t)
	for _, tc := range []struct {
		mode, want string
		timeout    string
	}{
		{"fail", "o arquivo nao e um pcap valido", "1m"},
		{"hang", "passou de --timeout", "400ms"},
	} {
		var out bytes.Buffer
		start := time.Now()
		err := sensorRun(fakeSensorBin(t, tc.mode)).run(context.Background(), []string{"--timeout", tc.timeout, writePcap(t)}, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("modo %s: erro %v, esperava citar %q", tc.mode, err, tc.want)
		}
		if !strings.Contains(out.String(), "analise INCOMPLETA") {
			t.Errorf("modo %s: relatorio sem a marca de incompleto:\n%s", tc.mode, out.String())
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("modo %s: demorou %v (o sensor devia ser morto no prazo)", tc.mode, time.Since(start))
		}
	}
}

func TestSensorSourceNoEvents(t *testing.T) {
	isolate(t)
	var out bytes.Buffer
	if err := sensorRun(fakeSensorBin(t, "empty")).run(context.Background(), []string{writePcap(t)}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "eventos analisados: 0") {
		t.Errorf("pcap sem eventos devia ser dito claramente:\n%s", out.String())
	}
}

func TestSensorSourceReconnectKeepsAllEvents(t *testing.T) {
	isolate(t)
	for range 5 { // a perda dependia de a 2a sessao ainda estar sendo lida: repete para pegar a corrida
		var out bytes.Buffer
		if err := sensorRun(fakeSensorBin(t, "reconnect")).run(context.Background(), []string{writePcap(t)}, &out); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		if !strings.Contains(out.String(), "eventos analisados: 30 ") {
			t.Fatalf("os 30 eventos das duas sessoes deviam chegar:\n%s", out.String())
		}
	}
}

func TestSensorSourceFailureDoesNotWaitForGrace(t *testing.T) {
	isolate(t)
	r := analyzeRun{source: func(string) (eventSource, error) {
		return sensorSource{bin: fakeSensorBin(t, "fail"), grace: time.Minute}, nil
	}}
	start := time.Now()
	var out bytes.Buffer
	if err := r.run(context.Background(), []string{writePcap(t)}, &out); err == nil {
		t.Fatal("esperava erro do sensor")
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("sensor que falhou sem conectar esperou o grace (%v)", d)
	}
}

func TestSensorSourceRejectsLongSocketPath(t *testing.T) {
	isolate(t)
	long := filepath.Join(t.TempDir(), strings.Repeat("d", 90))
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", long)
	var out bytes.Buffer
	err := sensorRun(fakeSensorBin(t, "ok")).run(context.Background(), []string{writePcap(t)}, &out)
	if err == nil || !strings.Contains(err.Error(), "TMPDIR") {
		t.Errorf("caminho de socket longo devia dar erro acionavel citando TMPDIR: %v", err)
	}
}

func TestFindSensor(t *testing.T) {
	exe := func(dir string) string {
		p := filepath.Join(dir, sensorBinary)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // executavel de teste
			t.Fatal(err)
		}
		return p
	}
	empty := t.TempDir()
	t.Setenv("PATH", empty)

	if p, err := findSensor("/qualquer/caminho", empty); err != nil || p != "/qualquer/caminho" {
		t.Errorf("--sensor explicito deve ser usado como esta: %q %v", p, err)
	}
	_, err := findSensor("", empty)
	if err == nil || !strings.Contains(err.Error(), "--sensor") || !strings.Contains(err.Error(), empty) {
		t.Errorf("sem sensor, o erro deve orientar (--sensor e onde procurei): %v", err)
	}
	fallback := t.TempDir()
	want := exe(fallback)
	if p, err := findSensor("", fallback); err != nil || p != want {
		t.Errorf("devia achar no diretorio de fallback: %q %v", p, err)
	}
	onPath := t.TempDir()
	wantPath := exe(onPath)
	t.Setenv("PATH", onPath)
	if p, err := findSensor("", fallback); err != nil || p != wantPath {
		t.Errorf("o PATH vem antes do fallback: %q %v", p, err)
	}
}

func TestWaitDrainedWaitsForEverySession(t *testing.T) {
	h := newReplayHandler(nil, func() {})
	h.OnConnect(nil)
	h.OnDisconnect(nil, nil)
	h.OnConnect(nil) // o sensor reconectou: a 1a desconexao nao encerra a leitura

	done := make(chan struct{})
	go func() { h.waitDrained(context.Background(), time.Minute); close(done) }()
	select {
	case <-done:
		t.Fatal("waitDrained voltou com uma sessao ainda aberta")
	case <-time.After(100 * time.Millisecond):
	}
	h.OnDisconnect(nil, nil)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitDrained nao voltou depois da ultima sessao fechar")
	}

	none := newReplayHandler(nil, func() {})
	start := time.Now()
	none.waitDrained(context.Background(), 20*time.Millisecond) // nenhuma conexao: vale so o grace
	if time.Since(start) > 5*time.Second {
		t.Error("sem conexao, waitDrained devia voltar logo depois do grace")
	}
}

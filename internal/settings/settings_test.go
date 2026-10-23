package settings

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

type fakeLive struct {
	mu    sync.Mutex
	calls []*config.Config
	err   error
}

func (f *fakeLive) Apply(_ context.Context, c *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return f.err
}

func (f *fakeLive) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

// fixture monta uma base vinda de um arquivo do administrador e um Manager sobre um diretorio temporario.
type fixture struct {
	base *config.Config
	path string
	live *fakeLive
	logs *bytes.Buffer
	m    *Manager
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "psychoscope.json")
	body := `{"detection":{"beacon":{"ignore_ports":[123]}},"storage":{"retention_days":10}}`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := config.Env{Getenv: func(string) string { return "" }, Euid: 0, DirUsable: func(string) bool { return false }}
	base, err := config.Load([]string{"-config", cfg}, env)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{base: base, path: filepath.Join(dir, "state", "overrides.json"), live: &fakeLive{}, logs: &bytes.Buffer{}}
	f.m = f.open(t)
	return f
}

func (f *fixture) open(t *testing.T) *Manager {
	t.Helper()
	m, err := New(f.base, f.path, f.live, slog.New(slog.NewTextHandler(f.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *fixture) field(t *testing.T, path string) Field {
	t.Helper()
	fs, err := f.m.Fields()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range fs {
		if x.Path == path {
			return x
		}
	}
	t.Fatalf("campo %s ausente do catalogo", path)
	return Field{}
}

var root = Caller{UID: 0, PID: 4242}

func TestCatalogCoversEveryEditableFieldWithDocsTypesAndOrigins(t *testing.T) {
	f := newFixture(t)
	fs, err := f.m.Fields()
	if err != nil {
		t.Fatal(err)
	}
	rc := config.DefaultDetection().Rules
	want := 4 // detection.window, detection.disabled, storage.retention_days, storage.max_alerts
	for _, ptr := range rc.Sections() {
		want += reflect.TypeOf(ptr).Elem().NumField()
	}
	if len(fs) != want {
		t.Fatalf("catalogo com %d campos, esperado %d (todo campo de regra + 4)", len(fs), want)
	}
	seen := map[string]bool{}
	for _, x := range fs {
		if seen[x.Path] {
			t.Errorf("caminho repetido: %s", x.Path)
		}
		seen[x.Path] = true
		if x.Doc == "" || x.Type == 0 || x.Value == "" || x.Default == "" || x.Origin == 0 {
			t.Errorf("campo incompleto: %+v", x)
		}
	}
	for path, want := range map[string]struct {
		typ        FieldType
		value, def string
		origin     Origin
	}{
		"detection.window":                {TypeDuration, `"1m"`, `"1m"`, OriginDefault},
		"detection.scan.vertical_ports":   {TypeInt, "15", "15", OriginDefault},
		"detection.beacon.max_cv":         {TypeDecimal, "0.2", "0.2", OriginDefault},
		"detection.beacon.ignore_ports":   {TypeIntList, "[123]", "[]", OriginFile},
		"detection.beacon.ignore_domains": {TypeTextList, "[]", "[]", OriginDefault},
		"detection.disabled":              {TypeTextList, "[]", "[]", OriginDefault},
		"storage.retention_days":          {TypeInt, "10", "30", OriginFile},
		"detection.nxdomain.cooldown":     {TypeDuration, `"2m"`, `"2m"`, OriginDefault},
	} {
		got := f.field(t, path)
		if got.Type != want.typ || got.Value != want.value || got.Default != want.def || got.Origin != want.origin {
			t.Errorf("%s: %+v, esperado %+v", path, got, want)
		}
	}
}

func TestApplyValidatesWritesApplyLiveAndAudits(t *testing.T) {
	f := newFixture(t)
	res, err := f.m.Apply(context.Background(), map[string]string{
		"detection.scan.vertical_ports":        "30",
		"detection.beacon.ignore_destinations": `["149.154.160.0/20"]`,
	}, nil, Caller{UID: 0, PID: 777})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 2 || len(res.Warnings) != 0 {
		t.Fatalf("resultado: %+v", res)
	}
	if got := f.field(t, "detection.scan.vertical_ports"); got.Value != "30" || got.Origin != OriginOverride {
		t.Fatalf("valor atual e origem: %+v", got)
	}
	// aplicado ao vivo uma vez, com a configuracao efetiva nova
	if f.live.n() != 1 || f.live.calls[0].Detection.Rules.Scan.VerticalPorts != 30 {
		t.Fatalf("aplicacao ao vivo: %d chamadas", f.live.n())
	}
	// arquivo: modo 0600, sem temporarios sobrando, conteudo no formato aninhado
	st, err := os.Stat(f.path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("arquivo de ajustes: %v %v", st, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(f.path), ".overrides-*")); len(left) != 0 {
		t.Fatalf("temporarios sobraram: %v", left)
	}
	data, _ := os.ReadFile(f.path)
	if !strings.Contains(string(data), `"vertical_ports": 30`) || !strings.Contains(string(data), `"detection"`) {
		t.Fatalf("conteudo: %s", data)
	}
	// auditoria: uma linha por campo, com quem pediu, valor antigo e novo
	logs := f.logs.String()
	for _, want := range []string{"configuracao alterada", "uid=0", "pid=777", "campo=detection.scan.vertical_ports", "antes=15", "depois=30",
		"campo=detection.beacon.ignore_destinations"} {
		if !strings.Contains(logs, want) {
			t.Errorf("auditoria sem %q:\n%s", want, logs)
		}
	}
	// a partida seguinte enxerga os ajustes gravados
	again := f.open(t)
	if got := again.Effective().Detection.Rules.Scan.VerticalPorts; got != 30 {
		t.Fatalf("apos reabrir: %d", got)
	}
}

func TestApplyRejectsInvalidChangesWithoutWritingAnything(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		patch   map[string]string
		wantErr string
	}{
		"janela da regra maior que a do motor": {map[string]string{"detection.scan.window": `"5m"`}, "detection.window"},
		"limiar negativo":                      {map[string]string{"detection.scan.vertical_ports": "-3"}, "positivo"},
		"destino que nao e IP":                 {map[string]string{"detection.beacon.ignore_destinations": `["telegram"]`}, "ignore_destinations"},
		"tipo errado":                          {map[string]string{"detection.scan.vertical_ports": `"muitas"`}, "vertical_ports"},
		"json invalido":                        {map[string]string{"detection.scan.vertical_ports": `{`}, "JSON"},
		"regra inexistente":                    {map[string]string{"detection.disabled": `["net.inexistente"]`}, "net.inexistente"},
		"nao editavel: queue_size":             {map[string]string{"detection.queue_size": "1"}, "nao editavel"},
		"nao editavel: modulos":                {map[string]string{"modules": `[]`}, "nao editavel"},
		"nao editavel: caminho do banco":       {map[string]string{"storage.path": `"/etc/x"`}, "nao editavel"},
	} {
		if _, err := f.m.Apply(context.Background(), tc.patch, nil, root); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: erro %v, esperado conter %q", name, err, tc.wantErr)
		}
	}
	// um valor bom junto com um ruim: nada vale
	_, err := f.m.Apply(context.Background(), map[string]string{
		"detection.scan.vertical_ports": "30", "detection.scan.window": `"5m"`}, nil, root)
	if err == nil {
		t.Fatal("pedido parcialmente invalido deve falhar inteiro")
	}
	if _, statErr := os.Stat(f.path); statErr == nil {
		t.Fatal("nada pode ser gravado quando a validacao falha")
	}
	if f.live.n() != 0 || f.field(t, "detection.scan.vertical_ports").Value != "15" {
		t.Fatal("nada pode ser aplicado quando a validacao falha")
	}
	if strings.Contains(f.logs.String(), "configuracao alterada") {
		t.Fatal("pedido recusado nao gera auditoria de mudanca")
	}
}

func TestInterdependentFieldsChangeTogether(t *testing.T) {
	f := newFixture(t)
	if _, err := f.m.Apply(context.Background(), map[string]string{
		"detection.scan.window": `"5m"`, "detection.window": `"10m"`}, nil, root); err != nil {
		t.Fatalf("janelas coerentes no mesmo pedido: %v", err)
	}
	if got := f.field(t, "detection.window"); got.Value != `"10m"` {
		t.Fatalf("%+v", got)
	}
}

func TestRestoreReturnsToTheBaseAndRemovesTheFileWhenEmpty(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.Apply(ctx, map[string]string{"storage.retention_days": "99", "detection.beacon.ignore_ports": "[]"}, nil, root); err != nil {
		t.Fatal(err)
	}
	// restaurar volta ao valor da BASE (o arquivo do administrador), nao ao padrao do Core
	res, err := f.m.Apply(ctx, nil, []string{"storage.retention_days"}, root)
	if err != nil || len(res.Changes) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := f.field(t, "storage.retention_days"); got.Value != "10" || got.Origin != OriginFile {
		t.Fatalf("restaurar volta ao valor do arquivo do administrador: %+v", got)
	}
	if _, err := f.m.Apply(ctx, nil, []string{"detection.beacon.ignore_ports"}, root); err != nil {
		t.Fatal(err)
	}
	if got := f.field(t, "detection.beacon.ignore_ports"); got.Value != "[123]" {
		t.Fatalf("lista restaurada: %+v", got)
	}
	if _, err := os.Stat(f.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sem ajustes o arquivo deve ser removido: %v", err)
	}
	if _, err := f.m.Apply(ctx, map[string]string{"storage.max_alerts": "5"}, []string{"storage.max_alerts"}, root); err == nil {
		t.Fatal("ajustar e restaurar o mesmo campo no mesmo pedido e erro")
	}
	if _, err := f.m.Apply(ctx, nil, []string{"storage.path"}, root); err == nil {
		t.Fatal("restaurar campo fora do catalogo e erro")
	}
}

func TestNoOpApplyDoesNothing(t *testing.T) {
	f := newFixture(t)
	res, err := f.m.Apply(context.Background(), nil, nil, root)
	if err != nil || len(res.Changes) != 0 || f.live.n() != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := os.Stat(f.path); err == nil {
		t.Fatal("pedido vazio nao grava arquivo")
	}
}

func TestLiveFailureKeepsTheSettingsAndWarns(t *testing.T) {
	f := newFixture(t)
	f.live.err = errors.New("motor travado")
	res, err := f.m.Apply(context.Background(), map[string]string{"detection.scan.vertical_ports": "40"}, nil, root)
	if err != nil {
		t.Fatalf("gravou: nao e erro: %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "reinicie") {
		t.Fatalf("aviso: %+v", res.Warnings)
	}
	if _, err := os.Stat(f.path); err != nil {
		t.Fatal("o ajuste fica gravado")
	}
	if got := f.open(t).Effective().Detection.Rules.Scan.VerticalPorts; got != 40 {
		t.Fatalf("vale na proxima partida: %d", got)
	}
}

func TestNewFailsOnAnInvalidOverridesFileWithAnActionableMessage(t *testing.T) {
	f := newFixture(t)
	for name, body := range map[string]string{
		"json quebrado":      `{"detection":`,
		"campo nao editavel": `{"modules":[{"id":"x","path":"/bin/sh"}]}`,
		"valor invalido":     `{"detection":{"scan":{"vertical_ports":-1}}}`,
		"janela incoerente":  `{"detection":{"scan":{"window":"10m"}}}`,
	} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := New(f.base, f.path, f.live, nil)
		if err == nil || !strings.Contains(err.Error(), f.path) || !strings.Contains(err.Error(), "remova") {
			t.Errorf("%s: o erro deve citar o arquivo e dizer como sair do problema: %v", name, err)
		}
	}
}

func TestConcurrentAppliesAreSerialized(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = f.m.Apply(context.Background(), map[string]string{"detection.scan.vertical_ports": time.Duration(i).String()[:1]}, nil, root)
			_, _ = f.m.Fields()
		}(i)
	}
	wg.Wait()
	// o estado final e coerente com o arquivo gravado
	again := f.open(t)
	if got, want := again.Effective().Detection.Rules.Scan.VerticalPorts, f.m.Effective().Detection.Rules.Scan.VerticalPorts; got != want {
		t.Fatalf("arquivo (%d) e memoria (%d) divergem", got, want)
	}
}

func TestPersistFailureIsMarkedSoCallersDoNotLeakThePath(t *testing.T) {
	f := newFixture(t)
	// o Manager abre normalmente; depois o diretorio de estado vira um arquivo comum e a
	// gravacao passa a falhar (a leitura na partida ja tinha acontecido)
	stateDir := filepath.Dir(f.path)
	if err := os.WriteFile(stateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := f.m.Apply(context.Background(), map[string]string{"detection.scan.vertical_ports": "40"}, nil, root)
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("falha de gravacao deve ser ErrPersist: %v", err)
	}
	if f.live.n() != 0 || f.m.Effective().Detection.Rules.Scan.VerticalPorts != 15 {
		t.Fatal("sem gravar, nada e aplicado")
	}
}

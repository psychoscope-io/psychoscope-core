package ctl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/settings"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

type fakeSettings struct {
	mu      sync.Mutex
	patches []map[string]string
	restore [][]string
	callers []settings.Caller
	err     error
	warn    []string
}

func (f *fakeSettings) Fields() ([]settings.Field, error) {
	return []settings.Field{
		{Path: "detection.scan.vertical_ports", Type: settings.TypeInt, Value: "15", Default: "15", Origin: settings.OriginDefault, Doc: "Portas."},
		{Path: "detection.window", Type: settings.TypeDuration, Value: `"1m"`, Default: `"1m"`, Origin: settings.OriginFile, Doc: "Janela."},
		{Path: "detection.beacon.ignore_ports", Type: settings.TypeIntList, Value: "[123]", Default: "[]", Origin: settings.OriginOverride, Label: "Portas ignoradas", Doc: "Portas ignoradas."},
	}, nil
}

func (f *fakeSettings) OverridesPath() string { return "/var/lib/psychoscope/overrides.json" }

func (f *fakeSettings) Apply(_ context.Context, patch map[string]string, restore []string, who settings.Caller) (settings.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.patches, f.restore, f.callers = append(f.patches, patch), append(f.restore, restore), append(f.callers, who)
	return settings.Result{Warnings: f.warn}, f.err
}

func (f *fakeSettings) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.patches) }

func withSettings(t *testing.T, fs *fakeSettings, admin func(uint32) bool) *Client {
	t.Helper()
	c, _ := startWith(t, func(cfg *Config) {
		if fs != nil {
			cfg.Settings = fs
		}
		cfg.Admin = admin
	})
	return c
}

func allow(uint32) bool { return true }
func deny(uint32) bool  { return false }

func TestReadConfigReturnsFieldsAndReadOnlyFlag(t *testing.T) {
	ctx := context.Background()
	l, err := withSettings(t, &fakeSettings{}, deny).Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !l.SomenteLeitura || len(l.Campos) != 3 || l.ArquivoAjustes == "" {
		t.Fatalf("quem nao e admin le em modo somente leitura: %+v", l)
	}
	f := l.Campos[2]
	if f.Caminho != "detection.beacon.ignore_ports" || f.Tipo != psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO ||
		f.ValorAtual != "[123]" || f.ValorPadrao != "[]" || f.Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE || f.Descricao == "" || f.Rotulo != "Portas ignoradas" {
		t.Fatalf("campo convertido: %+v", f)
	}
	if l.Campos[1].Tipo != psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO || l.Campos[1].Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO ||
		l.Campos[0].Tipo != psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO || l.Campos[0].Origem != psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO {
		t.Fatalf("tipos e origens: %+v", l.Campos)
	}

	l, err = withSettings(t, &fakeSettings{}, allow).Config(ctx)
	if err != nil || l.SomenteLeitura {
		t.Fatalf("admin nao fica em modo leitura: %+v %v", l, err)
	}
}

func TestApplyConfigIsDeniedToNonAdminsBeforeAnyInterpretation(t *testing.T) {
	fs := &fakeSettings{}
	c := withSettings(t, fs, deny)
	_, err := c.ApplyConfig(context.Background(), map[string]string{"detection.scan.vertical_ports": "30"}, []string{"detection.window"})
	if err == nil || !strings.Contains(err.Error(), "somente o root") {
		t.Fatalf("esperado recusa com mensagem acionavel: %v", err)
	}
	if fs.calls() != 0 {
		t.Fatal("o pedido nao pode chegar ao gerenciador de ajustes")
	}
	// um pedido vazio ou hostil tambem e recusado pela autorizacao, nao pela validacao
	if _, err := c.ApplyConfig(context.Background(), nil, nil); err == nil || !strings.Contains(err.Error(), "somente o root") {
		t.Fatalf("pedido vazio: %v", err)
	}
	// a leitura continua permitida
	if _, err := c.Config(context.Background()); err != nil {
		t.Fatalf("leitura: %v", err)
	}
}

func TestApplyConfigPassesTheKernelCredentialsAndReturnsTheUpdatedList(t *testing.T) {
	fs := &fakeSettings{warn: []string{"gravado, mas reinicie"}}
	c := withSettings(t, fs, allow)
	l, err := c.ApplyConfig(context.Background(), map[string]string{"detection.scan.vertical_ports": "30"}, []string{"detection.window"})
	if err != nil {
		t.Fatal(err)
	}
	if fs.calls() != 1 || fs.patches[0]["detection.scan.vertical_ports"] != "30" || fs.restore[0][0] != "detection.window" {
		t.Fatalf("pedido repassado: %v %v", fs.patches, fs.restore)
	}
	// quem pediu e identificado pelo kernel (SO_PEERCRED): este processo
	if fs.callers[0].UID != uint32(os.Geteuid()) || fs.callers[0].PID != int32(os.Getpid()) {
		t.Fatalf("credenciais: %+v", fs.callers[0])
	}
	if len(l.Campos) != 3 || len(l.Avisos) != 1 || l.Avisos[0] != "gravado, mas reinicie" {
		t.Fatalf("resposta: %+v", l)
	}
}

func TestApplyConfigErrors(t *testing.T) {
	fs := &fakeSettings{err: errors.New("detection.scan.window: 5m maior que detection.window")}
	c := withSettings(t, fs, allow)
	_, err := c.ApplyConfig(context.Background(), map[string]string{"x": "1"}, nil)
	if err == nil || err.Error() != fs.err.Error() {
		t.Fatalf("erro de validacao volta como veio, citando o campo: %v", err)
	}

	// falha de gravacao: a resposta e generica; o caminho do arquivo nao vaza
	fs.err = fmt.Errorf("%w em /var/lib/psychoscope/overrides.json: permission denied", settings.ErrPersist)
	_, err = c.ApplyConfig(context.Background(), map[string]string{"x": "1"}, nil)
	if err == nil || strings.Contains(err.Error(), "/var/lib") || strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "log do Core") {
		t.Fatalf("erro interno nao pode vazar detalhes: %v", err)
	}
}

func TestConfigUnavailableWithoutBackend(t *testing.T) {
	c := withSettings(t, nil, allow)
	for name, call := range map[string]func() error{
		"ler": func() error { _, err := c.Config(context.Background()); return err },
		"aplicar": func() error {
			_, err := c.ApplyConfig(context.Background(), map[string]string{"a": "1"}, nil)
			return err
		},
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "indisponivel") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDefaultAdminIsRootOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("o teste pressupoe um usuario comum")
	}
	c, _ := startWith(t, func(cfg *Config) { cfg.Settings = &fakeSettings{} }) // sem Admin: padrao
	if _, err := c.ApplyConfig(context.Background(), map[string]string{"a": "1"}, nil); err == nil || !strings.Contains(err.Error(), "somente o root") {
		t.Fatalf("o padrao deve ser somente root: %v", err)
	}
	l, err := c.Config(context.Background())
	if err != nil || !l.SomenteLeitura {
		t.Fatalf("usuario comum le em modo somente leitura: %+v %v", l, err)
	}
}

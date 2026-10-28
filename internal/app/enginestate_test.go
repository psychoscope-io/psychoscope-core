package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
)

func stateCfg(dir, statePath string) *config.Config {
	cfg := scanCfg(dir)
	cfg.Storage = config.Storage{Enabled: true, Path: filepath.Join(dir, "state", "alerts.db"), RetentionDays: 30, MaxAlerts: 1000}
	cfg.EngineStatePath = statePath
	return cfg
}

func metricValue(t *testing.T, cl *ctl.Client, name string) float64 {
	t.Helper()
	ms, err := cl.Metrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.GetNome() == name {
			return m.GetValor()
		}
	}
	return -1
}

func waitMetricAtLeast(t *testing.T, cl *ctl.Client, name string, want float64) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if metricValue(t, cl, name) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s < %v", name, want)
}

// O cooldown do motor sobrevive a um reinicio: o modulo falso reenvia a mesma varredura (mesmos
// instantes) e o alerta nao se repete. Sem o arquivo de estado, o mesmo trafego alerta de novo.
func TestEngineStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "engine-state.json")
	cl := &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}

	stop := startDaemon(t, stateCfg(dir, statePath))
	waitAlerts(t, cl, 1)
	stop()
	fi, err := os.Stat(statePath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("o estado deve ser gravado no encerramento com modo 0600: %v %v", fi, err)
	}

	stop = startDaemon(t, stateCfg(dir, statePath)) // segunda vida: o mesmo trafego, com o estado restaurado
	waitMetricAtLeast(t, cl, "psychoscope_engine_events_processed_total", 30)
	if n := len(waitAlerts(t, cl, 1)); n != 1 {
		t.Fatalf("o cooldown restaurado deve suprimir o alerta repetido: %d alertas", n)
	}
	if got := metricValue(t, cl, "psychoscope_engine_alerts_suppressed_total"); got < 1 {
		t.Fatalf("os eventos deveriam ter sido suprimidos pelo cooldown restaurado: %v", got)
	}
	stop()

	// controle: sem o arquivo, o mesmo trafego gera um alerta novo
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	startDaemon(t, stateCfg(dir, statePath))
	waitAlerts(t, cl, 2)
}

// Um arquivo corrompido nao impede a partida: o motor comeca vazio, detecta e o proximo
// salvamento o substitui por um arquivo valido.
func TestCorruptEngineStateDoesNotBlockStartup(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "engine-state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(`{"versao":1,"cooldowns":[{"regra":`), 0o600); err != nil {
		t.Fatal(err)
	}
	cl := &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}
	stop := startDaemon(t, stateCfg(dir, statePath))
	waitAlerts(t, cl, 1)
	stop()
	raw, err := os.ReadFile(statePath)
	if err != nil || len(raw) < 20 || raw[len(raw)-1] != '}' {
		t.Fatalf("o salvamento final deve substituir o arquivo corrompido: %v %q", err, raw)
	}
}

// Com o snapshot periodico ligado, o estado chega ao disco sem esperar o encerramento.
func TestEngineStateIsSavedPeriodically(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "engine-state.json")
	cfg := stateCfg(dir, statePath)
	cfg.EngineStateInterval = 50 * time.Millisecond
	cl := &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}
	startDaemon(t, cfg)
	waitAlerts(t, cl, 1)
	waitMetricAtLeast(t, cl, "psychoscope_engine_state_saves_total", 1)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("o snapshot periodico deveria ter criado o arquivo: %v", err)
	}
	if got := metricValue(t, cl, "psychoscope_engine_state_save_errors_total"); got != 0 {
		t.Fatalf("erros de gravacao: %v", got)
	}
}

// Um limiar editado no arquivo de configuracao entre duas partidas faz a regra recomecar vazia
// (como em Reconfigure): o cooldown antigo nao pode esconder o efeito do ajuste. Uma regra
// inalterada, ou so com cooldown/excecoes diferentes, mantem o estado.
func TestEngineStateIsDroppedForRulesWithAChangedThreshold(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "engine-state.json")
	cl := &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}

	stop := startDaemon(t, stateCfg(dir, statePath))
	waitAlerts(t, cl, 1)
	stop()

	same := stateCfg(dir, statePath)
	same.Detection.Rules.Scan.Cooldown = 2 * time.Minute // cooldown nao invalida o estado
	stop = startDaemon(t, same)
	waitMetricAtLeast(t, cl, "psychoscope_engine_events_processed_total", 30)
	if n := len(waitAlerts(t, cl, 1)); n != 1 {
		t.Fatalf("so o cooldown mudou, o estado vale: %d alertas", n)
	}
	stop()

	tuned := stateCfg(dir, statePath)
	tuned.Detection.Rules.Scan.VerticalPorts = 14 // limiar ajustado: a varredura recomeca sem cooldown
	startDaemon(t, tuned)
	waitAlerts(t, cl, 2)
}

// Uma partida sem nenhum evento processado nao reescreve o arquivo: ele fica como foi gravado,
// com o instante original, em vez de ser renovado a cada reinicio sem trafego.
func TestShutdownWithoutEventsKeepsTheStateFileUntouched(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state", "engine-state.json")
	cl := &ctl.Client{Path: filepath.Join(dir, "ctl.sock")}
	stop := startDaemon(t, stateCfg(dir, statePath))
	waitAlerts(t, cl, 1)
	stop()
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	idle := stateCfg(dir, statePath)
	idle.Modules = nil // nenhum modulo: o motor nao processa nada
	stop = startDaemon(t, idle)
	stop()
	after, err := os.ReadFile(statePath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("o arquivo nao pode mudar sem eventos: %v", err)
	}
}

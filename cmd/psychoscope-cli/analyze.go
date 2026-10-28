package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/detection"
	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	"github.com/psychoscope-io/psychoscope-core/internal/settings"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const (
	analyzeUsage = "uso: analyze [--set detection.regra.campo=valor]... [--config caminho] [--rule regra] [--json]\n" +
		"               [--fail-on-alert] [--sensor caminho] [--timeout 5m] [--max-alerts N] arquivo.pcap"

	defaultAnalyzeTimeout   = 5 * time.Minute
	defaultAnalyzeMaxAlerts = 10_000
)

// errAnalyzeAlerts faz o processo sair com 2 quando --fail-on-alert foi pedido e houve alertas;
// o relatorio ja foi impresso, entao main nao repete a mensagem.
var errAnalyzeAlerts = errors.New("a analise encontrou alertas")

type analyzeOptions struct {
	pcap        string
	sets        []string
	config      string
	rule        string
	json        bool
	failOnAlert bool
	sensor      string
	timeout     time.Duration
	maxAlerts   int
}

// parseAnalyzeArgs aceita as flags antes ou depois do arquivo.
func parseAnalyzeArgs(args []string) (analyzeOptions, error) {
	o := analyzeOptions{timeout: defaultAnalyzeTimeout, maxAlerts: defaultAnalyzeMaxAlerts}
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Func("set", "", func(v string) error { o.sets = append(o.sets, v); return nil })
	fs.StringVar(&o.config, "config", "", "")
	fs.StringVar(&o.rule, "rule", "", "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.failOnAlert, "fail-on-alert", false, "")
	fs.StringVar(&o.sensor, "sensor", "", "")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "")
	fs.IntVar(&o.maxAlerts, "max-alerts", o.maxAlerts, "")
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return o, errors.New(analyzeUsage)
		}
		if fs.NArg() == 0 {
			break
		}
		if o.pcap != "" {
			return o, fmt.Errorf("analyze: so um arquivo por vez (recebi %q e %q)\n%s", o.pcap, fs.Arg(0), analyzeUsage)
		}
		o.pcap, rest = fs.Arg(0), fs.Args()[1:]
	}
	switch {
	case o.pcap == "":
		return o, errors.New("analyze: falta o arquivo pcap\n" + analyzeUsage)
	case o.timeout <= 0:
		return o, errors.New("analyze: --timeout deve ser positivo (por exemplo 5m)")
	case o.maxAlerts <= 0:
		return o, errors.New("analyze: --max-alerts deve ser positivo")
	case o.rule != "" && !slices.Contains(rules.AllNames(), o.rule):
		return o, fmt.Errorf("analyze: --rule %q desconhecida (regras: %s)", o.rule, strings.Join(rules.AllNames(), ", "))
	}
	return o, nil
}

// checkPcapFile recusa o que nao e um arquivo comum nao vazio (o conteudo, quem valida e o sensor).
func checkPcapFile(path string) error {
	st, err := os.Stat(path)
	switch {
	case err != nil:
		return fmt.Errorf("analyze: nao consegui abrir %s: %w", path, err)
	case !st.Mode().IsRegular():
		return fmt.Errorf("analyze: %s nao e um arquivo comum (passe um arquivo .pcap, nao um diretorio ou dispositivo)", path)
	case st.Size() == 0:
		return fmt.Errorf("analyze: %s esta vazio", path)
	}
	return nil
}

// analysisRules monta as regras da analise: padroes embutidos (ou o arquivo de --config), mais
// os --set. Nada vem do overrides.json do servico, e nada e gravado: o resultado so depende dos
// argumentos e do pcap.
func analysisRules(o analyzeOptions) ([]detection.Rule, time.Duration, error) {
	var args []string
	if o.config != "" {
		args = []string{"--config", o.config}
	}
	base, err := config.Load(args, config.OSEnv())
	if err != nil {
		return nil, 0, fmt.Errorf("analyze: configuracao: %w", err)
	}
	ov, err := parseSets(base, o.sets)
	if err != nil {
		return nil, 0, err
	}
	cfg, err := config.Layer(base, ov)
	if err != nil {
		return nil, 0, fmt.Errorf("analyze: --set: %w", err)
	}
	rs, err := rules.Build(cfg.Detection.Rules)
	if err != nil {
		return nil, 0, fmt.Errorf("analyze: regras: %w", err)
	}
	return rs, cfg.Detection.Window, nil
}

// parseSets converte "campo=valor" (o mesmo texto de `config set`) nos ajustes tipados.
// So campos de deteccao: o armazenamento nao existe numa analise.
func parseSets(base *config.Config, sets []string) (config.Overrides, error) {
	ov := config.Overrides{}
	if len(sets) == 0 {
		return ov, nil
	}
	fields, err := settings.Catalog(base, nil)
	if err != nil {
		return nil, fmt.Errorf("analyze: catalogo de campos: %w", err)
	}
	for _, s := range sets {
		path, text, ok := strings.Cut(s, "=")
		path = strings.TrimSpace(path)
		if !ok || path == "" {
			return nil, fmt.Errorf("analyze: --set %q deve ser campo=valor (por exemplo detection.beacon.max_cv=0.1)", s)
		}
		i := slices.IndexFunc(fields, func(f settings.Field) bool { return f.Path == path && strings.HasPrefix(f.Path, "detection.") })
		if i < 0 {
			return nil, fmt.Errorf("analyze: --set: campo %q desconhecido; os campos de regra seguem detection.<regra>.<campo> (veja docs/REGRAS.md)", path)
		}
		v, err := ctl.SettingFromText(fields[i], text)
		if err != nil {
			return nil, fmt.Errorf("analyze: --set: %w", err)
		}
		ov[path] = json.RawMessage(v)
	}
	return ov, nil
}

// collector guarda os alertas do motor em memoria, ate o limite, e so os da regra pedida.
type collector struct {
	rule string
	max  int

	mu     sync.Mutex
	alerts []*psychoscopev1.Alerta
	over   int
}

func (c *collector) Publish(a *psychoscopev1.Alerta) {
	if c.rule != "" && a.Regra != c.rule {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.alerts) >= c.max {
		c.over++
		return
	}
	c.alerts = append(c.alerts, a)
}

// analyzeRun reune o que a analise usa do mundo externo.
type analyzeRun struct {
	// source devolve a fonte de eventos para o sensor escolhido (os testes trocam por uma falsa).
	source func(sensor string) (eventSource, error)
}

func cmdAnalyze(ctx context.Context, args []string, out io.Writer) error {
	return analyzeRun{source: func(explicit string) (eventSource, error) {
		bin, err := findSensor(explicit, sensorUserDir)
		if err != nil {
			return nil, fmt.Errorf("analyze: %w", err)
		}
		return sensorSource{bin: bin}, nil
	}}.run(ctx, args, out)
}

func (r analyzeRun) run(ctx context.Context, args []string, out io.Writer) error {
	o, err := parseAnalyzeArgs(args)
	if err != nil {
		return err
	}
	if err := checkPcapFile(o.pcap); err != nil {
		return err
	}
	rs, window, err := analysisRules(o)
	if err != nil {
		return err
	}
	src, err := r.source(o.sensor)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	col := &collector{rule: o.rule, max: o.maxAlerts}
	eng := detection.NewEngine(detection.EngineConfig{Window: window}, rs, col)
	engCtx, stopEngine := context.WithCancel(context.Background())
	engDone := make(chan struct{})
	go func() { defer close(engDone); eng.Run(engCtx) }()

	an := analysis{File: o.pcap, RuleFilter: o.rule}
	streamErr := src.Stream(ctx, o.pcap, func(module string, ev *psychoscopev1.EventoFluxoRede) error {
		if err := eng.SubmitWait(ctx, module, ev); err != nil {
			return err
		}
		an.noteEvent(ev.GetTimestampCaptura())
		return nil
	})
	stopEngine() // Run esvazia a fila antes de voltar
	<-engDone

	col.mu.Lock()
	an.Alerts, an.OverLimit = col.alerts, col.over
	col.mu.Unlock()
	if streamErr != nil {
		streamErr = analyzeFailure(streamErr, o.timeout)
		an.Err = streamErr.Error()
	}

	if o.json {
		err = an.writeJSON(out)
	} else {
		an.writeText(out)
	}
	switch {
	case err != nil:
		return err
	case streamErr != nil:
		return fmt.Errorf("analyze: %w", streamErr)
	case o.failOnAlert && len(an.Alerts) > 0:
		return errAnalyzeAlerts
	}
	return nil
}

// analyzeFailure traduz o motivo de a leitura ter parado.
func analyzeFailure(err error, timeout time.Duration) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("passou de --timeout (%s); aumente o prazo ou reduza o arquivo", timeout)
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("interrompida")
	}
	return err
}

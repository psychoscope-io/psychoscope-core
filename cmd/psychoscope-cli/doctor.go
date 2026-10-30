package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
)

const (
	defaultConfigPath = "/etc/psychoscope/psychoscope.json"
	doctorUsage       = "uso: doctor [--sensor] [--json] [--config caminho]"
)

// errDoctorFailed faz o processo sair com 1 quando alguma verificacao falhou; o relatorio ja
// foi impresso, entao main nao repete a mensagem.
var errDoctorFailed = errors.New("doctor encontrou falhas")

type doctorOptions struct {
	sensor bool
	json   bool
	config string
}

func parseDoctorArgs(args []string) (doctorOptions, error) {
	var o doctorOptions
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.sensor, "sensor", false, "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.StringVar(&o.config, "config", defaultConfigPath, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return o, errors.New(doctorUsage)
	}
	return o, nil
}

// doctorRun reune o que as verificacoes usam: o canal de controle, o sistema e o relogio.
type doctorRun struct {
	cl     *ctl.Client
	env    doctorEnv
	now    func() time.Time
	xdgDir string // $XDG_RUNTIME_DIR, para reconhecer o caminho de socket que nao e o do servico
}

func cmdDoctor(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	return doctorRun{cl: cl, env: osDoctorEnv{}, now: time.Now, xdgDir: os.Getenv("XDG_RUNTIME_DIR")}.run(ctx, args, out)
}

func (d doctorRun) run(ctx context.Context, args []string, out io.Writer) error {
	opts, err := parseDoctorArgs(args)
	if err != nil {
		return err
	}
	rep := d.checkCore(ctx)
	if opts.sensor {
		rep = append(rep, d.checkSensors(ctx, opts.config)...)
	}
	if opts.json {
		err = rep.writeJSON(out)
	} else {
		rep.writeText(out)
	}
	if err != nil {
		return err
	}
	if fails, _ := rep.counts(); fails > 0 {
		return errDoctorFailed
	}
	return nil
}

// checkCore verifica o canal de controle, o servico, o Core e os modulos. Se o Core nao
// responde, o que depende dele e pulado em vez de repetir o mesmo erro.
func (d doctorRun) checkCore(ctx context.Context) report {
	mods, listErr := d.cl.List(ctx)
	var info sockInfo
	var infoErr error
	if listErr != nil {
		info, infoErr = d.env.SocketInfo(d.cl.Path)
	}
	xdg := d.xdgDir != "" && strings.HasPrefix(d.cl.Path, d.xdgDir)
	rep := report{checkSocket(d.cl.Path, listErr, info, infoErr, xdg)}
	state, ok := d.env.ServiceState(ctx, serviceUnit)
	if f, ok := checkService(state, ok, listErr == nil); ok {
		rep = append(rep, f)
	}
	if listErr != nil {
		return append(rep, finding{Level: levelSkip, Item: "Core, modulos e perdas", Detail: "nao verificado: o Core nao respondeu"})
	}
	if ms, err := d.cl.Metrics(ctx); err != nil {
		rep = append(rep, finding{Level: levelWarn, Item: "Core", Detail: "nao foi possivel ler as metricas: " + err.Error()})
	} else {
		rep = append(rep, checkCoreMetrics(ms))
	}
	return append(rep, checkModules(mods, d.now())...)
}

// checkSensors roda o `--check` de cada sensor declarado no arquivo de configuracao.
func (d doctorRun) checkSensors(ctx context.Context, configPath string) report {
	specs, err := d.env.Modules(configPath)
	if err != nil {
		return report{{Level: levelWarn, Item: "configuracao", Detail: truncate(err.Error(), maxSensorLine),
			Fix: "informe o arquivo com --config; ele costuma ser legivel so pelo grupo psychoscope (rode com sudo)"}}
	}
	var rep report
	for _, s := range specs {
		if s.External && s.ID == sensorBinary {
			rep = append(rep, externalSensorFinding(s))
		}
	}
	sensors := sensorModules(specs)
	if len(sensors) == 0 && len(rep) == 0 {
		return report{{Level: levelWarn, Item: "sensor", Detail: "nenhum modulo " + sensorBinary + " em " + configPath}}
	}
	for _, s := range sensors {
		rep = append(rep, launchedSensorFinding(s), finding{Item: "sensor " + s.ID,
			Detail: fmt.Sprintf("o --check roda como %s, nao como o servico; para reproduzir o servico: sudo -u psychoscope %s %s --check",
				currentUser(), s.Path, strings.Join(s.Args, " "))})
		out, runErr := d.env.SensorCheck(ctx, s.Path, s.Args)
		rep = append(rep, sensorFindings(s.ID, out, runErr)...)
	}
	return rep
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "o usuario atual"
}

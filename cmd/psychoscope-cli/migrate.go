package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

const (
	defaultSensorEnvPath = "/etc/psychoscope/sensor.env"
	defaultSensorUser    = "psychoscope-sensor"
	migrationBackupExt   = ".antes-da-migracao"
)

// cmdMigrateConfig atende "migrate-config": passa o sensor que o Core lancava (configuracao ate
// a 0.11) para o modulo externo da unit psychoscope-sensor.service. O install.sh chama este
// comando ao atualizar; nada e escrito se a conversao nao for fiel. Com --check, so valida: diz
// se a migracao seria feita e sai com erro se ela for recusada, sem escrever nada (o install.sh
// valida antes de instalar e migra depois dos binarios).
func cmdMigrateConfig(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "configuracao do Core")
	envPath := fs.String("sensor-env", defaultSensorEnvPath, "arquivo de ambiente do sensor")
	sensorUser := fs.String("user", defaultSensorUser, "usuario do servico do sensor")
	check := fs.Bool("check", false, "so valida a migracao, sem escrever nada")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return fmt.Errorf("uso: migrate-config [--check] [--config %s] [--sensor-env %s] [--user %s]", defaultConfigPath, defaultSensorEnvPath, defaultSensorUser)
	}
	if *check {
		plan, err := planMigration(*configPath, *sensorUser, out)
		if err == nil && plan.Mig.Changed {
			fmt.Fprintf(out, "a migracao de %s seria feita (nada foi escrito); rode sem --check para aplicar\n", *configPath)
		}
		return err
	}
	return migrateConfig(*configPath, *envPath, *sensorUser, out)
}

// migrationPlan e o que a migracao vai gravar; Mig.Changed falso significa que nao ha o que migrar.
type migrationPlan struct {
	Raw    []byte
	Mig    config.SensorMigration
	Mode   os.FileMode
	Backup string
}

// planMigration le a configuracao e decide a migracao sem escrever nada: recusa se a conversao nao
// for fiel ou se o backup de uma migracao anterior ainda existe.
func planMigration(configPath, sensorUser string, out io.Writer) (*migrationPlan, error) {
	raw, err := os.ReadFile(configPath) //nolint:gosec // caminho dado pelo operador (root) ou o padrao da instalacao
	if err != nil {
		return nil, err
	}
	mig, err := config.MigrateSensorToExternal(raw, sensorUser)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", configPath, err)
	}
	if !mig.Changed {
		fmt.Fprintf(out, "nada a migrar em %s: o sensor ja e um modulo externo (ou nao esta na configuracao)\n", configPath)
		return &migrationPlan{Raw: raw, Mig: mig}, nil
	}
	info, err := os.Stat(configPath)
	if err != nil {
		return nil, err
	}
	backup := configPath + migrationBackupExt
	if _, err := os.Stat(backup); err == nil {
		return nil, fmt.Errorf("%s ja existe: mova-o antes de migrar de novo (ele guarda a configuracao original)", backup)
	}
	return &migrationPlan{Raw: raw, Mig: mig, Mode: info.Mode().Perm(), Backup: backup}, nil
}

func migrateConfig(configPath, envPath, sensorUser string, out io.Writer) error {
	plan, err := planMigration(configPath, sensorUser, out)
	if err != nil {
		return err
	}
	if !plan.Mig.Changed {
		return nil
	}
	raw, mig, backup := plan.Raw, plan.Mig, plan.Backup
	// Se algo falhar antes de a configuracao ser regravada, o backup (possivelmente parcial) sai de
	// cena: com ele no lugar, repetir o comando seria recusado e a original ainda esta intacta.
	if err := os.WriteFile(backup, raw, plan.Mode); err != nil { //nolint:gosec // copia ao lado da configuracao, no caminho dado pelo operador (root)
		_ = os.Remove(backup)
		return fmt.Errorf("salvando a configuracao original: %w", err)
	}
	if err := writeSensorEnv(envPath, mig.SensorEnv, out); err != nil {
		_ = os.Remove(backup)
		return err
	}
	if err := os.WriteFile(configPath, mig.Config, plan.Mode); err != nil { //nolint:gosec // mantem o modo e o dono do arquivo original
		return fmt.Errorf("gravando %s (a original esta em %s): %w", configPath, backup, err)
	}
	fmt.Fprintf(out, "migrado: o sensor agora e o modulo externo %q em %s (a configuracao original ficou em %s)\n", sensorUser, configPath, backup)
	return nil
}

// writeSensorEnv grava o sensor.env so se ele ainda nao existe: um arquivo do operador nunca e
// sobrescrito, e nesse caso as linhas calculadas sao mostradas para ele conferir.
func writeSensorEnv(path string, lines []string, out io.Writer) error {
	if len(lines) == 0 {
		return nil
	}
	body := "# Gerado por psychoscope-cli migrate-config a partir de args e env do sensor na configuracao antiga.\n" +
		strings.Join(lines, "\n") + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640) //nolint:gosec // lido pelo systemd (root); sem segredo
	switch {
	case err == nil:
		_, werr := f.WriteString(body)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("gravando %s: %w", path, werr)
		}
		fmt.Fprintf(out, "gravado %s com os argumentos e o ambiente do sensor\n", path)
		return nil
	case errors.Is(err, os.ErrExist):
		fmt.Fprintf(out, "aviso: %s ja existe e foi mantido; confira se ele tem:\n  %s\n", path, strings.Join(lines, "\n  "))
		return nil
	}
	return fmt.Errorf("gravando %s: %w", path, err)
}

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
// comando ao atualizar; nada e escrito se a conversao nao for fiel.
func cmdMigrateConfig(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", defaultConfigPath, "configuracao do Core")
	envPath := fs.String("sensor-env", defaultSensorEnvPath, "arquivo de ambiente do sensor")
	sensorUser := fs.String("user", defaultSensorUser, "usuario do servico do sensor")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return fmt.Errorf("uso: migrate-config [--config %s] [--sensor-env %s] [--user %s]", defaultConfigPath, defaultSensorEnvPath, defaultSensorUser)
	}
	return migrateConfig(*configPath, *envPath, *sensorUser, out)
}

func migrateConfig(configPath, envPath, sensorUser string, out io.Writer) error {
	raw, err := os.ReadFile(configPath) //nolint:gosec // caminho dado pelo operador (root) ou o padrao da instalacao
	if err != nil {
		return err
	}
	mig, err := config.MigrateSensorToExternal(raw, sensorUser)
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	if !mig.Changed {
		fmt.Fprintf(out, "nada a migrar em %s: o sensor ja e um modulo externo (ou nao esta na configuracao)\n", configPath)
		return nil
	}
	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}
	backup := configPath + migrationBackupExt
	if _, err := os.Stat(backup); err == nil {
		return fmt.Errorf("%s ja existe: mova-o antes de migrar de novo (ele guarda a configuracao original)", backup)
	}
	if err := os.WriteFile(backup, raw, info.Mode().Perm()); err != nil { //nolint:gosec // copia ao lado da configuracao, no caminho dado pelo operador (root)
		return fmt.Errorf("salvando a configuracao original: %w", err)
	}
	if err := writeSensorEnv(envPath, mig.SensorEnv, out); err != nil {
		return err
	}
	if err := os.WriteFile(configPath, mig.Config, info.Mode().Perm()); err != nil { //nolint:gosec // mantem o modo e o dono do arquivo original
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

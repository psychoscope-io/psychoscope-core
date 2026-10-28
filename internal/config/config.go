// Package config concentra flags, variaveis de ambiente e arquivo JSON do Core.
//
// Precedencia (maior primeiro): flag > variavel de ambiente > arquivo > default.
// Organizacao: config.go (Load e Validate), env.go (ambiente e diretorios padrao),
// file.go (flags e esquema do arquivo), e uma secao por arquivo (modules, storage,
// metrics, detection). overlay.go aplica JSON estrito sobre structs.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	EnvSocket    = "PSYCHOSCOPE_SOCKET"
	EnvCtlSocket = "PSYCHOSCOPE_CTL_SOCKET"
)

// Config e a configuracao efetiva do Core.
type Config struct {
	SocketPath     string
	CtlSocketPath  string
	SocketMode     os.FileMode // 0600 ou 0660
	AllowUnmanaged bool        // aceita modulos nao lancados pelo supervisor (apenas checa UID)
	AllowedUIDs    []uint32    // alem do UID do Core e root
	StatusInterval time.Duration
	CommandTimeout time.Duration
	LogLevel       string
	Modules        []ModuleSpec
	Detection      Detection
	Storage        Storage
	Metrics        Metrics
	// OverridesPath e o arquivo de ajustes feitos pelo canal de controle (tela de
	// configuracoes e CLI), no diretorio de estado. Vazio desliga a configuracao em tempo
	// de execucao (os testes que montam Config a mao nao a usam).
	OverridesPath string
	// EngineStatePath e o arquivo onde o estado do motor (cooldowns e series do beacon) e salvo
	// para sobreviver a um reinicio, no diretorio de estado. Vazio desliga o recurso (os testes
	// que montam Config a mao nao o usam). EngineStateInterval e o intervalo do snapshot
	// periodico; 0 grava so no encerramento.
	EngineStatePath     string
	EngineStateInterval time.Duration
}

// Load interpreta args (sem o nome do programa) e produz a configuracao validada.
func Load(args []string, e Env) (*Config, error) {
	fl, err := parseFlags(args)
	if err != nil {
		return nil, err
	}
	fc, err := readFile(fl.config)
	if err != nil {
		return nil, err
	}

	dir := DefaultSocketDir(e)
	c := &Config{
		SocketPath:      firstNonEmpty(fl.socket, e.Getenv(EnvSocket), fc.Socket, filepath.Join(dir, "core.sock")),
		CtlSocketPath:   firstNonEmpty(fl.ctlSocket, e.Getenv(EnvCtlSocket), fc.CtlSocket, filepath.Join(dir, "ctl.sock")),
		SocketMode:      0o660,
		AllowUnmanaged:  fl.allowUnmanaged || fc.AllowUnmanaged,
		AllowedUIDs:     fc.AllowedUIDs,
		LogLevel:        firstNonEmpty(fl.logLevel, fc.LogLevel, "info"),
		Storage:         loadStorage(fc.Storage, e),
		Metrics:         Metrics{Listen: fc.Metrics.Listen, AllowNonLoopback: fc.Metrics.AllowNonLoopback},
		OverridesPath:   firstNonEmpty(fc.OverridesPath, filepath.Join(DefaultStateDir(e), "overrides.json")),
		EngineStatePath: firstNonEmpty(fc.EngineStatePath, filepath.Join(DefaultStateDir(e), "engine-state.json")),
	}
	if err := c.loadScalars(fc); err != nil {
		return nil, err
	}
	if c.Modules, err = loadModules(fc.Modules); err != nil {
		return nil, err
	}
	if c.Detection, err = loadDetection(fc.Detection); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

// loadScalars preenche modo do socket e prazos globais a partir do arquivo.
func (c *Config) loadScalars(fc fileConfig) (err error) {
	if fc.SocketMode != "" {
		m, perr := strconv.ParseUint(fc.SocketMode, 8, 32)
		if perr != nil {
			return fmt.Errorf("socket_mode invalido %q: %w", fc.SocketMode, perr)
		}
		c.SocketMode = os.FileMode(m)
	}
	if c.StatusInterval, err = parseDur("status_interval", fc.StatusInterval, 5*time.Second); err != nil {
		return err
	}
	if c.CommandTimeout, err = parseDur("command_timeout", fc.CommandTimeout, 5*time.Second); err != nil {
		return err
	}
	c.EngineStateInterval, err = parseDur("engine_state_interval", fc.EngineStateInterval, 60*time.Second)
	return err
}

// Validate verifica invariantes da configuracao.
func (c *Config) Validate() error {
	if err := c.validateCore(); err != nil {
		return err
	}
	for _, v := range []func() error{c.Storage.validate, c.Metrics.validate, c.Detection.validate} {
		if err := v(); err != nil {
			return err
		}
	}
	return validateModules(c.Modules)
}

func (c *Config) validateCore() error {
	if c.SocketPath == "" || c.CtlSocketPath == "" {
		return errors.New("socket e ctl-socket sao obrigatorios")
	}
	if c.SocketPath == c.CtlSocketPath {
		return errors.New("socket e ctl-socket devem ser diferentes")
	}
	if c.SocketMode != 0o600 && c.SocketMode != 0o660 {
		return fmt.Errorf("socket_mode %#o nao permitido (use 0600 ou 0660)", uint32(c.SocketMode))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level invalido: %q", c.LogLevel)
	}
	if c.StatusInterval <= 0 || c.CommandTimeout <= 0 {
		return errors.New("status_interval e command_timeout devem ser positivos")
	}
	if c.EngineStateInterval < 0 {
		return errors.New("engine_state_interval nao pode ser negativo (use 0 para gravar so no encerramento)")
	}
	return nil
}

func parseDur(name, s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s invalido %q: %w", name, s, err)
	}
	return d, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// Package config concentra flags, variaveis de ambiente e arquivo JSON do Core.
//
// Precedencia (maior primeiro): flag > variavel de ambiente > arquivo > default.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection/rules"
	"golang.org/x/sys/unix"
)

const (
	EnvSocket    = "PSYCHOSCOPE_SOCKET"
	EnvCtlSocket = "PSYCHOSCOPE_CTL_SOCKET"

	systemSocketDir = "/var/run/psychoscope"
)

var moduleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ModuleSpec descreve um modulo filho supervisionado.
type ModuleSpec struct {
	ID             string
	Path           string
	Args           []string
	Env            []string // "CHAVE=valor", somado ao ambiente minimo do filho
	MinBackoff     time.Duration
	MaxBackoff     time.Duration
	StableAfter    time.Duration // execucao longa o bastante para zerar o backoff
	ConnectTimeout time.Duration // tempo maximo para (re)conectar ao socket apos subir
	StopGrace      time.Duration // espera por saida apos ENCERRAR antes de SIGTERM/SIGKILL
}

// Storage configura a persistencia de alertas (SQLite).
type Storage struct {
	Enabled       bool
	Path          string
	RetentionDays int // 0 = nao remove por idade
	MaxAlerts     int // 0 = sem teto
}

// Metrics configura o endpoint opcional de metricas (formato Prometheus).
type Metrics struct {
	Listen           string // "" = desligado; ex.: 127.0.0.1:9464
	AllowNonLoopback bool
}

// Detection configura a janela deslizante, a fila do motor e os limiares das regras.
type Detection struct {
	Window    time.Duration
	MaxEvents int
	QueueSize int
	Rules     rules.Config
}

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
}

type fileModule struct {
	ID             string   `json:"id"`
	Path           string   `json:"path"`
	Args           []string `json:"args"`
	Env            []string `json:"env"`
	MinBackoff     string   `json:"restart_min_backoff"`
	MaxBackoff     string   `json:"restart_max_backoff"`
	StableAfter    string   `json:"stable_after"`
	ConnectTimeout string   `json:"connect_timeout"`
	StopGrace      string   `json:"stop_grace"`
}

type fileStorage struct {
	Enabled       *bool  `json:"enabled"`
	Path          string `json:"path"`
	RetentionDays *int   `json:"retention_days"`
	MaxAlerts     *int   `json:"max_alerts"`
}

type fileMetrics struct {
	Listen           string `json:"listen"`
	AllowNonLoopback bool   `json:"allow_non_loopback"`
}

// fileDetection guarda a secao "detection" bruta: os campos proprios sao tratados em
// loadDetection e cada secao de regra e sobreposta por overlayStruct (estrito).
type fileDetection struct{ raw map[string]json.RawMessage }

func (f *fileDetection) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &f.raw) }

type fileConfig struct {
	Socket         string        `json:"socket"`
	CtlSocket      string        `json:"ctl_socket"`
	SocketMode     string        `json:"socket_mode"`
	AllowUnmanaged bool          `json:"allow_unmanaged"`
	AllowedUIDs    []uint32      `json:"allowed_uids"`
	StatusInterval string        `json:"status_interval"`
	CommandTimeout string        `json:"command_timeout"`
	LogLevel       string        `json:"log_level"`
	Modules        []fileModule  `json:"modules"`
	Detection      fileDetection `json:"detection"`
	Storage        fileStorage   `json:"storage"`
	Metrics        fileMetrics   `json:"metrics"`
}

// Env abstrai o ambiente para tornar Load testavel.
type Env struct {
	Getenv    func(string) string
	Euid      int
	DirUsable func(dir string) bool // existe e e gravavel pelo processo
}

// OSEnv devolve o ambiente real do processo.
func OSEnv() Env {
	return Env{
		Getenv: os.Getenv,
		Euid:   os.Geteuid(),
		DirUsable: func(dir string) bool {
			st, err := os.Stat(dir)
			return err == nil && st.IsDir() && unix.Access(dir, unix.W_OK) == nil
		},
	}
}

// DefaultSocketDir escolhe o diretorio dos sockets: /var/run/psychoscope quando
// root ou quando ja existe e e gravavel (ex.: RuntimeDirectory= do systemd);
// senao $XDG_RUNTIME_DIR/psychoscope; senao /var/run/psychoscope.
func DefaultSocketDir(e Env) string {
	if e.Euid == 0 || e.DirUsable(systemSocketDir) {
		return systemSocketDir
	}
	if x := e.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "psychoscope")
	}
	return systemSocketDir
}

// Load interpreta args (sem o nome do programa) e produz a configuracao validada.
func Load(args []string, e Env) (*Config, error) {
	fs := flag.NewFlagSet("psychoscope", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		cfgPath   = fs.String("config", "", "arquivo de configuracao JSON")
		socket    = fs.String("socket", "", "socket dos modulos (core.sock)")
		ctlSocket = fs.String("ctl-socket", "", "socket de controle da CLI (ctl.sock)")
		unmanaged = fs.Bool("allow-unmanaged", false, "aceita modulos nao lancados pelo supervisor (dev)")
		logLevel  = fs.String("log-level", "", "debug|info|warn|error")
	)
	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("argumentos inesperados: %v", fs.Args())
	}

	var fc fileConfig
	if *cfgPath != "" {
		raw, err := os.ReadFile(*cfgPath)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fc); err != nil {
			return nil, fmt.Errorf("config %s: %w", *cfgPath, err)
		}
	}

	dir := DefaultSocketDir(e)
	c := &Config{
		SocketPath:     firstNonEmpty(*socket, e.Getenv(EnvSocket), fc.Socket, filepath.Join(dir, "core.sock")),
		CtlSocketPath:  firstNonEmpty(*ctlSocket, e.Getenv(EnvCtlSocket), fc.CtlSocket, filepath.Join(dir, "ctl.sock")),
		SocketMode:     0o660,
		AllowUnmanaged: *unmanaged || fc.AllowUnmanaged,
		AllowedUIDs:    fc.AllowedUIDs,
		LogLevel:       firstNonEmpty(*logLevel, fc.LogLevel, "info"),
	}

	var err error
	if fc.SocketMode != "" {
		m, perr := strconv.ParseUint(fc.SocketMode, 8, 32)
		if perr != nil {
			return nil, fmt.Errorf("socket_mode invalido %q: %w", fc.SocketMode, perr)
		}
		c.SocketMode = os.FileMode(m)
	}
	if c.StatusInterval, err = parseDur("status_interval", fc.StatusInterval, 5*time.Second); err != nil {
		return nil, err
	}
	if c.CommandTimeout, err = parseDur("command_timeout", fc.CommandTimeout, 5*time.Second); err != nil {
		return nil, err
	}
	for _, fm := range fc.Modules {
		m := ModuleSpec{ID: fm.ID, Path: fm.Path, Args: fm.Args, Env: fm.Env}
		for _, d := range []struct {
			name string
			in   string
			def  time.Duration
			out  *time.Duration
		}{
			{"restart_min_backoff", fm.MinBackoff, time.Second, &m.MinBackoff},
			{"restart_max_backoff", fm.MaxBackoff, 30 * time.Second, &m.MaxBackoff},
			{"stable_after", fm.StableAfter, 30 * time.Second, &m.StableAfter},
			{"connect_timeout", fm.ConnectTimeout, 15 * time.Second, &m.ConnectTimeout},
			{"stop_grace", fm.StopGrace, 10 * time.Second, &m.StopGrace},
		} {
			if *d.out, err = parseDur(fmt.Sprintf("modulo %q %s", fm.ID, d.name), d.in, d.def); err != nil {
				return nil, err
			}
		}
		c.Modules = append(c.Modules, m)
	}

	c.Storage = Storage{Enabled: true, Path: filepath.Join(DefaultStateDir(e), "alerts.db"), RetentionDays: 30, MaxAlerts: 100_000}
	if fc.Storage.Enabled != nil {
		c.Storage.Enabled = *fc.Storage.Enabled
	}
	if fc.Storage.Path != "" {
		c.Storage.Path = fc.Storage.Path
	}
	if fc.Storage.RetentionDays != nil {
		c.Storage.RetentionDays = *fc.Storage.RetentionDays
	}
	if fc.Storage.MaxAlerts != nil {
		c.Storage.MaxAlerts = *fc.Storage.MaxAlerts
	}
	c.Metrics = Metrics{Listen: fc.Metrics.Listen, AllowNonLoopback: fc.Metrics.AllowNonLoopback}

	if c.Detection, err = loadDetection(fc.Detection); err != nil {
		return nil, err
	}

	return c, c.Validate()
}

// DefaultStateDir escolhe o diretorio de dados persistentes: /var/lib/psychoscope quando
// root ou quando ja existe e e gravavel (ex.: StateDirectory= do systemd); senao
// $XDG_STATE_HOME/psychoscope ou ~/.local/state/psychoscope; senao /var/lib/psychoscope.
func DefaultStateDir(e Env) string {
	const system = "/var/lib/psychoscope"
	if e.Euid == 0 || e.DirUsable(system) {
		return system
	}
	if x := e.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "psychoscope")
	}
	if h := e.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".local", "state", "psychoscope")
	}
	return system
}

// DefaultDetection devolve a configuracao padrao do motor de deteccao.
func DefaultDetection() Detection {
	return Detection{Window: time.Minute, MaxEvents: 200_000, QueueSize: 4096, Rules: rules.Default()}
}

// loadDetection sobrepoe a secao "detection" do arquivo aos defaults. Chaves desconhecidas
// sao erro; cada secao de regra aceita apenas os campos da sua struct (tags json).
func loadDetection(f fileDetection) (Detection, error) {
	d := DefaultDetection()
	sections := d.Rules.Sections()
	keys := make([]string, 0, len(f.raw))
	for k := range f.raw {
		keys = append(keys, k)
	}
	sort.Strings(keys) // erros deterministicos
	for _, k := range keys {
		raw := f.raw[k]
		var err error
		switch k {
		case "window":
			var s string
			if err = json.Unmarshal(raw, &s); err == nil {
				d.Window, err = parseDur("detection.window", s, d.Window)
			}
		case "max_events":
			err = json.Unmarshal(raw, &d.MaxEvents)
		case "queue_size":
			err = json.Unmarshal(raw, &d.QueueSize)
		case "disabled":
			err = json.Unmarshal(raw, &d.Rules.Disabled)
		default:
			dst, ok := sections[k]
			if !ok {
				return d, fmt.Errorf("detection: campo desconhecido %q", k)
			}
			err = overlayStruct(raw, dst, "detection."+k)
		}
		if err != nil {
			return d, fmt.Errorf("detection.%s: %w", k, err)
		}
	}
	return d, nil
}

// Validate verifica invariantes da configuracao.
func (c *Config) Validate() error {
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
	if c.Storage.Enabled && c.Storage.Path == "" {
		return errors.New("storage.path e obrigatorio quando storage.enabled")
	}
	if c.Storage.RetentionDays < 0 || c.Storage.MaxAlerts < 0 {
		return errors.New("storage.retention_days e storage.max_alerts nao podem ser negativos")
	}
	if c.Metrics.Listen != "" {
		host, port, err := net.SplitHostPort(c.Metrics.Listen)
		if err != nil || port == "" {
			return fmt.Errorf("metrics.listen invalido %q (use host:porta)", c.Metrics.Listen)
		}
		if !c.Metrics.AllowNonLoopback && !isLoopbackHost(host) {
			return fmt.Errorf("metrics.listen %q nao e loopback; o endpoint nao tem autenticacao (defina metrics.allow_non_loopback para permitir)", c.Metrics.Listen)
		}
	}
	if c.Detection.MaxEvents <= 0 || c.Detection.QueueSize <= 0 {
		return errors.New("detection.max_events e detection.queue_size devem ser positivos")
	}
	if err := c.Detection.Rules.Validate(); err != nil {
		return err
	}
	longest := c.Detection.Rules.LongestWindow()
	if c.Detection.Window < longest {
		return fmt.Errorf("detection.window (%v) deve cobrir a maior janela de regra (%v)", c.Detection.Window, longest)
	}
	seen := map[string]bool{}
	for _, m := range c.Modules {
		if !moduleIDRe.MatchString(m.ID) {
			return fmt.Errorf("id de modulo invalido: %q", m.ID)
		}
		if seen[m.ID] {
			return fmt.Errorf("id de modulo duplicado: %q", m.ID)
		}
		seen[m.ID] = true
		if m.Path == "" {
			return fmt.Errorf("modulo %q: path obrigatorio", m.ID)
		}
		if m.MinBackoff <= 0 || m.MaxBackoff < m.MinBackoff {
			return fmt.Errorf("modulo %q: backoff invalido (min=%v max=%v)", m.ID, m.MinBackoff, m.MaxBackoff)
		}
		if m.ConnectTimeout <= 0 || m.StopGrace <= 0 || m.StableAfter <= 0 {
			return fmt.Errorf("modulo %q: timeouts devem ser positivos", m.ID)
		}
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

// ValidModuleID informa se id e um identificador de modulo aceitavel.
func ValidModuleID(id string) bool { return moduleIDRe.MatchString(id) }

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// StorageRetention devolve a retencao como duracao (0 = sem limite por idade).
func (s Storage) Retention() time.Duration { return time.Duration(s.RetentionDays) * 24 * time.Hour }

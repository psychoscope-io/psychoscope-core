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
	"os"
	"path/filepath"
	"regexp"
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

type fileScan struct {
	Window          string `json:"window"`
	VerticalPorts   int    `json:"vertical_ports"`
	HorizontalHosts int    `json:"horizontal_hosts"`
	Cooldown        string `json:"cooldown"`
}

type fileNX struct {
	Window       string `json:"window"`
	MinResponses int    `json:"min_responses"`
	MinDistinct  int    `json:"min_distinct"`
	Cooldown     string `json:"cooldown"`
}

type fileTunnel struct {
	Window       string   `json:"window"`
	MinQueries   int      `json:"min_queries"`
	MinLabelLen  int      `json:"min_label_len"`
	MinEntropy   float64  `json:"min_entropy"`
	AllowedBases []string `json:"allowed_bases"`
	Cooldown     string   `json:"cooldown"`
}

type fileDetection struct {
	Window    string     `json:"window"`
	MaxEvents int        `json:"max_events"`
	QueueSize int        `json:"queue_size"`
	Disabled  []string   `json:"disabled"`
	Scan      fileScan   `json:"scan"`
	NXDomain  fileNX     `json:"nxdomain"`
	Tunnel    fileTunnel `json:"tunnel"`
}

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

	if c.Detection, err = loadDetection(fc.Detection); err != nil {
		return nil, err
	}

	return c, c.Validate()
}

// DefaultDetection devolve a configuracao padrao do motor de deteccao.
func DefaultDetection() Detection {
	return Detection{Window: time.Minute, MaxEvents: 200_000, QueueSize: 4096, Rules: rules.Default()}
}

// loadDetection sobrepoe os campos informados aos defaults das regras.
func loadDetection(f fileDetection) (Detection, error) {
	d := DefaultDetection()
	var err error
	dur := func(name, in string, out *time.Duration) {
		if err != nil || in == "" {
			return
		}
		*out, err = parseDur("detection."+name, in, *out)
	}
	num := func(in int, out *int) {
		if in != 0 {
			*out = in
		}
	}
	dur("window", f.Window, &d.Window)
	num(f.MaxEvents, &d.MaxEvents)
	num(f.QueueSize, &d.QueueSize)
	r := &d.Rules
	r.Disabled = f.Disabled
	dur("scan.window", f.Scan.Window, &r.Scan.Window)
	dur("scan.cooldown", f.Scan.Cooldown, &r.Scan.Cooldown)
	num(f.Scan.VerticalPorts, &r.Scan.VerticalPorts)
	num(f.Scan.HorizontalHosts, &r.Scan.HorizontalHosts)
	dur("nxdomain.window", f.NXDomain.Window, &r.NXDomain.Window)
	dur("nxdomain.cooldown", f.NXDomain.Cooldown, &r.NXDomain.Cooldown)
	num(f.NXDomain.MinResponses, &r.NXDomain.MinResponses)
	num(f.NXDomain.MinDistinct, &r.NXDomain.MinDistinct)
	dur("tunnel.window", f.Tunnel.Window, &r.Tunnel.Window)
	dur("tunnel.cooldown", f.Tunnel.Cooldown, &r.Tunnel.Cooldown)
	num(f.Tunnel.MinQueries, &r.Tunnel.MinQueries)
	num(f.Tunnel.MinLabelLen, &r.Tunnel.MinLabelLen)
	if f.Tunnel.MinEntropy != 0 {
		r.Tunnel.MinEntropy = f.Tunnel.MinEntropy
	}
	r.Tunnel.AllowedBases = f.Tunnel.AllowedBases
	return d, err
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
	if c.Detection.MaxEvents <= 0 || c.Detection.QueueSize <= 0 {
		return errors.New("detection.max_events e detection.queue_size devem ser positivos")
	}
	if err := c.Detection.Rules.Validate(); err != nil {
		return err
	}
	longest := max(c.Detection.Rules.Scan.Window, c.Detection.Rules.NXDomain.Window, c.Detection.Rules.Tunnel.Window)
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

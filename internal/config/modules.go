package config

import (
	"fmt"
	"regexp"
	"time"
)

var userNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var moduleIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidModuleID informa se id e um identificador de modulo aceitavel.
func ValidModuleID(id string) bool { return moduleIDRe.MatchString(id) }

// ModuleSpec descreve um modulo supervisionado: um filho lancado pelo Core (Path) ou, com
// External, um processo que o systemd (ou o operador) mantem e que so se conecta ao socket.
type ModuleSpec struct {
	ID             string
	External       bool   // nao e lancado pelo Core: so se autentica pelo UID do usuario User
	User           string // External: usuario do servico, conferido por SO_PEERCRED
	Path           string
	Args           []string
	Env            []string // "CHAVE=valor", somado ao ambiente minimo do filho
	MinBackoff     time.Duration
	MaxBackoff     time.Duration
	StableAfter    time.Duration // execucao longa o bastante para zerar o backoff
	ConnectTimeout time.Duration // tempo maximo para (re)conectar ao socket apos subir
	StopGrace      time.Duration // espera por saida apos ENCERRAR antes de SIGTERM/SIGKILL
}

type fileModule struct {
	ID             string   `json:"id"`
	External       bool     `json:"external"`
	User           string   `json:"user"`
	Path           string   `json:"path"`
	Args           []string `json:"args"`
	Env            []string `json:"env"`
	MinBackoff     string   `json:"restart_min_backoff"`
	MaxBackoff     string   `json:"restart_max_backoff"`
	StableAfter    string   `json:"stable_after"`
	ConnectTimeout string   `json:"connect_timeout"`
	StopGrace      string   `json:"stop_grace"`
}

// loadModules converte os modulos do arquivo aplicando os defaults de prazo.
func loadModules(fms []fileModule) ([]ModuleSpec, error) {
	var out []ModuleSpec
	for _, fm := range fms {
		m := ModuleSpec{ID: fm.ID, External: fm.External, User: fm.User, Path: fm.Path, Args: fm.Args, Env: fm.Env}
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
			var err error
			if *d.out, err = parseDur(fmt.Sprintf("modulo %q %s", fm.ID, d.name), d.in, d.def); err != nil {
				return nil, err
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func validateModules(ms []ModuleSpec) error {
	seen := map[string]bool{}
	for _, m := range ms {
		if !moduleIDRe.MatchString(m.ID) {
			return fmt.Errorf("id de modulo invalido: %q", m.ID)
		}
		if seen[m.ID] {
			return fmt.Errorf("id de modulo duplicado: %q", m.ID)
		}
		seen[m.ID] = true
		if err := validateModuleLaunch(m); err != nil {
			return err
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

// validateModuleLaunch confere como o modulo e lancado: pelo Core (path) ou por fora (external + user).
func validateModuleLaunch(m ModuleSpec) error {
	if !m.External {
		if m.User != "" {
			return fmt.Errorf("modulo %q: user so vale com external=true (o Core lanca o modulo com o proprio usuario)", m.ID)
		}
		if m.Path == "" {
			return fmt.Errorf("modulo %q: path obrigatorio (ou external=true e user, para um modulo mantido pelo systemd)", m.ID)
		}
		return nil
	}
	if m.Path != "" || len(m.Args) > 0 || len(m.Env) > 0 {
		return fmt.Errorf("modulo %q: external=true nao aceita path, args nem env (o systemd lanca o processo; veja a unit do modulo)", m.ID)
	}
	if !userNameRe.MatchString(m.User) {
		return fmt.Errorf("modulo %q: external=true exige user com o nome do usuario do servico (por exemplo \"psychoscope-sensor\")", m.ID)
	}
	return nil
}

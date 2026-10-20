package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const systemSocketDir = "/var/run/psychoscope"

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

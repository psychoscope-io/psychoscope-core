package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

// sensorCheckTimeout limita o `--check` do sensor: ele abre a captura de verdade.
const sensorCheckTimeout = 10 * time.Second

// maxCheckOutput limita o que se guarda da saida de um modulo (entrada nao confiavel).
const maxCheckOutput = 16 << 10

// sockInfo e o que o doctor precisa saber do arquivo do socket para explicar um erro.
type sockInfo struct {
	Mode     fs.FileMode
	UID, GID uint32
}

// doctorEnv reune tudo o que o doctor le do sistema fora do canal de controle; as decisoes
// ficam em funcoes puras que recebem o resultado, e os testes trocam esta interface.
type doctorEnv interface {
	// SocketInfo descreve o arquivo do socket (erro se nao existe ou nao pode ser lido).
	SocketInfo(path string) (sockInfo, error)
	// ServiceState devolve a saida de `systemctl is-active <unit>`; ok e falso sem systemctl.
	ServiceState(ctx context.Context, unit string) (state string, ok bool)
	// Modules le os modulos do arquivo de configuracao do Core.
	Modules(path string) ([]config.ModuleSpec, error)
	// SensorCheck roda `<bin> <args> --check` e devolve a saida e o erro do processo.
	SensorCheck(ctx context.Context, bin string, args []string) (string, error)
}

type osDoctorEnv struct{}

func (osDoctorEnv) SocketInfo(path string) (sockInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return sockInfo{}, err
	}
	info := sockInfo{Mode: st.Mode()}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		info.UID, info.GID = sys.Uid, sys.Gid
	}
	return info, nil
}

func (osDoctorEnv) ServiceState(ctx context.Context, unit string) (string, bool) {
	bin, err := exec.LookPath("systemctl")
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// is-active sai com codigo diferente de zero quando a unit nao esta ativa; a saida basta.
	out, _ := exec.CommandContext(ctx, bin, "is-active", unit).Output() //nolint:gosec // binario resolvido no PATH, argumentos fixos
	return string(bytes.TrimSpace(out)), true
}

func (osDoctorEnv) Modules(path string) ([]config.ModuleSpec, error) {
	cfg, err := config.Load([]string{"--config", path}, config.OSEnv())
	if err != nil {
		return nil, err
	}
	return cfg.Modules, nil
}

func (osDoctorEnv) SensorCheck(ctx context.Context, bin string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, sensorCheckTimeout)
	defer cancel()
	var buf limitedBuffer
	cmd := exec.CommandContext(ctx, bin, append(append([]string(nil), args...), "--check")...) //nolint:gosec // caminho e argumentos do arquivo de configuracao do administrador
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = context.DeadlineExceeded
	}
	return buf.String(), err
}

// limitedBuffer descarta o que passa de maxCheckOutput.
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := maxCheckOutput - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

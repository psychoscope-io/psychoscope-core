package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// eventSource entrega, em ordem, os eventos de rede de um pcap. emit pode bloquear (o motor
// tem fila limitada) e devolve erro quando a analise deve parar; a fonte para e devolve esse erro.
// Os testes trocam esta interface.
type eventSource interface {
	Stream(ctx context.Context, pcap string, emit func(module string, ev *psychoscopev1.EventoFluxoRede) error) error
}

// sensorSource roda o sensor real sobre o pcap e recebe os eventos por um socket efemero:
// o mesmo caminho do servico (decoders e protobuf), sem Core instalado, sem privilegios e
// sem tocar no estado do servico. O Go nunca interpreta o pcap: quem le e o sensor.
type sensorSource struct {
	bin string
	// grace e quanto esperar, depois que o sensor sai, por uma conexao que ainda esteja na fila
	// de aceite (sensor que conectou, enviou tudo e saiu antes de o Core aceitar).
	grace time.Duration
}

const (
	defaultSensorGrace = time.Second
	maxSocketPath      = 100 // sun_path tem 108 bytes; sobra margem
	sensorUserDir      = "/usr/local/bin"
)

// findSensor resolve o binario do sensor: o caminho dado, o PATH ou /usr/local/bin. Nunca o
// diretorio atual.
func findSensor(explicit, fallbackDir string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if p, err := exec.LookPath(sensorBinary); err == nil {
		return p, nil
	}
	if p := filepath.Join(fallbackDir, sensorBinary); fileExists(p) {
		return p, nil
	}
	return "", errors.New("nao encontrei o " + sensorBinary + " no PATH nem em " + fallbackDir +
		": instale o sensor (docs/INSTALL.md) ou aponte o binario com --sensor caminho")
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func (s sensorSource) Stream(ctx context.Context, pcap string, emit func(string, *psychoscopev1.EventoFluxoRede) error) error {
	dir, err := os.MkdirTemp("", "psychoscope-analyze-") // 0700: so este usuario fala com o socket
	if err != nil {
		return fmt.Errorf("criando o diretorio temporario: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // limpeza do diretorio temporario

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	h := newReplayHandler(emit, cancel)
	sock := filepath.Join(dir, "core.sock")
	if len(sock) > maxSocketPath {
		return fmt.Errorf("o caminho do socket temporario (%d bytes) passa do limite do Linux (~108): use um TMPDIR curto, por exemplo TMPDIR=/tmp", len(sock))
	}
	srv, err := ipc.NewServer(ipc.ServerConfig{
		Path: sock, Mode: 0o600, CoreVersion: version.Version,
		Auth: ownerOnly{ipc.NewUIDPolicy(uint32(os.Geteuid()), nil)}, Handler: h, //nolint:gosec // Geteuid nunca e negativo
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("abrindo o socket temporario: %w", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ctx)
	}()
	defer func() {
		srv.Shutdown()
		<-served
	}()

	// O caminho do pcap vai colado em --pcap-file=: nunca pode virar outra flag.
	cmd := exec.CommandContext(ctx, s.bin, "--pcap-file="+pcap, "--exit-on-eof", "--socket="+sock) //nolint:gosec // binario escolhido pelo operador
	cmd.Env = []string{"PSYCHOSCOPE_MODULE_ID=" + sensorBinary, "LC_ALL=C"}
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	grace := cmp.Or(s.grace, defaultSensorGrace)
	if runErr != nil {
		grace = 0 // sensor que falhou nao deixa conexao nova a espera; so drena a que existe
	}
	h.waitDrained(ctx, grace)
	switch {
	case h.err() != nil:
		return h.err()
	case ctx.Err() != nil:
		return ctx.Err()
	case runErr != nil:
		return fmt.Errorf("o sensor falhou (%w): %s", runErr, sensorMessage(stderr.String()))
	}
	return nil
}

// ownerOnly autoriza so o usuario que roda a analise (e o root): o diretorio do socket ja e 0700,
// e a identidade vem do kernel (SO_PEERCRED), nunca do que o modulo declara.
type ownerOnly struct{ ipc.UIDPolicy }

func (a ownerOnly) Authorize(_ *psychoscopev1.HelloModulo, cred ipc.PeerCred) error {
	if !a.Allows(cred.UID) {
		return errors.New("uid nao autorizado")
	}
	return nil
}

// sensorMessage resume o stderr do sensor (entrada nao confiavel: truncada, uma linha).
func sensorMessage(s string) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	if s == "" {
		return "sem mensagem"
	}
	return truncate(s, 2*maxSensorLine)
}

// replayHandler entrega ao emit os eventos de rede das sessoes do sensor (normalmente uma; mais
// de uma se ele reconectar). Bloquear aqui e proposital (ao contrario do servico ao vivo): a
// leitura do socket para e o sensor espera, de modo que nenhum evento do pcap e descartado.
type replayHandler struct {
	ipc.NopHandler
	emit   func(string, *psychoscopev1.EventoFluxoRede) error
	cancel context.CancelFunc

	wake chan struct{} // sinal (capacidade 1) de que seen ou active mudou

	mu     sync.Mutex
	seen   bool // alguma sessao ja conectou
	active int  // sessoes abertas agora
	rerr   error
}

func newReplayHandler(emit func(string, *psychoscopev1.EventoFluxoRede) error, cancel context.CancelFunc) *replayHandler {
	return &replayHandler{emit: emit, cancel: cancel, wake: make(chan struct{}, 1)}
}

func (h *replayHandler) notify() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

func (h *replayHandler) OnConnect(*ipc.Session) {
	h.mu.Lock()
	h.seen, h.active = true, h.active+1
	h.mu.Unlock()
	h.notify()
}

func (h *replayHandler) OnDisconnect(*ipc.Session, error) {
	h.mu.Lock()
	h.active--
	h.mu.Unlock()
	h.notify()
}

func (h *replayHandler) OnTelemetry(s *ipc.Session, ev *psychoscopev1.EventoTelemetria) {
	rede := ev.GetRede()
	if rede == nil || h.err() != nil {
		return
	}
	if err := h.emit(s.ID, rede); err != nil {
		h.mu.Lock()
		h.rerr = err
		h.mu.Unlock()
		h.cancel() // para o sensor
	}
}

func (h *replayHandler) err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rerr
}

// waitDrained espera, depois que o sensor saiu, o fim da leitura de todas as sessoes: uma sessao
// so termina depois de o servidor ler tudo o que ela enviou. Se nenhuma conexao apareceu, espera
// ate grace por uma que ainda esteja na fila de aceite (sensor que conectou, enviou e saiu antes
// de o Core aceitar). Com ctx encerrado, volta sem esperar mais.
func (h *replayHandler) waitDrained(ctx context.Context, grace time.Duration) {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	for {
		h.mu.Lock()
		seen, active := h.seen, h.active
		h.mu.Unlock()
		if seen && active == 0 {
			return
		}
		var expire <-chan time.Time
		if !seen {
			expire = timer.C
		}
		select {
		case <-h.wake:
		case <-expire:
			return
		case <-ctx.Done():
			return
		}
	}
}

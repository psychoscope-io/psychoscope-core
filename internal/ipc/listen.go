package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var umaskMu sync.Mutex

// ListenUnix cria o listener em path com permissoes mode (0600/0660), tratando:
//   - diretorio pai criado com 0750 se ausente;
//   - socket obsoleto de uma execucao anterior e removido, mas uma instancia viva
//     (dial com sucesso) e erro, e um arquivo que nao e socket nunca e apagado;
//   - socket criado sob umask restritiva, sem janela de permissoes frouxas.
func ListenUnix(path string, mode os.FileMode, log *slog.Logger) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s existe e nao e um socket", path)
		}
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			c.Close()
			return nil, fmt.Errorf("%s: ja existe uma instancia em execucao", path)
		}
		log.Warn("removendo socket obsoleto", "path", path)
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	umaskMu.Lock()
	old := unix.Umask(int(^mode & 0o777))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	umaskMu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// NewID gera um identificador aleatorio de 64 bits em hex.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand nao falha em sistemas suportados
	}
	return hex.EncodeToString(b[:])
}

// UIDPolicy decide quais UIDs podem falar com o Core: o do proprio processo,
// root e os explicitamente permitidos.
type UIDPolicy struct{ allowed map[uint32]bool }

// NewUIDPolicy cria a politica com own (UID efetivo do Core), root e extra.
func NewUIDPolicy(own uint32, extra []uint32) UIDPolicy {
	m := map[uint32]bool{own: true, 0: true}
	for _, u := range extra {
		m[u] = true
	}
	return UIDPolicy{allowed: m}
}

// Allows informa se uid esta permitido.
func (p UIDPolicy) Allows(uid uint32) bool { return p.allowed[uid] }

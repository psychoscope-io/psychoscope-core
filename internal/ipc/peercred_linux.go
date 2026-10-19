//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerCred identifica o processo do outro lado de um Unix socket (SO_PEERCRED).
// Os valores sao fixados pelo kernel no connect() e nao podem ser forjados pelo peer.
type PeerCred struct {
	PID int32
	UID uint32
	GID uint32
}

// PeerCredOf le as credenciais do peer de uma conexao Unix.
func PeerCredOf(c *net.UnixConn) (PeerCred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return PeerCred{}, err
	}
	var (
		ucred *unix.Ucred
		serr  error
	)
	if err := raw.Control(func(fd uintptr) {
		ucred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return PeerCred{}, err
	}
	if serr != nil {
		return PeerCred{}, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return PeerCred{PID: ucred.Pid, UID: ucred.Uid, GID: ucred.Gid}, nil
}

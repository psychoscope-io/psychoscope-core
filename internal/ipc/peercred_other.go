//go:build !linux

package ipc

import (
	"errors"
	"net"
)

// PeerCred identifica o processo do peer. Suportado apenas em Linux.
type PeerCred struct {
	PID int32
	UID uint32
	GID uint32
}

// PeerCredOf nao e suportado fora do Linux: o Core recusa conexoes (fail closed).
func PeerCredOf(*net.UnixConn) (PeerCred, error) {
	return PeerCred{}, errors.New("SO_PEERCRED requer Linux")
}

package app

import (
	"fmt"
	"os/user"
	"strconv"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ipc"
)

// externalUIDs resolve o usuario de cada modulo External para o UID que o kernel informa na
// conexao (SO_PEERCRED). Usuario inexistente impede a partida, com a instrucao de como criar:
// subir sem ele deixaria o modulo recusado em silencio.
func externalUIDs(specs []config.ModuleSpec, lookup func(string) (*user.User, error)) (map[string]uint32, error) {
	out := map[string]uint32{}
	for _, sp := range specs {
		if !sp.External {
			continue
		}
		u, err := lookup(sp.User)
		if err != nil {
			return nil, fmt.Errorf("modulo %q: usuario %q nao encontrado: %w (crie-o, por exemplo com o install.sh, ou ajuste \"user\" na configuracao)", sp.ID, sp.User, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("modulo %q: uid %q do usuario %q invalido: %w", sp.ID, u.Uid, sp.User, err)
		}
		out[sp.ID] = uint32(uid)
	}
	return out, nil
}

// uidPolicies separa quem pode falar como modulo de quem pode usar o canal de controle. O usuario
// de um modulo External entra so na politica dos modulos: ele processa dados hostis (pacotes) e
// nao pode listar, comandar nem ler alertas pelo ctl.sock, mesmo estando no grupo do socket.
func uidPolicies(own uint32, allowed []uint32, external map[string]uint32) (modules, control ipc.UIDPolicy) {
	extra := append([]uint32(nil), allowed...)
	for _, uid := range external {
		extra = append(extra, uid)
	}
	return ipc.NewUIDPolicy(own, extra), ipc.NewUIDPolicy(own, allowed)
}

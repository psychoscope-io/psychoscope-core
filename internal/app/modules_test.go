package app

import (
	"errors"
	"os/user"
	"strings"
	"testing"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

func TestExternalUIDsResolvesOnlyExternalModules(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		if name != "psychoscope-sensor" {
			return nil, errors.New("inesperado: " + name)
		}
		return &user.User{Uid: "998", Username: name}, nil
	}
	specs := []config.ModuleSpec{
		{ID: "mod-net-sensor", External: true, User: "psychoscope-sensor"},
		{ID: "filho", Path: "/bin/true"}, // lancado pelo Core: nao consulta usuario
	}
	got, err := externalUIDs(specs, lookup)
	if err != nil || len(got) != 1 || got["mod-net-sensor"] != 998 {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestExternalUIDsFailsWithActionableMessage(t *testing.T) {
	missing := func(string) (*user.User, error) { return nil, user.UnknownUserError("psychoscope-sensor") }
	_, err := externalUIDs([]config.ModuleSpec{{ID: "mod-net-sensor", External: true, User: "psychoscope-sensor"}}, missing)
	if err == nil || !strings.Contains(err.Error(), "psychoscope-sensor") || !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("erro deve citar o usuario e como cria-lo: %v", err)
	}
	badUID := func(string) (*user.User, error) { return &user.User{Uid: "-1"}, nil }
	if _, err := externalUIDs([]config.ModuleSpec{{ID: "m", External: true, User: "x"}}, badUID); err == nil {
		t.Error("uid invalido deve falhar")
	}
}

func TestExternalModuleUserCannotUseControlChannel(t *testing.T) {
	modules, control := uidPolicies(1000, []uint32{2000}, map[string]uint32{"mod-net-sensor": 998})
	for _, uid := range []uint32{0, 1000, 2000, 998} {
		if !modules.Allows(uid) {
			t.Errorf("uid %d deveria falar como modulo", uid)
		}
	}
	for _, uid := range []uint32{0, 1000, 2000} {
		if !control.Allows(uid) {
			t.Errorf("uid %d deveria usar o canal de controle", uid)
		}
	}
	if control.Allows(998) {
		t.Error("o usuario do sensor externo nao pode usar o canal de controle")
	}
}

package ipc

import (
	"fmt"
	"strings"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestLimitCountersKeepsValidKeysUntouched(t *testing.T) {
	st := &psychoscopev1.StatusModulo{Contadores: map[string]uint64{"perda.kernel": 1, "decode.nao_suportado": 2, "a-b_c.9": 3}}
	if n := limitCounters(st); n != 0 || len(st.Contadores) != 3 || st.Contadores["perda.kernel"] != 1 {
		t.Fatalf("chaves validas ficam como estao: n=%d %v", n, st.Contadores)
	}
	if limitCounters(&psychoscopev1.StatusModulo{}) != 0 || limitCounters(nil) != 0 {
		t.Fatal("sem contadores nao ha o que limitar")
	}
}

func TestLimitCountersDropsInvalidKeys(t *testing.T) {
	long := strings.Repeat("k", MaxCounterKeyLen+1)
	st := &psychoscopev1.StatusModulo{Contadores: map[string]uint64{
		"ok.chave": 1, "": 2, "Maiuscula": 3, "com espaco": 4, "quebra\nlinha": 5, "aspas\"": 6, long: 7, "acentuação": 8,
	}}
	if n := limitCounters(st); n != 7 || len(st.Contadores) != 1 || st.Contadores["ok.chave"] != 1 {
		t.Fatalf("so a chave valida fica: n=%d %v", n, st.Contadores)
	}
	exact := strings.Repeat("k", MaxCounterKeyLen)
	st = &psychoscopev1.StatusModulo{Contadores: map[string]uint64{exact: 1}}
	if limitCounters(st) != 0 {
		t.Fatal("o tamanho maximo ainda e valido")
	}
}

func TestLimitCountersCapsTheNumberOfKeysDeterministically(t *testing.T) {
	st := &psychoscopev1.StatusModulo{Contadores: map[string]uint64{}}
	for i := 0; i < MaxCounters+36; i++ {
		st.Contadores[fmt.Sprintf("c%03d", i)] = uint64(i)
	}
	if n := limitCounters(st); n != 36 || len(st.Contadores) != MaxCounters {
		t.Fatalf("n=%d len=%d", n, len(st.Contadores))
	}
	if _, ok := st.Contadores["c063"]; !ok {
		t.Fatal("ficam as primeiras em ordem alfabetica")
	}
	if _, ok := st.Contadores["c064"]; ok {
		t.Fatal("c064 passa do limite")
	}
}

// Um modulo que manda contadores demais ou com chaves invalidas nao chega com eles aos
// consumidores (TUI, metricas): o handler e LastStatus ja recebem o mapa limitado.
func TestServerLimitsHostileCountersBeforeTheHandlerSeesThem(t *testing.T) {
	_, h, path := startServer(t, nil)
	c := dial(t, path)
	_ = WriteMessage(c, hello("mod-a"))
	readHello(t, c)
	s := <-h.connected

	hostile := map[string]uint64{"perda.kernel": 7, "Chave\nruim": 1}
	for i := 0; i < 200; i++ {
		hostile[fmt.Sprintf("x%03d", i)] = 1
	}
	_ = WriteMessage(c, &psychoscopev1.MensagemIPC{Payload: &psychoscopev1.MensagemIPC_Status{
		Status: &psychoscopev1.StatusModulo{IdModulo: "mod-a", Contadores: hostile}}})

	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		n := len(h.status)
		h.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("o status nao chegou ao handler")
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	got := h.status[0].Contadores
	h.mu.Unlock()
	if len(got) != MaxCounters || got["perda.kernel"] != 7 {
		t.Fatalf("o handler deve ver %d chaves validas (perda.kernel inclusive): %d", MaxCounters, len(got))
	}
	if _, bad := got["Chave\nruim"]; bad {
		t.Fatal("chave invalida chegou ao handler")
	}
	if last := s.LastStatus(); len(last.Contadores) != MaxCounters {
		t.Fatalf("LastStatus tambem limitado: %d", len(last.Contadores))
	}
}

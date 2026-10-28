package enginestate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

var clock = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func storeAt(t *testing.T, now time.Time) Store {
	t.Helper()
	return Store{Path: filepath.Join(t.TempDir(), "state", "engine-state.json"), Now: func() time.Time { return now }}
}

func sample() *detection.Snapshot {
	return &detection.Snapshot{
		Cooldowns: []detection.CooldownEntry{{Regra: "net.scan.syn", Chave: "10.0.0.66", EmitidoEm: clock}},
		Regras:    map[string]any{"net.beacon": map[string]int{"x": 1}},
	}
}

func TestSaveLoadRoundTripAndPermissions(t *testing.T) {
	s := storeAt(t, clock)
	if err := s.Save(sample()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("arquivo deve ser 0600: %v %v", fi, err)
	}
	if di, err := os.Stat(filepath.Dir(s.Path)); err != nil || di.Mode().Perm() != 0o750 {
		t.Fatalf("diretorio deve ser 0750: %v %v", di, err)
	}
	got, err := s.Load()
	if err != nil || got == nil {
		t.Fatalf("Load: %v %v", got, err)
	}
	if len(got.Cooldowns) != 1 || got.Cooldowns[0].Chave != "10.0.0.66" || !got.SalvoEm.Equal(clock) || got.Versao != detection.SnapshotVersion {
		t.Fatalf("snapshot lido: %+v", got)
	}
	if _, ok := got.Regras["net.beacon"].(json.RawMessage); !ok {
		t.Fatalf("o estado das regras volta como json.RawMessage: %T", got.Regras["net.beacon"])
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Path))
	if len(entries) != 1 {
		t.Fatalf("nao deve sobrar arquivo temporario: %v", entries)
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	if snap, err := storeAt(t, clock).Load(); snap != nil || err != nil {
		t.Fatalf("arquivo ausente: %v %v", snap, err)
	}
}

func TestLoadRejectsUnusableFiles(t *testing.T) {
	write := func(t *testing.T, s Store, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.Path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	at := func(d time.Duration) string { return `"` + clock.Add(d).Format(time.RFC3339Nano) + `"` }
	cases := []struct {
		name    string
		content string
		want    error // nil = qualquer erro
	}{
		{"truncado", `{"versao":1,"salvo_em":`, nil},
		{"lixo", "nao e json", nil},
		{"campo desconhecido", `{"versao":1,"salvo_em":` + at(0) + `,"x":1}`, nil},
		{"versao futura", `{"versao":2,"salvo_em":` + at(0) + `}`, ErrVersion},
		{"sem versao", `{"salvo_em":` + at(0) + `}`, ErrVersion},
		{"velho demais", `{"versao":1,"salvo_em":` + at(-MaxAge-time.Minute) + `}`, ErrStale},
		{"no futuro (relogio voltou)", `{"versao":1,"salvo_em":` + at(10*time.Minute) + `}`, ErrFuture},
		{"tamanho gigante", `{"versao":1,"salvo_em":` + at(0) + `,"regras":{"x":"` + strings.Repeat("a", maxFileSize) + `"}}`, ErrTooBig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := storeAt(t, clock)
			write(t, s, c.content)
			snap, err := s.Load()
			if snap != nil || err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("snap=%v err=%v, esperado %v", snap, err, c.want)
			}
		})
	}
	s := storeAt(t, clock)
	write(t, s, `{"versao":1,"salvo_em":`+at(-time.Hour)+`}`)
	if snap, err := s.Load(); snap == nil || err != nil {
		t.Fatalf("estado de uma hora atras deve ser aceito: %v %v", snap, err)
	}
	write(t, s, `{"versao":1,"salvo_em":`+at(2*time.Minute)+`}`)
	if snap, err := s.Load(); snap == nil || err != nil {
		t.Fatalf("relogio adiantado ate 5 min e tolerado: %v %v", snap, err)
	}
}

func TestSaveFailureKeepsThePreviousFile(t *testing.T) {
	s := storeAt(t, clock)
	if err := s.Save(sample()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Path)
	bad := sample()
	bad.Regras = map[string]any{"x": make(chan int)} // nao e serializavel
	if err := s.Save(bad); err == nil {
		t.Fatal("esperava erro de codificacao")
	}
	if after, _ := os.ReadFile(s.Path); string(after) != string(before) {
		t.Fatal("uma gravacao que falha nao pode alterar o arquivo anterior")
	}
}

type fakeSource struct {
	snap  *detection.Snapshot
	err   error
	calls chan struct{}
}

func (f *fakeSource) Snapshot(context.Context) (*detection.Snapshot, error) {
	select {
	case f.calls <- struct{}{}:
	default:
	}
	return f.snap, f.err
}

func TestSaverWritesPeriodicallyAndCountsErrors(t *testing.T) {
	s := storeAt(t, clock)
	src := &fakeSource{snap: sample(), calls: make(chan struct{}, 100)}
	sv := &Saver{Store: s, Source: src, Interval: 10 * time.Millisecond, Log: discardLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sv.Run(ctx); close(done) }()
	end := time.Now().Add(3 * time.Second)
	for {
		if saves, _ := sv.Stats(); saves >= 2 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("o saver nao gravou periodicamente")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	src.err = errors.New("motor parado")
	sv2 := &Saver{Store: s, Source: src, Interval: 10 * time.Millisecond, Log: discardLogger()}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { sv2.Run(ctx2); close(done2) }()
	for end := time.Now().Add(3 * time.Second); ; {
		if _, errs := sv2.Stats(); errs >= 1 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("falha do motor deve ser contada")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel2()
	<-done2
}

func TestSaverWithZeroIntervalDoesNotRunPeriodically(t *testing.T) {
	src := &fakeSource{snap: sample(), calls: make(chan struct{}, 1)}
	sv := &Saver{Store: storeAt(t, clock), Source: src, Interval: 0, Log: discardLogger()}
	done := make(chan struct{})
	go func() { sv.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run deve retornar na hora quando o intervalo e zero")
	}
	sv.Save(sample())
	if saves, _ := sv.Stats(); saves != 1 {
		t.Fatalf("Save manual deve contar: %d", saves)
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/alerts"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var t0 = time.Unix(1_700_000_000, 0)

func alert(id, rule string, sev psychoscopev1.Severidade, module string, at time.Time) *psychoscopev1.Alerta {
	return &psychoscopev1.Alerta{IdAlerta: id, Regra: rule, Severidade: sev, Descricao: "desc " + id,
		IdModuloOrigem: module, Timestamp: timestamppb.New(at), Contexto: map[string]string{"origem": "10.0.0.1", "k": id}}
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPermissionsAndRoundTrip(t *testing.T) {
	s := open(t)
	if st, err := os.Stat(s.Path()); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("arquivo deve ser 0600: %v %v", st, err)
	}
	if st, _ := os.Stat(filepath.Dir(s.Path())); st.Mode().Perm() != 0o750 {
		t.Fatalf("diretorio deve ser 0750: %v", st.Mode().Perm())
	}
	in := alert("a1", "net.scan.syn", psychoscopev1.Severidade_SEVERIDADE_ALTA, "mod-net-sensor", t0)
	if err := s.Insert(context.Background(), []*psychoscopev1.Alerta{in}); err != nil {
		t.Fatal(err)
	}
	// -wal e -shm herdam 0600
	for _, suffix := range []string{"-wal", "-shm"} {
		if st, err := os.Stat(s.Path() + suffix); err == nil && st.Mode().Perm() != 0o600 {
			t.Errorf("%s com modo %v", suffix, st.Mode().Perm())
		}
	}
	got, total, err := s.Query(context.Background(), Filter{})
	if err != nil || total != 1 || len(got) != 1 {
		t.Fatalf("query: %v total=%d err=%v", got, total, err)
	}
	a := got[0]
	if a.IdAlerta != "a1" || a.Regra != "net.scan.syn" || a.Severidade != psychoscopev1.Severidade_SEVERIDADE_ALTA ||
		a.Descricao != "desc a1" || a.IdModuloOrigem != "mod-net-sensor" || !a.Timestamp.AsTime().Equal(t0) ||
		a.Contexto["origem"] != "10.0.0.1" || a.Contexto["k"] != "a1" {
		t.Fatalf("alerta recuperado difere: %v", a)
	}
}

func TestQueryFiltersOrderAndLimits(t *testing.T) {
	s := open(t)
	var as []*psychoscopev1.Alerta
	for i := 0; i < 30; i++ {
		sev := psychoscopev1.Severidade(1 + i%4)
		rule := "r.a"
		if i%3 == 0 {
			rule = "r.b"
		}
		mod := "m1"
		if i%2 == 0 {
			mod = "m2"
		}
		as = append(as, alert(fmt.Sprintf("id%02d", i), rule, sev, mod, t0.Add(time.Duration(i)*time.Minute)))
	}
	if err := s.Insert(context.Background(), as); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	got, total, _ := s.Query(ctx, Filter{Limit: 5})
	if total != 30 || len(got) != 5 || got[0].IdAlerta != "id29" || got[4].IdAlerta != "id25" {
		t.Fatalf("mais novo primeiro + total ignora limite: total=%d %v", total, ids(got))
	}
	// cada filtro confere com Filter.Match aplicado a todos os alertas (oraculo independente)
	filters := []Filter{
		{Since: t0.Add(20 * time.Minute)},
		{MinSeverity: psychoscopev1.Severidade_SEVERIDADE_ALTA},
		{Rule: "r.b"},
		{Module: "m1"},
		{Since: t0.Add(5 * time.Minute), MinSeverity: psychoscopev1.Severidade_SEVERIDADE_MEDIA, Rule: "r.a", Module: "m2", Limit: 1000},
	}
	for i, f := range filters {
		f.Limit = 1000
		want := 0
		for _, a := range as {
			if f.Match(a) {
				want++
			}
		}
		got, total, err := s.Query(ctx, f)
		if err != nil || int(total) != want || len(got) != want {
			t.Errorf("filtro %d: total=%d len=%d esperado=%d err=%v", i, total, len(got), want, err)
		}
		for _, a := range got {
			if !f.Match(a) {
				t.Errorf("filtro %d devolveu alerta fora do filtro: %v", i, a.IdAlerta)
			}
		}
	}
	if got, _, _ := s.Query(ctx, Filter{Limit: 100000}); len(got) != 30 {
		t.Errorf("limite acima do maximo e reduzido, mas ha so 30: %d", len(got))
	}
	rec, _ := s.Recent(ctx, 3)
	if len(rec) != 3 || rec[0].IdAlerta != "id27" || rec[2].IdAlerta != "id29" {
		t.Fatalf("Recent em ordem cronologica: %v", ids(rec))
	}
}

func ids(as []*psychoscopev1.Alerta) []string {
	var o []string
	for _, a := range as {
		o = append(o, a.IdAlerta)
	}
	return o
}

func TestSQLInjectionIsHarmless(t *testing.T) {
	s := open(t)
	evil := "x'; DROP TABLE alerts; --"
	if err := s.Insert(context.Background(), []*psychoscopev1.Alerta{alert("a1", evil, 1, evil, t0)}); err != nil {
		t.Fatal(err)
	}
	got, total, err := s.Query(context.Background(), Filter{Rule: evil, Module: evil})
	if err != nil || total != 1 || got[0].Regra != evil {
		t.Fatalf("valores devem ser tratados como dados: %v %d %v", got, total, err)
	}
	if n, err := s.Count(context.Background()); err != nil || n != 1 {
		t.Fatalf("tabela deve continuar existindo: %d %v", n, err)
	}
}

func TestInsertDuplicatesIgnoredAndPrune(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	var as []*psychoscopev1.Alerta
	for i := 0; i < 10; i++ {
		as = append(as, alert(fmt.Sprintf("id%d", i), "r", 1, "m", t0.Add(time.Duration(i)*time.Hour)))
	}
	_ = s.Insert(ctx, as)
	_ = s.Insert(ctx, as) // repetido
	if n, _ := s.Count(ctx); n != 10 {
		t.Fatalf("duplicatas devem ser ignoradas: %d", n)
	}
	// por idade: remove os 4 primeiros (horas 0..3)
	if n, err := s.Prune(ctx, t0.Add(4*time.Hour), 0); err != nil || n != 4 {
		t.Fatalf("prune por idade: %d %v", n, err)
	}
	// por teto: mantem os 3 mais recentes
	if n, err := s.Prune(ctx, time.Time{}, 3); err != nil || n != 3 {
		t.Fatalf("prune por teto: %d %v", n, err)
	}
	got, _, _ := s.Query(ctx, Filter{})
	if len(got) != 3 || got[0].IdAlerta != "id9" || got[2].IdAlerta != "id7" {
		t.Fatalf("restantes: %v", ids(got))
	}
	if st := s.Stats(); st.Pruned != 7 || st.Written != 20 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestPersistsAcrossReopenAndRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	s, _ := Open(path)
	_ = s.Insert(context.Background(), []*psychoscopev1.Alerta{alert("a1", "r", 2, "m", t0)})
	s.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Count(context.Background()); n != 1 {
		t.Fatalf("dados devem sobreviver: %d", n)
	}
	if _, err := s.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(path); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("esperado ErrNewerSchema: %v", err)
	}
}

func TestConcurrentInsertsAndQueries(t *testing.T) {
	s := open(t)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				_ = s.Insert(context.Background(), []*psychoscopev1.Alerta{alert(fmt.Sprintf("w%d-%d", w, i), "r", 1, "m", t0.Add(time.Duration(i)*time.Second))})
				_, _, _ = s.Query(context.Background(), Filter{Limit: 5})
			}
		}()
	}
	wg.Wait()
	if n, _ := s.Count(context.Background()); n != 100 {
		t.Fatalf("esperado 100, obtido %d", n)
	}
}

func TestOpenFailsOnUnwritableLocation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root escreve em qualquer lugar")
	}
	if _, err := Open("/proc/psychoscope/nope/alerts.db"); err == nil {
		t.Fatal("esperado erro")
	}
}

// ---- persister ----

func TestPersisterWritesBatchesAndFlushesOnShutdown(t *testing.T) {
	s := open(t)
	bus := alerts.NewBus()
	p := NewPersister(s, bus, PersisterConfig{FlushEvery: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()

	time.Sleep(50 * time.Millisecond) // garante a assinatura
	for i := 0; i < 150; i++ {
		bus.Publish(alert(fmt.Sprintf("p%03d", i), "r", 1, "m", t0.Add(time.Duration(i)*time.Second)))
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := s.Count(context.Background()); n >= 100 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 150; i < 160; i++ { // ainda no buffer quando o encerramento chega
		bus.Publish(alert(fmt.Sprintf("p%03d", i), "r", 1, "m", t0.Add(time.Duration(i)*time.Second)))
	}
	cancel()
	<-done
	if n, _ := s.Count(context.Background()); n != 160 {
		t.Fatalf("todos os alertas devem estar gravados apos o shutdown: %d", n)
	}
	if p.Dropped() != 0 {
		t.Errorf("dropped=%d", p.Dropped())
	}
}

func TestPersisterPrunesOnStartup(t *testing.T) {
	s := open(t)
	old := time.Now().Add(-48 * time.Hour)
	_ = s.Insert(context.Background(), []*psychoscopev1.Alerta{
		alert("velho", "r", 1, "m", old), alert("novo", "r", 1, "m", time.Now()),
	})
	p := NewPersister(s, alerts.NewBus(), PersisterConfig{Retention: 24 * time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	got, _, _ := s.Query(context.Background(), Filter{})
	if len(got) != 1 || got[0].IdAlerta != "novo" {
		t.Fatalf("retencao: %v", ids(got))
	}
}

func TestPersisterSetLimitsPrunesRightAway(t *testing.T) {
	s := open(t)
	now := time.Now()
	batch := []*psychoscopev1.Alerta{alert("velho", "r", 1, "m", now.Add(-48*time.Hour))}
	for i := 0; i < 6; i++ {
		batch = append(batch, alert(fmt.Sprintf("n%d", i), "r", 1, "m", now.Add(-time.Duration(i)*time.Minute)))
	}
	_ = s.Insert(context.Background(), batch)

	// sem limites na partida e poda periodica de 1 h: nada e removido
	p := NewPersister(s, alerts.NewBus(), PersisterConfig{PruneEvery: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	count := func() uint64 { n, _ := s.Count(context.Background()); return n }
	time.Sleep(100 * time.Millisecond)
	if count() != 7 {
		t.Fatalf("sem limites nada e podado: %d", count())
	}

	waitFor := func(what string, want uint64) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && count() != want {
			time.Sleep(10 * time.Millisecond)
		}
		if got := count(); got != want {
			t.Fatalf("%s: %d alertas, esperado %d", what, got, want)
		}
	}
	p.SetLimits(24*time.Hour, 0) // a retencao nova vale ja, sem esperar a proxima poda
	waitFor("retencao de 24 h", 6)
	p.SetLimits(0, 3) // desliga a idade e passa a limitar a quantidade: ficam os 3 mais novos
	waitFor("teto de 3", 3)
	got, _, _ := s.Query(context.Background(), Filter{})
	if want := []string{"n0", "n1", "n2"}; fmt.Sprint(ids(got)) != fmt.Sprint(want) {
		t.Fatalf("devem ficar os mais novos: %v", ids(got))
	}
}

// Corrida: SetLimits enquanto a poda periodica roda.
func TestPersisterSetLimitsIsRaceFree(t *testing.T) {
	s := open(t)
	p := NewPersister(s, alerts.NewBus(), PersisterConfig{PruneEvery: time.Millisecond, FlushEvery: time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	for i := 0; i < 200; i++ {
		p.SetLimits(time.Duration(i)*time.Hour, i)
	}
	cancel()
	<-done
}

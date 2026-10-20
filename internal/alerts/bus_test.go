package alerts

import (
	"sync"
	"testing"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

func TestFanOutAndClose(t *testing.T) {
	b := NewBus()
	s1, s2 := b.Subscribe(4), b.Subscribe(4)
	b.Publish(&psychoscopev1.Alerta{IdAlerta: "1"})
	for _, s := range []*Subscription{s1, s2} {
		if a := <-s.C; a.IdAlerta != "1" {
			t.Fatalf("alerta errado: %v", a)
		}
	}
	s1.Close()
	s1.Close() // idempotente
	if _, ok := <-s1.C; ok {
		t.Fatal("C deve ser fechado")
	}
	b.Publish(&psychoscopev1.Alerta{IdAlerta: "2"})
	if a := <-s2.C; a.IdAlerta != "2" {
		t.Fatal("s2 deve continuar recebendo")
	}
}

func TestSlowSubscriberNeverBlocksPublisher(t *testing.T) {
	b := NewBus()
	slow := b.Subscribe(2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish(&psychoscopev1.Alerta{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish bloqueou")
	}
	if slow.Dropped() != 998 {
		t.Fatalf("dropped=%d", slow.Dropped())
	}
}

func TestConcurrentPublishSubscribeClose(t *testing.T) {
	b := NewBus()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.Publish(&psychoscopev1.Alerta{})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s := b.Subscribe(1)
				s.Close()
			}
		}()
	}
	wg.Wait()
}

func TestHistoryRingAndReplay(t *testing.T) {
	b := NewBusWithHistory(3)
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		b.Publish(&psychoscopev1.Alerta{IdAlerta: id})
	}
	rec := b.Recent()
	if len(rec) != 3 || rec[0].IdAlerta != "3" || rec[2].IdAlerta != "5" {
		t.Fatalf("historico: %v", rec)
	}
	sub := b.SubscribeWithHistory(2)
	b.Publish(&psychoscopev1.Alerta{IdAlerta: "6"})
	var got []string
	for i := 0; i < 4; i++ {
		got = append(got, (<-sub.C).IdAlerta)
	}
	if got[0] != "3" || got[1] != "4" || got[2] != "5" || got[3] != "6" {
		t.Fatalf("replay + ao vivo sem lacunas/duplicatas: %v", got)
	}
	if plain := b.Subscribe(1); len(plain.C) != 0 {
		t.Fatal("Subscribe simples nao reenvia historico")
	}
	if none := NewBusWithHistory(0); len(none.Recent()) != 0 {
		t.Fatal("sem historico")
	}
}

func TestSeedFillsEmptyHistoryOnly(t *testing.T) {
	b := NewBusWithHistory(3)
	var past []*psychoscopev1.Alerta
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		past = append(past, &psychoscopev1.Alerta{IdAlerta: id})
	}
	b.Seed(past)
	if rec := b.Recent(); len(rec) != 3 || rec[0].IdAlerta != "3" || rec[2].IdAlerta != "5" {
		t.Fatalf("seed deve reter os mais recentes: %v", rec)
	}
	b.Seed([]*psychoscopev1.Alerta{{IdAlerta: "x"}})
	if rec := b.Recent(); len(rec) != 3 || rec[2].IdAlerta != "5" {
		t.Fatal("Seed nao pode sobrescrever historico existente")
	}
	b.Publish(&psychoscopev1.Alerta{IdAlerta: "6"})
	if rec := b.Recent(); rec[2].IdAlerta != "6" || rec[0].IdAlerta != "4" {
		t.Fatalf("publicar apos seed: %v", rec)
	}
	NewBusWithHistory(0).Seed(past) // sem historico: ignora sem panico
}

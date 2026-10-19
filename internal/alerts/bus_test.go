package alerts

import (
	"sync"
	"testing"
	"time"

	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
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

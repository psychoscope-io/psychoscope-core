package detection

import "time"

// Window e a janela deslizante em memoria: guarda os eventos dos ultimos `span` (no
// tempo dos eventos) e no maximo `max` eventos, com indices por origem e destino para
// que as regras consultem o historico de um IP sem varrer tudo.
//
// Nao e seguro para uso concorrente: pertence a goroutine do Engine.
type Window struct {
	span time.Duration
	max  int

	q    []*Event // fila global em ordem de chegada
	head int
	now  time.Time // maior At visto

	bySrc  map[string]*keyQueue // eventos de rede, por IP de origem
	byDst  map[string]*keyQueue // eventos de rede, por IP de destino
	byType map[string]*keyQueue // eventos genericos, por tipo
}

type keyQueue struct {
	evs  []*Event
	head int
}

func (k *keyQueue) len() int { return len(k.evs) - k.head }

// NewWindow cria uma janela de duracao span e capacidade max eventos.
func NewWindow(span time.Duration, max int) *Window {
	return &Window{span: span, max: max, bySrc: map[string]*keyQueue{}, byDst: map[string]*keyQueue{}, byType: map[string]*keyQueue{}}
}

// Now devolve o relogio da janela (maior instante de evento ja visto).
func (w *Window) Now() time.Time { return w.now }

// Len devolve quantos eventos estao retidos.
func (w *Window) Len() int { return len(w.q) - w.head }

// Span devolve a duracao da janela.
func (w *Window) Span() time.Duration { return w.span }

// SetSpan troca a duracao da janela e descarta o que ficou fora dela. Os eventos retidos
// continuam: as regras nao perdem o historico recente ao ser reconfiguradas.
func (w *Window) SetSpan(span time.Duration) {
	w.span = span
	w.evict()
}

// FromSrc devolve, em ordem de chegada, os eventos retidos cuja origem e ip.
// A fatia e somente leitura e so e valida ate o proximo Add.
func (w *Window) FromSrc(ip string) []*Event { return view(w.bySrc[ip]) }

// ToDst devolve, em ordem de chegada, os eventos retidos cujo destino e ip.
func (w *Window) ToDst(ip string) []*Event { return view(w.byDst[ip]) }

// OfType devolve, em ordem de chegada, os eventos genericos retidos do tipo dado.
// A fatia e somente leitura e so e valida ate o proximo Add.
func (w *Window) OfType(tipo string) []*Event { return view(w.byType[tipo]) }

func view(k *keyQueue) []*Event {
	if k == nil {
		return nil
	}
	return k.evs[k.head:]
}

// Add insere o evento, avanca o relogio e descarta o que saiu da janela.
func (w *Window) Add(e *Event) {
	// Evento tao atrasado que ja nasce fora da janela: nao entra (manteria a ordem por
	// chegada das filas por chave fora da ordem temporal).
	if !w.now.IsZero() && e.At.Before(w.now.Add(-w.span)) {
		return
	}
	w.q = append(w.q, e)
	w.index(e)
	if e.At.After(w.now) {
		w.now = e.At
	}
	w.evict()
}

// index e unindex mantem os indices por chave da variante do evento.
func (w *Window) index(e *Event) {
	switch e.Kind() {
	case KindNet:
		push(w.bySrc, e.Net.GetIpOrigem(), e)
		push(w.byDst, e.Net.GetIpDestino(), e)
	case KindGeneric:
		push(w.byType, e.Generic.GetTipo(), e)
	}
}

func (w *Window) unindex(e *Event) {
	switch e.Kind() {
	case KindNet:
		pop(w.bySrc, e.Net.GetIpOrigem(), e)
		pop(w.byDst, e.Net.GetIpDestino(), e)
	case KindGeneric:
		pop(w.byType, e.Generic.GetTipo(), e)
	}
}

func push(m map[string]*keyQueue, key string, e *Event) {
	k := m[key]
	if k == nil {
		k = &keyQueue{}
		m[key] = k
	}
	k.evs = append(k.evs, e)
}

func (w *Window) evict() {
	cutoff := w.now.Add(-w.span)
	for w.Len() > 0 {
		front := w.q[w.head]
		if w.Len() <= w.max && !front.At.Before(cutoff) {
			break
		}
		w.q[w.head] = nil
		w.head++
		w.unindex(front)
	}
	if w.head > 1024 && w.head*2 > len(w.q) {
		w.q = append([]*Event(nil), w.q[w.head:]...)
		w.head = 0
	}
}

func pop(m map[string]*keyQueue, key string, e *Event) {
	k := m[key]
	if k == nil {
		return
	}
	// O evento removido da fila global e sempre o mais antigo de sua chave.
	if k.head < len(k.evs) && k.evs[k.head] == e {
		k.evs[k.head] = nil
		k.head++
	}
	if k.len() == 0 {
		delete(m, key)
		return
	}
	if k.head > 256 && k.head*2 > len(k.evs) {
		k.evs = append([]*Event(nil), k.evs[k.head:]...)
		k.head = 0
	}
}

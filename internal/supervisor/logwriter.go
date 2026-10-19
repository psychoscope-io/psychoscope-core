package supervisor

import (
	"bytes"
	"log/slog"
)

const maxLogLine = 16 << 10

// lineLogger transforma a saida do filho (stdout/stderr) em registros slog, uma linha por registro.
// Linhas maiores que maxLogLine sao quebradas para limitar memoria.
type lineLogger struct {
	log    *slog.Logger
	stream string
	buf    []byte
}

func (w *lineLogger) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.buf = append(w.buf, p...)
			if len(w.buf) >= maxLogLine {
				w.flush()
			}
			break
		}
		w.buf = append(w.buf, p[:i]...)
		w.flush()
		p = p[i+1:]
	}
	return n, nil
}

func (w *lineLogger) flush() {
	if len(w.buf) == 0 {
		return
	}
	w.log.Info(string(bytes.TrimRight(w.buf, "\r")), "stream", w.stream)
	w.buf = w.buf[:0]
}

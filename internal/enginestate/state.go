// Package enginestate guarda em disco o estado do motor de deteccao (cooldowns e o estado das
// regras, como as series do beacon) para que um reinicio do Core nao traga de volta alertas ja
// vistos. O estado e so uma otimizacao: um arquivo ausente, ilegivel ou velho demais e
// descartado e o Core sobe vazio, nunca deixa de subir.
package enginestate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/detection"
)

const (
	// DefaultInterval e a frequencia padrao do snapshot periodico.
	DefaultInterval = 60 * time.Second

	// maxFutureSkew tolera um relogio levemente adiantado ao salvar. Um arquivo mais "novo" que
	// isso indica que o relogio voltou atras, e restaurar deixaria o beacon cego (ele rejeita
	// eventos mais antigos que o ultimo visto) pelo tempo do salto; saltos menores que o limite
	// passam. Nao ha idade maxima: o estado expira sozinho, no tempo dos eventos, e uma parada
	// longa so deixa entradas que a primeira atividade descarta.
	maxFutureSkew = time.Minute

	// maxFileSize limita a leitura e a gravacao: o arquivo e entrada nao confiavel, e o beacon
	// exporta no maximo 30 mil series (cerca de 25 MB), entao um arquivo legitimo cabe com folga.
	maxFileSize = 32 << 20
)

// Motivos pelos quais um arquivo existente nao e restaurado.
var (
	ErrVersion = errors.New("versao do formato desconhecida")
	ErrFuture  = errors.New("estado salvo no futuro (o relogio voltou atras?)")
	ErrTooBig  = errors.New("estado grande demais para o arquivo")
)

// Store le e grava o snapshot em Path (modo 0600, diretorio 0750). Now e o relogio de parede.
type Store struct {
	Path string
	Now  func() time.Time
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Load le o snapshot. Arquivo ausente devolve (nil, nil). Qualquer outro problema (ilegivel,
// versao desconhecida, no futuro, grande demais) devolve um erro: o chamador registra e segue vazio.
func (s Store) Load() (*detection.Snapshot, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileSize {
		return nil, ErrTooBig
	}
	var snap detection.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, fmt.Errorf("arquivo ilegivel: %w", err)
	}
	if snap.Versao != detection.SnapshotVersion {
		return nil, fmt.Errorf("%w: %d", ErrVersion, snap.Versao)
	}
	if s.now().Sub(snap.SalvoEm) < -maxFutureSkew {
		return nil, ErrFuture
	}
	return &snap, nil
}

// Save grava o snapshot de forma atomica (temporario no mesmo diretorio, sync e rename), com
// modo 0600, carimbando o instante da gravacao.
func (s Store) Save(snap *detection.Snapshot) error {
	snap.Versao = detection.SnapshotVersion
	snap.SalvoEm = s.now().UTC()
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if len(data) > maxFileSize { // Load recusaria o arquivo: melhor falhar aqui, visivel nas metricas
		return fmt.Errorf("%w (%d bytes, limite %d)", ErrTooBig, len(data), maxFileSize)
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".engine-state-*.tmp") // CreateTemp ja usa o modo 0600
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no sucesso o rename ja o moveu; sem efeito
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path)
}

package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

// ErrPersist marca a falha ao gravar o arquivo de ajustes. A mensagem completa traz o caminho
// do arquivo; quem responde a clientes deve registrar o detalhe no log e devolver so o aviso
// generico (erros para clientes nao vazam caminhos internos).
var ErrPersist = errors.New("nao foi possivel gravar os ajustes")

// Live aplica uma configuracao efetiva nos componentes em execucao (motor, gravador).
type Live interface {
	Apply(ctx context.Context, c *config.Config) error
}

// Caller identifica quem pediu a mudanca (credenciais do kernel, so para a auditoria).
type Caller struct {
	UID uint32
	PID int32
}

// Change e uma mudanca de valor efetivo, em JSON (para a auditoria e para a resposta).
type Change struct{ Path, Old, New string }

// Result e o que uma aplicacao produziu.
type Result struct {
	Changes  []Change
	Warnings []string
}

// Manager guarda a configuracao base (padroes + arquivo do administrador), os ajustes e a
// configuracao efetiva, e e o unico que escreve o arquivo de ajustes.
type Manager struct {
	path string
	live Live
	log  *slog.Logger

	mu   sync.Mutex // serializa Apply: a mudanca e validada, gravada e aplicada por inteiro
	base *config.Config
	ov   config.Overrides
	cur  *config.Config
}

// New le o arquivo de ajustes (ausente = sem ajustes) e calcula a configuracao efetiva. Um
// arquivo invalido e erro: o Core nao parte com uma configuracao que o usuario nao pediu.
func New(base *config.Config, overridesPath string, live Live, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ov, err := config.ReadOverrides(overridesPath)
	if err != nil {
		return nil, err
	}
	cur, err := config.Layer(base, ov)
	if err != nil {
		return nil, fmt.Errorf("ajustes %s: %w (corrija ou remova o arquivo para voltar a configuracao do administrador)", overridesPath, err)
	}
	return &Manager{path: overridesPath, live: live, log: log, base: base, ov: ov, cur: cur}, nil
}

// Effective devolve a configuracao efetiva atual (base + ajustes).
func (m *Manager) Effective() *config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// OverridesPath e o arquivo onde os ajustes ficam gravados.
func (m *Manager) OverridesPath() string { return m.path }

// Fields devolve o catalogo de campos editaveis com valor atual, padrao e origem.
func (m *Manager) Fields() ([]Field, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Catalog(m.cur, m.ov)
}

// Apply valida, grava e aplica os ajustes (caminho -> valor JSON) e as restauracoes (caminhos
// que voltam ao valor da base). Ou tudo vale, ou nada e alterado: a validacao e conjunta, e
// so depois dela o arquivo e gravado (de forma atomica) e a configuracao e aplicada ao vivo.
// Se a gravacao der certo e a aplicacao ao vivo falhar, o ajuste fica salvo e o resultado traz
// um aviso (vale na proxima partida). Toda mudanca de valor vai para o log de auditoria.
func (m *Manager) Apply(ctx context.Context, patch map[string]string, restore []string, who Caller) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	next, err := m.plan(patch, restore)
	if err != nil {
		return Result{}, err
	}
	eff, err := config.Layer(m.base, next)
	if err != nil {
		return Result{}, err
	}
	changes, err := diff(m.cur, eff)
	if err != nil {
		return Result{}, err
	}
	if len(changes) == 0 && sameOverrides(m.ov, next) {
		return Result{}, nil
	}
	if err := m.persist(next); err != nil {
		return Result{}, fmt.Errorf("%w em %s: %w", ErrPersist, m.path, err)
	}
	m.ov, m.cur = next, eff
	for _, c := range changes {
		m.log.Warn("configuracao alterada", "uid", who.UID, "pid", who.PID, "campo", c.Path, "antes", c.Old, "depois", c.New)
	}
	res := Result{Changes: changes}
	if m.live != nil && len(changes) > 0 {
		if err := m.live.Apply(ctx, eff); err != nil {
			m.log.Error("ajustes gravados, mas nao aplicados ao vivo", "err", err)
			res.Warnings = append(res.Warnings, fmt.Sprintf("ajustes gravados, mas nao foi possivel aplica-los ao vivo (%v); reinicie o servico para aplicar", err))
		}
	}
	return res, nil
}

// plan monta os novos ajustes: copia os atuais, aplica patch e restore. Todo caminho precisa
// estar no catalogo (a lista fechada de campos editaveis) e todo valor precisa ser JSON valido.
func (m *Manager) plan(patch map[string]string, restore []string) (config.Overrides, error) {
	known := map[string]bool{}
	entries, err := describe(m.cur)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		known[e.path] = true
	}
	next := make(config.Overrides, len(m.ov)+len(patch))
	for k, v := range m.ov {
		next[k] = v
	}
	for path, val := range patch {
		if !known[path] {
			return nil, fmt.Errorf("campo desconhecido ou nao editavel pelo canal de controle: %q", path)
		}
		if !json.Valid([]byte(val)) {
			return nil, fmt.Errorf("%s: valor nao e JSON valido: %q (duracoes entre aspas, listas como [\"a\",\"b\"])", path, val)
		}
		next[path] = json.RawMessage(val)
	}
	for _, path := range restore {
		if !known[path] {
			return nil, fmt.Errorf("campo desconhecido ou nao editavel pelo canal de controle: %q", path)
		}
		if _, both := patch[path]; both {
			return nil, fmt.Errorf("%s: o mesmo campo nao pode ser ajustado e restaurado no mesmo pedido", path)
		}
		delete(next, path)
	}
	return next, nil
}

// diff lista os campos cujo valor efetivo mudou.
func diff(old, now *config.Config) ([]Change, error) {
	a, err := describe(old)
	if err != nil {
		return nil, err
	}
	b, err := describe(now)
	if err != nil {
		return nil, err
	}
	var out []Change
	for i := range a {
		if a[i].value != b[i].value {
			out = append(out, Change{Path: a[i].path, Old: a[i].value, New: b[i].value})
		}
	}
	return out, nil
}

func sameOverrides(a, b config.Overrides) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !slices.Equal(v, w) {
			return false
		}
	}
	return true
}

// persist grava os ajustes de forma atomica (temporario no mesmo diretorio e rename), com
// modo 0600. Sem ajustes, remove o arquivo.
func (m *Manager) persist(o config.Overrides) error {
	if len(o) == 0 {
		if err := os.Remove(m.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := o.JSON()
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".overrides-*.tmp") // CreateTemp ja usa o modo 0600
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no sucesso o rename ja o moveu; sem efeito
	if _, err := tmp.Write(append(data, '\n')); err != nil {
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
	return os.Rename(tmp.Name(), m.path)
}

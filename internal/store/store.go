// Package store persiste alertas em SQLite (modernc.org/sqlite, sem CGO), para que o
// historico sobreviva a reinicios do Core e possa ser consultado por tempo, severidade,
// regra e modulo.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	_ "modernc.org/sqlite" // driver "sqlite"
)

const (
	schemaVersion = 1
	// DefaultLimit e MaxLimit delimitam o tamanho de uma consulta.
	DefaultLimit = 100
	MaxLimit     = 1000
)

// ErrNewerSchema indica um banco criado por uma versao mais nova do Psychoscope.
var ErrNewerSchema = errors.New("store: o banco foi criado por uma versao mais nova do Psychoscope")

// Filter descreve uma consulta de alertas. Campos zerados nao filtram.
type Filter struct {
	Limit       int // 0 = DefaultLimit; acima de MaxLimit e reduzido
	Since       time.Time
	MinSeverity psychoscopev1.Severidade
	Rule        string
	Module      string
}

func (f Filter) limit() int {
	switch {
	case f.Limit <= 0:
		return DefaultLimit
	case f.Limit > MaxLimit:
		return MaxLimit
	}
	return f.Limit
}

// Match informa se o alerta satisfaz o filtro (ignora Limit). Usado tambem para
// consultar o historico em memoria quando nao ha banco.
func (f Filter) Match(a *psychoscopev1.Alerta) bool {
	if !f.Since.IsZero() && (a.Timestamp == nil || a.Timestamp.AsTime().Before(f.Since)) {
		return false
	}
	if a.Severidade < f.MinSeverity {
		return false
	}
	if f.Rule != "" && a.Regra != f.Rule {
		return false
	}
	if f.Module != "" && a.IdModuloOrigem != f.Module {
		return false
	}
	return true
}

func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	if !f.Since.IsZero() {
		conds = append(conds, "ts_ns >= ?")
		args = append(args, f.Since.UnixNano())
	}
	if f.MinSeverity > 0 {
		conds = append(conds, "severidade >= ?")
		args = append(args, int32(f.MinSeverity))
	}
	if f.Rule != "" {
		conds = append(conds, "regra = ?")
		args = append(args, f.Rule)
	}
	if f.Module != "" {
		conds = append(conds, "id_modulo = ?")
		args = append(args, f.Module)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Stats sao contadores do store (monotonicos).
type Stats struct {
	Written     uint64
	WriteErrors uint64
	Pruned      uint64
}

// Store e o banco de alertas. Seguro para uso concorrente.
type Store struct {
	db   *sql.DB
	path string

	written, writeErrors, pruned atomic.Uint64
}

// Open abre (criando, se preciso) o banco em path. O diretorio e criado com 0750 e o
// arquivo com 0600 (os arquivos -wal/-shm herdam o modo do principal).
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: criando diretorio: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: abrindo %s: %w", path, err)
	}
	_ = f.Close()

	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Uma conexao: escritas serializadas e sem SQLITE_BUSY entre goroutines do proprio Core.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("%w (versao do esquema %d > %d)", ErrNewerSchema, v, schemaVersion)
	}
	if v == schemaVersion {
		return nil
	}
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS alerts (
  id         TEXT PRIMARY KEY,
  ts_ns      INTEGER NOT NULL,
  regra      TEXT NOT NULL,
  severidade INTEGER NOT NULL,
  descricao  TEXT NOT NULL,
  id_modulo  TEXT NOT NULL,
  contexto   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts_ns);
CREATE INDEX IF NOT EXISTS alerts_regra_ts ON alerts (regra, ts_ns);
CREATE INDEX IF NOT EXISTS alerts_sev_ts ON alerts (severidade, ts_ns);
PRAGMA user_version = 1;`)
	return err
}

// Path devolve o caminho do arquivo do banco.
func (s *Store) Path() string { return s.path }

// Stats devolve os contadores acumulados.
func (s *Store) Stats() Stats {
	return Stats{Written: s.written.Load(), WriteErrors: s.writeErrors.Load(), Pruned: s.pruned.Load()}
}

// Close fecha o banco (faz checkpoint do WAL).
func (s *Store) Close() error { return s.db.Close() }

// Insert grava os alertas em uma transacao. Ids repetidos sao ignorados.
func (s *Store) Insert(ctx context.Context, as []*psychoscopev1.Alerta) error {
	if len(as) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.writeErrors.Add(1)
		return err
	}
	defer tx.Rollback() //nolint:errcheck // sem efeito apos Commit
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO alerts (id, ts_ns, regra, severidade, descricao, id_modulo, contexto) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		s.writeErrors.Add(1)
		return err
	}
	defer stmt.Close()
	for _, a := range as {
		ctxJSON, err := json.Marshal(a.Contexto)
		if err != nil {
			s.writeErrors.Add(1)
			return err
		}
		ts := time.Now()
		if a.Timestamp != nil {
			ts = a.Timestamp.AsTime()
		}
		if _, err := stmt.ExecContext(ctx, a.IdAlerta, ts.UnixNano(), a.Regra, int32(a.Severidade), a.Descricao, a.IdModuloOrigem, string(ctxJSON)); err != nil {
			s.writeErrors.Add(1)
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		s.writeErrors.Add(1)
		return err
	}
	s.written.Add(uint64(len(as)))
	return nil
}

func scan(rows *sql.Rows) ([]*psychoscopev1.Alerta, error) {
	var out []*psychoscopev1.Alerta
	for rows.Next() {
		var (
			a      psychoscopev1.Alerta
			ts     int64
			sev    int32
			ctxRaw string
		)
		if err := rows.Scan(&a.IdAlerta, &ts, &a.Regra, &sev, &a.Descricao, &a.IdModuloOrigem, &ctxRaw); err != nil {
			return nil, err
		}
		a.Severidade = psychoscopev1.Severidade(sev)
		a.Timestamp = timestamppb.New(time.Unix(0, ts))
		if ctxRaw != "" && ctxRaw != "null" {
			if err := json.Unmarshal([]byte(ctxRaw), &a.Contexto); err != nil {
				return nil, fmt.Errorf("store: contexto do alerta %s: %w", a.IdAlerta, err)
			}
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// Query devolve os alertas que casam com f, do mais novo ao mais antigo, e o total
// que casa com o filtro ignorando o limite.
func (s *Store) Query(ctx context.Context, f Filter) ([]*psychoscopev1.Alerta, uint64, error) {
	where, args := f.where()
	var total uint64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, ts_ns, regra, severidade, descricao, id_modulo, contexto FROM alerts"+where+" ORDER BY ts_ns DESC, id DESC LIMIT ?",
		append(args, f.limit())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	as, err := scan(rows)
	return as, total, err
}

// Recent devolve os n alertas mais recentes em ordem cronologica (do mais antigo ao mais
// novo), a forma esperada por alerts.Bus.Seed.
func (s *Store) Recent(ctx context.Context, n int) ([]*psychoscopev1.Alerta, error) {
	as, _, err := s.Query(ctx, Filter{Limit: min(n, MaxLimit)})
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(as)-1; i < j; i, j = i+1, j-1 {
		as[i], as[j] = as[j], as[i]
	}
	return as, nil
}

// Count devolve o numero de alertas armazenados.
func (s *Store) Count(ctx context.Context) (uint64, error) {
	var n uint64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&n)
	return n, err
}

// Prune remove alertas mais antigos que olderThan (se nao zero) e, se maxRows > 0,
// o excedente alem das maxRows linhas mais recentes. Devolve quantas linhas removeu.
func (s *Store) Prune(ctx context.Context, olderThan time.Time, maxRows int) (int64, error) {
	var total int64
	if !olderThan.IsZero() {
		res, err := s.db.ExecContext(ctx, "DELETE FROM alerts WHERE ts_ns < ?", olderThan.UnixNano())
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	if maxRows > 0 {
		res, err := s.db.ExecContext(ctx,
			`DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY ts_ns DESC, id DESC LIMIT -1 OFFSET ?)`, maxRows)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
	}
	s.pruned.Add(uint64(total))
	return total, nil
}

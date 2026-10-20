package config

import (
	"errors"
	"path/filepath"
	"time"
)

// Storage configura a persistencia de alertas (SQLite).
type Storage struct {
	Enabled       bool
	Path          string
	RetentionDays int // 0 = nao remove por idade
	MaxAlerts     int // 0 = sem teto
}

type fileStorage struct {
	Enabled       *bool  `json:"enabled"`
	Path          string `json:"path"`
	RetentionDays *int   `json:"retention_days"`
	MaxAlerts     *int   `json:"max_alerts"`
}

// Retention devolve a retencao como duracao (0 = sem limite por idade).
func (s Storage) Retention() time.Duration { return time.Duration(s.RetentionDays) * 24 * time.Hour }

// loadStorage parte dos defaults (habilitado, 30 dias, 100 mil alertas) e sobrepoe o arquivo.
func loadStorage(f fileStorage, e Env) Storage {
	s := Storage{Enabled: true, Path: filepath.Join(DefaultStateDir(e), "alerts.db"), RetentionDays: 30, MaxAlerts: 100_000}
	if f.Enabled != nil {
		s.Enabled = *f.Enabled
	}
	if f.Path != "" {
		s.Path = f.Path
	}
	if f.RetentionDays != nil {
		s.RetentionDays = *f.RetentionDays
	}
	if f.MaxAlerts != nil {
		s.MaxAlerts = *f.MaxAlerts
	}
	return s
}

func (s Storage) validate() error {
	if s.Enabled && s.Path == "" {
		return errors.New("storage.path e obrigatorio quando storage.enabled")
	}
	if s.RetentionDays < 0 || s.MaxAlerts < 0 {
		return errors.New("storage.retention_days e storage.max_alerts nao podem ser negativos")
	}
	return nil
}

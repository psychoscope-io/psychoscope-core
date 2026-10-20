package config

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// fileConfig e o esquema do arquivo JSON (chaves desconhecidas sao erro).
type fileConfig struct {
	Socket         string        `json:"socket"`
	CtlSocket      string        `json:"ctl_socket"`
	SocketMode     string        `json:"socket_mode"`
	AllowUnmanaged bool          `json:"allow_unmanaged"`
	AllowedUIDs    []uint32      `json:"allowed_uids"`
	StatusInterval string        `json:"status_interval"`
	CommandTimeout string        `json:"command_timeout"`
	LogLevel       string        `json:"log_level"`
	Modules        []fileModule  `json:"modules"`
	Detection      fileDetection `json:"detection"`
	Storage        fileStorage   `json:"storage"`
	Metrics        fileMetrics   `json:"metrics"`
}

// flags sao as opcoes de linha de comando.
type flags struct {
	config, socket, ctlSocket, logLevel string
	allowUnmanaged                      bool
}

func parseFlags(args []string) (flags, error) {
	var f flags
	fs := flag.NewFlagSet("psychoscope", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.config, "config", "", "arquivo de configuracao JSON")
	fs.StringVar(&f.socket, "socket", "", "socket dos modulos (core.sock)")
	fs.StringVar(&f.ctlSocket, "ctl-socket", "", "socket de controle da CLI (ctl.sock)")
	fs.BoolVar(&f.allowUnmanaged, "allow-unmanaged", false, "aceita modulos nao lancados pelo supervisor (dev)")
	fs.StringVar(&f.logLevel, "log-level", "", "debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return f, fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("argumentos inesperados: %v", fs.Args())
	}
	return f, nil
}

// readFile le o arquivo de configuracao; path vazio devolve a configuracao vazia.
func readFile(path string) (fileConfig, error) {
	var fc fileConfig
	if path == "" {
		return fc, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fc, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return fc, fmt.Errorf("config %s: %w", path, err)
	}
	return fc, nil
}

// Command psychoscope e o daemon do Core (hub do MODR).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bandeira27/psychoscope-core/internal/app"
	"github.com/Bandeira27/psychoscope-core/internal/config"
)

func main() {
	cfg, err := config.Load(os.Args[1:], config.OSEnv())
	if err != nil {
		fmt.Fprintln(os.Stderr, "psychoscope:", err)
		os.Exit(2)
	}
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("falha fatal", "err", err)
		os.Exit(1)
	}
}

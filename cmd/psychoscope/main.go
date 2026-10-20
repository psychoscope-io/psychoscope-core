// Command psychoscope e o daemon do Core (hub do MODR).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/psychoscope-io/psychoscope-core/internal/app"
	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
)

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version" || os.Args[1] == "version") {
		fmt.Println("psychoscope", version.Version)
		return
	}
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

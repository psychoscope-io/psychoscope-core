// Command psychoscope-cli e o cliente do canal de controle (ctl.sock).
//
//	psychoscope-cli [--ctl-socket S]                       TUI interativa (terminal)
//	psychoscope-cli [--ctl-socket S] list                  tabela de modulos
//	psychoscope-cli [--ctl-socket S] cmd <modulo> pause|resume|reconfigure|stop [chave=valor ...]
//	psychoscope-cli [--ctl-socket S] alerts [--no-history] stream de alertas (Ctrl+C sai)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/tui"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"golang.org/x/term"
)

const usage = `uso: psychoscope-cli [--ctl-socket S] [comando]
  (sem comando)                       abre a TUI interativa
  list                                lista os modulos
  cmd <modulo> pause|resume|reconfigure|stop [k=v ...]
  alerts [--no-history]               acompanha os alertas`

var actions = map[string]psychoscopev1.ComandoControle_TipoAcao{
	"pause":       psychoscopev1.ComandoControle_PAUSAR,
	"resume":      psychoscopev1.ComandoControle_RETOMAR,
	"reconfigure": psychoscopev1.ComandoControle_RECONFIGURAR,
	"stop":        psychoscopev1.ComandoControle_ENCERRAR,
}

func main() {
	args := os.Args[1:]
	sock := firstNonEmpty(os.Getenv(config.EnvCtlSocket), config.DefaultSocketDir(config.OSEnv())+"/ctl.sock")
	if len(args) >= 2 && args[0] == "--ctl-socket" {
		sock, args = args[1], args[2:]
	} else if len(args) >= 1 && strings.HasPrefix(args[0], "--ctl-socket=") {
		sock, args = strings.TrimPrefix(args[0], "--ctl-socket="), args[1:]
	}
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		fmt.Println(usage)
		return
	}
	if err := run(&ctl.Client{Path: sock}, args); err != nil {
		fmt.Fprintln(os.Stderr, "psychoscope-cli:", err)
		os.Exit(1)
	}
}

func run(cl *ctl.Client, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if len(args) == 0 {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
			return fmt.Errorf("a TUI requer um terminal interativo\n%s", usage)
		}
		return tui.Run(tui.ClientBackend{Client: cl})
	}

	switch args[0] {
	case "list":
		mods, err := cl.List(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "MODULO\tESTADO\tPID\tREINICIOS\tEVENTOS\tPACOTES\tDESCARTES\tULTIMO CONTATO\tERRO")
		for _, m := range mods {
			contato := "-"
			if m.UltimoContato != nil {
				contato = m.UltimoContato.AsTime().Local().Format(time.TimeOnly)
			}
			st := m.UltimoStatus
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", m.IdModulo, strings.TrimPrefix(m.Estado.String(), "ESTADO_"), m.Pid, m.Reinicios,
				st.GetEventosProcessados(), st.GetPacotesCapturados(), st.GetPacotesDescartados(), contato, m.UltimoErro)
		}
		return tw.Flush()

	case "cmd":
		if len(args) < 3 {
			return fmt.Errorf("uso: cmd <modulo> pause|resume|reconfigure|stop [k=v ...]")
		}
		acao, ok := actions[args[2]]
		if !ok {
			return fmt.Errorf("acao desconhecida %q", args[2])
		}
		params := map[string]string{}
		for _, kv := range args[3:] {
			k, v, found := strings.Cut(kv, "=")
			if !found {
				return fmt.Errorf("parametro %q deve ser chave=valor", kv)
			}
			params[k] = v
		}
		if err := cl.Command(ctx, args[1], acao, params); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil

	case "alerts":
		history := !(len(args) > 1 && args[1] == "--no-history")
		st, err := cl.StreamAlerts(ctx, history)
		if err != nil {
			return err
		}
		defer st.Close()
		for a := range st.C {
			ts := "--:--:--"
			if a.Timestamp != nil {
				ts = a.Timestamp.AsTime().Local().Format(time.TimeOnly)
			}
			fmt.Printf("%s [%s] %s: %s\n", ts, strings.TrimPrefix(a.Severidade.String(), "SEVERIDADE_"), a.Regra, a.Descricao)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err := st.Err(); err != nil {
			return fmt.Errorf("stream encerrado: %w", err)
		}
		return nil
	}
	return fmt.Errorf("subcomando desconhecido %q\n%s", args[0], usage)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

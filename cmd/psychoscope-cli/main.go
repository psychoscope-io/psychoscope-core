// Command psychoscope-cli e o cliente do canal de controle (ctl.sock).
//
//	psychoscope-cli [--ctl-socket S]                       TUI interativa (terminal)
//	psychoscope-cli [--ctl-socket S] list                  tabela de modulos
//	psychoscope-cli [--ctl-socket S] cmd <modulo> pause|resume|reconfigure|stop [chave=valor ...]
//	psychoscope-cli [--ctl-socket S] alerts [--no-history] [-v] stream de alertas ao vivo (Ctrl+C sai)
//	psychoscope-cli [--ctl-socket S] alerts --history [-v] ... consulta o historico persistido
//	psychoscope-cli [--ctl-socket S] metrics               metricas do Core
//	psychoscope-cli [--ctl-socket S] config [set|reset ...] configuracao editavel em tempo de execucao
//	psychoscope-cli [--ctl-socket S] doctor [--sensor] [--json] diagnostico da instalacao (sai com 1 se houver falha)
//	psychoscope-cli analyze [--set k=v] [--json] arquivo.pcap analise offline de um pcap, sem o servico (nao usa o Core)
//	psychoscope-cli migrate-config [--config arq] [--sensor-env arq] [--user nome] migra o sensor da configuracao antiga (modulo externo)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	"github.com/psychoscope-io/psychoscope-core/internal/tui"
	"github.com/psychoscope-io/psychoscope-core/internal/version"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
	"golang.org/x/term"
)

const usage = `uso: psychoscope-cli [--ctl-socket S] [comando]
  (sem comando)                       abre a TUI interativa
  list                                lista os modulos
  cmd <modulo> pause|resume|reconfigure|stop [k=v ...]
  alerts [--no-history] [-v]          acompanha os alertas ao vivo
  alerts --history [-n 50] [--since 1h] [--min-severity alta] [--rule R] [--module M] [-v]
                                      consulta o historico persistido
                                      (-v mostra o contexto chave=valor de cada alerta)
  metrics                             metricas do Core
  config [-v] [prefixo]               lista os campos de configuracao editaveis (valor, padrao, origem)
  config set campo=valor [...]        ajusta campos (so root); listas separadas por virgula, duracoes como 30s
  config reset campo [...]            volta ao valor do arquivo do administrador, ou ao padrao (so root)
  doctor [--sensor] [--json] [--config caminho]
                                      diagnostica a instalacao e diz o que corrigir
                                      (--sensor roda o --check do sensor; --json para scripts)
  analyze [--set campo=valor]... [--rule R] [--config arq] [--json] [--fail-on-alert] arquivo.pcap
                                      analisa um pcap sem o servico (precisa do mod-net-sensor; --set testa um ajuste;
                                      sai com 2 se --fail-on-alert e houver alertas)
  migrate-config [--config arq] [--sensor-env arq] [--user nome]
                                      passa o sensor lancado pelo Core (configuracao ate a 0.11) para o modulo
                                      externo da unit psychoscope-sensor (so root; o install.sh ja chama)
  --version                           versao`

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
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			fmt.Println(usage)
			return
		case "--version", "-version", "version":
			fmt.Println("psychoscope-cli", version.Version)
			return
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, &ctl.Client{Path: sock}, args, os.Stdout); err != nil {
		if errors.Is(err, errAnalyzeAlerts) { // o analyze ja imprimiu o relatorio
			os.Exit(2)
		}
		if !errors.Is(err, errDoctorFailed) { // o doctor ja imprimiu o relatorio
			fmt.Fprintln(os.Stderr, "psychoscope-cli:", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
			return fmt.Errorf("a TUI requer um terminal interativo\n%s", usage)
		}
		return tui.Run(tui.ClientBackend{Client: cl})
	}

	switch args[0] {
	case "list":
		return cmdList(ctx, cl, out)
	case "cmd":
		return cmdCommand(ctx, cl, args[1:], out)
	case "alerts":
		return cmdAlerts(ctx, cl, args[1:], out)
	case "metrics":
		return cmdMetrics(ctx, cl, out)
	case "config":
		return cmdConfig(ctx, cl, args[1:], out)
	case "doctor":
		return cmdDoctor(ctx, cl, args[1:], out)
	case "analyze":
		return cmdAnalyze(ctx, args[1:], out)
	case "migrate-config":
		return cmdMigrateConfig(args[1:], out)
	}
	return fmt.Errorf("subcomando desconhecido %q\n%s", args[0], usage)
}

func cmdList(ctx context.Context, cl *ctl.Client, out io.Writer) error {
	mods, err := cl.List(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
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
}

func cmdCommand(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("uso: cmd <modulo> pause|resume|reconfigure|stop [k=v ...]")
	}
	acao, ok := actions[args[1]]
	if !ok {
		return fmt.Errorf("acao desconhecida %q", args[1])
	}
	params := map[string]string{}
	for _, kv := range args[2:] {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return fmt.Errorf("parametro %q deve ser chave=valor", kv)
		}
		params[k] = v
	}
	if err := cl.Command(ctx, args[0], acao, params); err != nil {
		return err
	}
	fmt.Fprintln(out, "ok")
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

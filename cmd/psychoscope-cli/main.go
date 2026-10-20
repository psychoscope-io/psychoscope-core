// Command psychoscope-cli e o cliente do canal de controle (ctl.sock).
// A TUI Bubbletea (Fase 5) reutiliza internal/ctl; por ora ha subcomandos simples:
//
//	psychoscope-cli [--ctl-socket S] list
//	psychoscope-cli [--ctl-socket S] cmd <modulo> pause|resume|reconfigure|stop [chave=valor ...]
//	psychoscope-cli [--ctl-socket S] alerts
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Bandeira27/psychoscope-core/internal/config"
	"github.com/Bandeira27/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/Bandeira27/psychoscope-proto/gen/go/psychoscope/v1"
)

var actions = map[string]psychoscopev1.ComandoControle_TipoAcao{
	"pause":       psychoscopev1.ComandoControle_PAUSAR,
	"resume":      psychoscopev1.ComandoControle_RETOMAR,
	"reconfigure": psychoscopev1.ComandoControle_RECONFIGURAR,
	"stop":        psychoscopev1.ComandoControle_ENCERRAR,
}

func main() {
	e := config.OSEnv()
	def := config.EnvCtlSocket
	sock := flag.String("ctl-socket", firstNonEmpty(os.Getenv(def), config.DefaultSocketDir(e)+"/ctl.sock"), "socket de controle do Core")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "uso: psychoscope-cli [--ctl-socket S] list | cmd <modulo> pause|resume|reconfigure|stop [k=v ...] | alerts")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*sock, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "psychoscope-cli:", err)
		os.Exit(1)
	}
}

func run(sock string, args []string) error {
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	switch args[0] {
	case "list":
		r, err := call(conn, &psychoscopev1.RequisicaoControle{IdRequisicao: "list",
			Pedido: &psychoscopev1.RequisicaoControle_ListarModulos{ListarModulos: &psychoscopev1.PedidoListarModulos{}}})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "MODULO\tESTADO\tPID\tREINICIOS\tEVENTOS\tPACOTES\tDESCARTES\tULTIMO CONTATO\tERRO")
		for _, m := range r.GetModulos().GetModulos() {
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
		if _, err := call(conn, &psychoscopev1.RequisicaoControle{IdRequisicao: "cmd",
			Pedido: &psychoscopev1.RequisicaoControle_EnviarComando{EnviarComando: &psychoscopev1.PedidoEnviarComando{
				IdModulo: args[1], Acao: acao, Parametros: params}}}); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil

	case "alerts":
		if _, err := call(conn, &psychoscopev1.RequisicaoControle{IdRequisicao: "alerts",
			Pedido: &psychoscopev1.RequisicaoControle_AssinarAlertas{AssinarAlertas: &psychoscopev1.PedidoAssinarAlertas{}}}); err != nil {
			return err
		}
		for {
			r, err := ctl.ReadResponse(conn)
			if err != nil {
				return err
			}
			if a := r.GetAlerta(); a != nil {
				fmt.Printf("%s [%s] %s: %s\n", a.Timestamp.AsTime().Local().Format(time.TimeOnly),
					strings.TrimPrefix(a.Severidade.String(), "SEVERIDADE_"), a.Regra, a.Descricao)
			}
		}
	}
	return fmt.Errorf("subcomando desconhecido %q", args[0])
}

func call(conn net.Conn, req *psychoscopev1.RequisicaoControle) (*psychoscopev1.RespostaControle, error) {
	_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
	if err := ctl.WriteRequest(conn, req); err != nil {
		return nil, err
	}
	r, err := ctl.ReadResponse(conn)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if !r.Sucesso {
		return nil, fmt.Errorf("%s", r.MensagemErro)
	}
	return r, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

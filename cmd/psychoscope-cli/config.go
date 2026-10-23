package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// cmdConfig atende "config": lista os campos editaveis, ajusta (set) e restaura (reset). A
// escrita exige root, o que o Core confere pelo UID do kernel; aqui so se repassa o pedido.
func cmdConfig(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return configSet(ctx, cl, args[1:], out)
		case "reset":
			return configReset(ctx, cl, args[1:], out)
		}
	}
	return configList(ctx, cl, args, out)
}

func configList(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	verbose, prefix := false, ""
	for _, a := range args {
		switch {
		case a == "-v":
			verbose = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("config: opcao desconhecida %q (uso: config [-v] [prefixo] | config set campo=valor ... | config reset campo ...)", a)
		case prefix == "":
			prefix = a
		default:
			return errors.New("config: informe um unico prefixo (por exemplo detection.beacon)")
		}
	}
	l, err := cl.Config(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CAMPO\tVALOR\tPADRAO\tORIGEM")
	n := 0
	for _, f := range l.Campos {
		if !strings.HasPrefix(f.Caminho, prefix) {
			continue
		}
		n++
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Caminho, ctl.DisplayValue(f, f.ValorAtual), ctl.DisplayValue(f, f.ValorPadrao), ctl.OriginLabel(f.Origem))
		if verbose {
			fmt.Fprintf(tw, "  %s\t\t\t\n", f.Descricao)
		}
	}
	_ = tw.Flush()
	if n == 0 {
		return fmt.Errorf("config: nenhum campo comeca com %q", prefix)
	}
	fmt.Fprintf(out, "-- %d campos; ajustes gravados em %s --\n", n, l.ArquivoAjustes)
	if l.SomenteLeitura {
		fmt.Fprintln(out, "somente leitura: para alterar, rode como root (sudo)")
	}
	return nil
}

func configSet(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("uso: config set campo=valor [campo=valor ...] (listas separadas por virgula, duracoes como 30s)")
	}
	before, err := cl.Config(ctx)
	if err != nil {
		return err
	}
	patch := map[string]string{}
	for _, kv := range args {
		path, text, found := strings.Cut(kv, "=")
		if !found {
			return fmt.Errorf("config set: %q deve ser campo=valor", kv)
		}
		f := ctl.FindField(before, path)
		if f == nil {
			return fmt.Errorf("config set: campo desconhecido ou nao editavel: %q (veja: psychoscope-cli config)", path)
		}
		v, err := ctl.ValueFromText(f, text)
		if err != nil {
			return err
		}
		patch[path] = v
	}
	return apply(ctx, cl, before, patch, nil, out)
}

func configReset(ctx context.Context, cl *ctl.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("uso: config reset campo [campo ...] (volta ao valor do arquivo do administrador, ou ao padrao)")
	}
	before, err := cl.Config(ctx)
	if err != nil {
		return err
	}
	for _, path := range args {
		if ctl.FindField(before, path) == nil {
			return fmt.Errorf("config reset: campo desconhecido ou nao editavel: %q (veja: psychoscope-cli config)", path)
		}
	}
	return apply(ctx, cl, before, nil, args, out)
}

// apply envia o pedido e mostra o que mudou (valor antes e depois) e os avisos do Core.
func apply(ctx context.Context, cl *ctl.Client, before *psychoscopev1.ListaConfig, patch map[string]string, restore []string, out io.Writer) error {
	after, err := cl.ApplyConfig(ctx, patch, restore)
	if err != nil {
		return err
	}
	changed := 0
	for _, f := range after.Campos {
		old := ctl.FindField(before, f.Caminho)
		if old != nil && old.ValorAtual != f.ValorAtual {
			changed++
			fmt.Fprintf(out, "%s: %s -> %s\n", f.Caminho, ctl.DisplayValue(old, old.ValorAtual), ctl.DisplayValue(f, f.ValorAtual))
		}
	}
	if changed == 0 {
		fmt.Fprintln(out, "nada mudou: os valores ja eram esses")
	}
	for _, w := range after.Avisos {
		fmt.Fprintln(out, "aviso:", w)
	}
	return nil
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// level e a gravidade de um achado do doctor.
type level int

const (
	levelOK level = iota
	levelWarn
	levelFail
	levelSkip // verificacao que nao pode rodar; nao conta como falha nem como aviso
)

func (l level) String() string {
	switch l {
	case levelWarn:
		return "aviso"
	case levelFail:
		return "falha"
	case levelSkip:
		return "pulado"
	}
	return "ok"
}

// finding e uma verificacao do doctor: o que foi olhado, o que se viu e, quando ha conserto,
// o comando ou a acao para aplica-lo.
type finding struct {
	Level  level
	Item   string
	Detail string
	Fix    string
}

// report e o resultado do doctor, na ordem em que as verificacoes rodaram.
type report []finding

func (r report) counts() (fails, warns int) {
	for _, f := range r {
		switch f.Level {
		case levelFail:
			fails++
		case levelWarn:
			warns++
		}
	}
	return fails, warns
}

// writeText imprime no formato do `mod-net-sensor --check`: uma linha por achado, o conserto
// recuado abaixo e o resultado no fim.
func (r report) writeText(w io.Writer) {
	for _, f := range r {
		line := f.Item
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		fmt.Fprintf(w, "%-9s%s\n", "["+f.Level.String()+"]", line)
		if f.Fix != "" {
			fmt.Fprintf(w, "%s como corrigir: %s\n", strings.Repeat(" ", 9), f.Fix)
		}
	}
	fails, warns := r.counts()
	fmt.Fprintf(w, "resultado: %d falha(s), %d aviso(s)\n", fails, warns)
}

type jsonFinding struct {
	Nivel        string `json:"nivel"`
	Item         string `json:"item"`
	Detalhe      string `json:"detalhe,omitempty"`
	ComoCorrigir string `json:"como_corrigir,omitempty"`
}

type jsonReport struct {
	Resultado struct {
		Falhas int `json:"falhas"`
		Avisos int `json:"avisos"`
	} `json:"resultado"`
	Achados []jsonFinding `json:"achados"`
}

// writeJSON imprime o mesmo relatorio em JSON; as chaves fazem parte do contrato da CLI.
func (r report) writeJSON(w io.Writer) error {
	out := jsonReport{Achados: make([]jsonFinding, 0, len(r))}
	out.Resultado.Falhas, out.Resultado.Avisos = r.counts()
	for _, f := range r {
		out.Achados = append(out.Achados, jsonFinding{f.Level.String(), f.Item, f.Detail, f.Fix})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

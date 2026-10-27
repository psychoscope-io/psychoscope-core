package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/psychoscope-io/psychoscope-core/internal/config"
)

const (
	sensorBinary      = "mod-net-sensor"
	maxSensorFindings = 20
	maxSensorLine     = 300
)

// sensorModules filtra os modulos configurados que sao o sensor de rede, o unico que tem --check.
func sensorModules(specs []config.ModuleSpec) []config.ModuleSpec {
	var out []config.ModuleSpec
	for _, s := range specs {
		if filepath.Base(s.Path) == sensorBinary {
			out = append(out, s)
		}
	}
	return out
}

// sensorFindings converte a saida do `--check` do sensor (linhas `[ok]`, `[aviso]`, `[falha]` e
// `como corrigir:`) em achados. A saida e entrada nao confiavel: so as linhas conhecidas contam,
// truncadas, e no maximo maxSensorFindings.
func sensorFindings(id, output string, runErr error) []finding {
	item := "sensor " + id + " --check"
	var out []finding
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "[falha]"):
			out = append(out, finding{Level: levelFail, Item: item, Detail: sensorLine(line, "[falha]")})
		case strings.HasPrefix(line, "[aviso]"):
			out = append(out, finding{Level: levelWarn, Item: item, Detail: sensorLine(line, "[aviso]")})
		case strings.HasPrefix(line, "como corrigir:") && len(out) > 0 && out[len(out)-1].Fix == "":
			out[len(out)-1].Fix = sensorLine(line, "como corrigir:")
		}
		if len(out) >= maxSensorFindings {
			break
		}
	}
	switch {
	case errors.Is(runErr, context.DeadlineExceeded):
		out = append(out, finding{Level: levelFail, Item: item, Detail: "nao terminou a tempo (" + sensorCheckTimeout.String() + ")"})
	case len(out) == 0 && runErr != nil:
		out = append(out, finding{Level: levelFail, Item: item, Detail: "falhou sem explicacao: " + truncate(runErr.Error(), maxSensorLine)})
	case len(out) == 0:
		out = append(out, finding{Item: item, Detail: "passou"})
	}
	return out
}

func sensorLine(line, prefix string) string {
	return truncate(strings.TrimSpace(strings.TrimPrefix(line, prefix)), maxSensorLine)
}

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

// externalSensorFinding explica que o sensor mantido pelo systemd nao e verificado aqui: o
// --check precisa rodar como o usuario e com as capabilities da unit, e o doctor nao as tem.
func externalSensorFinding(s config.ModuleSpec) finding {
	return finding{Level: levelSkip, Item: "sensor " + s.ID,
		Detail: "modulo externo (usuario " + s.User + "): o --check do sensor nao foi executado",
		Fix:    "systemctl status psychoscope-sensor e journalctl -u psychoscope-sensor -n 50"}
}

// launchedSensorFinding avisa que o sensor lancado pelo Core nao captura sob a unit instalada,
// que roda o Core sem capabilities; fora do systemd (desenvolvimento, sudo) isso e legitimo.
func launchedSensorFinding(s config.ModuleSpec) finding {
	return finding{Level: levelWarn, Item: "sensor " + s.ID,
		Detail: "o Core lanca o sensor; sob a unit systemd instalada (Core sem capabilities) a captura falha",
		Fix:    "sudo psychoscope-cli migrate-config && sudo systemctl daemon-reload && sudo systemctl restart psychoscope"}
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

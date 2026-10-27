package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"syscall"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/ctl"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

const (
	serviceUnit = "psychoscope"
	// lossFailRatio e a fracao de pacotes perdidos a partir da qual a perda deixa de ser um
	// aviso: com 1 % ou mais, os alertas ja nao refletem o trafego real.
	lossFailRatio = 0.01
	journalHint   = "journalctl -u psychoscope -n 50"
	serviceSocket = "/run/psychoscope/ctl.sock"
)

// checkSocket explica por que o canal de controle nao respondeu (err) ou confirma que abriu.
// info/infoErr descrevem o arquivo do socket; xdgFallback diz que o caminho veio do diretorio
// do usuario, e nao do diretorio do servico.
func checkSocket(path string, err error, info sockInfo, infoErr error, xdgFallback bool) finding {
	const item = "socket de controle"
	if err == nil {
		return finding{Item: item, Detail: path}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		f := finding{Level: levelFail, Item: item, Detail: path + " nao existe",
			Fix: "sudo systemctl start psychoscope, ou aponte o socket certo com --ctl-socket"}
		if xdgFallback {
			f.Detail += " (o servico instalado usa " + serviceSocket + ")"
			f.Fix = "psychoscope-cli --ctl-socket " + serviceSocket + " doctor"
		}
		return f
	case errors.Is(err, fs.ErrPermission):
		detail := path + ": sem permissao para abrir"
		if infoErr == nil {
			detail += fmt.Sprintf(" (modo %04o, dono uid %d, grupo %d)", info.Mode.Perm(), info.UID, info.GID)
		}
		return finding{Level: levelFail, Item: item, Detail: detail,
			Fix: "entre no grupo do socket (sudo usermod -aG psychoscope $USER e abra uma nova sessao) ou rode com sudo"}
	case errors.Is(err, syscall.ECONNREFUSED):
		return finding{Level: levelFail, Item: item, Detail: path + ": o arquivo existe, mas ninguem escuta (o Core morreu?)",
			Fix: "sudo systemctl restart psychoscope e " + journalHint}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return finding{Level: levelFail, Item: item, Detail: path + ": o Core fechou a conexao sem responder (seu usuario nao esta autorizado)",
			Fix: "inclua seu UID em allowed_uids no psychoscope.json e reinicie o servico, ou rode com sudo"}
	}
	return finding{Level: levelFail, Item: item, Detail: path + ": " + err.Error(), Fix: journalHint}
}

// checkService avalia `systemctl is-active`; ok falso (sem systemctl) pula a verificacao.
// coreAnswers diz que o Core respondeu pelo socket: nesse caso uma unit parada so indica que o
// Core foi iniciado a mao, o que merece aviso e nao falha.
func checkService(state string, ok, coreAnswers bool) (finding, bool) {
	const item = "servico systemd"
	switch {
	case !ok:
		return finding{}, false
	case state == "active":
		return finding{Item: item, Detail: serviceUnit + " ativo"}, true
	case coreAnswers:
		return finding{Level: levelWarn, Item: item, Detail: serviceUnit + " esta " + orUnknown(state) + ", mas o Core responde (iniciado fora do systemd?)"}, true
	}
	return finding{Level: levelFail, Item: item, Detail: serviceUnit + " esta " + orUnknown(state),
		Fix: "sudo systemctl start psychoscope e " + journalHint}, true
}

func orUnknown(s string) string {
	if s == "" {
		return "em estado desconhecido"
	}
	return s
}

// checkCoreMetrics resume versao e tempo ligado a partir das metricas do Core.
func checkCoreMetrics(ms []*psychoscopev1.Metrica) finding {
	var ver string
	var up float64
	var hasUp bool
	for _, m := range ms {
		switch m.GetNome() {
		case "psychoscope_info":
			ver = m.GetRotulos()["version"]
		case "psychoscope_uptime_seconds":
			up, hasUp = m.GetValor(), true
		}
	}
	if ver == "" || !hasUp {
		return finding{Level: levelWarn, Item: "Core", Detail: "as metricas nao trouxeram versao e tempo ligado (Core antigo?)"}
	}
	return finding{Item: "Core", Detail: fmt.Sprintf("versao %s, ligado ha %s", ver, humanDuration(time.Duration(up*float64(time.Second))))}
}

// checkModules avalia o estado de cada modulo; sem nenhum, avisa.
func checkModules(mods []*psychoscopev1.ModuloInfo, now time.Time) []finding {
	if len(mods) == 0 {
		return []finding{{Level: levelWarn, Item: "modulos", Detail: "nenhum modulo configurado",
			Fix: "declare o sensor em modules no psychoscope.json (veja docs/INSTALL.md)"}}
	}
	out := make([]finding, 0, 2*len(mods))
	for _, m := range mods {
		out = append(out, moduleState(m, now))
		if f, ok := moduleLoss(m); ok {
			out = append(out, f)
		}
	}
	return out
}

func moduleState(m *psychoscopev1.ModuloInfo, now time.Time) finding {
	id := m.GetIdModulo()
	f := finding{Item: "modulo " + id}
	state := strings.ToLower(strings.TrimPrefix(m.GetEstado().String(), "ESTADO_"))
	switch m.GetEstado() {
	case psychoscopev1.EstadoModulo_ESTADO_CONECTADO:
		f.Detail = "conectado"
		if m.GetConectadoDesde() != nil {
			f.Detail += " ha " + humanDuration(now.Sub(m.GetConectadoDesde().AsTime()))
		}
		if v := m.GetVersaoModulo(); v != "" {
			f.Detail += ", versao " + v
		}
		f.Detail += fmt.Sprintf(", pid %d", m.GetPid())
	case psychoscopev1.EstadoModulo_ESTADO_PAUSADO:
		f.Level, f.Detail, f.Fix = levelWarn, "pausado (nao esta detectando)", "psychoscope-cli cmd "+id+" resume"
	case psychoscopev1.EstadoModulo_ESTADO_INICIANDO, psychoscopev1.EstadoModulo_ESTADO_REINICIANDO:
		f.Level, f.Detail, f.Fix = levelWarn, state+", ainda sem conexao", "aguarde alguns segundos e rode de novo; se persistir, "+journalHint
	case psychoscopev1.EstadoModulo_ESTADO_ENCERRADO:
		f.Level, f.Detail, f.Fix = levelFail, "encerrado", "psychoscope-cli cmd "+id+" resume"
	case psychoscopev1.EstadoModulo_ESTADO_FALHOU:
		f.Level, f.Detail, f.Fix = levelFail, "falhou e nao sera reiniciado", journalHint
	default:
		f.Level, f.Detail = levelWarn, "estado desconhecido"
	}
	if m.GetReinicios() > 0 {
		f.Level = max(f.Level, levelWarn)
		f.Detail += fmt.Sprintf("; reiniciou %d vez(es)", m.GetReinicios())
		if f.Fix == "" {
			f.Fix = journalHint
		}
	}
	if e := m.GetUltimoErro(); e != "" && f.Level != levelOK {
		f.Detail += "; ultimo erro: " + truncate(e, 200)
	}
	return f
}

// moduleLoss avalia a perda de pacotes de um modulo conectado. Os contadores sao cumulativos
// desde que o processo do modulo subiu.
func moduleLoss(m *psychoscopev1.ModuloInfo) (finding, bool) {
	st := m.GetUltimoStatus()
	if st == nil || m.GetEstado() != psychoscopev1.EstadoModulo_ESTADO_CONECTADO {
		return finding{}, false
	}
	f := finding{Item: "perdas do modulo " + m.GetIdModulo()}
	losses := ctl.Losses(st)
	if len(losses) == 0 && st.GetPacotesDescartados() == 0 {
		f.Detail = fmt.Sprintf("nenhuma (%d pacotes capturados)", st.GetPacotesCapturados())
		return f, true
	}
	ratio := float64(st.GetPacotesDescartados()) / float64(max(st.GetPacotesCapturados(), 1))
	f.Level = levelWarn
	if ratio >= lossFailRatio {
		f.Level = levelFail
	}
	parts := make([]string, 0, len(losses))
	for _, c := range losses {
		parts = append(parts, fmt.Sprintf("%s: %d", strings.ToLower(c.Label), c.Value))
	}
	f.Detail = fmt.Sprintf("%d descartes em %d pacotes (%.2f%%) desde que o modulo subiu", st.GetPacotesDescartados(), st.GetPacotesCapturados(), ratio*100)
	if len(parts) > 0 {
		f.Detail += " [" + strings.Join(parts, ", ") + "]"
	}
	f.Fix = lossFix(st)
	return f, true
}

func lossFix(st *psychoscopev1.StatusModulo) string {
	c := st.GetContadores()
	switch {
	case c["perda.kernel"] > 0 || c["perda.interface"] > 0 || c["perda.fila_captura"] > 0:
		return "o trafego supera a captura: estreite o que o sensor captura (filtro BPF, --bpf) ou libere CPU para ele"
	case c["perda.fila_eventos"] > 0 || c["perda.ipc"] > 0:
		return "o Core nao acompanha o sensor: veja o uso de CPU do servico e psychoscope-cli metrics"
	}
	return "veja psychoscope-cli list e psychoscope-cli metrics"
}

// humanDuration abrevia uma duracao ("3d 4h", "2h 5m", "45s"); negativa vira 0s.
func humanDuration(d time.Duration) string {
	d = max(d, 0).Round(time.Second)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", d/(24*time.Hour), d%(24*time.Hour)/time.Hour)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", d/time.Hour, d%time.Hour/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %ds", d/time.Minute, d%time.Minute/time.Second)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

package ctl

import (
	"context"
	"errors"
	"time"

	"github.com/psychoscope-io/psychoscope-core/internal/settings"
	psychoscopev1 "github.com/psychoscope-io/psychoscope-proto/gen/go/psychoscope/v1"
)

// SettingsBackend e o que o canal de controle precisa da configuracao em tempo de execucao
// (satisfeito por *settings.Manager).
type SettingsBackend interface {
	Fields() ([]settings.Field, error)
	Apply(ctx context.Context, patch map[string]string, restore []string, who settings.Caller) (settings.Result, error)
	OverridesPath() string
}

// applyTimeout limita a aplicacao de ajustes (inclui a troca de regras no motor).
const applyTimeout = 15 * time.Second

func (c *clientConn) readConfig(id string) *psychoscopev1.RespostaControle {
	if c.srv.cfg.Settings == nil {
		return fail(id, "configuracao por este canal indisponivel neste Core")
	}
	lista, err := c.configList(nil)
	if err != nil {
		c.srv.log.Error("ctl: leitura da configuracao", "err", err)
		return fail(id, "erro ao ler a configuracao")
	}
	return configResponse(id, lista)
}

// applyConfig aplica ajustes. Somente o root escreve: a decisao usa o UID que o kernel
// informou (SO_PEERCRED), nunca algo declarado pelo cliente, e vem antes de qualquer
// interpretacao do pedido.
func (c *clientConn) applyConfig(id string, p *psychoscopev1.PedidoAplicarConfig) *psychoscopev1.RespostaControle {
	if c.srv.cfg.Settings == nil {
		return fail(id, "configuracao por este canal indisponivel neste Core")
	}
	if !c.srv.cfg.Admin(c.cred.UID) {
		c.srv.log.Warn("ctl: alteracao de configuracao negada", "uid", c.cred.UID, "pid", c.cred.PID)
		return fail(id, "somente o root pode alterar a configuracao (rode com sudo)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout)
	defer cancel()
	res, err := c.srv.cfg.Settings.Apply(ctx, p.GetAjustes(), p.GetRestaurar(),
		settings.Caller{UID: c.cred.UID, PID: c.cred.PID})
	if err != nil {
		if errors.Is(err, settings.ErrPersist) { // o detalhe tem caminhos: vai para o log
			c.srv.log.Error("ctl: gravacao dos ajustes", "err", err)
			return fail(id, "nao foi possivel gravar os ajustes (veja o log do Core)")
		}
		return fail(id, err.Error()) // erro de validacao: diz qual campo e por que
	}
	lista, err := c.configList(res.Warnings)
	if err != nil {
		c.srv.log.Error("ctl: leitura da configuracao apos aplicar", "err", err)
		return fail(id, "ajustes aplicados, mas houve erro ao ler a configuracao")
	}
	return configResponse(id, lista)
}

func (c *clientConn) configList(warnings []string) (*psychoscopev1.ListaConfig, error) {
	fields, err := c.srv.cfg.Settings.Fields()
	if err != nil {
		return nil, err
	}
	lista := &psychoscopev1.ListaConfig{
		SomenteLeitura: !c.srv.cfg.Admin(c.cred.UID), ArquivoAjustes: c.srv.cfg.Settings.OverridesPath(), Avisos: warnings,
	}
	for _, f := range fields {
		lista.Campos = append(lista.Campos, &psychoscopev1.CampoConfig{
			Caminho: f.Path, Tipo: fieldType(f.Type), ValorAtual: f.Value, ValorPadrao: f.Default,
			Origem: fieldOrigin(f.Origin), Rotulo: f.Label, Descricao: f.Doc,
		})
	}
	return lista, nil
}

func configResponse(id string, l *psychoscopev1.ListaConfig) *psychoscopev1.RespostaControle {
	return &psychoscopev1.RespostaControle{
		IdRequisicaoReferencia: id, Sucesso: true,
		Resultado: &psychoscopev1.RespostaControle_Config{Config: l},
	}
}

func fieldType(t settings.FieldType) psychoscopev1.TipoCampo {
	switch t {
	case settings.TypeInt:
		return psychoscopev1.TipoCampo_TIPO_CAMPO_INTEIRO
	case settings.TypeDecimal:
		return psychoscopev1.TipoCampo_TIPO_CAMPO_DECIMAL
	case settings.TypeDuration:
		return psychoscopev1.TipoCampo_TIPO_CAMPO_DURACAO
	case settings.TypeTextList:
		return psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_TEXTO
	case settings.TypeIntList:
		return psychoscopev1.TipoCampo_TIPO_CAMPO_LISTA_INTEIRO
	}
	return psychoscopev1.TipoCampo_TIPO_CAMPO_DESCONHECIDO
}

func fieldOrigin(o settings.Origin) psychoscopev1.OrigemCampo {
	switch o {
	case settings.OriginDefault:
		return psychoscopev1.OrigemCampo_ORIGEM_CAMPO_PADRAO
	case settings.OriginFile:
		return psychoscopev1.OrigemCampo_ORIGEM_CAMPO_ARQUIVO
	case settings.OriginOverride:
		return psychoscopev1.OrigemCampo_ORIGEM_CAMPO_AJUSTE
	}
	return psychoscopev1.OrigemCampo_ORIGEM_CAMPO_DESCONHECIDA
}

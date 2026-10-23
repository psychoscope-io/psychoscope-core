---
name: adicionar-campo-de-configuracao
description: Criar ou mudar um campo de configuração que a tela de configurações da TUI e a CLI `config` devem editar em tempo de execução. Use ao adicionar um limiar, uma lista de exceções ou um limite de retenção.
---
# Adicionar um campo de configuração editável

A configuração em tempo de execução (`internal/settings`) descreve os campos **por reflexão** sobre `rules.Config`, então um campo de regra novo aparece sozinho na tela e na CLI. O que vale conferir:

1. **Campo de regra** (`internal/detection/rules/rules.go`): tags `json:"nome"` e `doc:"Descrição em português, terminada em ponto."`; valor em `Default()`; checagem em `Validate()`. `TestEveryRuleConfigFieldIsDocumented` falha sem `doc`.
2. **Tipo:** o catálogo entende inteiro, decimal, `time.Duration`, lista de texto e lista de inteiros (`describeField` em `internal/settings/catalog.go`). Outro tipo (bool, mapa...) faz o catálogo falhar com uma mensagem acionável: acrescente o caso em `describeField`, o tipo correspondente em `psychoscope-proto` (`TipoCampo`, mudança só aditiva) e a conversão de texto em `internal/ctl/configvalue.go` (`ValueFromText` e `TextFromValue`), com testes.
3. **Campo fora de `rules.Config`:** os de `storage` entram com **uma linha** em `config.EditableStorage` (`internal/config/overrides.go`: chave, descrição e ponteiro para o valor); o `Layer` e o catálogo leem dessa tabela. `detection.window` e `detection.disabled` têm constantes (`PathDetection*`). Só entra o que é seguro mudar ao vivo; **nunca** caminho de executável, socket, `allowed_uids` ou endereço de escuta. `TestEveryCatalogFieldIsAcceptedByLayer` garante que o que a tela mostra é o que o Core aceita gravar.
4. **Aplicação ao vivo:** campos de regra e `detection.window` já são aplicados por `Engine.Reconfigure` (cooldowns e estado das regras recomeçam). Campo de outro componente precisa de um método de troca seguro (como `Persister.SetLimits`) ligado em `internal/app/settings.go` (`liveSettings.Apply`), testado com `-race`.
5. **Testes:** o catálogo (`internal/settings`) conta os campos de `rules.Config` sozinho; acrescente o caso de validação inválida em `TestApplyRejectsInvalidChangesWithoutWritingAnything` e, se mudar o comportamento da regra, o teste que prova o efeito com o limiar novo (e que "morde" ao reverter).
6. **Documente** no README (seção da regra e, se for novo, "Configuração em tempo de execução") e em `docs/INSTALL.md` se houver chave nova no arquivo do administrador.
7. Rode a skill `verificar-core`; para a tela de configurações em pty real: `../mod-net-sensor/scripts/live_smoke.sh`.

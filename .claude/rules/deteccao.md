---
paths:
  - "internal/detection/**"
---
# Regras de detecção

- Implemente `detection.Rule` e, quando possível, `detection.Gated` (`Key` barata + `Cooldown`): o motor pula a avaliação enquanto a chave está em cooldown, medido no **tempo dos eventos**, nunca no relógio do sistema.
- Antes de varrer a janela, faça o corte barato (`len(w.FromSrc(ip)) < limiar` → `nil`). Limite a varredura por avaliação.
- Estado próprio (como `net.beacon`) é limitado por teto de chaves com despejo e só é tocado pela goroutine do motor. Se ele precisa sobreviver a reinício e a `Reconfigure`, implemente `detection.Stateful` (`ExportState` copia só o que ainda é útil; `ImportState` valida cada entrada, trata o arquivo como hostil e aparda para o teto) e guarde o **instante** do evento, nunca o prazo. Toda regra expõe `StateKey()` (`rules/statekey.go`): campo novo de `rules.Config` que só filtra ou limita (cooldown, teto, lista de exceção) leva a tag `keepstate:"true"`; limiar e janela não, para que ajustá-los reinicie o estado da regra.
- Limiares ficam em `rules.Config` com tags `json` **e `doc`** (a descrição que a tela de configurações mostra; um teste exige as duas), default em `Default()`, validação em `Validate()`, nome em `AllNames()` e `LongestWindow()` atualizado. `detection.window` tem de cobrir a maior janela.
- Alerta: severidade coerente, descrição em português com os números, `contexto` com as chaves que explicam o disparo.
- **Heurística tem falso positivo documentado** e uma válvula de escape na configuração (lista de exceções). Nada de lista fixa embutida no código.
- Se a regra tem uma lista de exceções que cobre o que causou o alerta, ensine `rules.Exception` (`exceptions.go`) a sugeri-la a partir do `contexto`; o teste prova de ponta a ponta que aplicar a sugestão silencia o mesmo tráfego e só ele.

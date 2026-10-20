---
paths:
  - "internal/detection/**"
---
# Regras de detecção

- Implemente `detection.Rule` e, quando possível, `detection.Gated` (`Key` barata + `Cooldown`): o motor pula a avaliação enquanto a chave está em cooldown, medido no **tempo dos eventos**, nunca no relógio do sistema.
- Antes de varrer a janela, faça o corte barato (`len(w.FromSrc(ip)) < limiar` → `nil`). Limite a varredura por avaliação.
- Estado próprio (como `net.beacon`) é limitado por teto de chaves com despejo e só é tocado pela goroutine do motor.
- Limiares ficam em `rules.Config` com tag `json`, default em `Default()`, validação em `Validate()`, nome em `AllNames()` e `LongestWindow()` atualizado. `detection.window` tem de cobrir a maior janela.
- Alerta: severidade coerente, descrição em português com os números, `contexto` com as chaves que explicam o disparo.
- **Heurística tem falso positivo documentado** e uma válvula de escape na configuração (lista de exceções). Nada de lista fixa embutida no código.

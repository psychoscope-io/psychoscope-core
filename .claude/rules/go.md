---
paths:
  - "**/*.go"
---
# Regras de Go

- Biblioteca padrão primeiro; dependência nova só com justificativa. Sem CGO.
- Interfaces pequenas, definidas onde são consumidas (`ctl.Backend`, `ipc.Handler`); funções aceitam interfaces e devolvem tipos concretos. Pacote nomeado pelo que oferece, nunca `util`/`common`.
- Sem variável global mutável nem `init()` com efeito; as peças são conectadas em `internal/app`.
- Erros embrulhados com `%w` e comparados com `errors.Is/As`; erros sentinela exportados para o que o chamador precisa distinguir.
- Toda goroutine tem dono e condição de parada (contexto ou canal fechado); `Shutdown`/`Close` esperam as goroutines terminarem.
- Handlers de sessão (`ipc.Handler`) não bloqueiam: enfileire e descarte contando.
- Teste com `-race`; tabelas para casos, `t.TempDir()` para arquivos e sockets, esperas por condição em vez de `time.Sleep` fixo.
- Processos filhos nos testes usam o padrão do `internal/testmod` (o binário de teste se re-executa).
- `gofmt` limpo; comentários de pacote e de símbolos exportados em português.

# psychoscope-core

Orquestrador (hub) e CLI/TUI do Psychoscope MODR, em Go.

Estado: Fase 2 — framer IPC (`internal/ipc`) com testes, golden vectors e fuzz.
`go.mod` usa `replace` para `../psychoscope-proto` durante o desenvolvimento; remover antes de publicar.
`testdata/framing_vectors.json` é cópia de `psychoscope-proto/testdata/`.

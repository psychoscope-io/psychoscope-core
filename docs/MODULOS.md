# Módulos e privilégios

O Core roda sem privilégios (`psychoscope.service`: usuário `psychoscope`, sem capabilities, `NoNewPrivileges=yes`) e **não lança** os módulos novos. Cada módulo é um serviço do systemd com usuário próprio, que se conecta ao socket do Core. O sensor de rede (`psychoscope-sensor.service`) é o modelo; um módulo seu segue o mesmo desenho.

## O que cada parte faz

| Quem | Faz | Não faz |
|---|---|---|
| Core | autentica o módulo pelo UID que o kernel informa na conexão (`SO_PEERCRED`) e rejeita qualquer outro | confiar no `id_modulo` ou no PID declarados pelo módulo |
| systemd | inicia, reinicia e isola o módulo; entrega as capabilities declaradas | |
| Módulo | conecta em `/run/psychoscope/core.sock`, envia o `Hello` e a telemetria, responde aos comandos | ter acesso ao banco de alertas do Core (`/var/lib/psychoscope`) |

## Registrar um módulo

1. Crie o usuário do módulo: `sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin psychoscope-MODULO`.
2. Copie `deploy/systemd/psychoscope-module.service.example` para `/etc/systemd/system/psychoscope-MODULO.service` e troque `MODULO`.
3. Declare o módulo em `/etc/psychoscope/psychoscope.json`:

   ```json
   { "id": "MODULO", "external": true, "user": "psychoscope-MODULO" }
   ```

   O `id` segue `[a-z0-9][a-z0-9._-]{0,62}`. O Core falha na partida se o usuário não existir.
4. `sudo systemctl daemon-reload && sudo systemctl enable --now psychoscope-MODULO && sudo systemctl restart psychoscope`.
5. `psychoscope-cli list` mostra o módulo como `CONECTADO`; `psychoscope-cli doctor` confere as perdas.

## Privilégios: o que o molde dá e o que pedir

O molde **não tem capability alguma**, roda com `NoNewPrivileges=yes` e só fala com o socket do Core (`RestrictAddressFamilies=AF_UNIX`). Um módulo que precisa de algo a mais:

- **Declara e documenta** cada capability e cada família de endereços de que precisa, e o motivo.
- **As entrega como ambientes** (`AmbientCapabilities=` e `CapabilityBoundingSet=` com a mesma lista), como o sensor faz com `CAP_NET_RAW` e `CAP_NET_ADMIN`.
- **Nunca usa `setcap`** no binário (o systemd 252 do Debian 12 anula as file capabilities quando a unit usa opções de isolamento) e **nunca `NoNewPrivileges=no`**.
- Não amplia o que o Core tem: o Core continua sem capabilities.
- O molde usa `MemoryDenyWriteExecute=yes`, que impede memória gravável e executável: módulos em Go, Rust ou Python rodam; runtimes com JIT (Node.js, Java, PyPy) precisam tirar essa linha, documentando o motivo.
- O molde foi conferido com `systemd-analyze verify` (sem erro de sintaxe), mas não foi iniciado com um módulo de verdade; o módulo de exemplo fará isso.

## Eventos

Um módulo sem variante própria no contrato envia o `EventoGenerico`: veja [EVENTOS-GENERICOS.md](EVENTOS-GENERICOS.md) para os limites e para como uma regra o consome.

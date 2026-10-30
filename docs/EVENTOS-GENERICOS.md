# Eventos genéricos

Um módulo que ainda não tem variante própria no contrato (`psychoscope-proto`) envia o `EventoGenerico`: um `tipo`, um `timestamp` opcional e `atributos` em texto. É o formato para módulos de terceiros; um módulo com semântica estável deve ganhar uma variante tipada, porque atributos em texto não são verificados pelo contrato.

## Limites que o Core aplica

O Core descarta o evento que violar qualquer um (a sessão continua) e conta em `psychoscope_engine_events_rejected_total`. O motivo vai ao log em nível debug.

| Campo | Limite |
|---|---|
| `tipo` | `[a-z0-9._-]`, começando por letra ou dígito, até 64 caracteres; não pode ser vazio |
| chave de atributo | mesma forma do tipo |
| atributos | até 32 por evento |
| valor de atributo | até 256 bytes |
| `timestamp` | até 5 minutos à frente da chegada; ausente = o instante de chegada |

O limite do `timestamp` existe porque o relógio da janela segue os instantes dos eventos: um módulo com data no futuro faria a janela descartar os eventos de todos os módulos. Datas no passado são aceitas, mas um evento mais antigo que a janela corrente não é retido.

## Como uma regra os consome

Uma regra declara `Kind()` igual a `detection.KindGeneric` e consulta `w.OfType("tipo")`, que devolve os eventos retidos daquele tipo **de todos os módulos**; filtre por `Event.Module` quando precisar de um só. O conteúdo está em `ev.Generic`. O motor só entrega à regra eventos da variante que ela declara.

## Memória da janela

A janela limita a contagem de eventos (`detection.max_events`) e também o peso estimado em bytes: um evento de rede conta 256 bytes, e um genérico conta pelo tamanho do tipo, das chaves e dos valores. O teto de bytes é a contagem multiplicada por 256, então eventos genéricos grandes enchem a janela mais rápido e empurram os mais antigos (de qualquer módulo) para fora.

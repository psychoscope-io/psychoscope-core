# Atalhos de desenvolvimento. `make check` e o que o CI e o hook pre-push executam.


.PHONY: build clean fmt lint nowork vuln test check precommit hooks tag

# Receita unica de compilacao: a release (.github/workflows/release.yml) e o desenvolvimento local
# usam este alvo, entao o binario local tambem informa a versao (`psychoscope --version`).
# GOOS/GOARCH/CGO_ENABLED vem do ambiente; VERSION e DIST podem ser sobrescritos na linha de comando.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
ifeq ($(VERSION),)
VERSION := 0.0.0-dev
endif
DIST ?= dist
LDFLAGS = -s -w -X github.com/psychoscope-io/psychoscope-core/internal/version.Version=$(VERSION)

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/psychoscope ./cmd/psychoscope
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/psychoscope-cli ./cmd/psychoscope-cli

clean:
	rm -rf dist

fmt:
	gofmt -w .

# Verificacoes rapidas, usadas pelo hook pre-commit.
precommit:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "fora do padrao gofmt (rode make fmt):" >&2; echo "$$out" >&2; exit 1; fi
	go vet ./...

# Compila sem o go.work (git-ignorado): e como a CI e a release enxergam o modulo. Pega o go.mod
# atrasado em relacao a um contrato novo do psychoscope-proto, que o go.work local esconde.
nowork:
	GOWORK=off go build ./...

lint: precommit nowork
	golangci-lint run ./...
	git ls-files -z '*.sh' '.githooks/*' | xargs -0 shellcheck
	actionlint

vuln:
	govulncheck ./...

test:
	go test -race ./...

check: lint vuln test

# Ativa os hooks versionados em .githooks (commit-msg, pre-commit, pre-push).
hooks:
	git config core.hooksPath .githooks

# Cria a tag anotada da proxima versao (interativo; so local, nao faz push). Veja scripts/tag.sh --help.
tag:
	scripts/tag.sh

# Atalhos de desenvolvimento. `make check` e o que o CI e o hook pre-push executam.


.PHONY: fmt lint nowork vuln test check precommit hooks

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

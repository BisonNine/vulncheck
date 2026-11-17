# vulncheck

Runs govulncheck and fails on any called vulnerability that the project's
`b9.yaml` does not ignore. A small library at the module root plus the command
in `cmd/vulncheck`.

## Status

UNRELEASED until the first tag (v0.1.0). Do not keep legacy behaviour or add
backward compatibility before then. After the first tag the exported API and
the command's flags, messages and exit statuses are depended on by other
tools and Makefiles: ask before changing them.

## Module path

The module path is the vanity alias `go.bison9.com/vulncheck`, which resolves
to github.com/BisonNine/vulncheck. Always import and document it by the alias,
never by the GitHub path.

## Public repository

This repository is public. Keep personal names, user names, host names, home
directory paths and the names of private projects out of code, tests,
fixtures, docs and commit messages. Tests use example.com modules and
temporary directories.

## Layout

- `config.go`: `Config`, `Ignore`, `Day`, `Parse`, `LoadFile`, `Validate`.
  Only the top-level `govulncheck` key is read; decoding is strict inside it.
- `decide.go`: `Decide` judges a `govulncheck -format json` stream; `Report`.
- `check.go`: `Check` locates and runs govulncheck. `GovulncheckPackage` pins
  the release used through `go run` when govulncheck is not on PATH; bump it
  deliberately.
- `cmd/vulncheck`: the command. Exit 0 pass, 1 vulnerable, 2 error.
- `app/`: application identity, from the standard template.

## Conventions

- Dependencies: the standard library and github.com/goccy/go-yaml only.
- The clock and the command runner are injected (`Options.Now`,
  `Options.Runner`); tests need no network, real time or real govulncheck.
- `make test` is the gate: formatting check, go vet, golangci-lint (0
  findings) and `go test -race`. `make lint`, `make fmt`, `make update`.
- `make install` copies the binary to /usr/local/bin as root, otherwise to an
  existing ~/bin; `make uninstall` removes it. No logging: the command prints
  its result lines and errors only.

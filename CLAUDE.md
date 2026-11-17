# vulncheck

## What it is and why it exists

vulncheck is govulncheck with an ignore list. It runs govulncheck on a Go
project and fails on every vulnerability the code calls, unless the project's
`b9.yaml` ignores it. It is the one implementation of that check, shared by
the Makefiles of a family of projects and by a release tool, so they cannot
disagree about what passes. It is public so that anyone who clones one of
those projects can run its tests, which include this check.

It is a small library at the module root plus the command in `cmd/vulncheck`.

## Module path

The module path is the vanity alias `go.bison9.com/vulncheck`; the repository
is github.com/BisonNine/vulncheck. Always import, document and `go run` it by
the alias. Never use the GitHub path as the module path.

## Status: released

v0.1.0 is tagged, so the code is RELEASED. The exported API and the command's
flags, messages and exit statuses are depended on by other tools and
Makefiles. Add to them freely when asked; ask before changing or removing
anything. The version is in `app/app.go`.

## How it works

- It runs the `govulncheck` found on PATH, or the program named in
  `Options.Govulncheck` (`-govulncheck` on the command line). It never pins a
  release and never installs govulncheck; when it is missing the check fails
  with the install command (`InstallCommand`).
- It runs `govulncheck -format json ./...` in the project directory and reads
  the JSON stream.
- Only called vulnerabilities count: govulncheck reports a finding at
  function level when the code reaches a vulnerable function. Imported but
  uncalled vulnerabilities never fail the check.
- It fails closed. Because the govulncheck version is whatever is installed,
  `decide.go` accepts only known message keys and known JSON protocol
  versions and requires a symbol-level scan. Unknown output, an unknown
  protocol version or a scan that fails is an error that names the program
  run, never a pass. When govulncheck adds a key or protocol version, check
  it and extend the lists deliberately.

## Configuration

Only the top-level `govulncheck` key of the project's `b9.yaml` is read. The
file is shared with a release tool; every other key is ignored.

- `govulncheck: true` scans; `govulncheck: false` turns the scan off.
- The mapping form is `enabled` (required) plus `ignore`, a list of entries.
- An entry has `id` (required, `GO-YYYY-N`, each ID once), `reason`
  (required, printed when the entry is used) and `until` (optional).
- `until` is the last day the entry applies, inclusive, as a local date:
  `20261231`, `"20261231"` or `2026-12-31`. Without it the entry never
  expires.
- A key that is present but empty is an error: `govulncheck:` with no value,
  `until:` with no value.
- Unknown keys inside the block are errors; decoding is strict there, also
  when a host decodes `Config` as part of its own struct.
- No file, or no `govulncheck` key, is a strict scan: nothing ignored.
- The zero `Config` scans (the field is `Disabled`, not `Enabled`). Keep it
  that way.
- A file with more than one YAML document is an error.

## Exit codes (the command)

- 0: nothing fails the check, or the scan is turned off.
- 1: a called vulnerability is not ignored, or its ignore entry expired.
- 2: usage, configuration or scan error, including govulncheck not installed.

## Exported API

- `DefaultFile`: the configuration file name, `b9.yaml`.
- `Config`: the `govulncheck` block (`Disabled`, `Ignore`); `Validate` checks it.
- `Ignore`: one ignore entry (`ID`, `Reason`, `Until`).
- `Day`: a local calendar day; `ParseDay`, `Covers`, `Set`, `String`.
- `Parse`: reads the configuration from `b9.yaml` bytes.
- `LoadFile`: reads it from a file; a missing file wraps `fs.ErrNotExist`.
- `Options`: what `Check` scans and how (`Dir`, `Ignore`, `Govulncheck`,
  `Now`, `Runner`).
- `Options.Command`: the `Command` that `Check` would run, without running it;
  `Check` uses it, so they cannot diverge.
- `Check`: runs govulncheck and decides the result.
- `Decide`: judges a captured `govulncheck -format json` stream.
- `Report`: the result (`Fatal`, `Expired`, `Ignored`, `Unused`); `Lines` for
  output, `Err` for pass or fail.
- `Vuln`: one called vulnerability.
- `Command`: a program, its arguments and its directory; `String` renders it.
- `Runner`: runs a `Command` and returns its standard output.
- `ErrNotInstalled`: wrapped by `Check` and `Options.Command` when govulncheck
  is not on PATH (and `Options.Govulncheck` is empty).
- `InstallCommand`: the command that installs govulncheck.

## How consumers use it

- A Makefile target runs the command at a released version:

  ```make
  govulncheck:
  	@go run go.bison9.com/vulncheck/cmd/vulncheck@vX.Y.Z .
  ```

- A Go program imports `go.bison9.com/vulncheck`: `LoadFile`, then `Check`.

## Layout

- `config.go`: configuration.
- `decide.go`: `Decide`, `Report`, `Vuln`.
- `check.go`: `Check`, `Options`, `Command`, `Runner`, `ErrNotInstalled`,
  `InstallCommand`.
- `cmd/vulncheck`: the command.
- `app/`: application identity and version, from the standard template.

## Workflow

- Work on `dev/<version>` (the version in development), and PR it to main.
  Never push to main. Tags only when the maintainer says so.
- New projects in this family start at 0.0.1; this one started at 0.1.0 and
  stays on 0.1.x. Bumping the patch digit for the version in development is
  normal; never bump major or minor without the maintainer.
- `make test` is the gate and must be clean: formatting check, go vet,
  golangci-lint with 0 findings, and `go test -race`. Also `make lint`,
  `make fmt`, `make update`.
- Dependencies: the standard library and github.com/goccy/go-yaml only.
- The clock and the command runner are injected (`Options.Now`,
  `Options.Runner`); tests need no network, real time or real govulncheck.
- No logging: the command prints its result lines and errors only.
- `make install` copies the binary to /usr/local/bin as root, otherwise to an
  existing ~/bin; `make uninstall` removes it.

## Public repository

This repository is public. Never put personal names, user names, host names,
home directory paths, private repository names or text from private standards
into code, tests, fixtures, docs or commit messages. The file name `b9.yaml`
and the fact that a release tool shares it may be mentioned; that tool and its
repository must not be described or named. Tests use example.com modules and
temporary directories.

# vulncheck

Runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) and
fails on any called vulnerability that is not explicitly ignored.

govulncheck reports a vulnerability as called when the code reaches a
vulnerable function. vulncheck fails on every such vulnerability unless the
project lists it in its ignore list, optionally only until a date. Imported
but uncalled vulnerabilities never fail the check.

## Run

```sh
go run go.bison9.com/vulncheck/cmd/vulncheck@v0.1.0 [flags] [dir]
```

`dir` is the project to scan and defaults to the current directory.

| Flag | Meaning |
| --- | --- |
| `-config file` | Read the configuration from `file` instead of `<dir>/b9.yaml`. The file must exist. |
| `-govulncheck program` | Run this govulncheck, a path or a name on `PATH`, instead of the pinned release. |
| `-version` | Print the version and exit. |

vulncheck runs a pinned govulncheck release with
`go run golang.org/x/vuln/cmd/govulncheck@v1.9.0`, so the output is in the
format it reads and nothing is installed. A `govulncheck` on `PATH` is not
used unless you ask for it. To use a local binary, for instance offline:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
vulncheck -govulncheck "$(go env GOPATH)/bin/govulncheck" .
```

vulncheck fails, rather than passes, if govulncheck's output is in a format
it does not know.

From a Makefile:

```make
govulncheck:
	@go run go.bison9.com/vulncheck/cmd/vulncheck@v0.1.0 .
```

To install the command instead: `go install go.bison9.com/vulncheck/cmd/vulncheck@v0.1.0`.

## Configuration

The configuration is the `govulncheck` key of `b9.yaml` in the project
directory. The file is called `b9.yaml` because it is shared with a release
tool; vulncheck reads only the `govulncheck` key and ignores everything else.
Without the file, or without the key, every called vulnerability fails the
check.

```yaml
govulncheck: true          # or false to turn the scan off
```

or, to ignore advisories:

```yaml
govulncheck:
  enabled: true
  ignore:
    - id: GO-2026-0001
      reason: no fixed release yet
      until: 20261231
```

- `enabled` is required in the mapping form.
- `id` is required and is a Go vulnerability ID, `GO-YYYY-N`. Each ID may be
  listed once.
- `reason` is required and is printed when the entry is used.
- `until` is optional. It is the last day the entry applies, in local time,
  written `20261231`, `"20261231"` or `2026-12-31`. Without it the entry
  never expires; an `until` with no value is an error.
- Unknown keys inside the `govulncheck` block are errors.

When the scan is turned off, vulncheck says so and exits 0.

## Output and exit status

One line per vulnerability or entry:

```
Vulnerable: GO-… <module> <version>, fixed in <version>. <summary>. https://pkg.go.dev/vuln/GO-…
Vulnerable, ignore expired on 2026-12-31: GO-…
Ignored until 2026-12-31 (<reason>): GO-…
Ignore entry GO-… is no longer needed and can be removed.
No called vulnerabilities.
```

| Exit status | Meaning |
| --- | --- |
| 0 | No called vulnerability fails the check, or the scan is turned off. |
| 1 | A called vulnerability is not ignored, or its entry has expired. |
| 2 | Usage, configuration or scan error. |

A scan that fails or produces output vulncheck cannot read is an error, never
a pass.

## Limits

- govulncheck scans the module in the scanned directory, for the platform it
  runs on. Code built only for another GOOS/GOARCH, and nested modules, are
  not scanned; scan them separately, a nested module with
  `vulncheck <its directory>`.
- With `-mod=vendor` in `GOFLAGS`, `go run` cannot fetch govulncheck. Install
  it with that setting cleared (`GOFLAGS= go install …`) and pass
  `-govulncheck` as above. A `vendor` directory alone is fine.

## Library

The package `go.bison9.com/vulncheck` offers the same check to Go programs:
`LoadFile` or `Parse` reads the configuration, `Check` runs govulncheck and
`Decide` judges a captured `govulncheck -format json` stream. See the
[package documentation](https://pkg.go.dev/go.bison9.com/vulncheck).

## Licence

MIT. See [LICENSE](LICENSE).

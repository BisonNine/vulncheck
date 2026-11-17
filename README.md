# vulncheck

Runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) and
fails on any called vulnerability that is not explicitly ignored.

govulncheck reports a vulnerability as called when the code reaches a
vulnerable function. vulncheck fails on every such vulnerability unless the
project lists it in its ignore list, optionally only until a date. Imported
but uncalled vulnerabilities never fail the check.

## Requirements

govulncheck must be installed and on `PATH`:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
```

vulncheck never installs it. Without it, vulncheck exits 2 and prints that
command.

## Run

```sh
go run go.bison9.com/vulncheck/cmd/vulncheck@latest [flags] [dir]
```

`dir` is the project to scan and defaults to the current directory.

| Flag | Meaning |
| --- | --- |
| `-config file` | Read the configuration from `file` instead of `<dir>/b9.yaml`. The file must exist. |
| `-govulncheck program` | Run this govulncheck, a path or a name on `PATH`, instead of `govulncheck` from `PATH`. |
| `-version` | Print the version and exit. |

vulncheck fails, rather than passes, if govulncheck's output is in a format
it does not know, and names the govulncheck it ran so you know which one to
update.

From a Makefile:

```make
govulncheck:
	@go run go.bison9.com/vulncheck/cmd/vulncheck@latest .
```

To install the command instead: `go install go.bison9.com/vulncheck/cmd/vulncheck@latest`.

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
- Vendored projects, including with `-mod=vendor` in `GOFLAGS`, are scanned
  from their `vendor` directory.

## Library

The package `go.bison9.com/vulncheck` offers the same check to Go programs:
`LoadFile` or `Parse` reads the configuration, `Check` runs govulncheck and
`Decide` judges a captured `govulncheck -format json` stream.
`Options.Command` returns the command `Check` would run, without running it,
for a dry run. When govulncheck is not on `PATH`, both return an error that
wraps `ErrNotInstalled`; `InstallCommand` is the command that installs it. See
the [package documentation](https://pkg.go.dev/go.bison9.com/vulncheck).

## Licence

MIT. See [LICENSE](LICENSE).

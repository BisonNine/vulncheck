/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Command vulncheck runs govulncheck on a project and fails on any
// vulnerability the code calls, except those the project's b9.yaml ignores.
//
//	vulncheck [flags] [dir]
//
// Exit status: 0 when nothing fails the check, 1 when vulnerable code is
// called, 2 for a usage, configuration or scan error.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"

	"go.bison9.com/vulncheck"
	"go.bison9.com/vulncheck/app"
)

// Exit statuses.
const (
	exitPass       = 0
	exitVulnerable = 1
	exitError      = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// args is what the command line asks for.
type args struct {
	dir         string
	configPath  string // "" for <dir>/b9.yaml
	govulncheck string
	version     bool
}

// parseArgs parses the command line. When done is true the command has
// finished, after help or on a usage error, and code is its exit status.
func parseArgs(argv []string, stderr io.Writer) (a args, code int, done bool) {
	flags := flag.NewFlagSet(app.BinaryName(), flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&a.configPath, "config", "", "read the configuration from `file` (default <dir>/"+vulncheck.DefaultFile+")")
	flags.StringVar(&a.govulncheck, "govulncheck", "",
		"run this govulncheck `program` (default: govulncheck from PATH)")
	flags.BoolVar(&a.version, "version", false, "print the version and exit")
	flags.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: %s [flags] [dir]\n\n%s.\n\nExit status: 0 pass, 1 vulnerable code is called, 2 error.\n\nFlags:\n",
			app.BinaryName(), app.TagLine())
		flags.PrintDefaults()
	}

	if err := flags.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return a, exitPass, true
		}
		return a, exitError, true
	}
	if flags.NArg() > 1 {
		_, _ = fmt.Fprintf(stderr, "%s: give one directory at most, got %d\n", app.BinaryName(), flags.NArg())
		flags.Usage()
		return a, exitError, true
	}
	a.dir = "."
	if flags.NArg() == 1 {
		a.dir = flags.Arg(0)
	}
	return a, exitPass, false
}

// run is the command. runner is passed to vulncheck.Check; nil runs
// govulncheck as a child process.
func run(ctx context.Context, argv []string, stdout, stderr io.Writer, runner vulncheck.Runner) int {
	a, code, done := parseArgs(argv, stderr)
	if done {
		return code
	}
	if a.version {
		_, _ = fmt.Fprintf(stdout, "%s %s\n%s\n", app.Name(), app.Version(), app.Copyright())
		return exitPass
	}

	path := a.configPath
	if path == "" {
		path = filepath.Join(a.dir, vulncheck.DefaultFile)
	}
	cfg, err := vulncheck.LoadFile(path)
	switch {
	case err == nil:
	case a.configPath == "" && errors.Is(err, fs.ErrNotExist):
		// No configuration: scan with nothing ignored.
		cfg = vulncheck.Config{}
	default:
		return fail(stderr, err, exitError)
	}
	if cfg.Disabled {
		_, _ = fmt.Fprintf(stdout, "govulncheck is disabled in %s.\n", path)
		return exitPass
	}

	report, err := vulncheck.Check(ctx, vulncheck.Options{
		Dir:         a.dir,
		Ignore:      cfg.Ignore,
		Govulncheck: a.govulncheck,
		Runner:      runner,
	})
	if err != nil {
		return fail(stderr, err, exitError)
	}
	for _, line := range report.Lines() {
		_, _ = fmt.Fprintln(stdout, line)
	}
	if err := report.Err(); err != nil {
		return fail(stderr, err, exitVulnerable)
	}
	return exitPass
}

// fail prints err, prefixed with the command's name, and returns code.
func fail(stderr io.Writer, err error, code int) int {
	_, _ = fmt.Fprintf(stderr, "%s: %v\n", app.BinaryName(), err)
	return code
}

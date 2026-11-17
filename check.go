/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GovulncheckPackage is the govulncheck release that Check runs with
// `go run` when govulncheck is not on PATH, so that nothing is installed as a
// side effect.
const GovulncheckPackage = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"

// Command is one program to run: its name or path, its arguments, and the
// directory to run it in.
type Command struct {
	Name string
	Args []string
	Dir  string
}

// String renders the command as it would be typed.
func (c Command) String() string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// Runner runs a command and returns its standard output. It returns an error
// when the command cannot be started or exits with a non-zero status.
type Runner func(ctx context.Context, c Command) ([]byte, error)

// Options configures Check.
type Options struct {
	// Dir is the project directory to scan; "" is the current directory.
	Dir string
	// Ignore is the ignore list, normally Config.Ignore.
	Ignore []Ignore
	// Govulncheck is the govulncheck program to run, a name looked up on PATH
	// or a path. When it is "", govulncheck is taken from PATH if it is there
	// and otherwise run with `go run` at GovulncheckPackage.
	Govulncheck string
	// Now returns the current time; nil is time.Now. Ignore entries are
	// compared with its date in its location.
	Now func() time.Time
	// Runner runs govulncheck; nil runs it as a child process.
	Runner Runner
}

// Check runs govulncheck -format json ./... in opts.Dir and decides the
// result with Decide. The error is for a scan that could not be run or read;
// the vulnerabilities that fail the check are in the report (see Report.Err).
func Check(ctx context.Context, opts Options) (Report, error) {
	cmd, err := opts.command()
	if err != nil {
		return Report{}, err
	}
	run := opts.Runner
	if run == nil {
		run = execRunner
	}
	out, err := run(ctx, cmd)
	if err != nil {
		return Report{}, fmt.Errorf("govulncheck: %w", err)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	return Decide(bytes.NewReader(out), opts.Ignore, now())
}

// command is the govulncheck invocation for opts. A program found on PATH or
// given as a relative path is made absolute, so it is the same program when
// run in Dir.
func (o Options) command() (Command, error) {
	dir := o.Dir
	if dir == "" {
		dir = "."
	}
	args := []string{"-format", "json", "./..."}

	if o.Govulncheck != "" {
		path, err := lookAbs(o.Govulncheck)
		if err != nil {
			return Command{}, fmt.Errorf("govulncheck: %w", err)
		}
		return Command{Name: path, Args: args, Dir: dir}, nil
	}
	if path, err := lookAbs("govulncheck"); err == nil {
		return Command{Name: path, Args: args, Dir: dir}, nil
	}
	return Command{Name: "go", Args: append([]string{"run", GovulncheckPackage}, args...), Dir: dir}, nil
}

// lookAbs finds a program as exec.LookPath does and makes the result absolute.
func lookAbs(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

// execRunner runs the command as a child process. On failure the error
// carries what the command printed, standard error first.
func execRunner(ctx context.Context, c Command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...) //nolint:gosec // the command is govulncheck, chosen by the caller
	cmd.Dir = c.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg != "" {
			return nil, fmt.Errorf("%s: %w\n%s", c, err, indent(msg))
		}
		return nil, fmt.Errorf("%s: %w", c, err)
	}
	return stdout.Bytes(), nil
}

// indent prefixes every line of s with two spaces.
func indent(s string) string {
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}

/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// InstallCommand is the command that installs govulncheck. Check and
// Options.Command never run it; the error for a missing govulncheck names it.
const InstallCommand = "go install golang.org/x/vuln/cmd/govulncheck@latest"

// ErrNotInstalled is returned, wrapped, by Check and Options.Command when
// Options.Govulncheck is "" and govulncheck is not on PATH.
var ErrNotInstalled = errors.New("govulncheck is not on PATH")

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
	// or a path; "" is govulncheck from PATH. Whatever version it is, its
	// output must be in a JSON protocol version Decide knows.
	Govulncheck string
	// Now returns the current time; nil is time.Now. Ignore entries are
	// compared with its date in its location.
	Now func() time.Time
	// Runner runs govulncheck; nil runs it as a child process.
	Runner Runner
}

// Check validates opts.Ignore, runs govulncheck -format json ./... in
// opts.Dir and decides the result with Decide. The error is for an invalid
// ignore list, a govulncheck that is not installed, or a scan that could not
// be run or read, which names the program that was run; the vulnerabilities
// that fail the check are in the report (see Report.Err).
func Check(ctx context.Context, opts Options) (Report, error) {
	if err := (Config{Ignore: opts.Ignore}).Validate(); err != nil {
		return Report{}, err
	}
	cmd, err := opts.Command()
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
	report, err := Decide(bytes.NewReader(out), opts.Ignore, now())
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", cmd.Name, err)
	}
	return report, nil
}

// Command returns the govulncheck command Check runs for o, without running
// it: o.Govulncheck, else govulncheck from PATH, with -format json ./... in
// o.Dir ("" is "."). The program is made absolute, so a relative path means
// the same program when run in Dir. When o.Govulncheck is "" and govulncheck
// is not on PATH the error wraps ErrNotInstalled and names InstallCommand.
func (o Options) Command() (Command, error) {
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
	path, err := lookAbs("govulncheck")
	if err != nil {
		return Command{}, fmt.Errorf("%w; install it with: %s", ErrNotInstalled, InstallCommand)
	}
	return Command{Name: path, Args: args, Dir: dir}, nil
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

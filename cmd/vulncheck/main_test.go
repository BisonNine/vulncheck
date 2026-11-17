/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.bison9.com/vulncheck"
	"go.bison9.com/vulncheck/app"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fake is a runner that returns out and err, and records what it was asked
// to run.
type fake struct {
	out  []byte
	err  error
	ran  []vulncheck.Command
	used bool
}

func (f *fake) run(_ context.Context, c vulncheck.Command) ([]byte, error) {
	f.used = true
	f.ran = append(f.ran, c)
	return f.out, f.err
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const otherKeys = "name: demo\nbuild:\n  targets: [linux/amd64]\n  anything: goes\n"

func TestRun(t *testing.T) {
	called := fixture(t, "govulncheck-called.json")
	imported := fixture(t, "govulncheck-imported.json")

	tests := []struct {
		name       string
		conf       string // b9.yaml in the project directory; "" for none
		out        []byte
		runErr     error
		wantCode   int
		wantStdout []string
		wantStderr []string
		wantNoScan bool
	}{
		{
			name:       "no file is a strict scan",
			out:        called,
			wantCode:   1,
			wantStdout: []string{"Vulnerable: GO-2026-6911 "},
			wantStderr: []string{"govulncheck: vulnerable code is called: GO-2026-6911"},
		},
		{
			name:       "file without the key is a strict scan",
			conf:       otherKeys,
			out:        called,
			wantCode:   1,
			wantStdout: []string{"Vulnerable: GO-2026-6911 "},
		},
		{
			name:       "nothing called",
			out:        imported,
			wantCode:   0,
			wantStdout: []string{"No called vulnerabilities."},
		},
		{
			name:       "ignored among other keys",
			conf:       otherKeys + "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix yet}\n",
			out:        called,
			wantCode:   0,
			wantStdout: []string{"Ignored (no fix yet): GO-2026-6911 "},
		},
		{
			name:       "expired",
			conf:       "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix yet, until: 20200101}\n",
			out:        called,
			wantCode:   1,
			wantStdout: []string{"Vulnerable, ignore expired on 2020-01-01: GO-2026-6911 "},
			wantStderr: []string{"GO-2026-6911"},
		},
		{
			name:       "unused entry passes",
			conf:       "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix yet}\n",
			out:        imported,
			wantCode:   0,
			wantStdout: []string{"Ignore entry GO-2026-6911 is no longer needed and can be removed.", "No called vulnerabilities."},
		},
		{
			name:       "disabled",
			conf:       otherKeys + "govulncheck: false\n",
			wantCode:   0,
			wantNoScan: true,
		},
		{
			name:       "disabled in the mapping form",
			conf:       "govulncheck:\n  enabled: false\n",
			wantCode:   0,
			wantNoScan: true,
		},
		{
			name:       "invalid configuration",
			conf:       "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911}\n",
			wantCode:   2,
			wantStderr: []string{"missing required field: govulncheck.ignore[0] (GO-2026-6911).reason"},
			wantNoScan: true,
		},
		{
			name:       "scan fails",
			runErr:     errors.New("exit status 1"),
			wantCode:   2,
			wantStderr: []string{"govulncheck: exit status 1"},
		},
		{
			name:       "output is not govulncheck JSON",
			out:        []byte("No vulnerabilities found.\n"),
			wantCode:   2,
			wantStderr: []string{"reading govulncheck output"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			confPath := filepath.Join(dir, vulncheck.DefaultFile)
			if tt.conf != "" {
				writeFile(t, confPath, tt.conf)
			}
			f := &fake{out: tt.out, err: tt.runErr}
			var stdout, stderr bytes.Buffer

			code := run(t.Context(), []string{dir}, &stdout, &stderr, f.run)
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, &stdout, &stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, &stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, &stderr)
				}
			}
			if f.used == tt.wantNoScan {
				t.Errorf("scanned = %v, want %v", f.used, !tt.wantNoScan)
			}
			if f.used && f.ran[0].Dir != dir {
				t.Errorf("scanned %s, want %s", f.ran[0].Dir, dir)
			}
			if strings.HasPrefix(tt.name, "disabled") {
				if got, want := stdout.String(), "govulncheck is disabled in "+confPath+".\n"; got != want {
					t.Errorf("stdout = %q, want %q", got, want)
				}
			}
		})
	}
}

func TestRunConfigFlag(t *testing.T) {
	called := fixture(t, "govulncheck-called.json")
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, vulncheck.DefaultFile), "govulncheck: false\n")
	other := filepath.Join(t.TempDir(), "other.yaml")
	writeFile(t, other, "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix yet}\n")

	f := &fake{out: called}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"-config", other, dir}, &stdout, &stderr, f.run); code != 0 {
		t.Fatalf("exit = %d\n%s%s", code, &stdout, &stderr)
	}
	if !strings.Contains(stdout.String(), "Ignored (no fix yet): GO-2026-6911") {
		t.Errorf("stdout = %q, want the entry from %s", &stdout, other)
	}

	// A configuration file named on the command line must exist.
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	stderr.Reset()
	if code := run(t.Context(), []string{"-config", missing, dir}, &stdout, &stderr, (&fake{out: called}).run); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), missing) {
		t.Errorf("stderr = %q, want it to name %s", &stderr, missing)
	}
}

func TestRunGovulncheckFlag(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake program is a shell script")
	}
	prog := filepath.Join(t.TempDir(), "scanner")
	writeFile(t, prog, "")
	if err := os.Chmod(prog, 0o700); err != nil {
		t.Fatal(err)
	}
	f := &fake{out: fixture(t, "govulncheck-imported.json")}
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), []string{"-govulncheck", prog, t.TempDir()}, &stdout, &stderr, f.run); code != 0 {
		t.Fatalf("exit = %d\n%s", code, &stderr)
	}
	if got := f.ran[0]; got.Name != prog || strings.Join(got.Args, " ") != "-format json ./..." {
		t.Errorf("ran %s, want %s -format json ./...", got, prog)
	}

	stderr.Reset()
	missing := filepath.Join(t.TempDir(), "nothing")
	if code := run(t.Context(), []string{"-govulncheck", missing, t.TempDir()}, &stdout, &stderr, f.run); code != 2 {
		t.Errorf("exit = %d with a missing program, want 2", code)
	}
}

func TestRunDefaultDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	writeFile(t, vulncheck.DefaultFile, "govulncheck: false\n")
	var stdout, stderr bytes.Buffer
	if code := run(t.Context(), nil, &stdout, &stderr, (&fake{}).run); code != 0 {
		t.Fatalf("exit = %d\n%s", code, &stderr)
	}
	if got, want := stdout.String(), "govulncheck is disabled in "+vulncheck.DefaultFile+".\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestRunUsage(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"-version"}, 0, app.Name() + " " + app.Version() + "\n" + app.Copyright() + "\n", ""},
		{"help", []string{"-h"}, 0, "", "Usage: "},
		{"unknown flag", []string{"-nope"}, 2, "", "flag provided but not defined: -nope"},
		{"two directories", []string{"a", "b"}, 2, "", "give one directory at most, got 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fake{}
			var stdout, stderr bytes.Buffer
			if code := run(t.Context(), tt.args, &stdout, &stderr, f.run); code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", &stdout, tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", &stderr, tt.wantStderr)
			}
			if f.used {
				t.Error("scanned")
			}
		})
	}
}

// The built command, run as a process with a stand-in govulncheck: exit
// statuses are what a Makefile sees.
func TestBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in govulncheck is a shell script")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go is required to build the command: %v", err)
	}
	bin := t.TempDir()
	exe := filepath.Join(bin, "vulncheck")
	build := exec.CommandContext(t.Context(), goBin, "build", "-o", exe, ".")
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Fatalf("go build: %v\n%s", buildErr, out)
	}
	fixturePath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "govulncheck-called.json"))
	if err != nil {
		t.Fatal(err)
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatalf("cat is required for the stand-in govulncheck: %v", err)
	}
	writeFile(t, filepath.Join(bin, "govulncheck"), "#!/bin/sh\nexec '"+cat+"' '"+fixturePath+"'\n")
	if err := os.Chmod(filepath.Join(bin, "govulncheck"), 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		conf     string
		wantCode int
		want     string
	}{
		{"vulnerable", "", 1, "Vulnerable: GO-2026-6911"},
		{"ignored", "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix yet}\n", 0, "Ignored (no fix yet): GO-2026-6911"},
		{"invalid", "govulncheck: maybe\n", 2, `got the string "maybe"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.conf != "" {
				writeFile(t, filepath.Join(dir, vulncheck.DefaultFile), tt.conf)
			}
			cmd := exec.CommandContext(t.Context(), exe, "-govulncheck", filepath.Join(bin, "govulncheck"), dir)
			out, err := cmd.CombinedOutput()
			code := 0
			if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != tt.wantCode || !strings.Contains(string(out), tt.want) {
				t.Errorf("exit %d, output:\n%s\nwant exit %d and %q", code, out, tt.wantCode, tt.want)
			}
		})
	}
}

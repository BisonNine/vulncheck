/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeProgram writes an executable shell script named name into dir.
func fakeProgram(t *testing.T, dir, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake program is a shell script")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeOnPath puts a stand-in govulncheck alone on PATH and returns its path.
func fakeOnPath(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	path := fakeProgram(t, bin, "govulncheck", "exit 0\n")
	t.Setenv("PATH", bin)
	return path
}

func mustDay(t *testing.T, s string) Day {
	t.Helper()
	d, err := ParseDay(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCommandSelection(t *testing.T) {
	scan := []string{"-format", "json", "./..."}

	t.Run("from PATH", func(t *testing.T) {
		want := fakeOnPath(t)
		c, err := Options{Dir: "/src/demo"}.Command()
		if err != nil {
			t.Fatal(err)
		}
		if c.Name != want || !slices.Equal(c.Args, scan) || c.Dir != "/src/demo" {
			t.Errorf("command = %+v, want %s %v in /src/demo", c, want, scan)
		}
	})

	t.Run("dir defaults to the current directory", func(t *testing.T) {
		fakeOnPath(t)
		c, err := Options{}.Command()
		if err != nil || c.Dir != "." {
			t.Errorf("command = %+v, %v; want it run in .", c, err)
		}
	})

	t.Run("not on PATH", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		_, err := Options{}.Command()
		want := "govulncheck is not on PATH; install it with: go install golang.org/x/vuln/cmd/govulncheck@latest"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
		}
		if !errors.Is(err, ErrNotInstalled) {
			t.Errorf("error = %v, want one wrapping ErrNotInstalled", err)
		}
		_, err = Check(t.Context(), Options{})
		if !errors.Is(err, ErrNotInstalled) {
			t.Errorf("Check error = %v, want one wrapping ErrNotInstalled", err)
		}
	})

	t.Run("override by path", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		fakeProgram(t, dir, "scanner", "exit 0\n")
		// Another govulncheck on PATH must not be preferred to the override.
		bin := t.TempDir()
		fakeProgram(t, bin, "govulncheck", "exit 0\n")
		t.Setenv("PATH", bin)

		c, err := Options{Dir: t.TempDir(), Govulncheck: "./scanner"}.Command()
		if err != nil {
			t.Fatal(err)
		}
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		// Relative to where the caller is, not to the directory scanned.
		if want := filepath.Join(wd, "scanner"); c.Name != want || !slices.Equal(c.Args, scan) {
			t.Errorf("command = %+v, want %s %v", c, want, scan)
		}
	})

	t.Run("override by name", func(t *testing.T) {
		bin := t.TempDir()
		want := fakeProgram(t, bin, "govulncheck-1.9", "exit 0\n")
		t.Setenv("PATH", bin)
		c, err := Options{Govulncheck: "govulncheck-1.9"}.Command()
		if err != nil || c.Name != want {
			t.Errorf("command = %+v, %v; want %s", c, err, want)
		}
	})

	t.Run("override that does not exist", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nothing")
		if _, err := (Options{Govulncheck: missing}).Command(); err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("error = %v, want one naming %s", err, missing)
		}
	})
}

// TestCheckRunsCommand checks that Check runs exactly what Command returns.
func TestCheckRunsCommand(t *testing.T) {
	bin := t.TempDir()
	fakeProgram(t, bin, "govulncheck", "exit 0\n")
	explicit := fakeProgram(t, t.TempDir(), "scanner", "exit 0\n")
	t.Setenv("PATH", bin)
	stream := readFixture(t, "govulncheck-imported.json")

	tests := []struct {
		name string
		opts Options
	}{
		{"from PATH", Options{Dir: "/src/demo"}},
		{"explicit program", Options{Dir: "/src/demo", Govulncheck: explicit}},
		{"default dir", Options{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := tt.opts.Command()
			if err != nil {
				t.Fatal(err)
			}
			var got Command
			opts := tt.opts
			opts.Runner = func(_ context.Context, c Command) ([]byte, error) {
				got = c
				return []byte(stream), nil
			}
			if _, err := Check(t.Context(), opts); err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Name != want.Name || got.Dir != want.Dir || !slices.Equal(got.Args, want.Args) {
				t.Errorf("Check ran %+v, Command returned %+v", got, want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	called := readFixture(t, "govulncheck-called.json")
	prog := fakeOnPath(t) // the runner is fake; the program need only exist
	today := time.Date(2026, 11, 17, 9, 0, 0, 0, time.Local)

	var got Command
	opts := Options{
		Dir:    "/src/demo",
		Ignore: []Ignore{{ID: "GO-2026-6911", Reason: "no fix yet", Until: mustDay(t, "2026-11-17")}},
		Now:    func() time.Time { return today },
		Runner: func(_ context.Context, c Command) ([]byte, error) {
			got = c
			return []byte(called), nil
		},
	}
	r, err := Check(t.Context(), opts)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Dir != "/src/demo" || got.Name != prog {
		t.Errorf("ran %+v", got)
	}
	if r.Err() != nil || !slices.Equal(ids(r.Ignored), []string{"GO-2026-6911"}) {
		t.Errorf("report = %+v, want GO-2026-6911 ignored", r)
	}

	// The next day the same entry has expired: the clock is Now, not the
	// real time.
	opts.Now = func() time.Time { return today.AddDate(0, 0, 1) }
	r, err = Check(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids(r.Expired), []string{"GO-2026-6911"}) || r.Err() == nil {
		t.Errorf("report = %+v, want GO-2026-6911 expired", r)
	}
}

// An ignore list built in code is validated before anything runs.
func TestCheckValidatesIgnores(t *testing.T) {
	until, err := ParseDay("20261231")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		ignore []Ignore
		want   string
	}{
		{"missing reason", []Ignore{{ID: "GO-2026-6911"}}, "(GO-2026-6911).reason"},
		{"bad id", []Ignore{{ID: "CVE-2026-1", Reason: "r"}}, "id must be a Go vulnerability ID"},
		{"duplicate id", []Ignore{{ID: "GO-2026-6911", Reason: "a"}, {ID: "GO-2026-6911", Reason: "b", Until: until}}, "duplicate id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ran := false
			opts := Options{Ignore: tt.ignore, Runner: func(context.Context, Command) ([]byte, error) {
				ran = true
				return nil, nil
			}}
			_, err := Check(t.Context(), opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one containing %q", err, tt.want)
			}
			if ran {
				t.Error("govulncheck ran with an invalid ignore list")
			}
		})
	}
}

// A scan that fails is an error, never an empty result.
func TestCheckFailsClosed(t *testing.T) {
	fakeOnPath(t)
	tests := []struct {
		name string
		out  string
		err  error
	}{
		{"runner error", "", errors.New("exit status 1")},
		{"runner error with output", readFixture(t, "govulncheck-called.json"), errors.New("exit status 1")},
		{"no output", "", nil},
		{"text output", "No vulnerabilities found.\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{Runner: func(context.Context, Command) ([]byte, error) { return []byte(tt.out), tt.err }}
			if _, err := Check(t.Context(), opts); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// An output error names the program that was run, so the operator knows
// which govulncheck to update.
func TestCheckNamesProgram(t *testing.T) {
	prog := fakeOnPath(t)
	stream := strings.Replace(readFixture(t, "govulncheck-called.json"), `"protocol_version": "v1.0.0"`, `"protocol_version": "v2.0.0"`, 1)
	opts := Options{Runner: func(context.Context, Command) ([]byte, error) { return []byte(stream), nil }}
	_, err := Check(t.Context(), opts)
	want := prog + `: govulncheck JSON protocol version "v2.0.0" is not supported (supported: v1.0.0)`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}

func TestExecRunner(t *testing.T) {
	dir := t.TempDir()
	ok := fakeProgram(t, dir, "ok", "pwd\n")
	out, err := execRunner(t.Context(), Command{Name: ok, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != wantDir {
		t.Errorf("ran in %q, want %q", got, wantDir)
	}

	bad := fakeProgram(t, dir, "bad", "echo 'partial' \necho 'go: errors loading packages' >&2\nexit 1\n")
	_, err = execRunner(t.Context(), Command{Name: bad, Args: []string{"-x"}, Dir: dir})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{bad + " -x: exit status 1", "\n  go: errors loading packages"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}

	silent := fakeProgram(t, dir, "silent", "exit 3\n")
	if _, err := execRunner(t.Context(), Command{Name: silent, Dir: dir}); err == nil || err.Error() != silent+": exit status 3" {
		t.Errorf("error = %v", err)
	}
}

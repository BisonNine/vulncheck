/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// others is the rest of a release description: keys this package must not
// read, check or mind, including ones that look like typos.
const others = `name: demo
github: example/demo
build:
  targets: [linux/amd64]
  unknown_option: 1
artifacts:
  - name: demo
    from: ./cmd/demo
`

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		conf        string
		wantEnabled bool
		wantIgnore  int
		wantUntil   string // String() of the first entry's until; "" when unset
	}{
		{name: "absent", conf: "", wantEnabled: true},
		{name: "true", conf: "govulncheck: true", wantEnabled: true},
		{name: "false", conf: "govulncheck: false"},
		{
			name:        "mapping without ignore",
			conf:        "govulncheck:\n  enabled: true",
			wantEnabled: true,
		},
		{
			name:        "ignore without a date",
			conf:        "govulncheck:\n  enabled: true\n  ignore:\n    - id: GO-2026-6911\n      reason: no fixed release yet",
			wantEnabled: true, wantIgnore: 1,
		},
		{
			name:        "date as an integer",
			conf:        "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix, until: 20261231}",
			wantEnabled: true, wantIgnore: 1, wantUntil: "2026-12-31",
		},
		{
			name:        "date as a string",
			conf:        "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix, until: \"20261231\"}",
			wantEnabled: true, wantIgnore: 1, wantUntil: "2026-12-31",
		},
		{
			name:        "date with dashes",
			conf:        "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix, until: 2026-12-31}",
			wantEnabled: true, wantIgnore: 1, wantUntil: "2026-12-31",
		},
		{
			name:        "quoted date with dashes",
			conf:        "govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix, until: '2026-12-31'}",
			wantEnabled: true, wantIgnore: 1, wantUntil: "2026-12-31",
		},
		{
			name:       "ignore with the scan disabled",
			conf:       "govulncheck:\n  enabled: false\n  ignore:\n    - {id: GO-2026-6911, reason: no fix}",
			wantIgnore: 1,
		},
	}
	for _, tt := range tests {
		for _, prefix := range []string{"", others} {
			name := tt.name
			if prefix != "" {
				name += " among other keys"
			}
			t.Run(name, func(t *testing.T) {
				cfg, err := Parse([]byte(prefix + tt.conf + "\n"))
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if cfg.Enabled != tt.wantEnabled || len(cfg.Ignore) != tt.wantIgnore {
					t.Fatalf("Config = %+v, want enabled %v with %d ignore entries", cfg, tt.wantEnabled, tt.wantIgnore)
				}
				if tt.wantIgnore == 0 {
					return
				}
				e := cfg.Ignore[0]
				if e.ID != "GO-2026-6911" || e.Reason == "" {
					t.Errorf("entry = %+v", e)
				}
				if e.Until.Set() != (tt.wantUntil != "") {
					t.Errorf("Until.Set() = %v", e.Until.Set())
				}
				if tt.wantUntil != "" && e.Until.String() != tt.wantUntil {
					t.Errorf("Until = %s, want %s", e.Until, tt.wantUntil)
				}
			})
		}
	}
}

func TestParseRejects(t *testing.T) {
	block := func(entries string) string {
		return "govulncheck:\n  enabled: true\n  ignore:\n" + entries
	}
	tests := []struct {
		name string
		conf string
		want string
	}{
		{"missing id", block("    - {reason: no fix}"), "govulncheck.ignore[0].id"},
		{"blank id", block("    - {id: ' ', reason: no fix}"), "govulncheck.ignore[0]"},
		{"CVE instead of a Go ID", block("    - {id: CVE-2026-1234, reason: no fix}"), "CVE-2026-1234"},
		{"lower-case ID", block("    - {id: go-2026-6911, reason: no fix}"), "go-2026-6911"},
		{"missing reason", block("    - {id: GO-2026-6911}"), "(GO-2026-6911).reason"},
		{"blank reason", block("    - {id: GO-2026-6911, reason: '  '}"), "(GO-2026-6911).reason"},
		{"date out of range", block("    - {id: GO-2026-6911, reason: no fix, until: 20261332}"), "GO-2026-6911"},
		{"date too short", block("    - {id: GO-2026-6911, reason: no fix, until: 2026123}"), "GO-2026-6911"},
		{"date in another order", block("    - {id: GO-2026-6911, reason: no fix, until: 31-12-2026}"), "GO-2026-6911"},
		{"empty date", block("    - {id: GO-2026-6911, reason: no fix, until: ''}"), "(GO-2026-6911): until is empty"},
		{"until with no value", block("    - id: GO-2026-6911\n      reason: no fix\n      until:"), "(GO-2026-6911): until is empty"},
		{"null date", block("    - {id: GO-2026-6911, reason: no fix, until: null}"), "(GO-2026-6911): until is empty"},
		{"tilde date", block("    - {id: GO-2026-6911, reason: no fix, until: ~}"), "(GO-2026-6911): until is empty"},
		{"duplicate id", block("    - {id: GO-2026-6911, reason: a}\n    - {id: GO-2026-6911, reason: b}"), "duplicate"},
		{"unknown key in an entry", block("    - {id: GO-2026-6911, reason: no fix, untill: 20261231}"), "untill"}, //nolint:misspell // the typo is the test
		{"unknown key in the block", "govulncheck:\n  enabled: true\n  ignores: []", "ignores"},
		{"mapping without enabled", "govulncheck:\n  ignore:\n    - {id: GO-2026-6911, reason: no fix}", "enabled is required"},
		{"neither bool nor mapping", "govulncheck: 1", "got 1 (uint64)"},
		{"quoted bool", `govulncheck: "true"`, `got the string "true"`},
		{"null", "govulncheck:", "govulncheck must be true, false or a mapping with enabled and ignore, got null"},
		{"tilde", "govulncheck: ~", "got null"},
		{"duplicate key", "govulncheck: true\ngovulncheck: false", `mapping key "govulncheck" already defined`},
		{"not YAML", "govulncheck: [true", ""},
	}
	for _, tt := range tests {
		for _, prefix := range []string{"", others} {
			name := tt.name
			if prefix != "" {
				name += " among other keys"
			}
			t.Run(name, func(t *testing.T) {
				_, err := Parse([]byte(prefix + tt.conf + "\n"))
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("Parse error = %v, want one containing %q", err, tt.want)
				}
			})
		}
	}
}

// Every problem is reported at once, each one separately unwrappable.
func TestValidateReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte("govulncheck:\n  enabled: true\n  ignore:\n    - {id: CVE-1}\n    - {id: GO-2026-1, reason: r, until: 1}\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	var multi interface{ Unwrap() []error }
	if !errors.As(err, &multi) || len(multi.Unwrap()) != 3 {
		t.Fatalf("error = %v, want three problems", err)
	}
	want := "invalid configuration:\n" +
		"  - govulncheck.ignore[0] (CVE-1): id must be a Go vulnerability ID such as GO-2024-1234\n" +
		"  - missing required field: govulncheck.ignore[0] (CVE-1).reason\n" +
		`  - govulncheck.ignore[1] (GO-2026-1): until must be a date written YYYYMMDD or YYYY-MM-DD, got "1"`
	if err.Error() != want {
		t.Errorf("error =\n%s\nwant\n%s", err, want)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadFile(filepath.Join(dir, DefaultFile))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadFile(missing) error = %v, want fs.ErrNotExist", err)
	}

	path := filepath.Join(dir, DefaultFile)
	err = os.WriteFile(path, []byte(others+"govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix}\n"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFile(path)
	if err != nil || !cfg.Enabled || len(cfg.Ignore) != 1 {
		t.Errorf("LoadFile = %+v, %v", cfg, err)
	}

	if err = os.WriteFile(path, []byte("govulncheck: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadFile(path); err == nil || !strings.HasPrefix(err.Error(), path+": ") {
		t.Errorf("LoadFile(invalid) error = %v, want one naming %s", err, path)
	}
}

func TestDayCovers(t *testing.T) {
	cfg, err := Parse([]byte("govulncheck:\n  enabled: true\n  ignore:\n    - {id: GO-2026-6911, reason: no fix, until: 20261231}\n    - {id: GO-2026-6912, reason: no fix}\n"))
	if err != nil {
		t.Fatal(err)
	}
	dated, open := cfg.Ignore[0].Until, cfg.Ignore[1].Until
	east := time.FixedZone("UTC+14", 14*3600)
	tests := []struct {
		name  string
		day   Day
		today time.Time
		want  bool
	}{
		{"day before", dated, time.Date(2026, 12, 30, 12, 0, 0, 0, time.UTC), true},
		{"the day itself, last second", dated, time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), true},
		{"the next day", dated, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), false},
		// The local date decides, whatever the instant is in UTC.
		{"next local day", dated, time.Date(2027, 1, 1, 1, 0, 0, 0, east), false},
		{"no end date", open, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.day.Covers(tt.today); got != tt.want {
				t.Errorf("Covers(%s) = %v, want %v", tt.today, got, tt.want)
			}
		})
	}
}

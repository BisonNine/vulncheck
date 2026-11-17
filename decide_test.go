/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

// A second called vulnerability, appended to the captured stream.
const otherCalled = `
{"osv": {"id": "GO-2025-0001", "summary": "Example flaw in example.com/lib"}}
{"finding": {"osv": "GO-2025-0001", "fixed_version": "v1.2.4", "trace": [
  {"module": "example.com/lib", "version": "v1.2.3", "package": "example.com/lib", "function": "Parse"},
  {"module": "example.com/demo", "package": "example.com/demo", "function": "main"}]}}
`

// readFixture returns a captured govulncheck -format json stream.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ignores decodes an ignore list as Parse does.
func ignores(t *testing.T, src string) []Ignore {
	t.Helper()
	if src == "" {
		return nil
	}
	var out []Ignore
	if err := yaml.Unmarshal([]byte(src), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(vs []Vuln) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}

func TestDecide(t *testing.T) {
	called := readFixture(t, "govulncheck-called.json")
	imported := readFixture(t, "govulncheck-imported.json")
	today := time.Date(2026, 11, 17, 15, 0, 0, 0, time.Local)

	tests := []struct {
		name        string
		stream      string
		ignore      string
		wantFatal   []string
		wantExpired []string
		wantIgnored []string
		wantUnused  []string
	}{
		{
			name:   "module and package findings are not fatal",
			stream: imported,
		},
		{
			name:      "called finding is fatal",
			stream:    called,
			wantFatal: []string{"GO-2026-6911"},
		},
		{
			name:        "ignored without a date",
			stream:      called,
			ignore:      "- {id: GO-2026-6911, reason: no fixed release}",
			wantIgnored: []string{"GO-2026-6911"},
		},
		{
			name:        "ignored until today is still ignored",
			stream:      called,
			ignore:      "- {id: GO-2026-6911, reason: no fixed release, until: 20261117}",
			wantIgnored: []string{"GO-2026-6911"},
		},
		{
			name:        "expired yesterday is fatal",
			stream:      called,
			ignore:      "- {id: GO-2026-6911, reason: no fixed release, until: 2026-11-16}",
			wantExpired: []string{"GO-2026-6911"},
		},
		{
			name:       "ignore entry that matches nothing is unused",
			stream:     imported,
			ignore:     "- {id: GO-2026-6911, reason: no fixed release}",
			wantUnused: []string{"GO-2026-6911"},
		},
		{
			name:        "two vulnerabilities, one ignored",
			stream:      called + otherCalled,
			ignore:      "- {id: GO-2026-6911, reason: no fixed release}",
			wantFatal:   []string{"GO-2025-0001"},
			wantIgnored: []string{"GO-2026-6911"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Decide(strings.NewReader(tt.stream), ignores(t, tt.ignore), today)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			var unused []string
			for _, e := range r.Unused {
				unused = append(unused, e.ID)
			}
			if !slices.Equal(ids(r.Fatal), tt.wantFatal) || !slices.Equal(ids(r.Expired), tt.wantExpired) ||
				!slices.Equal(ids(r.Ignored), tt.wantIgnored) || !slices.Equal(unused, tt.wantUnused) {
				t.Errorf("fatal %v expired %v ignored %v unused %v; want %v %v %v %v",
					ids(r.Fatal), ids(r.Expired), ids(r.Ignored), unused,
					tt.wantFatal, tt.wantExpired, tt.wantIgnored, tt.wantUnused)
			}
			wantErr := len(tt.wantFatal)+len(tt.wantExpired) > 0
			if err := r.Err(); (err != nil) != wantErr {
				t.Errorf("Err() = %v, want error %v", err, wantErr)
			}
			for _, id := range append(tt.wantFatal, tt.wantExpired...) {
				if err := r.Err(); err == nil || !strings.Contains(err.Error(), id) {
					t.Errorf("Err() = %v, does not name %s", err, id)
				}
			}
		})
	}
}

func TestDecideRejectsBadOutput(t *testing.T) {
	called := readFixture(t, "govulncheck-called.json")
	tests := []struct {
		name   string
		stream string
	}{
		{"empty", ""},
		{"truncated", called[:len(called)/2]},
		{"not json", "No vulnerabilities found.\n"},
		{"no config message", `{"finding": {"osv": "GO-2026-6911", "trace": [{"module": "m", "function": "F"}]}}`},
		{"module scan level", strings.Replace(called, `"scan_level": "symbol"`, `"scan_level": "module"`, 1)},
		{"finding without trace", called + `{"finding": {"osv": "GO-2025-0001", "trace": []}}`},
		{"finding without id", called + `{"finding": {"trace": [{"module": "m", "function": "F"}]}}`},
		{"unknown message", called + `{"verdict": {"ok": true}}`},
		{"message with no key", called + `{}`},
		{"message with two known keys", called + `{"config": {"protocol_version": "v1.0.0", "scan_level": "symbol"}, "finding": {"osv": "GO-2025-0001", "trace": [{"module": "m", "function": "F"}]}}`},
		{"known key in another case", called + `{"Finding": {"osv": "GO-2025-0001", "trace": [{"module": "m", "function": "F"}]}}`},
		{"message that is not an object", called + `["finding"]`},
		{"unknown protocol version", strings.Replace(called, `"protocol_version": "v1.0.0"`, `"protocol_version": "v2.0.0"`, 1)},
		{"no protocol version", strings.Replace(called, `"protocol_version": "v1.0.0",`, ``, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decide(strings.NewReader(tt.stream), nil, time.Now()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDecideErrorMessages(t *testing.T) {
	called := readFixture(t, "govulncheck-called.json")
	tests := []struct {
		name   string
		stream string
		want   string
	}{
		{"unknown message", called + `{"verdict": {}}`, `unknown message "verdict"`},
		{"two keys", called + `{"osv": {}, "finding": {}}`, `a message has 2 keys ["finding" "osv"], expected exactly one`},
		{
			"protocol", strings.Replace(called, `"protocol_version": "v1.0.0"`, `"protocol_version": "v2.0.0"`, 1),
			`govulncheck JSON protocol version "v2.0.0" is not supported (supported: v1.0.0)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decide(strings.NewReader(tt.stream), nil, time.Now())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// Every top-level message govulncheck v1.9.0 writes is accepted, SBOM
// included, which the captured fixtures lack.
func TestDecideAcceptsEveryMessage(t *testing.T) {
	sbom := `{"SBOM": {"go_version": "go1.27.4", "modules": [{"path": "example.com/demo"}], "roots": ["example.com/demo"]}}` + "\n"
	r, err := Decide(strings.NewReader(readFixture(t, "govulncheck-called.json")+sbom), nil, time.Now())
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !slices.Equal(ids(r.Fatal), []string{"GO-2026-6911"}) {
		t.Errorf("fatal = %v", ids(r.Fatal))
	}
}

func TestDecideValidatesIgnores(t *testing.T) {
	_, err := Decide(strings.NewReader(readFixture(t, "govulncheck-called.json")), []Ignore{{ID: "GO-2026-6911"}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("error = %v, want the missing reason", err)
	}
}

func TestReportLines(t *testing.T) {
	called := readFixture(t, "govulncheck-called.json")
	today := time.Date(2026, 11, 17, 0, 0, 0, 0, time.Local)
	const url = "https://pkg.go.dev/vuln/GO-2026-6911"
	const found = "GO-2026-6911 github.com/mark3labs/mcp-go v1.5.0, no fixed version. SSRF and credential leak"

	tests := []struct {
		name   string
		stream string
		ignore string
		want   []string
	}{
		{"fatal", called, "", []string{"Vulnerable: " + found}},
		{
			"ignored until", called, "- {id: GO-2026-6911, reason: no fix yet, until: 20261231}",
			[]string{"Ignored until 2026-12-31 (no fix yet): " + found},
		},
		{
			"ignored", called, "- {id: GO-2026-6911, reason: no fix yet}",
			[]string{"Ignored (no fix yet): " + found},
		},
		{
			"expired", called, "- {id: GO-2026-6911, reason: no fix yet, until: 20261116}",
			[]string{"Vulnerable, ignore expired on 2026-11-16: " + found},
		},
		{
			"unused", readFixture(t, "govulncheck-imported.json"), "- {id: GO-2026-6911, reason: no fix yet}",
			[]string{"Ignore entry GO-2026-6911 is no longer needed and can be removed.", "No called vulnerabilities."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Decide(strings.NewReader(tt.stream), ignores(t, tt.ignore), today)
			if err != nil {
				t.Fatal(err)
			}
			lines := r.Lines()
			if len(lines) != len(tt.want) {
				t.Fatalf("lines = %q, want %d", lines, len(tt.want))
			}
			for i, want := range tt.want {
				if !strings.HasPrefix(lines[i], want) {
					t.Errorf("line %d = %q, want prefix %q", i, lines[i], want)
				}
				if strings.HasPrefix(want, "Ignore entry") || strings.HasPrefix(want, "No called") {
					continue
				}
				if !strings.HasSuffix(lines[i], url) {
					t.Errorf("line %d = %q, want the advisory URL", i, lines[i])
				}
			}
		})
	}
}

func TestReportLinesFixedVersion(t *testing.T) {
	r, err := Decide(strings.NewReader(readFixture(t, "govulncheck-imported.json")+otherCalled), nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := "Vulnerable: GO-2025-0001 example.com/lib v1.2.3, fixed in v1.2.4. Example flaw in example.com/lib. https://pkg.go.dev/vuln/GO-2025-0001"
	if lines := r.Lines(); len(lines) != 1 || lines[0] != want {
		t.Errorf("lines = %q, want [%q]", lines, want)
	}
}

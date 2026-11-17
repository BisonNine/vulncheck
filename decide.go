/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package vulncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
)

// govulncheck's JSON output is a stream of messages, each an object with
// exactly one of these keys; see golang.org/x/vuln's internal/govulncheck
// Message type. Only the fields the decision needs are declared.
const (
	keyConfig   = "config"
	keyProgress = "progress"
	keySBOM     = "SBOM"
	keyOSV      = "osv"
	keyFinding  = "finding"
)

// protocolVersions are the versions of govulncheck's JSON protocol this
// package reads.
var protocolVersions = []string{"v1.0.0"}

type configMessage struct {
	ProtocolVersion string `json:"protocol_version"`
	ScanLevel       string `json:"scan_level"`
}

type osvMessage struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type findingMessage struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Function string `json:"function"`
	} `json:"trace"`
}

// Vuln is one vulnerability the scanned code calls.
type Vuln struct {
	ID      string
	Module  string
	Version string
	Fixed   string // the first fixed version, or "" if there is none
	Summary string
	Ignore  *Ignore // the entry that names it, if any
}

// Report sorts the called vulnerabilities by what happens to them. Fatal and
// Expired fail the check; Ignored is reported and passes; Unused lists ignore
// entries that matched nothing in the scan.
type Report struct {
	Fatal   []Vuln
	Expired []Vuln
	Ignored []Vuln
	Unused  []Ignore
}

// Decide reads the output of govulncheck -format json and sorts what it found
// against the ignore list, on the given day. The ignore list is validated
// first, as Config.Validate does.
//
// In JSON mode govulncheck exits 0 whatever it finds and reports findings at
// module, package and symbol level. Its text mode fails only on a called
// vulnerability: one with a finding whose innermost frame names a function.
// Decide reproduces that. Output that is not a symbol-level govulncheck
// stream in a protocol version this package knows, or that holds a message
// it does not recognise, is an error, never "no findings".
func Decide(stream io.Reader, ignores []Ignore, today time.Time) (Report, error) {
	if err := (Config{Ignore: ignores}).Validate(); err != nil {
		return Report{}, err
	}
	called, err := readCalled(stream)
	if err != nil {
		return Report{}, err
	}
	return sortCalled(called, ignores, today), nil
}

// readCalled returns the vulnerabilities a govulncheck JSON stream reports as
// called, by ID.
func readCalled(stream io.Reader) (map[string]*Vuln, error) {
	summaries := map[string]string{}
	called := map[string]*Vuln{}
	sawConfig := false

	dec := json.NewDecoder(stream)
	for {
		var m map[string]json.RawMessage
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading govulncheck output: %w", err)
		}
		key, body, err := onlyKey(m)
		if err != nil {
			return nil, err
		}
		switch key {
		case keyConfig:
			if err := readConfig(body); err != nil {
				return nil, err
			}
			sawConfig = true
		case keyProgress, keySBOM:
			// Neither affects the decision.
		case keyOSV:
			var o osvMessage
			if err := json.Unmarshal(body, &o); err != nil {
				return nil, fmt.Errorf("reading govulncheck output: %w", err)
			}
			summaries[o.ID] = o.Summary
		case keyFinding:
			var f findingMessage
			if err := json.Unmarshal(body, &f); err != nil {
				return nil, fmt.Errorf("reading govulncheck output: %w", err)
			}
			if f.OSV == "" || len(f.Trace) == 0 {
				return nil, errors.New("reading govulncheck output: a finding has no vulnerability ID or no trace")
			}
			if f.Trace[0].Function == "" || called[f.OSV] != nil {
				continue
			}
			called[f.OSV] = &Vuln{ID: f.OSV, Module: f.Trace[0].Module, Version: f.Trace[0].Version, Fixed: f.FixedVersion}
		}
	}
	if !sawConfig {
		return nil, errors.New("reading govulncheck output: no config message; is this govulncheck -format json output?")
	}
	for id, v := range called {
		v.Summary = summaries[id]
	}
	return called, nil
}

// onlyKey returns the one key of a message and its value. A message with no
// key, more than one, or one this package does not know is an error: the
// format has changed and the stream cannot be trusted.
func onlyKey(m map[string]json.RawMessage) (string, json.RawMessage, error) {
	if len(m) != 1 {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "", nil, fmt.Errorf("reading govulncheck output: a message has %d keys %q, expected exactly one", len(m), keys)
	}
	var key string
	for k := range m {
		key = k
	}
	switch key {
	case keyConfig, keyProgress, keySBOM, keyOSV, keyFinding:
		return key, m[key], nil
	default:
		return "", nil, fmt.Errorf("reading govulncheck output: unknown message %q", key)
	}
}

// readConfig checks the config message: a protocol version this package
// reads and a symbol-level scan.
func readConfig(body json.RawMessage) error {
	var c configMessage
	if err := json.Unmarshal(body, &c); err != nil {
		return fmt.Errorf("reading govulncheck output: %w", err)
	}
	if !slices.Contains(protocolVersions, c.ProtocolVersion) {
		return fmt.Errorf("govulncheck JSON protocol version %q is not supported (supported: %s)",
			c.ProtocolVersion, strings.Join(protocolVersions, ", "))
	}
	if c.ScanLevel != "symbol" {
		return fmt.Errorf("govulncheck scanned at %q level, expected symbol", c.ScanLevel)
	}
	return nil
}

// sortCalled sorts the called vulnerabilities against the ignore list.
func sortCalled(called map[string]*Vuln, ignores []Ignore, today time.Time) Report {
	var report Report

	byID := map[string]*Ignore{}
	for i := range ignores {
		byID[ignores[i].ID] = &ignores[i]
	}

	ids := make([]string, 0, len(called))
	for id := range called {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		v := *called[id]
		v.Ignore = byID[id]
		switch {
		case v.Ignore == nil:
			report.Fatal = append(report.Fatal, v)
		case !v.Ignore.Until.Covers(today):
			report.Expired = append(report.Expired, v)
		default:
			report.Ignored = append(report.Ignored, v)
		}
	}
	for _, e := range ignores {
		if called[e.ID] == nil {
			report.Unused = append(report.Unused, e)
		}
	}
	return report
}

// Lines renders the report, one line per item.
func (r Report) Lines() []string {
	var out []string
	for _, v := range r.Fatal {
		out = append(out, "Vulnerable: "+v.describe())
	}
	for _, v := range r.Expired {
		out = append(out, fmt.Sprintf("Vulnerable, ignore expired on %s: %s", v.Ignore.Until, v.describe()))
	}
	for _, v := range r.Ignored {
		status := "Ignored"
		if v.Ignore.Until.Set() {
			status += " until " + v.Ignore.Until.String()
		}
		out = append(out, fmt.Sprintf("%s (%s): %s", status, v.Ignore.Reason, v.describe()))
	}
	for _, e := range r.Unused {
		out = append(out, fmt.Sprintf("Ignore entry %s is no longer needed and can be removed.", e.ID))
	}
	if len(r.Fatal)+len(r.Expired)+len(r.Ignored) == 0 {
		out = append(out, "No called vulnerabilities.")
	}
	return out
}

// Err returns the check's failure, naming every vulnerability that fails it,
// or nil when every called vulnerability is ignored and in date.
func (r Report) Err() error {
	ids := make([]string, 0, len(r.Fatal)+len(r.Expired))
	for _, v := range r.Fatal {
		ids = append(ids, v.ID)
	}
	for _, v := range r.Expired {
		ids = append(ids, v.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	return fmt.Errorf("govulncheck: vulnerable code is called: %s", strings.Join(ids, ", "))
}

// describe is the vulnerability's ID, module, versions, summary and link.
func (v Vuln) describe() string {
	fixed := "no fixed version"
	if v.Fixed != "" {
		fixed = "fixed in " + v.Fixed
	}
	s := fmt.Sprintf("%s %s %s, %s", v.ID, v.Module, v.Version, fixed)
	if v.Summary != "" {
		s += ". " + v.Summary
	}
	return s + ". https://pkg.go.dev/vuln/" + v.ID
}

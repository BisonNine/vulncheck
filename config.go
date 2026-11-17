/******************************************************************************
 * Copyright (c) 2026 Bison9 Software,                                        *
 * a division of Tenebris Technologies Inc.                                   *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

// Package vulncheck runs govulncheck and fails on any vulnerability the code
// calls, except those a project's configuration explicitly ignores, each
// optionally only until a date.
//
// The configuration is the govulncheck key of a YAML file, by default
// b9.yaml in the project directory. Every other key in that file is ignored.
package vulncheck

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// DefaultFile is the name of the file, in the project directory, that holds
// the configuration.
const DefaultFile = "b9.yaml"

// Config controls the scan. In YAML it is either a plain boolean, which
// enables or disables the scan, or a mapping with enabled and ignore. A called
// vulnerability is fatal unless it is listed in Ignore and the entry has not
// expired.
type Config struct {
	Enabled bool
	Ignore  []Ignore
}

// Ignore excuses one advisory, by its Go vulnerability ID, optionally only
// until a date.
type Ignore struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
	Until  Day    `yaml:"until"`
}

// Day is the calendar day an ignore entry runs to, inclusive. In YAML it is
// YYYYMMDD, as an integer or a string, or YYYY-MM-DD. A malformed value is
// kept as written and reported by Validate.
type Day struct {
	raw     string
	present bool
	day     time.Time // midnight UTC of the day; zero when absent or malformed
}

// LoadFile reads the configuration from the govulncheck key of the YAML file
// at path; see Parse. A missing file is an error that wraps fs.ErrNotExist.
func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // reading the file the caller names is the point
	if err != nil {
		return Config{}, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse reads the configuration from the govulncheck key of a YAML document
// and validates it. Every other top-level key is ignored; inside the
// govulncheck block an unknown key is an error. A document without the key
// gives an enabled scan with no ignore entries.
func Parse(data []byte) (Config, error) {
	var top struct {
		Govulncheck *nodeOf `yaml:"govulncheck"`
	}
	if err := yaml.Unmarshal(data, &top); err != nil {
		return Config{}, err
	}
	if top.Govulncheck == nil {
		// The decoder passes over a null value, so tell an absent key from
		// `govulncheck:` with nothing after it, which is a mistake.
		var keys map[string]any
		if err := yaml.Unmarshal(data, &keys); err != nil {
			return Config{}, err
		}
		if _, ok := keys["govulncheck"]; ok {
			return Config{}, errors.New("govulncheck must be true, false or a mapping with enabled and ignore, got null")
		}
		return Config{Enabled: true}, nil
	}
	var cfg Config
	// Strict decoding: a typo in a key is a silent misconfiguration otherwise.
	if err := yaml.NodeToValue(top.Govulncheck.node, &cfg, yaml.Strict()); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// nodeOf captures a value's syntax tree, so that one key of a document can be
// decoded strictly while the rest of the document is not decoded at all.
type nodeOf struct {
	node ast.Node
}

// UnmarshalYAML records the node.
func (n *nodeOf) UnmarshalYAML(node ast.Node) error {
	n.node = node
	return nil
}

// configBlock is the mapping form. Enabled is a pointer so that a block which
// leaves it out is reported rather than silently disabling the scan.
type configBlock struct {
	Enabled *bool    `yaml:"enabled"`
	Ignore  []Ignore `yaml:"ignore"`
}

// UnmarshalYAML accepts true, false or the mapping form. The mapping is
// decoded by the same decoder, so strict decoding still rejects an unknown
// key inside it.
func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case bool:
		*c = Config{Enabled: v}
		return nil
	case map[string]any:
		var b configBlock
		if err := unmarshal(&b); err != nil {
			return err
		}
		if b.Enabled == nil {
			return errors.New("govulncheck: enabled is required when govulncheck is a mapping")
		}
		*c = Config{Enabled: *b.Enabled, Ignore: b.Ignore}
		return nil
	case string:
		return fmt.Errorf("govulncheck must be true, false or a mapping with enabled and ignore, got the string %q", v)
	default:
		return fmt.Errorf("govulncheck must be true, false or a mapping with enabled and ignore, got %v (%T)", v, v)
	}
}

// UnmarshalYAML decodes an entry, and records an until key that is present
// but null (`until:`, `until: null`, `until: ~`), which the decoder would
// otherwise treat as absent and so as no end date at all.
func (e *Ignore) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Ignore
	var p plain
	if err := unmarshal(&p); err != nil {
		return err
	}
	var keys map[string]any
	if err := unmarshal(&keys); err != nil {
		return err
	}
	if v, ok := keys["until"]; ok && v == nil {
		p.Until = Day{present: true}
	}
	*e = Ignore(p)
	return nil
}

// UnmarshalYAML records the value as written and parses it if it can.
func (d *Day) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	d.present = true
	switch v := raw.(type) {
	case string:
		d.raw = v
	case time.Time:
		// A YAML timestamp such as 2026-12-31 may arrive already parsed.
		d.raw = v.Format(time.DateOnly)
	default:
		d.raw = fmt.Sprint(v)
	}
	d.day = parseDay(d.raw)
	return nil
}

// parseDay parses YYYYMMDD or YYYY-MM-DD, returning the zero time for
// anything else.
func parseDay(s string) time.Time {
	for _, layout := range []string{"20060102", time.DateOnly} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Set reports whether the entry has an end date.
func (d Day) Set() bool { return d.present }

// String renders the day as YYYY-MM-DD.
func (d Day) String() string { return d.day.Format(time.DateOnly) }

// Covers reports whether an entry with this end date still applies on today's
// date in today's location. An entry without an end date always applies.
func (d Day) Covers(today time.Time) bool {
	if !d.present {
		return true
	}
	y, m, dd := today.Date()
	return !time.Date(y, m, dd, 0, 0, 0, 0, time.UTC).After(d.day)
}

var vulnID = regexp.MustCompile(`^GO-\d{4}-\d+$`)

// Validate checks the ignore list, whether or not the scan is enabled, so a
// list kept beside `enabled: false` is still well formed when the scan is
// turned back on. The error lists every problem; errors.Join-style unwrapping
// yields one error per problem.
func (c Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	seen := map[string]bool{}
	for i, e := range c.Ignore {
		where := fmt.Sprintf("govulncheck.ignore[%d]", i)
		if e.ID != "" {
			where += " (" + e.ID + ")"
		}
		switch {
		case strings.TrimSpace(e.ID) == "":
			add("missing required field: %s.id", where)
		case !vulnID.MatchString(e.ID):
			add("%s: id must be a Go vulnerability ID such as GO-2024-1234", where)
		case seen[e.ID]:
			add("%s: duplicate id", where)
		}
		seen[e.ID] = true
		if strings.TrimSpace(e.Reason) == "" {
			add("missing required field: %s.reason", where)
		}
		switch {
		case e.Until.Set() && strings.TrimSpace(e.Until.raw) == "":
			add("%s: until is empty; give a date or remove the key", where)
		case e.Until.Set() && e.Until.day.IsZero():
			add("%s: until must be a date written YYYYMMDD or YYYY-MM-DD, got %q", where, e.Until.raw)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return invalidConfigError(errs)
}

// invalidConfigError is every problem Validate found.
type invalidConfigError []error

func (e invalidConfigError) Error() string {
	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = err.Error()
	}
	return "invalid configuration:\n  - " + strings.Join(msgs, "\n  - ")
}

func (e invalidConfigError) Unwrap() []error { return e }

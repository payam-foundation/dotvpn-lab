// Package report holds the matrix result model, its markdown rendering and
// the baseline diff used by CI.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Verdicts for one profile x placement x carrier cell.
const (
	Works     = "works"      // fetch succeeded promptly
	Degraded  = "degraded"   // fetch succeeded but slowly
	FailsFast = "fails-fast" // every attempt failed quickly (reset, refused)
	Hangs     = "hangs"      // attempts ran into their timeout (silent drop)
)

// Disclaimer is printed at the top of every rendered report.
const Disclaimer = "Lab results are mechanism checks against dated, sourced models of reported censor behaviour. " +
	"A green cell never means \"works in Iran\" or \"works in Russia\". Validate with in-country testers or OONI-style probes."

// Cell is one measurement.
type Cell struct {
	Profile   string   `json:"profile"`
	Placement string   `json:"placement"`
	Carrier   string   `json:"carrier"`
	Verdict   string   `json:"verdict"`
	TTFBms    int64    `json:"ttfb_ms,omitempty"`
	Landed    string   `json:"landed,omitempty"` // ladder: carrier it ended on
	Rules     []string `json:"rules,omitempty"`  // rules that fired
	Detail    string   `json:"detail,omitempty"`
}

// Key identifies a cell in the baseline.
func (c Cell) Key() string { return c.Profile + "/" + c.Placement + "/" + c.Carrier }

// Matrix is the full result of one run.
type Matrix struct {
	Generated  string            `json:"generated"`
	Disclaimer string            `json:"disclaimer"`
	Confidence map[string]string `json:"rule_confidence,omitempty"` // "profile/rule" -> tag
	Cells      []Cell            `json:"cells"`
}

// Expect is a baseline entry: the verdict we expect and, for anything other
// than "works", why.
type Expect struct {
	Verdict string `json:"verdict"`
	Landed  string `json:"landed,omitempty"` // ladder cells: carrier it should land on
	Reason  string `json:"reason,omitempty"`
}

// Baseline maps cell keys to expectations.
type Baseline struct {
	Note     string            `json:"note"`
	Expected map[string]Expect `json:"expected"`
}

// ReadBaseline loads a baseline file.
func ReadBaseline(path string) (*Baseline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bl Baseline
	return &bl, json.Unmarshal(b, &bl)
}

// ReadMatrix loads a matrix file.
func ReadMatrix(path string) (*Matrix, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Matrix
	return &m, json.Unmarshal(b, &m)
}

// Diff lists the cells whose verdict differs from the baseline, cells with no
// baseline entry, and baseline entries with no cell. Cells whose carrier was
// not run (verdict "skipped") are ignored.
func Diff(m *Matrix, b *Baseline) (changed, added, missing []string) {
	seen := map[string]bool{}
	for _, c := range m.Cells {
		seen[c.Key()] = true
		if c.Verdict == "skipped" {
			continue
		}
		e, ok := b.Expected[c.Key()]
		switch {
		case !ok:
			added = append(added, fmt.Sprintf("%s: %s (no baseline)", c.Key(), c.Verdict))
		case e.Verdict != c.Verdict:
			changed = append(changed, fmt.Sprintf("%s: %s -> %s", c.Key(), e.Verdict, c.Verdict))
		case e.Landed != "" && e.Landed != c.Landed:
			changed = append(changed, fmt.Sprintf("%s: landed on %s -> %s", c.Key(), e.Landed, c.Landed))
		}
	}
	for k := range b.Expected {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(changed)
	sort.Strings(added)
	sort.Strings(missing)
	return
}

// BaselineFrom builds a baseline from a matrix, keeping reasons from old.
func BaselineFrom(m *Matrix, old *Baseline) *Baseline {
	nb := &Baseline{Note: "Expected verdicts. A change in either direction fails CI. Edit reasons by hand; regenerate with LAB_UPDATE=1.", Expected: map[string]Expect{}}
	for _, c := range m.Cells {
		if c.Verdict == "skipped" {
			continue
		}
		e := Expect{Verdict: c.Verdict}
		if old != nil {
			if o, ok := old.Expected[c.Key()]; ok && o.Verdict == c.Verdict {
				e.Reason = o.Reason
			}
		}
		if c.Carrier == "ladder" {
			e.Landed = c.Landed
		}
		nb.Expected[c.Key()] = e
	}
	return nb
}

// Markdown renders the matrix: one table per profile, carriers as columns.
func Markdown(m *Matrix, b *Baseline) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Censorship lab matrix\n\n> %s\n\nGenerated %s.\n\n", m.Disclaimer, m.Generated)
	var profiles, carriers []string
	idx := map[string]Cell{}
	pseen, cseen := map[string]bool{}, map[string]bool{}
	var rows []string
	rseen := map[string]bool{}
	for _, c := range m.Cells {
		if !pseen[c.Profile] {
			pseen[c.Profile] = true
			profiles = append(profiles, c.Profile)
		}
		if !cseen[c.Carrier] {
			cseen[c.Carrier] = true
			carriers = append(carriers, c.Carrier)
		}
		if k := c.Profile + "/" + c.Placement; !rseen[k] {
			rseen[k] = true
			rows = append(rows, k)
		}
		idx[c.Key()] = c
	}
	for _, p := range profiles {
		fmt.Fprintf(&sb, "## %s\n\n| placement | %s |\n| --- |%s\n", p, strings.Join(carriers, " | "), strings.Repeat(" --- |", len(carriers)))
		for _, r := range rows {
			pp, pl, _ := strings.Cut(r, "/")
			if pp != p {
				continue
			}
			fmt.Fprintf(&sb, "| %s |", pl)
			for _, car := range carriers {
				c, ok := idx[p+"/"+pl+"/"+car]
				cell := "n/a"
				if ok {
					cell = c.Verdict
					if c.Landed != "" {
						cell += " (" + c.Landed + ")"
					}
					if c.TTFBms > 0 {
						cell += fmt.Sprintf(" %dms", c.TTFBms)
					}
					if b != nil {
						if e, have := b.Expected[c.Key()]; have && e.Verdict != c.Verdict {
							cell += " **CHANGED from " + e.Verdict + "**"
						}
					}
				}
				fmt.Fprintf(&sb, " %s |", cell)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	var conf []string
	for k, v := range m.Confidence {
		conf = append(conf, fmt.Sprintf("| %s | %s |", k, v))
	}
	if len(conf) > 0 {
		sort.Strings(conf)
		sb.WriteString("## Rule confidence\n\nRows tagged `assumed` are our guesses, not measurements.\n\n| rule | confidence |\n| --- | --- |\n" + strings.Join(conf, "\n") + "\n\n")
	}
	if b != nil {
		var why []string
		for k, e := range b.Expected {
			if e.Reason != "" {
				why = append(why, fmt.Sprintf("- `%s` (%s): %s", k, e.Verdict, e.Reason))
			}
		}
		if len(why) > 0 {
			sort.Strings(why)
			sb.WriteString("## Expected non-working cells\n\n" + strings.Join(why, "\n") + "\n")
		}
	}
	return sb.String()
}

package report

import (
	"strings"
	"testing"
)

func TestDiffAndMarkdown(t *testing.T) {
	m := &Matrix{Disclaimer: Disclaimer, Cells: []Cell{
		{Profile: "p", Placement: "a", Carrier: "h2", Verdict: Works},
		{Profile: "p", Placement: "a", Carrier: "h3", Verdict: Works},
		{Profile: "p", Placement: "a", Carrier: "dns", Verdict: "skipped"},
		{Profile: "p", Placement: "a", Carrier: "new", Verdict: Hangs},
	}}
	b := &Baseline{Expected: map[string]Expect{
		"p/a/h2":   {Verdict: Works},
		"p/a/h3":   {Verdict: Hangs, Reason: "quic blocked"},
		"p/a/gone": {Verdict: Works},
	}}
	ch, add, miss := Diff(m, b)
	if len(ch) != 1 || !strings.Contains(ch[0], "p/a/h3: hangs -> works") || len(add) != 1 || len(miss) != 1 {
		t.Fatalf("%v %v %v", ch, add, miss)
	}
	if md := Markdown(m, b); !strings.Contains(md, "CHANGED from hangs") || !strings.Contains(md, "mechanism checks") {
		t.Fatal(md)
	}
}

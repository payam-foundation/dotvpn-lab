// Package censor is the lab's policy-driven censor: a Profile (data) is
// evaluated by an Engine (stateful, portable) that either a userspace proxy or
// a Linux packet backend enforces. Every rule names the row of
// docs/lab/documented-behaviours.md it implements and how much we trust
// that row. Results are mechanism checks, never "this works in <country>".
package censor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

// Confidence mirrors the tags in documented-behaviours.md.
const (
	Observed = "observed"
	Reported = "reported"
	Derived  = "derived"
	Assumed  = "assumed"
)

// Action types.
const (
	Pass      = "pass"
	Drop      = "drop"       // silently discard: the peer hangs
	RST       = "rst"        // reset: the peer fails fast
	Throttle  = "throttle"   // limit bytes/s (userspace) and packets/s (netns)
	InjectDNS = "inject-dns" // answer a DNS query ourselves
	Delay     = "delay"      // add latency to every chunk
)

// Profile is a dated model of one reported behaviour set.
type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Reviewed    string `json:"reviewed"` // date the sources were last re-read
	// DPI is "naive" (first packet only, no reassembly validation) or
	// "strict" (reassembles and validates). Default strict.
	DPI string `json:"dpi,omitempty"`
	// Extends names another profile in the same directory. Its rules and
	// placements follow this profile's own (own rules win), and its DPI mode
	// applies unless this one sets one.
	Extends    string      `json:"extends,omitempty"`
	Placements []Placement `json:"placements,omitempty"`
	Rules      []Rule      `json:"rules"`
}

// Placement is a lab address for the node under test; some rules only bite on
// some placements (a banned hosting prefix versus a clean one).
type Placement struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// Rule is evaluated in order; the first rule that matches decides. A rule
// whose payload predicates cannot be evaluated yet (not enough bytes seen)
// stops evaluation and the flow passes for now, so put L3/L4 and volume rules
// first, payload rules next, catch-alls last.
type Rule struct {
	ID         string  `json:"id"`         // row in documented-behaviours.md (or LAB-*)
	Source     string  `json:"source"`     // URL or citation
	Confidence string  `json:"confidence"` // observed|reported|derived|assumed
	Note       string  `json:"note,omitempty"`
	Prob       float64 `json:"prob,omitempty"` // 0 means always; else per-flow probability
	Match      Match   `json:"match"`
	Action     Action  `json:"action"`
}

// Match is a conjunction: every field that is set must hold.
type Match struct {
	Proto       string   `json:"proto,omitempty"` // tcp|udp|icmp
	Dir         string   `json:"dir,omitempty"`   // c2s|s2c (relative to the flow initiator), egress|ingress (relative to the border)
	Ports       []int    `json:"ports,omitempty"` // destination ports
	Prefixes    []string `json:"prefixes,omitempty"`
	NotPrefixes []string `json:"not_prefixes,omitempty"`

	Class    []string `json:"class,omitempty"`     // tls|http|quic|dns|unknown
	NotClass []string `json:"not_class,omitempty"` // first payload is none of these
	SNI      []string `json:"sni,omitempty"`       // TLS or QUIC SNI, suffix match
	SNINotIn []string `json:"sni_not_in,omitempty"`
	Host     []string `json:"host,omitempty"` // HTTP Host
	DNS      []string `json:"dns,omitempty"`  // DNS qname
	// Entropy: first client payload passes the GFW fully-encrypted heuristic.
	Entropy    bool `json:"entropy,omitempty"`
	Fragmented bool `json:"fragmented_hello,omitempty"`

	AfterBytes int64 `json:"after_bytes,omitempty"` // flow has carried at least this many bytes
	RateBps    int64 `json:"rate_bps,omitempty"`    // bytes/s sustained ...
	RatePPS    int64 `json:"rate_pps,omitempty"`    // ... or packets/s (either trips it) ...
	ForSec     int   `json:"for_sec,omitempty"`     // ... for this many seconds

	// Packet-level (netns backend): ICMP message types (8 = echo request) and
	// a minimum payload size of the packet being judged.
	ICMPType []int `json:"icmp_type,omitempty"`
	MinLen   int   `json:"min_len,omitempty"`

	prefixes, notPrefixes []netip.Prefix
}

// Action is what a matching rule does.
type Action struct {
	Type    string `json:"type"`
	TTLSec  int    `json:"ttl_s,omitempty"`    // residual blocking: later flows with the same Key get this action
	Key     string `json:"key,omitempty"`      // "4tuple" or "src-dst" (default)
	RateBps int64  `json:"rate_bps,omitempty"` // throttle: bytes/s
	RatePPS int64  `json:"rate_pps,omitempty"` // throttle: packets/s (netns backend)
	DelayMS int    `json:"delay_ms,omitempty"`
	Rcode   int    `json:"rcode,omitempty"` // inject-dns: 3 = NXDOMAIN (default)
}

func (a Action) sticky() bool { return a.Type != Pass && a.Type != InjectDNS }

// Parse reads and validates a profile.
func Parse(b []byte) (*Profile, error) {
	var p Profile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, err
	}
	return &p, p.Validate()
}

// Validate checks the profile and prepares it for evaluation. It insists that
// every rule carries a source and a confidence.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile has no name")
	}
	switch p.DPI {
	case "", "naive", "strict":
	default:
		return fmt.Errorf("%s: dpi %q", p.Name, p.DPI)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" || r.Source == "" {
			return fmt.Errorf("%s: rule %d lacks id or source", p.Name, i)
		}
		switch r.Confidence {
		case Observed, Reported, Derived, Assumed:
		default:
			return fmt.Errorf("%s/%s: confidence %q", p.Name, r.ID, r.Confidence)
		}
		switch r.Action.Type {
		case Pass, Drop, RST, Throttle, InjectDNS, Delay:
		default:
			return fmt.Errorf("%s/%s: action %q", p.Name, r.ID, r.Action.Type)
		}
		if r.Action.Type == Throttle && r.Action.RateBps <= 0 && r.Action.RatePPS <= 0 {
			return fmt.Errorf("%s/%s: throttle needs rate_bps or rate_pps", p.Name, r.ID)
		}
		switch r.Match.Dir {
		case "", "c2s", "s2c", "egress", "ingress":
		default:
			return fmt.Errorf("%s/%s: dir %q", p.Name, r.ID, r.Match.Dir)
		}
		var err error
		if r.Match.prefixes, err = parsePrefixes(r.Match.Prefixes); err != nil {
			return fmt.Errorf("%s/%s: %w", p.Name, r.ID, err)
		}
		if r.Match.notPrefixes, err = parsePrefixes(r.Match.NotPrefixes); err != nil {
			return fmt.Errorf("%s/%s: %w", p.Name, r.ID, err)
		}
		if (r.Match.RateBps > 0 || r.Match.RatePPS > 0) && r.Match.ForSec <= 0 {
			return fmt.Errorf("%s/%s: rate_bps and rate_pps need for_sec", p.Name, r.ID)
		}
	}
	for _, pl := range p.Placements {
		if _, err := netip.ParseAddr(pl.IP); err != nil {
			return fmt.Errorf("%s: placement %s: %w", p.Name, pl.Name, err)
		}
	}
	return nil
}

// PlacementList returns the placements, defaulting to one clean address.
func (p *Profile) PlacementList() []Placement {
	if len(p.Placements) == 0 {
		return []Placement{{Name: "clean", IP: "192.0.2.10"}}
	}
	return p.Placements
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range in {
		pf, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, pf)
	}
	return out, nil
}

// Load reads profiles/<name>.json from dir, resolving Extends.
func Load(dir, name string) (*Profile, error) {
	return load(dir, name, 0)
}

func load(dir, name string, depth int) (*Profile, error) {
	if depth > 4 {
		return nil, fmt.Errorf("%s: extends chain too deep", name)
	}
	b, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return nil, err
	}
	var p Profile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if p.Extends != "" {
		base, err := load(dir, p.Extends, depth+1)
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, base.Rules...)
		if len(p.Placements) == 0 {
			p.Placements = base.Placements
		}
		if p.DPI == "" {
			p.DPI = base.DPI
		}
	}
	return &p, p.Validate()
}

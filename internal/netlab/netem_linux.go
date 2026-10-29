//go:build linux

package netlab

import "fmt"

// Netem is a link impairment: tc netem options applied to both border
// interfaces, so each direction sees it once.
type Netem struct {
	Name string
	Args []string // tc netem arguments
}

// Presets for the "every profile can be combined with a netem preset" rule.
var (
	NetemMobile    = Netem{"mobile", []string{"delay", "60ms", "20ms", "loss", "1%"}}
	NetemCongested = Netem{"congested", []string{"delay", "150ms", "30ms", "rate", "5mbit"}}
	NetemLossy     = Netem{"lossy", []string{"loss", "5%", "reorder", "5%", "delay", "10ms"}}
)

// SetNetem applies n to the border's two interfaces; a zero Netem clears it.
func (l *Lab) SetNetem(n Netem) error {
	for _, dev := range []string{l.bdI, l.bdO} {
		if len(n.Args) == 0 {
			_, _ = l.Run(l.Border, "tc", "qdisc", "del", "dev", dev, "root")
			continue
		}
		args := append([]string{"qdisc", "replace", "dev", dev, "root", "netem"}, n.Args...)
		if out, err := l.Run(l.Border, "tc", args...); err != nil {
			return fmt.Errorf("tc %v: %v: %s", args, err, out)
		}
	}
	return nil
}

// SetLink brings the border's link toward the outside up or down (a flap).
func (l *Lab) SetLink(up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	if out, err := l.Run(l.Border, "ip", "link", "set", l.bdO, state); err != nil {
		return fmt.Errorf("ip link set %s %s: %v: %s", l.bdO, state, err, out)
	}
	if up { // the kernel drops routes over a downed link; put the abroad ones back
		for _, ip := range l.abroad {
			if out, err := l.Run(l.Border, "ip", "route", "replace", ip+"/32", "via", OutAddr); err != nil {
				return fmt.Errorf("route %s: %v: %s", ip, err, out)
			}
		}
	}
	return nil
}

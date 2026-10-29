// Package measure turns captured bytes into what an observer would compute:
// JA3/JA4 of a ClientHello, a ServerHello summary, and per-connection size
// and timing records.
package measure

import (
	"crypto/md5" // #nosec G501 -- JA3 is defined with MD5
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
)

// ReadRecord reads one TLS record (header included).
func ReadRecord(c net.Conn) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if n > 1<<15 {
		return nil, errors.New("record too large")
	}
	b := make([]byte, 5+n)
	copy(b, h[:])
	_, err := io.ReadFull(c, b[5:])
	return b, err
}

func isGrease(v uint16) bool { return v&0x0f0f == 0x0a0a }

type Hello struct {
	version              uint16
	ciphers, exts        []uint16
	curves, sigAlgs      []uint16
	points               []uint8
	alpn                 []string
	sni, supportedVers   bool
	extData              map[uint16][]byte
	maxVersion           uint16
	sessionIDLen, random int
}

func ParseHello(rec []byte) (*Hello, error) {
	if len(rec) < 43 || rec[0] != 0x16 || rec[5] != 0x01 {
		return nil, errors.New("not a ClientHello")
	}
	b := rec[9:] // after record and handshake headers
	h := &Hello{version: binary.BigEndian.Uint16(b), random: 32}
	b = b[34:]
	sl := int(b[0])
	h.sessionIDLen = sl
	b = b[1+sl:]
	cl := int(binary.BigEndian.Uint16(b))
	for i := 0; i < cl; i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(b[2+i:]))
	}
	b = b[2+cl:]
	b = b[1+int(b[0]):] // compression
	el := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if el > len(b) {
		return nil, errors.New("truncated extensions")
	}
	b = b[:el]
	for len(b) >= 4 {
		t, l := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		d := b[4 : 4+l]
		b = b[4+l:]
		h.exts = append(h.exts, t)
		if h.extData == nil {
			h.extData = map[uint16][]byte{}
		}
		h.extData[t] = d
		switch t {
		case 0:
			h.sni = true
		case 10:
			for i := 2; i+1 < len(d); i += 2 {
				h.curves = append(h.curves, binary.BigEndian.Uint16(d[i:]))
			}
		case 11:
			h.points = append(h.points, d[1:]...)
		case 13:
			for i := 2; i+1 < len(d); i += 2 {
				h.sigAlgs = append(h.sigAlgs, binary.BigEndian.Uint16(d[i:]))
			}
		case 16:
			for i := 2; i < len(d); {
				n := int(d[i])
				h.alpn = append(h.alpn, string(d[i+1:i+1+n]))
				i += 1 + n
			}
		case 43:
			h.supportedVers = true
			for i := 1; i+1 < len(d); i += 2 {
				if v := binary.BigEndian.Uint16(d[i:]); !isGrease(v) && v > h.maxVersion {
					h.maxVersion = v
				}
			}
		}
	}
	return h, nil
}

func filter(in []uint16) []uint16 {
	var out []uint16
	for _, v := range in {
		if !isGrease(v) {
			out = append(out, v)
		}
	}
	return out
}

func join[T any](in []T, f func(T) string) string {
	s := make([]string, len(in))
	for i, v := range in {
		s[i] = f(v)
	}
	return strings.Join(s, "-")
}

func dec(v uint16) string  { return strconv.Itoa(int(v)) }
func hex4(v uint16) string { return fmt.Sprintf("%04x", v) }

func (h *Hello) JA3() string {
	pts := join(h.points, func(v uint8) string { return strconv.Itoa(int(v)) })
	s := fmt.Sprintf("%d,%s,%s,%s,%s", h.version, join(filter(h.ciphers), dec), join(filter(h.exts), dec), join(filter(h.curves), dec), pts)
	sum := md5.Sum([]byte(s)) // #nosec G401
	return hex.EncodeToString(sum[:])
}

func (h *Hello) JA4() string {
	v := "00"
	switch h.maxVersion {
	case 0x0304:
		v = "13"
	case 0x0303:
		v = "12"
	}
	if h.maxVersion == 0 && h.version == 0x0303 {
		v = "12"
	}
	sni := "i"
	if h.sni {
		sni = "d"
	}
	al := "00"
	if len(h.alpn) > 0 && len(h.alpn[0]) > 0 {
		a := h.alpn[0]
		al = string(a[0]) + string(a[len(a)-1])
	}
	ciphers, exts := filter(h.ciphers), filter(h.exts)
	a := fmt.Sprintf("t%s%s%02d%02d%s", v, sni, len(ciphers), len(exts), al)
	cs := slices.Clone(ciphers)
	slices.Sort(cs)
	b := sha256.Sum256([]byte(join2(cs)))
	var es []uint16
	for _, e := range exts {
		if e != 0 && e != 16 {
			es = append(es, e)
		}
	}
	slices.Sort(es)
	c := join2(es)
	if sa := filter(h.sigAlgs); len(sa) > 0 {
		c += "_" + join2(sa)
	}
	cc := sha256.Sum256([]byte(c))
	return a + "_" + hex.EncodeToString(b[:6]) + "_" + hex.EncodeToString(cc[:6])
}

func join2(in []uint16) string {
	s := make([]string, len(in))
	for i, v := range in {
		s[i] = hex4(v)
	}
	return strings.Join(s, ",")
}

func (h *Hello) Describe() string {
	es := slices.Clone(filter(h.exts))
	slices.Sort(es)
	var extra string
	for _, id := range []uint16{17613, 51764, 65037} {
		if d, ok := h.extData[id]; ok {
			extra += fmt.Sprintf(" ext%d=%dB:%s", id, len(d), hex.EncodeToString(d[:min(len(d), 400)]))
		}
	}
	return extra + fmt.Sprintf(" JA4=%s JA3=%s ciphers=%d exts=%d sessionID=%dB alpn=%v sortedExts=%v sigAlgs=%s groups=%s", h.JA4(), h.JA3(), len(filter(h.ciphers)), len(es), h.sessionIDLen, h.alpn, es, join2(h.sigAlgs), join2(filter(h.curves)))
}

func DescribeServer(rec []byte) string {
	if rec[0] != 0x16 || len(rec) < 11 || rec[5] != 0x02 {
		return fmt.Sprintf("first record type=%#x handshake=%#x len=%d", rec[0], rec[5], len(rec))
	}
	b := rec[9:]
	ver := binary.BigEndian.Uint16(b)
	sl := int(b[34])
	cipher := binary.BigEndian.Uint16(b[35+sl:])
	var exts []uint16
	b = b[35+sl+3:]
	if len(b) >= 2 {
		el := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if el <= len(b) {
			b = b[:el]
		}
		for len(b) >= 4 {
			l := int(binary.BigEndian.Uint16(b[2:]))
			exts = append(exts, binary.BigEndian.Uint16(b))
			if 4+l > len(b) {
				break
			}
			b = b[4+l:]
		}
	}
	s := fmt.Sprintf("ServerHello v=%#x cipher=%#04x exts=%v recordLen=%d", ver, cipher, exts, len(rec)-5)
	sum := md5.Sum([]byte(fmt.Sprintf("%d,%d,%s", ver, cipher, join2(exts)))) // #nosec G401
	return s + " JA3S-ish=" + hex.EncodeToString(sum[:])
}

// Extensions returns the non-GREASE extension ids in wire order.
func (h *Hello) Extensions() []uint16 { return filter(h.exts) }

// SortedExtensions returns the non-GREASE extension ids in ascending order
// (Chrome shuffles the wire order per connection).
func (h *Hello) SortedExtensions() []uint16 {
	es := slices.Clone(filter(h.exts))
	slices.Sort(es)
	return es
}

// Ciphers returns the non-GREASE cipher suites.
func (h *Hello) Ciphers() []uint16 { return filter(h.ciphers) }

// ALPN returns the offered protocols.
func (h *Hello) ALPN() []string { return h.alpn }

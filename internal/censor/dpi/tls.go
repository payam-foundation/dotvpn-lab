// Package dpi holds the packet parsers a lab censor uses. Parsers are
// tolerant: they return what they can see, because a real DPI box works with
// partial data too.
package dpi

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrShort means a strict parser needs more bytes before it can decide.
	ErrShort = errors.New("dpi: need more bytes")
	// ErrNotTLS means the bytes are not the start of a TLS ClientHello.
	ErrNotTLS = errors.New("dpi: not a TLS ClientHello")
)

// Hello is what a censor learns from a ClientHello.
type Hello struct {
	SNI        string
	Fragmented bool // the handshake message spans more than one TLS record
}

// ParseClientHello reads a ClientHello from the start of a TCP stream.
//
// Naive mode looks at the first record only and takes the SNI if it lies in
// the bytes present, so a hello split across records can hide its SNI.
// Strict mode reassembles records (ErrShort until the message is complete).
func ParseClientHello(b []byte, strict bool) (Hello, error) {
	var hs []byte
	records := 0
	for rest := b; len(rest) > 0; {
		if len(rest) < 5 || rest[0] != 0x16 || rest[1] != 3 {
			if records == 0 && (len(rest) >= 5 || rest[0] != 0x16) {
				return Hello{}, ErrNotTLS
			}
			if records == 0 {
				return Hello{}, ErrShort
			}
			break
		}
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if len(rest) < 5+n { // partial record
			if strict {
				return Hello{}, ErrShort
			}
			hs = append(hs, rest[5:]...)
			records++
			break
		}
		hs = append(hs, rest[5:5+n]...)
		records++
		rest = rest[5+n:]
		if !strict {
			break
		}
		if sni, complete := sniFromHandshake(hs); complete {
			return Hello{SNI: sni, Fragmented: records > 1}, nil
		}
	}
	if records == 0 {
		return Hello{}, ErrShort
	}
	if len(hs) < 4 || hs[0] != 1 {
		if len(hs) > 0 && hs[0] != 1 {
			return Hello{}, ErrNotTLS
		}
		return Hello{}, ErrShort
	}
	sni, complete := sniFromHandshake(hs)
	if strict && !complete {
		return Hello{}, ErrShort
	}
	return Hello{SNI: sni, Fragmented: strict && (!complete || records > 1)}, nil
}

// sniFromHandshake walks a ClientHello handshake message. complete reports
// whether the whole message is present; sni is set if the extension was seen.
func sniFromHandshake(m []byte) (sni string, complete bool) {
	if len(m) < 4 || m[0] != 1 {
		return "", false
	}
	want := int(m[1])<<16 | int(m[2])<<8 | int(m[3])
	complete = len(m) >= 4+want
	p := m[4:]
	skip := func(n int) bool {
		if len(p) < n {
			return false
		}
		p = p[n:]
		return true
	}
	if !skip(2+32) || len(p) < 1 {
		return "", complete
	}
	if !skip(1+int(p[0])) || len(p) < 2 { // session id
		return "", complete
	}
	if !skip(2+int(binary.BigEndian.Uint16(p))) || len(p) < 1 { // cipher suites
		return "", complete
	}
	if !skip(1+int(p[0])) || len(p) < 2 { // compression
		return "", complete
	}
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if extLen < len(p) {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if typ == 0 { // server_name
			d := p
			if n < len(d) {
				d = d[:n]
			}
			// list len(2) type(1) name len(2) name
			if len(d) >= 5 && d[2] == 0 {
				l := int(binary.BigEndian.Uint16(d[3:]))
				if len(d) >= 5+l {
					return string(d[5 : 5+l]), complete
				}
			}
			return "", complete
		}
		if n > len(p) {
			return "", complete
		}
		p = p[n:]
	}
	return "", complete
}

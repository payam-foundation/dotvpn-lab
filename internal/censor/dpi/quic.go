package dpi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// ErrNotQUICv1 means the datagram is not a QUIC v1 Initial packet.
var ErrNotQUICv1 = errors.New("dpi: not a QUIC v1 Initial")

var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

// IsQUICv1Initial reports whether d looks like a QUIC v1 Initial packet
// (long header, Initial type, version 1). It does not decrypt.
func IsQUICv1Initial(d []byte) bool {
	return len(d) >= 7 && d[0]&0xf0 == 0xc0 && binary.BigEndian.Uint32(d[1:5]) == 1
}

func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	l := "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(l))}
	info = append(info, l...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

func varint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// Frag is a slice of the ClientHello carried in one CRYPTO frame.
type Frag struct {
	Off  uint64
	Data []byte
}

// QUICInitialSNI is QUICInitialFrags plus SNI extraction from this packet
// alone, like a single-packet DPI. A hello that does not fit one packet, or
// whose frames arrive out of order (quic-go does this), yields "".
func QUICInitialSNI(d []byte) (string, error) {
	fr, err := QUICInitialFrags(d)
	if err != nil {
		return "", err
	}
	return SNIFromFrags(fr), nil
}

// QUICInitialFrags decrypts a client Initial packet with the keys everyone
// can derive from the destination connection ID (RFC 9001 5.2) and returns
// its CRYPTO frames.
func QUICInitialFrags(d []byte) ([]Frag, error) {
	if !IsQUICv1Initial(d) {
		return nil, ErrNotQUICv1
	}
	p := d[5:]
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return nil, ErrNotQUICv1
	}
	dcid := p[1 : 1+int(p[0])]
	p = p[1+int(p[0]):]
	if len(p) < 1 || len(p) < 1+int(p[0]) {
		return nil, ErrNotQUICv1
	}
	p = p[1+int(p[0]):] // scid
	tl, n := varint(p)
	if n == 0 || uint64(len(p)-n) < tl {
		return nil, ErrNotQUICv1
	}
	p = p[n+int(tl):] // token
	plen, n := varint(p)
	if n == 0 || uint64(len(p)-n) < plen {
		return nil, ErrNotQUICv1
	}
	pnOff := len(d) - len(p) + n
	end := pnOff + int(plen)
	if end-pnOff < 20 {
		return nil, ErrNotQUICv1
	}

	initial, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return nil, err
	}
	cs, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, _ := expandLabel(cs, "quic key", 16)
	iv, _ := expandLabel(cs, "quic iv", 12)
	hp, _ := expandLabel(cs, "quic hp", 16)

	blk, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	blk.Encrypt(mask[:], d[pnOff+4:pnOff+20])
	hdr := append([]byte(nil), d[:pnOff+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	hdr = hdr[:pnOff+pnLen]
	var pn uint64
	for i := range pnLen {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	nonce := append([]byte(nil), iv...)
	for i := range 8 {
		nonce[11-i] ^= byte(pn >> (8 * i))
	}
	kb, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(kb)
	plain, err := aead.Open(nil, nonce, d[pnOff+pnLen:end], hdr)
	if err != nil {
		return nil, err
	}
	return cryptoFrags(plain), nil
}

func cryptoFrags(f []byte) (out []Frag) {
	for len(f) > 0 {
		switch t := f[0]; {
		case t == 0 || t == 1: // PADDING, PING
			f = f[1:]
		case t == 6:
			off, n1 := varint(f[1:])
			l, n2 := varint(f[1+n1:])
			if n1 == 0 || n2 == 0 || uint64(len(f)-1-n1-n2) < l {
				return out
			}
			out = append(out, Frag{off, f[1+n1+n2 : 1+n1+n2+int(l)]})
			f = f[1+n1+n2+int(l):]
		default:
			return out // ACK and others are not sent in a first Initial
		}
	}
	return out
}

// SNIFromFrags stitches the contiguous prefix of the hello from fragments
// (any order, any number of packets) and reads the SNI if it is covered.
func SNIFromFrags(fr []Frag) string {
	var hello []byte
	for progress := true; progress; {
		progress = false
		for _, f := range fr {
			if f.Off <= uint64(len(hello)) && f.Off+uint64(len(f.Data)) > uint64(len(hello)) {
				hello = append(hello, f.Data[uint64(len(hello))-f.Off:]...)
				progress = true
			}
		}
	}
	sni, _ := sniFromHandshake(hello)
	return sni
}

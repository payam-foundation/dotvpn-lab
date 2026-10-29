package dpi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
)

// Class names for first-packet protocol classification.
const (
	ClassTLS     = "tls"
	ClassHTTP    = "http"
	ClassQUIC    = "quic"
	ClassDNS     = "dns"
	ClassUnknown = "unknown"
)

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "}

// Classify names the protocol of the first payload of a flow.
func Classify(first []byte, udp bool, dstPort int) string {
	if udp {
		switch {
		case dstPort == 53 && len(first) >= 12:
			return ClassDNS
		case len(first) > 0 && first[0]&0x80 != 0 && len(first) >= 5: // QUIC long header
			return ClassQUIC
		}
		return ClassUnknown
	}
	if len(first) >= 3 && first[0] == 0x16 && first[1] == 3 {
		return ClassTLS
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(first, []byte(m)) {
			return ClassHTTP
		}
	}
	return ClassUnknown
}

// HTTPHost returns the Host header of an HTTP/1.x request, if present.
func HTTPHost(b []byte) (string, bool) {
	for _, l := range strings.Split(string(b), "\r\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "host") {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

func printable(b byte) bool { return b >= 0x20 && b <= 0x7e }

// FullyEncrypted implements the GFW heuristic of Wu et al. (USENIX Security
// 2023, Algorithm 1; row CN-ENT-1): a first client payload is flagged as
// fully encrypted unless one of five exemptions holds.
func FullyEncrypted(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	ones := 0
	for _, b := range p {
		ones += bits.OnesCount8(b)
	}
	if avg := float64(ones) / float64(len(p)); avg <= 3.4 || avg >= 4.6 { // Ex1
		return false
	}
	if len(p) >= 6 { // Ex2
		all := true
		for _, b := range p[:6] {
			all = all && printable(b)
		}
		if all {
			return false
		}
	}
	run, best, pr := 0, 0, 0
	for _, b := range p {
		if printable(b) {
			pr++
			run++
			best = max(best, run)
		} else {
			run = 0
		}
	}
	if pr*2 > len(p) || best > 20 { // Ex3, Ex4
		return false
	}
	c := Classify(p, false, 0)
	return c != ClassTLS && c != ClassHTTP // Ex5
}

// DNSQuestion returns the first question name (lower case, no trailing dot).
func DNSQuestion(m []byte) (string, error) {
	if len(m) < 13 || binary.BigEndian.Uint16(m[4:]) == 0 {
		return "", errors.New("dpi: not a DNS query")
	}
	var labels []string
	for p := 12; p < len(m); {
		n := int(m[p])
		if n == 0 {
			return strings.ToLower(strings.Join(labels, ".")), nil
		}
		if n&0xc0 != 0 || p+1+n > len(m) {
			break
		}
		labels = append(labels, string(m[p+1:p+1+n]))
		p += 1 + n
	}
	return "", errors.New("dpi: bad DNS name")
}

// DNSReply turns a query into an empty reply with the given rcode
// (3 = NXDOMAIN), echoing the question.
func DNSReply(q []byte, rcode int) []byte {
	if len(q) < 12 {
		return nil
	}
	r := append([]byte(nil), q...)
	r[2] = 0x80 | q[2]&0x01 | 0x04 // QR, RD copied, AA
	r[3] = 0x80 | byte(rcode)      // RA
	binary.BigEndian.PutUint16(r[6:], 0)
	binary.BigEndian.PutUint16(r[8:], 0)
	binary.BigEndian.PutUint16(r[10:], 0)
	return r
}

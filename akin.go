// Package akin computes the Akin HTTP request fingerprint.
//
// Akin identifies an HTTP/1.x client from a single bare request head. It needs
// no pcap, no TLS handshake and no connection state, so it works anywhere the
// request bytes are available.
//
// The middle section of the token is a presence bitmap over a frozen header
// vocabulary rather than a hash, so the Hamming distance between two tokens is
// the number of vocabulary headers the two clients differ by. See SPEC.md.
package akin

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SpecVersion is the leading character of every token. A format revision bumps
// it so that parsers written against one version reject the next rather than
// misreading it.
const SpecVersion = "a"

// Vocab is normative. Bit i corresponds to Vocab[i]. Reordering it changes
// every fingerprint and breaks distance comparability between implementations.
var Vocab = [32]string{
	"accept", "connection", "accept-encoding", "host",
	"accept-language", "upgrade-insecure-requests", "user-agent", "range",
	"cache-control", "content-length", "content-type", "sec-fetch-mode",
	"pragma", "sec-fetch-dest", "sec-fetch-site", "sec-fetch-user",
	"metadata-flavor", "metadata", "sec-ch-ua-platform", "sec-ch-ua-mobile",
	"sec-ch-ua", "x-requested-with", "referer", "accept-charset",
	"x-csrf-token", "proxy-authorization", "origin", "wsmanidentify",
	"sec-gpc", "upgrade", "sec-websocket-version", "sec-websocket-key",
}

var vocabIndex = func() map[string]uint {
	m := make(map[string]uint, len(Vocab))
	for i, n := range Vocab {
		m[n] = uint(i)
	}
	return m
}()

// negotiation headers contribute the grammar of their value, never the value.
var negotiation = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true,
	"accept-charset": true, "connection": true, "te": true,
	"upgrade-insecure-requests": true, "cache-control": true, "pragma": true,
}

type header struct{ name, value string }

// Fingerprint returns the Akin token for a request head, or "" if the input is
// not a parsable HTTP/1.x request.
func Fingerprint(data []byte) string {
	return FingerprintSession(data, nil)
}

// FingerprintSession appends the session section, derived from the
// per-connection record numbers seen for this connection. Pass nil when the
// caller does not track connections; the token is then emitted without it.
func FingerprintSession(data []byte, sequence []int) string {
	version, hdrs, crlf, ok := parseHead(data)
	if !ok {
		return ""
	}

	// Scratch space sized for the common case. Scanner requests carry a
	// handful of headers, so this stays on the stack and the whole
	// fingerprint runs without touching the heap.
	var caseArr [24]byte
	var lowBuf [64]byte
	var shapeBuf [32]byte
	casePattern := caseArr[:0]

	sum := sha256.New()
	var bits uint32
	extra, negCount := 0, 0
	dup, hasCL, hasTE := false, false, false

	for i, h := range hdrs {
		// Compared against the original names rather than a lowered copy, so
		// nothing has to outlive this iteration.
		for j := 0; j < i; j++ {
			if strings.EqualFold(h.name, hdrs[j].name) {
				dup = true
				break
			}
		}
		casePattern = append(casePattern, caseClass(h.name))

		// Go compiles map and switch lookups keyed by string(someBytes)
		// without allocating, so the lowered name never reaches the heap.
		low := lowerASCII(h.name, lowBuf[:])
		if idx, in := vocabIndex[string(low)]; in {
			bits |= 1 << idx
		} else {
			extra++
		}
		switch string(low) {
		case "content-length":
			hasCL = true
		case "transfer-encoding":
			hasTE = true
		}
		if negotiation[string(low)] {
			if negCount > 0 {
				sum.Write([]byte{'|'})
			}
			negCount++
			sum.Write(low)
			sum.Write([]byte{'='})
			sum.Write(shapeInto(h.value, shapeBuf[:0]))
		}
	}
	sum.Write([]byte{'#'})
	sum.Write(casePattern)
	var digest [sha256.Size]byte
	sum.Sum(digest[:0])

	n := len(hdrs)
	if n > 99 {
		n = 99
	}
	if extra > 9 {
		extra = 9
	}

	out := make([]byte, 0, 40)
	out = append(out, SpecVersion...)
	out = appendVersionDigits(out, version)
	if crlf {
		out = append(out, 'c')
	} else {
		out = append(out, 'l')
	}
	if dup {
		out = append(out, 'd')
	} else {
		out = append(out, 'u')
	}
	switch {
	case hasCL:
		out = append(out, 'q')
	case hasTE:
		out = append(out, 'k')
	default:
		out = append(out, 'n')
	}
	out = append(out, byte('0'+n/10), byte('0'+n%10), byte('0'+extra))

	out = append(out, '_')
	for shift := 28; shift >= 0; shift -= 4 {
		out = append(out, hexDigits[(bits>>uint(shift))&0xf])
	}
	out = append(out, '_')
	for _, b := range digest[:4] {
		out = append(out, hexDigits[b>>4], hexDigits[b&0xf])
	}

	if sequence != nil {
		out = append(out, '_')
		out = append(out, SessionField(sequence)...)
	}
	return string(out)
}

const hexDigits = "0123456789abcdef"

// lowerASCII lowercases into buf and returns the slice. Header names are
// ASCII in every request this format targets; anything else falls back to a
// general lowercase, which is the only path that allocates.
func lowerASCII(s string, buf []byte) []byte {
	if len(s) > len(buf) {
		return []byte(strings.ToLower(s))
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return []byte(strings.ToLower(s))
		}
	}
	b := buf[:len(s)]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return b
}

// caseClass mirrors Python's str.isupper/str.islower: a string is upper or
// lower only if it has at least one cased rune and every cased rune agrees.
// Titlecase runes satisfy neither, so they clear both.
func caseClass(s string) byte {
	hasCased, upper, lower := false, true, true
	for _, r := range s {
		if !unicode.IsUpper(r) && !unicode.IsLower(r) && !unicode.IsTitle(r) {
			continue
		}
		hasCased = true
		if !unicode.IsLower(r) {
			lower = false
		}
		if !unicode.IsUpper(r) {
			upper = false
		}
	}
	switch {
	case !hasCased:
		return 'C'
	case upper:
		return 'U'
	case lower:
		return 'l'
	}
	return 'C'
}

// Shape collapses a header value to its grammar: ASCII letter runs become "a",
// ASCII digit runs become "9", and any run of three or more identical
// characters is cut to two. The result is truncated to 24 runes.
func Shape(value string) string {
	return string(shapeInto(value, nil))
}

func shapeInto(value string, buf []byte) []byte {
	v := strings.TrimSpace(value)
	if buf == nil {
		buf = make([]byte, 0, 32)
	}
	runes := 0
	var prevClass byte
	var lastRune rune
	var runLen int
	for _, r := range v {
		var class byte
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
			class = 'a'
		case r >= '0' && r <= '9':
			class = '9'
		}
		var emit rune
		if class != 0 {
			if class == prevClass {
				continue // still inside a letter or digit run
			}
			prevClass = class
			emit = rune(class)
		} else {
			prevClass = 0
			emit = r
		}
		if emit == lastRune {
			runLen++
		} else {
			runLen = 1
			lastRune = emit
		}
		if runLen > 2 {
			continue // run of three or more identical characters
		}
		if runes == 24 {
			break
		}
		runes++
		buf = utf8.AppendRune(buf, emit)
	}
	return buf
}

// SessionField is one character: "1" single request, "c" a contiguous run of
// record numbers, "g" a run with gaps.
func SessionField(sequence []int) string {
	if len(sequence) <= 1 {
		return "1"
	}
	for i := 1; i < len(sequence); i++ {
		if sequence[i]-sequence[i-1] != 1 {
			return "g"
		}
	}
	return "c"
}

// Distance reports how many vocabulary headers two fingerprints differ by.
// It returns -1 if either token is malformed.
func Distance(a, b string) int {
	ba, oka := bitmapOf(a)
	bb, okb := bitmapOf(b)
	if !oka || !okb {
		return -1
	}
	return bits.OnesCount32(ba ^ bb)
}

func bitmapOf(fp string) (uint32, bool) {
	first := strings.IndexByte(fp, '_')
	if first < 0 {
		return 0, false
	}
	rest := fp[first+1:]
	second := strings.IndexByte(rest, '_')
	if second != 8 {
		return 0, false
	}
	var v uint32
	for i := 0; i < 8; i++ {
		c := rest[i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// appendVersionDigits writes exactly two digits, so the readable prefix is
// always nine characters and a parser can index it. A request line carrying no
// recognisable HTTP/1.x version yields "00".
func appendVersionDigits(out []byte, version string) []byte {
	if i := strings.LastIndexByte(version, '/'); i >= 0 {
		version = version[i+1:]
	}
	var digits [2]byte
	n := 0
	for i := 0; i < len(version); i++ {
		c := version[i]
		if c == '.' {
			continue
		}
		if n == 2 || c < '0' || c > '9' {
			return append(out, '0', '0')
		}
		digits[n] = c
		n++
	}
	if n != 2 {
		return append(out, '0', '0')
	}
	return append(out, digits[0], digits[1])
}

// parseHead splits a request head into its version, headers and line ending.
// Invalid UTF-8 is replaced rune by rune, matching the reference decoder.
func parseHead(data []byte) (version string, hdrs []header, crlf bool, ok bool) {
	head := data
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
	} else if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		head = data[:i]
	}
	text := sanitize(head)
	crlf = strings.Contains(text, "\r\n")

	line, rest := nextLine(text)
	sp1 := strings.IndexByte(line, ' ')
	if sp1 < 0 {
		return "", nil, false, false
	}
	sp2 := strings.IndexByte(line[sp1+1:], ' ')
	if sp2 < 0 {
		return "", nil, false, false
	}
	version = line[sp1+1+sp2+1:]
	if strings.IndexByte(version, ' ') >= 0 {
		return "", nil, false, false // more than three fields
	}

	for rest != "" || strings.Contains(text, "\n") {
		line, rest = nextLine(rest)
		if line == "" && rest == "" {
			break
		}
		if i := strings.IndexByte(line, ':'); i >= 0 {
			hdrs = append(hdrs, header{name: line[:i], value: line[i+1:]})
		}
		if rest == "" {
			break
		}
	}
	return version, hdrs, crlf, true
}

// nextLine splits off one line terminated by CRLF or bare LF.
func nextLine(s string) (line, rest string) {
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return s, ""
	}
	line = s[:i]
	line = strings.TrimSuffix(line, "\r")
	return line, s[i+1:]
}

func sanitize(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	out.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		out.WriteRune(r)
		b = b[size:]
	}
	return out.String()
}

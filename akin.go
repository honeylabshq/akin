// Package akin computes the Akin HTTP request fingerprint, format b.
//
// Akin identifies an HTTP client from a single request: an HTTP/1.x request
// head, or the field list of an HTTP/2 or HTTP/3 request. It needs no packet
// capture, no TLS handshake and no connection state, so it can be computed
// wherever the request is available: a honeypot, a proxy log, a WAF, a stored
// column.
//
// A token has a nine-character readable prefix, a 32-bit map over a frozen
// core list of header names, a hash over the grammar of the negotiation
// header values and the casing of the header names, an optional list of
// 16-bit codes for the headers outside the core list, and an optional
// session field:
//
//	b11cun030_00040014_54d07b6d                 default curl
//	b11cdn053_00040000_2e792dd9_x22692f93bcb1   Host plus three headers outside the core list
//	b11cun030_00040014_54d07b6d_c               the same curl, with a session field
//
// Distance between two tokens is the number of headers the two clients differ
// by: the popcount of the XOR of the core maps plus the size of the symmetric
// difference of the code lists. Header order never enters the token.
package akin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SpecVersion is the leading character of every token. A format revision bumps
// it so that parsers written against one version reject the next rather than
// misreading it.
const SpecVersion = "b"

// MaxExtras is the largest number of headers outside the core list that a
// token carries by code. The prefix digit saturates at the same value.
const MaxExtras = 9

// Core is normative. Bit i of the core map is Core[i]. It is the 32 header
// names with the highest presence entropy across 107,559 addresses that sent
// HTTP to HoneyLabs sensors between 1 June and 29 September 2026, ordered by
// that entropy, minimum 50 addresses. It is frozen: headers outside it are
// carried by code in their own section, so the list never needs to grow.
var Core = [32]string{
	"connection", "accept-encoding", "accept", "accept-language",
	"user-agent", "upgrade-insecure-requests", "sec-fetch-mode", "sec-fetch-site",
	"sec-fetch-dest", "sec-fetch-user", "referer", "content-length",
	"sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile", "sec-gpc",
	"content-type", "accept-charset", "host", "priority",
	"cache-control", "pragma", "authorization", "soapaction",
	"dnt", "wsmanidentify", "x-aggregate-auth", "cookie",
	"origin", "mcp-protocol-version", "upgrade", "x-forwarded-for",
}

var coreIndex = func() map[string]uint {
	m := make(map[string]uint, len(Core))
	for i, n := range Core {
		m[n] = uint(i)
	}
	return m
}()

// negotiation headers contribute the grammar of their value to the detail
// hash. The value itself never reaches the token.
var negotiation = map[string]bool{
	"accept": true, "accept-encoding": true, "accept-language": true,
	"accept-charset": true, "connection": true, "te": true,
	"upgrade-insecure-requests": true, "cache-control": true, "pragma": true,
}

type header struct{ name, value string }

// Fingerprint returns the token for a request head, or "" if the input is not
// a parsable HTTP/1.x request.
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
	eol := byte('l')
	if crlf {
		eol = 'c'
	}
	return build(versionDigits(version), eol, hdrs, sequence)
}

// Field is one header field of a request as an HTTP/2 or HTTP/3 server
// decodes it, pseudo-header fields included.
type Field struct{ Name, Value string }

// FingerprintFields returns the token for a request decoded from HTTP/2
// (version 2) or HTTP/3 (version 3), or "" for any other version. The two
// protocols carry the same field list, so they share one path and differ only
// in the version digits. The line-ending flag is "h", since neither protocol
// has line endings.
//
// Pseudo-header fields are dropped, except :authority, which counts as Host:
// it carries what Host carries in HTTP/1.x, and mapping it keeps the core map
// comparable across versions. Repeated Cookie fields are one header, because
// HTTP/2 and HTTP/3 let a client split Cookie into crumbs and a recipient
// must join them.
func FingerprintFields(version int, fields []Field) string {
	var digits string
	switch version {
	case 2:
		digits = "20"
	case 3:
		digits = "30"
	default:
		return ""
	}
	hdrs := make([]header, 0, len(fields))
	cookie := false
	for _, f := range fields {
		name := f.Name
		switch {
		case name == ":authority":
			name = "host"
		case strings.HasPrefix(name, ":"):
			continue
		case strings.EqualFold(name, "cookie"):
			if cookie {
				continue
			}
			cookie = true
		}
		hdrs = append(hdrs, header{name: name, value: f.Value})
	}
	return build(digits, 'h', hdrs, nil)
}

// build computes the token from the version digits, the line-ending flag and
// the header list.
func build(digits string, eol byte, hdrs []header, sequence []int) string {
	n := len(hdrs)
	lows := make([]string, n)
	for i, h := range hdrs {
		lows[i] = strings.ToLower(h.name)
	}

	// Core map, extra codes, and the three flags, in one pass.
	var core uint32
	extraCodes := make([]string, 0, 4)
	seen := make(map[string]bool, n)
	seenExtra := map[string]bool{}
	dup, hasCL, hasTE := false, false, false
	for _, low := range lows {
		if seen[low] {
			dup = true
		}
		seen[low] = true
		if idx, in := coreIndex[low]; in {
			core |= 1 << idx
		} else if !seenExtra[low] {
			seenExtra[low] = true
			extraCodes = append(extraCodes, Code(low))
		}
		switch low {
		case "content-length":
			hasCL = true
		case "transfer-encoding":
			hasTE = true
		}
	}
	sort.Strings(extraCodes)
	extras := len(extraCodes)
	if extras > MaxExtras {
		extras = MaxExtras
		extraCodes = extraCodes[:MaxExtras]
	}

	// Everything hashed is ordered by header name, never by position in the
	// request: header order follows the disguise, not the client. Repeated
	// names keep request order (the sort is stable); repeated negotiation
	// names sort by value shape so that two implementations agree.
	shapes := make([]string, n)
	for i := range hdrs {
		if negotiation[lows[i]] {
			shapes[i] = Shape(hdrs[i].value)
		}
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		if lows[order[a]] != lows[order[b]] {
			return lows[order[a]] < lows[order[b]]
		}
		return shapes[order[a]] < shapes[order[b]]
	})
	sum := sha256.New()
	first := true
	for _, i := range order {
		if !negotiation[lows[i]] {
			continue
		}
		if !first {
			sum.Write([]byte{'|'})
		}
		first = false
		sum.Write([]byte(lows[i]))
		sum.Write([]byte{'='})
		sum.Write([]byte(shapes[i]))
	}
	sum.Write([]byte{'#'})
	for _, i := range order {
		sum.Write([]byte{caseClass(hdrs[i].name)})
	}
	var digest [sha256.Size]byte
	sum.Sum(digest[:0])

	if n > 99 {
		n = 99
	}
	out := make([]byte, 0, 48)
	out = append(out, SpecVersion...)
	out = append(out, digits...)
	out = append(out, eol)
	if dup {
		out = append(out, 'd')
	} else {
		out = append(out, 'u')
	}
	switch {
	case hasCL && hasTE:
		out = append(out, 'b')
	case hasCL:
		out = append(out, 'q')
	case hasTE:
		out = append(out, 'k')
	default:
		out = append(out, 'n')
	}
	out = append(out, byte('0'+n/10), byte('0'+n%10), byte('0'+extras))
	out = append(out, '_')
	for shift := 28; shift >= 0; shift -= 4 {
		out = append(out, hexDigits[(core>>uint(shift))&0xf])
	}
	out = append(out, '_')
	for _, b := range digest[:4] {
		out = append(out, hexDigits[b>>4], hexDigits[b&0xf])
	}
	if extras > 0 {
		out = append(out, '_', 'x')
		for _, c := range extraCodes {
			out = append(out, c...)
		}
	}
	if sequence != nil {
		out = append(out, '_')
		out = append(out, SessionField(sequence)...)
	}
	return string(out)
}

// Code returns the four-hex-digit code a header name outside the core list is
// carried by: the first two bytes of the SHA-256 of the lowercased name.
// Anyone who knows a header name can compute its code, so a token's extra
// headers can be read back against any list of names.
func Code(name string) string {
	d := sha256.Sum256([]byte(strings.ToLower(name)))
	return hex.EncodeToString(d[:2])
}

// Lookup returns the code of every name in names, so a decoder can turn the
// codes in a token back into header names it knows about.
func Lookup(names []string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[Code(n)] = strings.ToLower(n)
	}
	return m
}

// Fields is a decoded token.
type Fields struct {
	Spec        byte     // format letter, 'b'
	HTTPVersion string   // "11", "10", "20", "30", or "00" when unrecognised
	CRLF        bool     // CRLF line endings
	EOL         byte     // 'c' CRLF, 'l' bare LF, 'h' HTTP/2 or HTTP/3 fields
	Duplicate   bool     // some header name repeats
	Body        byte     // 'q' Content-Length, 'k' Transfer-Encoding, 'b' both, 'n' neither
	Headers     int      // header count, capped at 99
	Extras      int      // headers outside the core list, capped at MaxExtras
	Core        uint32   // core map
	CoreNames   []string // the names the core map sets, in Core order
	Detail      string   // eight hex digits
	Codes       []string // codes of the extra headers, sorted
	Session     byte     // '1', 'c', 'g', or 0 when absent
}

// ErrMalformed is returned by Decode for anything that is not a format-b token.
var ErrMalformed = errors.New("akin: malformed token")

// Decode parses a token. It accepts only the current format.
func Decode(token string) (Fields, error) {
	var f Fields
	parts := strings.Split(token, "_")
	if len(parts) < 3 || len(parts) > 5 || len(parts[0]) != 9 || parts[0][0] != SpecVersion[0] {
		return f, ErrMalformed
	}
	p := parts[0]
	if !isDigit(p[1]) || !isDigit(p[2]) || !isDigit(p[6]) || !isDigit(p[7]) || !isDigit(p[8]) ||
		(p[3] != 'c' && p[3] != 'l' && p[3] != 'h') || (p[4] != 'u' && p[4] != 'd') ||
		(p[5] != 'n' && p[5] != 'q' && p[5] != 'k' && p[5] != 'b') {
		return f, ErrMalformed
	}
	core, ok := parseHex32(parts[1])
	if !ok || len(parts[2]) != 8 || !isHex(parts[2]) {
		return f, ErrMalformed
	}
	f = Fields{Spec: p[0], HTTPVersion: p[1:3], CRLF: p[3] == 'c', EOL: p[3], Duplicate: p[4] == 'd', Body: p[5],
		Headers: int(p[6]-'0')*10 + int(p[7]-'0'), Extras: int(p[8] - '0'), Core: core, Detail: parts[2]}
	for i, name := range Core {
		if core>>uint(i)&1 == 1 {
			f.CoreNames = append(f.CoreNames, name)
		}
	}
	for _, s := range parts[3:] {
		switch {
		case len(s) == 1 && (s[0] == '1' || s[0] == 'c' || s[0] == 'g') && f.Session == 0:
			f.Session = s[0]
		case len(s) > 1 && s[0] == 'x' && (len(s)-1)%4 == 0 && isHex(s[1:]) && f.Codes == nil && f.Session == 0:
			for i := 1; i < len(s); i += 4 {
				f.Codes = append(f.Codes, s[i:i+4])
			}
			if len(f.Codes) > MaxExtras || !sort.StringsAreSorted(f.Codes) {
				return Fields{}, ErrMalformed
			}
		default:
			return Fields{}, ErrMalformed
		}
	}
	if f.Extras > 0 && len(f.Codes) != f.Extras || f.Extras == 0 && len(f.Codes) != 0 {
		return Fields{}, ErrMalformed
	}
	return f, nil
}

// Distance reports how many headers two clients differ by: core headers by
// the XOR of the core maps, headers outside the core list by the codes only
// one of the two tokens carries. It returns -1 if either token is malformed.
//
// The result never overcounts. It can undercount when a request carries more
// than MaxExtras headers outside the core list, or when two different header
// names share a 16-bit code.
func Distance(a, b string) int {
	fa, ea := Decode(a)
	fb, eb := Decode(b)
	if ea != nil || eb != nil {
		return -1
	}
	d := bits.OnesCount32(fa.Core ^ fb.Core)
	i, j := 0, 0
	for i < len(fa.Codes) && j < len(fb.Codes) {
		switch {
		case fa.Codes[i] == fb.Codes[j]:
			i++
			j++
		case fa.Codes[i] < fb.Codes[j]:
			d++
			i++
		default:
			d++
			j++
		}
	}
	return d + (len(fa.Codes) - i) + (len(fb.Codes) - j)
}

const hexDigits = "0123456789abcdef"

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isDigit(c) || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func parseHex32(s string) (uint32, bool) {
	if len(s) != 8 || !isHex(s) {
		return 0, false
	}
	var v uint32
	for i := 0; i < 8; i++ {
		c := s[i]
		var d uint32
		if isDigit(c) {
			d = uint32(c - '0')
		} else {
			d = uint32(c-'a') + 10
		}
		v = v<<4 | d
	}
	return v, true
}

// caseClass classifies a header name's casing: a string is upper or
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
	v := strings.TrimSpace(value)
	buf := make([]byte, 0, 32)
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
	return string(buf)
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

// versionDigits returns the two version digits of an HTTP/1.x request line,
// so the readable prefix is always nine characters and a parser can index it.
// Anything other than "HTTP/1." and one digit yields "00".
func versionDigits(version string) string {
	if len(version) == 8 && strings.HasPrefix(version, "HTTP/1.") && isDigit(version[7]) {
		return "1" + version[7:]
	}
	return "00"
}

// parseHead splits a request head into its version, headers and line ending.
// Invalid UTF-8 is replaced byte by byte with U+FFFD.
func parseHead(data []byte) (version string, hdrs []header, crlf bool, ok bool) {
	// The head ends at whichever blank line comes first, so a body can never
	// be read as headers. The line ending is judged on the head including its
	// terminator, so a request with no headers still reports it.
	end, term := len(data), 0
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		end, term = i, 4
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 && i < end {
		end, term = i, 2
	}
	text := sanitize(data[:end])
	crlf = bytes.Contains(data[:end+term], []byte("\r\n"))

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

package akin

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

type vector struct {
	Name        string `json:"name"`
	RequestHex  string `json:"request_hex"`
	Fingerprint string `json:"fingerprint"`
}

func loadVectors(t testing.TB) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vs
}

// TestVectors pins the implementation to the vectors in testdata.
func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		raw, err := hex.DecodeString(v.RequestHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", v.Name, err)
		}
		if got := Fingerprint(raw); got != v.Fingerprint {
			t.Errorf("%s:\n got %s\nwant %s", v.Name, got, v.Fingerprint)
		}
	}
}

func TestNotHTTP(t *testing.T) {
	for _, in := range []string{"", "hello", "\x16\x03\x01\x02\x00", "GET /\r\n\r\n"} {
		if got := Fingerprint([]byte(in)); got != "" {
			t.Errorf("Fingerprint(%q) = %q, want empty", in, got)
		}
	}
}

// TestDistance is the property the format exists for: one added header must
// move the token by exactly one, whether or not the header is in the core list.
func TestDistance(t *testing.T) {
	base := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n"))
	plus := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"))
	extra := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nX-Api-Key: k\r\n\r\n"))
	both := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nAccept-Encoding: gzip\r\nX-Api-Key: k\r\n\r\n"))
	cases := []struct {
		a, b string
		want int
	}{
		{base, plus, 1},
		{base, extra, 1},
		{base, both, 2},
		{plus, extra, 2},
		{extra, both, 1},
		{base, base, 0},
		{extra, extra, 0},
		{"garbage", base, -1},
		{base, "a11cun030_00000049_54d07b6d", -1}, // the previous format is not comparable
	}
	for _, c := range cases {
		if d := Distance(c.a, c.b); d != c.want {
			t.Errorf("Distance(%s, %s) = %d, want %d", c.a, c.b, d, c.want)
		}
	}
}

// TestExtras pins the section that carries headers outside the core list:
// codes are sorted, deduplicated, capped at MaxExtras, and absent when there
// are none, so the prefix digit and the section always agree.
func TestExtras(t *testing.T) {
	fp := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nX-Foo: 1\r\nx-bar: 2\r\nX-FOO: 3\r\n\r\n"))
	f, err := Decode(fp)
	if err != nil {
		t.Fatalf("%s: %v", fp, err)
	}
	if f.Extras != 2 || len(f.Codes) != 2 {
		t.Errorf("extras = %d, codes = %v, want 2 and 2 (%s)", f.Extras, f.Codes, fp)
	}
	want := []string{Code("x-foo"), Code("x-bar")}
	sort.Strings(want)
	if f.Codes[0] != want[0] || f.Codes[1] != want[1] {
		t.Errorf("codes = %v, want %v", f.Codes, want)
	}
	if !f.Duplicate {
		t.Errorf("X-Foo repeated in a different case must set the duplicate flag: %s", fp)
	}

	none := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	if strings.Count(none, "_") != 2 {
		t.Errorf("no extras must mean no extras section: %s", none)
	}

	req := "GET / HTTP/1.1\r\n"
	for i := 0; i < 12; i++ {
		req += "X-H" + string(rune('a'+i)) + ": v\r\n"
	}
	many, err := Decode(Fingerprint([]byte(req + "\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	if many.Extras != MaxExtras || len(many.Codes) != MaxExtras || !sort.StringsAreSorted(many.Codes) {
		t.Errorf("12 extras must be capped at %d sorted codes, got %d/%v", MaxExtras, many.Extras, many.Codes)
	}
	if !sort.StringsAreSorted(f.Codes) {
		t.Errorf("codes not sorted: %v", f.Codes)
	}
}

func TestCode(t *testing.T) {
	if Code("Range") != Code("range") || len(Code("range")) != 4 {
		t.Errorf("Code must be four hex digits of the lowercased name, got %q and %q", Code("Range"), Code("range"))
	}
	if Lookup([]string{"Range"})[Code("range")] != "range" {
		t.Error("Lookup must map a code back to the lowercased name")
	}
}

func TestDecode(t *testing.T) {
	f, err := Decode("b11cun030_00040014_54d07b6d")
	if err != nil {
		t.Fatal(err)
	}
	if f.HTTPVersion != "11" || !f.CRLF || f.Duplicate || f.Body != 'n' || f.Headers != 3 || f.Extras != 0 ||
		f.Core != 0x00040014 || f.Detail != "54d07b6d" || f.Session != 0 || len(f.Codes) != 0 {
		t.Errorf("unexpected fields: %+v", f)
	}
	if strings.Join(f.CoreNames, ",") != "accept,user-agent,host" {
		t.Errorf("core names = %v", f.CoreNames)
	}
	if f, err := Decode("b11cun030_00040014_54d07b6d_c"); err != nil || f.Session != 'c' {
		t.Errorf("session field: %+v %v", f, err)
	}
	if f, err := Decode("b11cun031_00040014_54d07b6d_x2269_1"); err != nil || f.Session != '1' || len(f.Codes) != 1 {
		t.Errorf("extras then session: %+v %v", f, err)
	}
	bad := []string{
		"", "b11cun030", "a11cun030_00000049_54d07b6d", "b11cun030_0004001_54d07b6d",
		"b11cun030_00040014_54d07b6", "b11cun031_00040014_54d07b6d", // extras digit without a section
		"b11cun030_00040014_54d07b6d_x2269",     // section without the digit
		"b11cun032_00040014_54d07b6d_x2f932269", // codes out of order
		"b11cun030_00040014_54d07b6d_1_x2269",   // sections out of order
		"b11cun030_00040014_54d07b6d_c_c", "b11cxn030_00040014_54d07b6d", "b11cun030_00040014_54d07b6d_z",
	}
	for _, tok := range bad {
		if _, err := Decode(tok); err == nil {
			t.Errorf("Decode(%q) accepted a malformed token", tok)
		}
	}
}

func TestSessionField(t *testing.T) {
	cases := []struct {
		seq  []int
		want string
	}{
		{[]int{1}, "1"},
		{[]int{1, 2, 3}, "c"},
		{[]int{1, 3, 4}, "g"},
		{[]int{}, "1"},
	}
	for _, c := range cases {
		if got := SessionField(c.seq); got != c.want {
			t.Errorf("SessionField(%v) = %q, want %q", c.seq, got, c.want)
		}
	}
	fp := FingerprintSession([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), []int{1, 2, 3})
	if fp[len(fp)-2:] != "_c" {
		t.Errorf("session section not appended: %s", fp)
	}
	if nilSeq := FingerprintSession([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), nil); nilSeq != Fingerprint([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) {
		t.Errorf("nil sequence must omit the section, got %s", nilSeq)
	}
}

// TestCoreFrozen guards the one thing that must never drift: bit positions are
// normative, so a reorder silently breaks comparability across implementations.
func TestCoreFrozen(t *testing.T) {
	want := "connection|accept-encoding|accept|accept-language|user-agent|upgrade-insecure-requests|" +
		"sec-fetch-mode|sec-fetch-site|sec-fetch-dest|sec-fetch-user|referer|content-length|" +
		"sec-ch-ua-platform|sec-ch-ua|sec-ch-ua-mobile|sec-gpc|content-type|accept-charset|host|" +
		"priority|cache-control|pragma|authorization|soapaction|dnt|wsmanidentify|x-aggregate-auth|" +
		"cookie|origin|mcp-protocol-version|upgrade|x-forwarded-for"
	got := ""
	for i, n := range Core {
		if i > 0 {
			got += "|"
		}
		got += n
	}
	if got != want {
		t.Errorf("core list changed, every fingerprint moves:\n got %s\nwant %s", got, want)
	}
}

func TestShape(t *testing.T) {
	cases := map[string]string{
		"  gzip, deflate  ": "a, a",
		"curl/8.5.0":        "a/9.9.9",
		"aaaaaa":            "a",
		"!!!!!":             "!!",
		"":                  "",
	}
	for in, want := range cases {
		if got := Shape(in); got != want {
			t.Errorf("Shape(%q) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkFingerprint(b *testing.B) {
	req := []byte("GET /index.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n" +
		"Accept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\nConnection: keep-alive\r\n\r\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(req)))
	for i := 0; i < b.N; i++ {
		_ = Fingerprint(req)
	}
}

// TestDuplicateMixedCase pins duplicate detection to the lowercased name,
// whatever else sits between the two occurrences.
func TestDuplicateMixedCase(t *testing.T) {
	cases := []struct {
		name string
		req  string
		dup  bool
	}{
		{"same case", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", true},
		{"mixed case", "GET / HTTP/1.1\r\nHost: a\r\nHOST: b\r\n\r\n", true},
		{"separated by longer header", "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\nhOsT: b\r\n\r\n", true},
		{"no duplicate", "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\nAccept: */*\r\n\r\n", false},
		{"prefix is not a duplicate", "GET / HTTP/1.1\r\nAccept: a\r\nAccept-Encoding: gzip\r\n\r\n", false},
	}
	for _, c := range cases {
		fp := Fingerprint([]byte(c.req))
		if fp == "" {
			t.Fatalf("%s: no fingerprint", c.name)
		}
		got := fp[4] == 'd'
		if got != c.dup {
			t.Errorf("%s: duplicate flag %q, want dup=%v (%s)", c.name, fp[4:5], c.dup, fp)
		}
	}
}

// TestLongHeaderName checks that an 80-character name is handled like any
// other, including duplicate detection.
func TestLongHeaderName(t *testing.T) {
	long := ""
	for i := 0; i < 80; i++ {
		long += "X"
	}
	req := "GET / HTTP/1.1\r\nHost: a\r\n" + long + ": v\r\n" + long + ": w\r\n\r\n"
	fp := Fingerprint([]byte(req))
	if fp == "" {
		t.Fatal("no fingerprint")
	}
	if fp[4] != 'd' {
		t.Errorf("duplicate long header not detected: %s", fp)
	}
}

// TestPrefixWidth pins the readable prefix to nine characters so a consumer can
// index it without splitting.
func TestPrefixWidth(t *testing.T) {
	cases := []string{
		"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.0\r\nHost: a\r\n\r\n",
		"GET / HTTP/0.9\r\nHost: a\r\n\r\n",
		"GET / \r\nHost: a\r\n\r\n",
		"GET / SOMETHING\r\nHost: a\r\n\r\n",
		"GET / HTTP/1.10\r\nHost: a\r\n\r\n",
	}
	for _, req := range cases {
		fp := Fingerprint([]byte(req))
		if fp == "" {
			t.Fatalf("%q: no fingerprint", req)
		}
		prefix := fp[:strings.IndexByte(fp, '_')]
		if len(prefix) != 9 {
			t.Errorf("%q: prefix %q is %d chars, want 9", req, prefix, len(prefix))
		}
	}
}

// TestOrderIndependent: the same headers in any order give the same token.
// Header order follows the disguise, not the client.
func TestOrderIndependent(t *testing.T) {
	a := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nAccept-Encoding: gzip\r\nX-Foo: 1\r\nUser-Agent: u\r\n\r\n"))
	b := Fingerprint([]byte("GET / HTTP/1.1\r\nUser-Agent: u\r\nX-Foo: 1\r\nAccept-Encoding: gzip\r\nAccept: */*\r\nHost: a\r\n\r\n"))
	if a != b {
		t.Errorf("order changed the token:\n%s\n%s", a, b)
	}
	c := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate\r\nX-Foo: 1\r\nUser-Agent: u\r\n\r\n"))
	if a == c {
		t.Errorf("a different negotiation value shape must change the detail hash: %s", a)
	}
}

// TestFields covers HTTP/2 and HTTP/3 field lists: pseudo-headers other than
// :authority are dropped, :authority counts as Host, cookie crumbs are one
// header, and the core map matches the same client over HTTP/1.1.
func TestFields(t *testing.T) {
	curl := []Field{
		{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "a"},
		{"user-agent", "curl/8.5.0"}, {"accept", "*/*"},
	}
	h1 := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"))
	h2 := FingerprintFields(2, curl)
	h3 := FingerprintFields(3, curl)
	if !strings.HasPrefix(h2, "b20hun030_00040014_") || !strings.HasPrefix(h3, "b30hun030_00040014_") {
		t.Fatalf("got %q and %q", h2, h3)
	}
	if h2[3:] != h3[3:] {
		t.Errorf("HTTP/2 and HTTP/3 differ beyond the version: %q %q", h2, h3)
	}
	if d := Distance(h1, h2); d != 0 {
		t.Errorf("Distance(HTTP/1.1, HTTP/2) = %d, want 0", d)
	}

	crumbs := append(curl[:len(curl):len(curl)], Field{"cookie", "a=1"}, Field{"cookie", "b=2"})
	if got := FingerprintFields(2, crumbs); !strings.HasPrefix(got, "b20hun040_") {
		t.Errorf("cookie crumbs: got %q, want one cookie header and no duplicate flag", got)
	}
	both := append(curl[:len(curl):len(curl)], Field{"host", "a"})
	if got := FingerprintFields(2, both); !strings.HasPrefix(got, "b20hdn040_") {
		t.Errorf(":authority plus host: got %q, want the duplicate flag", got)
	}
	if got := FingerprintFields(1, curl); got != "" {
		t.Errorf("version 1: got %q, want empty", got)
	}
	f, err := Decode(h2)
	if err != nil || f.EOL != 'h' || f.CRLF || f.HTTPVersion != "20" {
		t.Errorf("Decode(%q) = %+v, %v", h2, f, err)
	}
}

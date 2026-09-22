package akin

import (
	"encoding/hex"
	"encoding/json"
	"os"
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

// TestVectors pins this implementation to the Python reference. Every vector
// in testdata was produced by reference/reference.py.
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

// TestDistance is the property the format exists for: one added vocabulary
// header must move the token by exactly one.
func TestDistance(t *testing.T) {
	base := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n"))
	plus := Fingerprint([]byte("GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"))
	if d := Distance(base, plus); d != 1 {
		t.Errorf("Distance = %d, want 1", d)
	}
	if d := Distance(base, base); d != 0 {
		t.Errorf("Distance to self = %d, want 0", d)
	}
	if d := Distance("garbage", base); d != -1 {
		t.Errorf("Distance(garbage) = %d, want -1", d)
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

// TestVocabFrozen guards the one thing that must never drift: bit positions are
// normative, so a reorder silently breaks comparability across implementations.
func TestVocabFrozen(t *testing.T) {
	want := "accept|connection|accept-encoding|host|accept-language|upgrade-insecure-requests|" +
		"user-agent|range|cache-control|content-length|content-type|sec-fetch-mode|pragma|" +
		"sec-fetch-dest|sec-fetch-site|sec-fetch-user|metadata-flavor|metadata|" +
		"sec-ch-ua-platform|sec-ch-ua-mobile|sec-ch-ua|x-requested-with|referer|accept-charset|" +
		"x-csrf-token|proxy-authorization|origin|wsmanidentify|sec-gpc|upgrade|" +
		"sec-websocket-version|sec-websocket-key"
	got := ""
	for i, n := range Vocab {
		if i > 0 {
			got += "|"
		}
		got += n
	}
	if got != want {
		t.Errorf("vocabulary changed, every fingerprint moves:\n got %s\nwant %s", got, want)
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

// TestDuplicateMixedCase covers a bug where duplicate detection compared
// lowered names held in a reused scratch buffer, so a longer header later in
// the request could corrupt an earlier comparison.
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

// TestLongHeaderName exercises the fallback path where a name does not fit the
// stack buffer.
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

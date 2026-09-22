package akin

import (
	"strings"
	"testing"
)

// FuzzFingerprint guards the property that matters on a sensor: arbitrary
// attacker-controlled bytes must never panic, and any token produced must be
// well formed enough for Distance to read it back.
func FuzzFingerprint(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
	f.Add([]byte("POST /x HTTP/1.0\nContent-Length: 4\n\nabcd"))
	f.Add([]byte("\x16\x03\x01\x02\x00\x01\x00"))
	f.Add([]byte("GET / HTTP/1.1\r\n\xff\xfe: \xc3\x28\r\n\r\n"))
	f.Add([]byte(strings.Repeat("A: b\r\n", 300)))

	f.Fuzz(func(t *testing.T, data []byte) {
		fp := Fingerprint(data)
		if fp == "" {
			return
		}
		parts := strings.Split(fp, "_")
		if len(parts) != 3 {
			t.Fatalf("expected three sections, got %q", fp)
		}
		if len(parts[0]) != 9 {
			t.Fatalf("prefix must be 9 chars: %q", fp)
		}
		if len(parts[1]) != 8 {
			t.Fatalf("bitmap must be 8 hex digits: %q", fp)
		}
		if len(parts[2]) != 8 {
			t.Fatalf("detail must be 8 hex digits: %q", fp)
		}
		if d := Distance(fp, fp); d != 0 {
			t.Fatalf("Distance to self = %d for %q", d, fp)
		}
	})
}

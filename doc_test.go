package akin

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestSpecVocabularyMatchesCode stops the specification and the reference
// implementation drifting apart. Bit positions are normative, so a vocabulary
// table in SPEC.md that disagrees with Vocab would make two conforming
// implementations produce different fingerprints for the same request.
func TestSpecVocabularyMatchesCode(t *testing.T) {
	raw, err := os.ReadFile("SPEC.md")
	if err != nil {
		t.Fatalf("read SPEC.md: %v", err)
	}
	entry := regexp.MustCompile(`(?m)\b(\d{1,2})\s+([a-z][a-z0-9-]+)`)
	fromSpec := map[int]string{}
	for _, m := range entry.FindAllStringSubmatch(string(raw), -1) {
		i, err := strconv.Atoi(m[1])
		if err != nil || i >= len(Vocab) {
			continue
		}
		// Only accept names that are actually header-shaped, so prose
		// containing a number followed by a word is not mistaken for a row.
		if _, ok := vocabIndex[m[2]]; !ok {
			continue
		}
		if prev, seen := fromSpec[i]; seen && prev != m[2] {
			t.Fatalf("bit %d listed twice in SPEC.md as %q and %q", i, prev, m[2])
		}
		fromSpec[i] = m[2]
	}
	if len(fromSpec) != len(Vocab) {
		t.Fatalf("SPEC.md lists %d vocabulary entries, code has %d", len(fromSpec), len(Vocab))
	}
	for i, name := range Vocab {
		if fromSpec[i] != name {
			t.Errorf("bit %d: SPEC.md says %q, code says %q", i, fromSpec[i], name)
		}
	}
}

// TestDocumentedTokensReproduce recomputes every fingerprint printed in the
// README and the spec, so documentation cannot claim output the code no longer
// produces.
func TestDocumentedTokensReproduce(t *testing.T) {
	documented := map[string]string{
		"README.md": "GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n",
	}
	for file, request := range documented {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		want := Fingerprint([]byte(request))
		if want == "" {
			t.Fatalf("%s: sample request does not fingerprint", file)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s does not contain %q, the fingerprint of the request it shows", file, want)
		}
	}
	// Every token-shaped string in the docs must at least be well formed.
	token := regexp.MustCompile(`\ba[0-9]{2}[cl][du][qkn][0-9]{3}_[0-9a-f]{8}_[0-9a-f]{8}\b`)
	for _, file := range []string{"README.md", "SPEC.md"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, tok := range token.FindAllString(string(raw), -1) {
			if d := Distance(tok, tok); d != 0 {
				t.Errorf("%s: token %q is malformed", file, tok)
			}
		}
	}
}

// Command akin prints the Akin fingerprint of HTTP requests, reads a token
// back into its fields, or measures the distance between two tokens.
//
// By default it reads one raw request head from stdin. With -hex it reads one
// hex-encoded request per line, which is the form request bytes usually take
// in a log or a column of a database. With -fields 2 or -fields 3 it reads an
// HTTP/2 or HTTP/3 field list, one "name: value" per line, pseudo-headers
// included.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/honeylabshq/akin"
)

func main() {
	hexMode := flag.Bool("hex", false, "read one hex-encoded request per line")
	decode := flag.String("decode", "", "print the fields of a token")
	distance := flag.String("distance", "", "two tokens separated by a space: print how many headers they differ by")
	fields := flag.Int("fields", 0, "read an HTTP/2 (2) or HTTP/3 (3) field list, one \"name: value\" per line")
	names := flag.String("names", "", "comma-separated header names to resolve extra-header codes against when decoding")
	flag.Parse()

	switch {
	case *decode != "":
		printFields(*decode, *names)
	case *distance != "":
		printDistance(*distance)
	case *fields != 0:
		fieldList(*fields)
	case *hexMode:
		hexLines()
	default:
		one()
	}
}

func one() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	fp := akin.Fingerprint(raw)
	if fp == "" {
		fail(fmt.Errorf("not a parsable HTTP/1.x request"))
	}
	fmt.Println(fp)
}

func fieldList(version int) {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var list []akin.Field
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		// A pseudo-header starts with a colon, so the separator is the
		// first colon after the first character.
		i := strings.IndexByte(line[min(1, len(line)):], ':') + min(1, len(line))
		if i < 1 {
			fail(fmt.Errorf("field without a colon: %q", line))
		}
		list = append(list, akin.Field{Name: line[:i], Value: strings.TrimSpace(line[i+1:])})
	}
	fp := akin.FingerprintFields(version, list)
	if fp == "" {
		fail(fmt.Errorf("-fields takes 2 or 3"))
	}
	fmt.Println(fp)
}

func hexLines() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		raw, err := hex.DecodeString(in.Text())
		if err != nil {
			fmt.Fprintln(out, "")
			continue
		}
		fmt.Fprintln(out, akin.Fingerprint(raw))
	}
	if err := in.Err(); err != nil {
		fail(err)
	}
}

func printFields(token, names string) {
	f, err := akin.Decode(token)
	if err != nil {
		fail(err)
	}
	known := akin.Lookup(strings.Split(names, ","))
	body := map[byte]string{'n': "none", 'q': "Content-Length", 'k': "Transfer-Encoding", 'b': "both"}[f.Body]
	eol := map[byte]string{'c': "CRLF", 'l': "LF", 'h': "none (HTTP/2 or HTTP/3)"}[f.EOL]
	fmt.Printf("http      %s.%s\n", f.HTTPVersion[:1], f.HTTPVersion[1:])
	fmt.Printf("eol       %s\n", eol)
	fmt.Printf("duplicate %v\n", f.Duplicate)
	fmt.Printf("body      %s\n", body)
	fmt.Printf("headers   %d\n", f.Headers)
	fmt.Printf("core      %s\n", strings.Join(f.CoreNames, " "))
	fmt.Printf("detail    %s\n", f.Detail)
	if f.Extras > 0 {
		var parts []string
		for _, c := range f.Codes {
			if n, ok := known[c]; ok {
				parts = append(parts, n)
			} else {
				parts = append(parts, c)
			}
		}
		fmt.Printf("extras    %s\n", strings.Join(parts, " "))
	}
	if f.Session != 0 {
		fmt.Printf("session   %c\n", f.Session)
	}
}

func printDistance(pair string) {
	toks := strings.Fields(pair)
	if len(toks) != 2 {
		fail(fmt.Errorf("-distance takes two tokens separated by a space"))
	}
	d := akin.Distance(toks[0], toks[1])
	if d < 0 {
		fail(fmt.Errorf("malformed token"))
	}
	fmt.Println(d)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "akin:", err)
	os.Exit(1)
}

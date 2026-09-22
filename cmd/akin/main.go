// Command akin prints the Akin fingerprint of HTTP requests.
//
// By default it reads one raw request head from stdin. With -hex it reads one
// hex-encoded request per line, which is the form request bytes usually take
// in a log or a column of a database.
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/honeylabshq/akin"
)

func main() {
	hexMode := flag.Bool("hex", false, "read one hex-encoded request per line")
	flag.Parse()

	if !*hexMode {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "akin:", err)
			os.Exit(1)
		}
		fp := akin.Fingerprint(raw)
		if fp == "" {
			fmt.Fprintln(os.Stderr, "akin: not a parsable HTTP/1.x request")
			os.Exit(1)
		}
		fmt.Println(fp)
		return
	}

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
		fmt.Fprintln(os.Stderr, "akin:", err)
		os.Exit(1)
	}
}

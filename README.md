# Akin

An open HTTP request fingerprint.

    b11cun030_00040014_54d07b6d

Akin identifies an HTTP/1.x client from a single bare request head. No pcap, no
TLS handshake, no connection state, so it works anywhere the request bytes are
available: a honeypot, a proxy log, a WAF, a stored column in a database.

Two tokens compare without a lookup table: the middle section is a presence map
over a frozen list of 32 header names, and headers outside that list travel as
short codes in their own section, so the distance between two tokens is the
number of headers the two clients differ by. Header order never enters the
token, and the value of `User-Agent` never does either.

## Use

```go
import "github.com/honeylabshq/akin"

fp := akin.Fingerprint(requestBytes)   // "" if not a parsable HTTP/1.x request
d := akin.Distance(fpA, fpB)           // headers they differ by, -1 if malformed
f, err := akin.Decode(fp)              // the readable fields
```

```
$ go install github.com/honeylabshq/akin/cmd/akin@latest

$ printf 'GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n' | akin
b11cun030_00040014_54d07b6d

$ akin -hex < payloads.hex   # one hex-encoded request per line

$ akin -decode b11cdn053_00040000_2e792dd9_x22692f93bcb1 -names range,x-foo,x-bar
http      1.1
eol       CRLF
duplicate true
body      none
headers   5
core      host
detail    2e792dd9
extras    range x-foo x-bar

$ akin -distance "b11cun030_00040014_54d07b6d b11cdn053_00040000_2e792dd9_x22692f93bcb1"
5
```

## Status

Draft, so treat the format as unstable. Licensed under Apache-2.0, which
carries an express patent grant, so anyone adopting Akin gets one.

The format is specified in [SPEC.md](SPEC.md). The vectors in
`testdata/vectors.json` pin the implementation, and CI checks every one.

Bit positions in the core list are normative and frozen. Reordering them
changes every token, so `TestCoreFrozen` fails if anyone tries.

HTTP/1.x only.

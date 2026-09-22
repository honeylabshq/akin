# Akin

An open HTTP request fingerprint.

    a11cun030_00000049_54d07b6d

Akin identifies an HTTP/1.x client from a single bare request head. No pcap, no
TLS handshake, no connection state, so it works anywhere the request bytes are
available: a honeypot, a proxy log, a WAF, a stored column in a database.

The middle section is a presence bitmap over a frozen header vocabulary rather
than a hash, so the Hamming distance between two tokens is the number of
vocabulary headers the two clients differ by.

## Use

```go
import "github.com/honeylabshq/akin"

fp := akin.Fingerprint(requestBytes)   // "" if not a parsable HTTP/1.x request
d := akin.Distance(fpA, fpB)           // vocabulary headers they differ by
```

```
$ go install github.com/honeylabshq/akin/cmd/akin@latest

$ printf 'GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n' | akin
a11cun030_00000049_54d07b6d

$ akin -hex < payloads.hex   # one hex-encoded request per line
```

## Status

Draft, so treat the format as unstable. Licensed under Apache-2.0, which
carries an express patent grant, so anyone adopting Akin gets one.

The format is specified in [SPEC.md](SPEC.md). The Go implementation is pinned
to the Python reference in [reference/](reference/) by the vectors in
`testdata/vectors.json`; the two agree byte for byte across 60,001 real
requests.

Bit positions in the vocabulary are normative and frozen. Reordering them
changes every fingerprint, so `TestVocabFrozen` fails if anyone tries.

HTTP/1.x only.

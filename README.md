# Akin

An HTTP request fingerprint that tells you how different two clients are, not
just whether they differ.

    a11cun040_0000002b_608dab68

Akin identifies an HTTP/1.x client from a single bare request head. It needs no
pcap, no TLS handshake and no connection state, so it works anywhere the
request bytes are available: a honeypot, a proxy log, a WAF, a stored column in
a database.

## The point

The middle section is a presence bitmap over a frozen header vocabulary, not a
hash. The Hamming distance between two Akin tokens is the number of vocabulary
headers the two clients differ by, correct 95% of the time on 21 days of
scanner traffic.

```go
a := akin.Fingerprint(requestA)
b := akin.Fingerprint(requestB)
akin.Distance(a, b) // 1: same tool, one extra header
```

JA4H hashes its ordered header-name list, so one added header produces a token
with no visible relationship to the old one. In the corpus behind this repo,
560 JA4H cluster pairs differ by exactly one header and 1,158 by exactly two,
and JA4H gives every one of those pairs unrelated hashes.

## Use it

```go
import "github.com/honeylabshq/akin"

fp := akin.Fingerprint(requestBytes)          // "" if not HTTP/1.x
fp = akin.FingerprintSession(requestBytes, seq) // adds the session section
```

Command line:

```
$ printf 'GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n' | akin
a11cun030_00000049_54d07b6d

$ akin -hex < payloads.hex   # one hex-encoded request per line
```

## Status

Draft. The format is specified in [SPEC.md](SPEC.md) and measured against JA4H
and p0f in [BENCHMARK.md](BENCHMARK.md).

The Go implementation is pinned to the Python reference in
[reference/](reference/) by test vectors in `testdata/vectors.json`, and the two
agree byte for byte across 60,001 real requests. The fingerprint runs in about
4 µs with 5 allocations on a Raspberry Pi 5 core.

Bit positions in the vocabulary are normative and frozen. Reordering them
changes every fingerprint and breaks comparability between implementations, so
`TestVocabFrozen` fails if anyone tries.

## Prior art and clearance

The construction is a presence bitmap over a published vocabulary plus a hash
of value grammars. The vocabulary-presence idea is p0f's, published in 2006
under the GPL. No JA4+ format is reproduced: JA4H hashes an ordered header-name
list and has a cookie section, Akin does neither. See SPEC.md for the full
clearance note.

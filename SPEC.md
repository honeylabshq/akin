# Akin: an open HTTP request fingerprint

Version 1 (token prefix `a`). Draft.

## What this is for

Akin identifies an HTTP/1.x client from a single bare request head. It needs no
packet capture, no TLS handshake and no connection state, so it can be computed
anywhere the request bytes are available: a honeypot, a reverse proxy log, a
WAF, or a stored column in a database.

It is aimed at scanner and crawler traffic, which is what honeypots and edge
logs mostly see.

## The property the format exists for

The middle section of the token is a presence bitmap over a fixed published
vocabulary rather than a hash. The Hamming distance between two bitmaps is the
number of vocabulary headers the two clients differ by, and within the
vocabulary that is exact by construction rather than by measurement.

Counted against every header a client sends, the distance is a lower bound. A
header outside the vocabulary cannot set a bit, so the distance can undercount,
and no mechanism exists by which it can overcount. Measured over 2,016 cluster
pairs in 21 days of traffic, every error was an undercount: the distance was
exact for 95.7% of near neighbours (a true difference of one or two headers)
and 84.9% of all pairs, and within one of correct for 96.6%.

This makes "is this the same tool with one header added" a question the token
can answer by itself, with no lookup table and no access to the original
requests.

## Format

    <spec><ver><eol><dup><body><nhdr><extra>_<bitmap>_<detail>[_<session>]

Example: `a11cun040_0000002b_608dab68`

| Section | Width | Meaning |
|---|---|---|
| `spec` | 1 | Akin format version. `a` is version 1. A revision bumps it to `b` so that v1 parsers reject v2 tokens rather than misreading them |
| `ver` | 2 | HTTP version digits, `11` or `10`. A request line with no recognisable HTTP/1.x version gives `00` |
| `eol` | 1 | `c` if the head uses CRLF, `l` if bare LF |
| `dup` | 1 | `d` if any header name repeats, else `u` |
| `body` | 1 | `q` Content-Length, `k` Transfer-Encoding, `n` neither |
| `nhdr` | 2 | Header count, capped at 99 |
| `extra` | 1 | Headers outside the vocabulary, capped at 9 |
| `bitmap` | 8 | 32-bit vocabulary presence bitmap, big-endian hex |
| `detail` | 8 | Truncated SHA-256 over negotiation-header value shapes and the header-name casing pattern |
| `session` | 1 | Optional. `1` single request, `c` contiguous run, `g` gapped run |

The prefix is always exactly nine characters, so a consumer can index it
without splitting, and it is readable without tooling. The bitmap carries the
distance property. The detail hash carries the parts that are too
high-cardinality to print.

## Vocabulary

Thirty-two header names, ordered by presence entropy over 120,000 scanner
requests. Bit 0 is the first entry. Bit positions are normative and frozen:
reordering them changes every fingerprint and breaks the distance property
between implementations.

    0  accept                      16 metadata-flavor
    1  connection                  17 metadata
    2  accept-encoding             18 sec-ch-ua-platform
    3  host                        19 sec-ch-ua-mobile
    4  accept-language             20 sec-ch-ua
    5  upgrade-insecure-requests   21 x-requested-with
    6  user-agent                  22 referer
    7  range                       23 accept-charset
    8  cache-control               24 x-csrf-token
    9  content-length              25 proxy-authorization
    10 content-type                26 origin
    11 sec-fetch-mode              27 wsmanidentify
    12 pragma                      28 sec-gpc
    13 sec-fetch-dest              29 upgrade
    14 sec-fetch-site              30 sec-websocket-version
    15 sec-fetch-user              31 sec-websocket-key

The list covers 99.9% of header occurrences in the measured corpus and no bit
is dead. An earlier hand-picked vocabulary left 7 of 28 bits unused and dropped
distance accuracy to 89%.

## Detail hash

The detail section is the first four bytes of a SHA-256 over:

    <negotiation pairs joined by "|"> "#" <casing pattern>

A negotiation pair is `<lowercased header name>=<value shape>` for each of
these headers, in the order they appear in the request: `accept`,
`accept-encoding`, `accept-language`, `accept-charset`, `connection`, `te`,
`upgrade-insecure-requests`, `cache-control`, `pragma`.

A value shape collapses the value to its grammar: runs of ASCII letters become
`a`, runs of ASCII digits become `9`, any run of three or more identical
characters is cut to two, and the result is truncated to 24 characters. The
value itself never reaches the token.

The casing pattern is one character per header in request order: `U` if the
header name is entirely uppercase, `l` if entirely lowercase, `C` otherwise.

## What is deliberately excluded

User-Agent presence is a bit, but its value never reaches the fingerprint.
Neither does the request path. Measured over 40,000 requests, consistency
within a single known operator was 0.77 for the User-Agent string and 0.71 for
the path shape, against 1.00 for the structural features. Both track the
disguise rather than the client.

This was tested rather than assumed. An early revision included the User-Agent
shape and looked better on cluster counts. Against a known botnet of 6,910 IPs
running one exploit it produced 327 fingerprints where the correct answer is
one. Removing the User-Agent brought it to one across all 8,000 sampled
requests, and the current revision holds at one across 20,000 sessions.

## Session section

Optional, and only meaningful where the collector tracks connections. It
records whether the per-connection record numbers form a contiguous run.

Measured per source IP across 21 days, that field stays constant 0.99 of the
time, which puts it with the structural features rather than with the
User-Agent.

It costs a little persistence: mean cluster lifetime falls from 16.8 days to
15.9. Implementations that do not track connections omit the section.

A collector writing a record while the connection is still open does not yet
know whether more requests will follow, and a client must not change
fingerprint mid-connection. Such collectors emit the request-only form and
leave the session section to offline analysis, where the whole connection is
known.

## Limits

HTTP/1.x only. The corpus this was built and measured on is scanner and crawler
traffic from one honeypot network, and it contains no HTTP/2 at all across 1.58
million requests, so Akin makes no claim about browser traffic or about HTTP/2
clients.

Only 82 distinct header names appear in that corpus and only seven carry
meaningful presence entropy, which bounds how finely any scheme built on header
structure can separate this kind of traffic.

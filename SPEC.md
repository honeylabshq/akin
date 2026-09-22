# Akin: a draft open HTTP request fingerprint

Status: draft for internal review. The licence is not decided here.

## What this is for

A fingerprint computed from a single bare HTTP/1.x request head, with no pcap,
no TLS handshake and no connection state required. It is aimed at scanner and
crawler traffic, which is what honeypots and edge logs mostly see.

It exists because the two usable options both fail for this job. JA4H is
correct and well designed, but the FoxIO licence restricts it to non-commercial
use and the method is marked patent pending. p0f's HTTP scheme is GPL and
unencumbered, but its `expsw` field reads the User-Agent, which scatters one
operator across hundreds of fingerprints whenever the operator rotates the
string.

## The property Akin has and JA4H does not

The middle section is a presence bitmap over a fixed published vocabulary, not
a hash. The Hamming distance between two bitmaps is the number of vocabulary
headers the two clients differ by. Over 21 days of traffic that distance
matched the true header difference in 95% of cluster pairs.

JA4H hashes its ordered header-name list, so a client that adds one header gets
a token with no visible relationship to the old one. In the same corpus, 560
JA4H cluster pairs differ by exactly one header and 1,158 by exactly two, and
JA4H gives every one of those pairs unrelated hashes. Asking "is this the same
tool with one header added" requires a lookup table it does not have.

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
| `bitmap` | 8 | 32-bit vocabulary presence bitmap, little-endian hex |
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

## What is deliberately excluded

User-Agent presence is a bit, but its value never reaches the fingerprint.
Neither does the request path. Measured over 40,000 requests, consistency
within a single known operator was 0.77 for the User-Agent string and 0.71 for
the path shape, against 1.00 for the structural features. Both track the
disguise rather than the client.

This was tested rather than assumed. An early revision included the User-Agent
shape and looked better on cluster counts. Against a known botnet of 6,910 IPs
running one CVE exploit it produced 327 fingerprints where the correct answer
is one. Removing the User-Agent brought it to one across all 8,000 sampled
requests, and the current revision holds at one across 20,000 sessions.

## Session section

Optional, and only meaningful where the collector tracks connections. It
records whether the per-connection record numbers form a contiguous run.

Measured per source IP across 21 days, that field stays constant 0.99 of the
time, which puts it with the structural features rather than with the
User-Agent. It splits 27 of 155 JA4H clusters into groups JA4H cannot separate,
because JA4H is a single-request construction by definition.

It costs a little persistence: mean cluster lifetime falls from 16.8 days to
15.9. Implementations that do not track connections omit the section.

## Prior art and clearance

The construction is a presence bitmap over a published vocabulary plus a hash
of value grammars. Bitmaps and Hamming distance are not encumbered. The
vocabulary-presence idea is p0f's, published in 2006 under the GPL, which
predates both the FoxIO methods and the Verizon patent family.

The Verizon family covering client application fingerprinting from request
analysis (US8694608, US9251258, US10169460, US10885128, US11354364, priority
2008-07-21, expiring 2028-07-21) claims summing numeric per-header values into
a score and matching that score against ranges. Akin computes no numeric
per-header values, no sum and no score, and performs no range matching.

No JA4+ format is reproduced. JA4H's construction is a truncated hash over the
ordered header-name list with a separate cookie section; nothing here hashes an
ordered header-name list, and there is no cookie section.

## Limits

Cluster counts are close to JA4H's, and the agreement between the two is high
(ARI 0.949). That agreement is a property of the domain rather than evidence of
derivation: p0f's independent scheme agrees with JA4H at 0.997 and the
User-Agent alone at 0.992. The case for Akin is the distance property,
the ability to compute it from a bare request, and the licence, not a higher
discrimination score.

The corpus is scanner and crawler traffic from one honeypot network. It
contains zero HTTP/2 requests across 1.58 million samples, so the format is
specified for HTTP/1.x only and makes no claim about browser traffic.

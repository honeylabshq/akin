# Akin: an open HTTP request fingerprint

Format b. Draft. Tokens of the previous format start with `a`; they are not
comparable with format b tokens and a format b decoder rejects them.

## What this is for

Akin identifies an HTTP/1.x client from a single bare request head. It needs no
packet capture, no TLS handshake and no connection state, so it can be computed
anywhere the request bytes are available: a honeypot, a reverse proxy log, a
WAF, or a stored column in a database.

It is aimed at scanner and crawler traffic, which is what honeypots and edge
logs mostly see.

## The property the format exists for

Two tokens can be compared without a lookup table and without the original
requests, and the comparison answers a concrete question: how many headers do
these two clients differ by. Within the core list that number is exact by
construction. Outside it, every header is carried as a short code, so a
difference in a header the list never heard of still counts.

Header order never enters the token. A tool that shuffles its header order on
every request, and one such exploit tool held five tokens under the previous
format, gets one token.

## Format

    <spec><ver><eol><dup><body><nhdr><extra>_<core>_<detail>[_x<codes>][_<session>]

Examples:

    b11cun030_00040014_54d07b6d                 default curl
    b11cdn053_00040000_2e792dd9_x22692f93bcb1   Host plus three headers outside the core list
    b11cun030_00040014_54d07b6d_c               default curl with a session field

| Section | Width | Meaning |
|---|---|---|
| `spec` | 1 | Format letter, `b`. A revision changes it so a decoder for one format rejects the next instead of misreading it |
| `ver` | 2 | HTTP version digits, `11` or `10`. A request line with no recognisable HTTP/1.x version gives `00` |
| `eol` | 1 | `c` if the head uses CRLF, `l` if bare LF |
| `dup` | 1 | `d` if any header name repeats, compared case-insensitively, else `u` |
| `body` | 1 | `q` Content-Length, `k` Transfer-Encoding, `n` neither |
| `nhdr` | 2 | Header count, capped at 99 |
| `extra` | 1 | Distinct header names outside the core list, capped at 9 |
| `core` | 8 | 32-bit presence map over the core list, big-endian hex |
| `detail` | 8 | Truncated SHA-256 over negotiation-header value shapes and the header-name casing pattern |
| `x` + `codes` | 4 per code | Present only when `extra` is not 0. The codes of the headers outside the core list, sorted, exactly `extra` of them |
| `session` | 1 | Optional. `1` single request, `c` contiguous run, `g` gapped run |

The prefix is always exactly nine characters, so a consumer can index it
without splitting, and it is readable without tooling. The core map and the
codes carry the distance property. The detail hash carries the parts that are
too high-cardinality to print.

Sections are separated by `_`. A token has three, four or five sections, and
the extras section, when present, always precedes the session section.

## Core list

Thirty-two header names. Bit 0 is the first entry. Bit positions are normative
and frozen: reordering them changes every token and breaks the distance
property between implementations. The list never grows, because a header
outside it is carried by code instead.

    0  connection                  16 content-type
    1  accept-encoding             17 accept-charset
    2  accept                      18 host
    3  accept-language             19 priority
    4  user-agent                  20 cache-control
    5  upgrade-insecure-requests   21 pragma
    6  sec-fetch-mode              22 authorization
    7  sec-fetch-site              23 soapaction
    8  sec-fetch-dest              24 dnt
    9  sec-fetch-user              25 wsmanidentify
    10 referer                     26 x-aggregate-auth
    11 content-length              27 cookie
    12 sec-ch-ua-platform          28 origin
    13 sec-ch-ua                   29 mcp-protocol-version
    14 sec-ch-ua-mobile            30 upgrade
    15 sec-gpc                     31 x-forwarded-for

The list is the 32 header names with the highest presence entropy over the
107,559 addresses that sent HTTP/1.x to HoneyLabs honeypot sensors between
1 June and 29 September 2026, in that order, with a floor of 50 addresses per
name. Presence entropy rewards a header that some clients send and others do
not; a header every client sends, or one almost none do, separates nothing.
The floor keeps a header that a single campaign sent from taking a bit.

## Extra headers

A header name outside the core list is carried by its code: the first two
bytes of the SHA-256 of the lowercased name, as four hex digits. Codes are
sorted, repeated names count once, and at most nine are carried. The `extra`
digit of the prefix is the number of codes, so it saturates at 9 too.

    range      2269
    x-foo      2f93
    x-bar      bcb1

Anyone holding a list of header names can compute their codes and read a
token's extras back; the command-line tool does this with `-names`. Over seven
days of scanner traffic, 263 distinct header names appeared outside the core
list; they were sent in 1.2% of requests and by 7.7% of addresses, and they
separated 36% of the distinct tokens. The previous format counted them and
threw the names away.

Two different names share a code with probability 1 in 65,536. A collision
makes two clients that differ in those two headers look one header closer than
they are; it can never make them look further apart.

## Detail hash

The detail section is the first four bytes of a SHA-256 over:

    <negotiation pairs joined by "|"> "#" <casing pattern>

A negotiation pair is `<lowercased header name>=<value shape>` for each of
these headers: `accept`, `accept-encoding`, `accept-language`,
`accept-charset`, `connection`, `te`, `upgrade-insecure-requests`,
`cache-control`, `pragma`. Pairs are sorted by header name, then by value
shape, never by position in the request.

A value shape collapses the value to its grammar: runs of ASCII letters become
`a`, runs of ASCII digits become `9`, any run of three or more identical
characters is cut to two, and the result is truncated to 24 characters. The
value itself never reaches the token.

The casing pattern has one character for every header, in the same
name-sorted order as the pairs above (a repeated name keeps request order):
`U` if the header name is entirely uppercase, `l` if entirely lowercase, `C`
otherwise.

Over seven days of scanner traffic, hashing in request order gave 457 tokens
where the sorted form gives 407, and every token the change removed had
differed from another in header order alone.

## Distance

    distance(a, b) = popcount(core(a) XOR core(b)) + |codes(a) Δ codes(b)|

The first term is the number of core headers one client sends and the other
does not. The second is the number of codes carried by only one of the two
tokens. The result is the number of headers the two clients differ by, and it
is a lower bound: it can undercount when a request carries more than nine
headers outside the core list or when two names share a code, and it cannot
overcount. A malformed token gives -1.

## What is deliberately excluded

User-Agent presence is a bit, but its value never reaches the token. Neither
does the request path. Measured over 40,000 requests, consistency within a
single known operator was 0.77 for the User-Agent string and 0.71 for the path
shape, against 1.00 for the structural features. Both track the disguise, not
the client.

Header order is excluded everywhere: the core map and the codes never saw it,
and the detail hash sorts before hashing.

This was tested. An early revision included the User-Agent shape and looked
better on cluster counts. Against a known botnet of 6,910 IPs running one
exploit it produced 327 fingerprints where the correct answer is one. Removing
the User-Agent brought it to one across all 8,000 sampled requests, and the
current revision holds at one across 20,000 sessions.

## Session section

Optional, and only meaningful where the collector tracks connections. It
records whether the per-connection record numbers form a contiguous run.

Measured per source IP across 21 days, that field stays constant 0.99 of the
time, which puts it with the structural features rather than with the
User-Agent.

A collector writing a record while the connection is still open does not yet
know whether more requests will follow, and a client must not change token
mid-connection. Such collectors emit the request-only form and leave the
session section to offline analysis, where the whole connection is known.

## Decoding

Every section except the detail hash is readable. A decoder returns the HTTP
version, line ending, duplicate flag, body signal, header count, the names of
the core headers present, the codes of the extra headers, and the session
field if any. It rejects a token whose `extra` digit disagrees with its codes
section, whose codes are unsorted, or whose sections are out of order.

## Limits

HTTP/1.x only. The corpus this was built and measured on is scanner and crawler
traffic reaching one honeypot network, whose listeners speak HTTP/1.1 only, so
Akin makes no claim about HTTP/2 or HTTP/3 clients.

The core list is tuned to that traffic. A population of ordinary browser
sessions would spend its bits differently, and a client that sends many
headers outside the list is described less finely than one that stays inside
it.

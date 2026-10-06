# Akin: an open HTTP request fingerprint

This document specifies format b, which is a draft. Tokens of the previous
format start with `a`. They are not comparable with format b tokens, and a
format b decoder rejects them.

## Scope

Akin identifies an HTTP client from a single request: an HTTP/1.x request
head, or the field list of an HTTP/2 or HTTP/3 request. It needs no packet
capture, TLS handshake or connection state, so it can be computed wherever the
request is available, such as a honeypot, a reverse proxy log, a WAF or a
stored database column. It was built for scanner and crawler traffic, which is
most of what honeypots and edge logs see.

Two tokens can be compared without a lookup table and without the original
requests. The comparison gives the number of headers the two clients differ
by. For headers in the core list that number is exact, and every other header
is carried as a short code, so a header the list does not name still counts.

Header order is not part of the token. A client that shuffles its headers on
every request gets one token; one exploit tool that does this had five tokens
under the previous format.

## Format

    <spec><ver><eol><dup><body><nhdr><extra>_<core>_<detail>[_x<codes>][_<session>]

Examples:

    b11cun030_00040014_54d07b6d                 default curl
    b11cdn053_00040000_2e792dd9_x22692f93bcb1   Host plus three headers outside the core list
    b11cun030_00040014_54d07b6d_c               default curl with a session field

| Section | Width | Meaning |
|---|---|---|
| `spec` | 1 | Format letter, `b`. Each revision changes it, so a decoder for one format rejects the next one instead of misreading it |
| `ver` | 2 | HTTP version digits: `1` and the minor digit of an `HTTP/1.x` request line, `20` for HTTP/2, `30` for HTTP/3. Any other request-line version gives `00` |
| `eol` | 1 | `c` if the head uses CRLF, `l` if bare LF, `h` for an HTTP/2 or HTTP/3 field list. The blank line that ends the head counts, so a head with no headers still reports its line ending |
| `dup` | 1 | `d` if any header name repeats, compared case-insensitively, else `u` |
| `body` | 1 | `q` Content-Length, `k` Transfer-Encoding, `b` both, `n` neither |
| `nhdr` | 2 | Header count, capped at 99 |
| `extra` | 1 | Distinct header names outside the core list, capped at 9 |
| `core` | 8 | 32-bit presence map over the core list, big-endian hex |
| `detail` | 8 | Truncated SHA-256 over negotiation-header value shapes and the header-name casing pattern |
| `x` + `codes` | 4 per code | Present only when `extra` is not 0. The codes of the headers outside the core list, sorted, exactly `extra` of them |
| `session` | 1 | Optional. `1` single request, `c` contiguous run, `g` gapped run |

The prefix is always nine characters, so a consumer can index into it without
splitting the token, and a person can read it without tooling. The core map
and the codes give the distance. The detail hash covers the signals that have
too many values to print.

Sections are separated by `_`. A token has three, four or five sections, and
when the extras section is present it comes before the session section.

## Request head

The head ends at the first blank line, CRLF CRLF or LF LF, whichever comes
first. Anything after it is body and is never read as headers. The request
line must have exactly three space-separated fields. A header is a line that
contains a colon, and its name is everything before the first colon, kept as
sent.

## Core list

The core list has 32 header names, and bit 0 is the first entry. Bit positions
are normative and frozen, because reordering them would change every token and
break the distance between implementations. The list never grows, since a
header outside it is carried by code.

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

These are the 32 header names with the highest presence entropy over the
107,559 addresses that sent HTTP/1.x to HoneyLabs honeypot sensors between
1 June and 29 September 2026, in that order, with a floor of 50 addresses per
name. Presence entropy is high for a header that some clients send and others
do not. A header that every client sends, or that almost none do, separates
nothing. The floor stops a header sent by a single campaign from taking a bit.

That traffic is scanners and crawlers, so the list is tuned to them. A
population of ordinary browser sessions would spend the bits differently, and
a client that sends many headers outside the list is described less finely
than one that stays inside it.

## Extra headers

A header name outside the core list is carried by its code, which is the first
two bytes of the SHA-256 of the lowercased name written as four hex digits.
Codes are sorted, a repeated name counts once, and at most nine are carried.
The `extra` digit of the prefix is the number of codes, so it also stops at 9.

    range      2269
    x-foo      2f93
    x-bar      bcb1

Anyone with a list of header names can compute their codes and read a token's
extras back. The command-line tool does this with `-names`. Over seven days of
scanner traffic, 263 distinct header names appeared outside the core list.
They were sent in 1.2% of requests and by 7.7% of addresses, and they
separated 36% of the distinct tokens. The previous format counted these
headers and dropped their names.

Two different names share a code with probability 1 in 65,536. A collision
makes two clients that differ in those two headers look one header closer
than they are. It cannot make them look further apart.

## Detail hash

The detail section is the first four bytes of a SHA-256 over:

    <negotiation pairs joined by "|"> "#" <casing pattern>

A negotiation pair is `<lowercased header name>=<value shape>` for each of
these headers: `accept`, `accept-encoding`, `accept-language`,
`accept-charset`, `connection`, `te`, `upgrade-insecure-requests`,
`cache-control`, `pragma`. Pairs are sorted by header name and then by value
shape, never by position in the request.

A value shape reduces the value to its grammar. Runs of ASCII letters become
`a`, runs of ASCII digits become `9`, any run of three or more identical
characters is cut to two, and the result is truncated to 24 characters. The
value itself never reaches the token.

The casing pattern has one character per header, in the same name-sorted
order as the pairs (a repeated name keeps request order): `U` if the header
name is all uppercase, `l` if all lowercase, `C` otherwise.

Over seven days of scanner traffic, hashing in request order gave 457 tokens
and the sorted form gives 407. Every token that sorting removed had differed
from another only in header order.

## HTTP/2 and HTTP/3

Both protocols deliver a request as a list of fields, and Akin reads that list
after HPACK or QPACK decoding. They share one procedure and differ only in the
version digits.

- Pseudo-header fields are dropped, except `:authority`, which counts as a
  `host` header in its position. It carries what Host carries in HTTP/1.x, so
  one client's core map stays comparable across versions.
- Repeated `cookie` fields count as one header in the position of the first.
  Both protocols let a client split Cookie into crumbs, and a recipient must
  join them.
- Everything else, the duplicate flag included, follows the HTTP/1.x rules.

Both protocols require lowercase field names, so a conforming client's casing
pattern is all `l`. Connection-specific headers such as `connection`,
`upgrade` and `transfer-encoding` are forbidden in both, so a client that
sends them is breaking the protocol.

Frame-level signals such as SETTINGS values, WINDOW_UPDATE, PRIORITY,
pseudo-header order and QUIC transport parameters are out of scope, because
they need the connection and Akin reads one request. The sensors the core
list was measured on speak HTTP/1.1 only, so this procedure follows from the
protocols and has not yet been measured on traffic.

## Distance

    distance(a, b) = popcount(core(a) XOR core(b)) + |codes(a) Δ codes(b)|

The first term counts the core headers that one client sends and the other
does not. The second counts the codes that only one of the two tokens
carries. The sum is the number of headers the two clients differ by. It is a
lower bound: it undercounts when a request carries more than nine headers
outside the core list or when two names share a code, and it never
overcounts. A malformed token gives -1.

## Excluded signals

The token records that a User-Agent header is present, never its value. The
request path is left out as well. Over 40,000 requests, the share of requests
from one known operator that agreed on a signal was 0.77 for the User-Agent
string and 0.71 for the path shape, against 1.00 for the structural features.
An operator changes the User-Agent and the path to look like someone else,
while the header set comes from the HTTP library and stays put.

An early revision included the User-Agent shape and produced fewer clusters
overall. Against a known botnet of 6,910 addresses running one exploit, it
produced 327 fingerprints where the correct answer is one. Without the
User-Agent the count was one across all 8,000 sampled requests, and the
current format holds at one across 20,000 sessions.

Header order is excluded from every section, since the core map and the
codes have no order and the detail hash sorts before hashing.

## Session section

The session section is optional and only means something where the collector
tracks connections. It records whether the per-connection record numbers form
a contiguous run. Measured per source address across 21 days, the field stays
constant 99% of the time, which puts it with the structural features and well
above the User-Agent.

A collector that writes a record while the connection is still open does not
yet know whether more requests will follow, and a client must not change
token in the middle of a connection. Such collectors emit the request-only
form and leave the session section to offline analysis, where the whole
connection is known.

## Decoding

Every section except the detail hash can be read back. A decoder returns the
HTTP version, line ending, duplicate flag, body signal, header count, the
names of the core headers present, the codes of the extra headers, and the
session field if there is one. It rejects a token whose `extra` digit
disagrees with its codes section, whose codes are unsorted, or whose sections
are out of order.

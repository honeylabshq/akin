# Akin

Akin is an open fingerprint for HTTP clients. It reads one request and writes a
short token, and the distance between two tokens is the number of headers the
two clients differ by.

    b11cun030_00040014_54d07b6d

That token is curl 8.5 with its default headers. Akin needs only the request,
so it runs anywhere requests are seen or stored: a honeypot, a proxy or WAF
log, or a column in a database. It reads HTTP/1.x request heads as raw bytes,
and HTTP/2 and HTTP/3 requests as the field list the server decoded.

## Install

    go get github.com/honeylabshq/akin
    go install github.com/honeylabshq/akin/cmd/akin@latest

## Go

```go
fp := akin.Fingerprint(requestBytes)     // HTTP/1.x head, "" if it does not parse
fp2 := akin.FingerprintFields(2, fields) // HTTP/2 field list, 3 for HTTP/3
d := akin.Distance(fp, fp2)              // headers they differ by, -1 if malformed
f, err := akin.Decode(fp)                // the readable fields
```

## Command line

```
$ printf 'GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n' | akin
b11cun030_00040014_54d07b6d

$ akin -hex < payloads.hex   # one hex-encoded request per line

$ printf ':method: GET\n:path: /\n:authority: a\nuser-agent: curl/8.5.0\naccept: */*\n' | akin -fields 2
b20hun030_00040014_03330a18

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

## The token

The first nine characters are readable: format letter, HTTP version, line
ending, duplicate flag, body signal, header count and the number of headers
outside the core list. The next eight are a 32-bit map of which headers from a
fixed list of 32 names the request carried. A header outside that list is
carried as a four-digit code in its own section, so a difference in any header
counts toward the distance. The last eight characters hash the grammar of the
negotiation headers and the capitalisation of the header names.

Header order and the User-Agent value are left out, because a scanner changes
both between requests while the set of headers its HTTP library sends stays
the same. [SPEC.md](SPEC.md) has the format, the core list and the
measurements behind each choice.

## Background

Akin follows p0f, Michal Zalewski's passive fingerprinting tool, which added
HTTP signatures in version 3 in 2012. A p0f HTTP signature describes a client
by which headers it sends from a list of known names, and the core map in an
Akin token does the same.

The idea of a short fingerprint string that analysts can share and search for
comes from JA3, the TLS client fingerprint John Althouse, Jeff Atkinson and
Josh Atkins published at Salesforce in 2017, and from HASSH, the SSH
fingerprint Ben Reardon and Adel Karimi published at Salesforce in 2018. Akin
applies that idea to HTTP requests and adds a distance, so two tokens that are
not equal still say how close the clients are.

## Status

The format is a draft until version 1.0. The bit positions of the core list
are already fixed, and `TestCoreFrozen` fails if they are reordered. The
vectors in `testdata/vectors.json` pin the output, and CI checks every one.

Licensed under Apache-2.0, which includes a patent grant from every
contributor.

"""Akin: reference implementation of an open HTTP request fingerprint.

Draft specification. See SPEC.md.

Input is a bare HTTP/1.x request head as bytes, which is what a honeypot or a
proxy log already has. No pcap, no TLS, no connection state required.
"""
import hashlib, re

# Leading character of every token. Bump to "b" for a format revision so that
# parsers written against v1 reject v2 tokens instead of misreading them.
SPEC_VERSION = "a"

# Bit positions are part of the specification and MUST NOT be reordered.
# Derived by presence entropy over 120,000 scanner requests; every bit is used.
VOCAB = [
    "accept", "connection", "accept-encoding", "host",
    "accept-language", "upgrade-insecure-requests", "user-agent", "range",
    "cache-control", "content-length", "content-type", "sec-fetch-mode",
    "pragma", "sec-fetch-dest", "sec-fetch-site", "sec-fetch-user",
    "metadata-flavor", "metadata", "sec-ch-ua-platform", "sec-ch-ua-mobile",
    "sec-ch-ua", "x-requested-with", "referer", "accept-charset",
    "x-csrf-token", "proxy-authorization", "origin", "wsmanidentify",
    "sec-gpc", "upgrade", "sec-websocket-version", "sec-websocket-key",
]

# Headers whose *value grammar* is structural rather than content. Their shapes
# go into the detail hash; their raw values never do.
NEGOTIATION = (
    "accept", "accept-encoding", "accept-language", "accept-charset",
    "connection", "te", "upgrade-insecure-requests", "cache-control", "pragma",
)


def shape(value):
    """Collapse a header value to its grammar: letters -> a, digits -> 9."""
    s = re.sub(r"[A-Za-z]+", "a", value.strip())
    s = re.sub(r"[0-9]+", "9", s)
    return re.sub(r"(.)\1{2,}", r"\1\1", s)[:24]


def parse_head(data: bytes):
    """Split a request head into (version, [(name, value)], crlf). None if not HTTP."""
    head = data.split(b"\r\n\r\n")[0] if b"\r\n\r\n" in data else data.split(b"\n\n")[0]
    text = head.decode("utf-8", "replace")
    lines = re.split(r"\r\n|\n", text)
    if not lines or len(lines[0].split(" ")) != 3:
        return None
    _method, _path, version = lines[0].split(" ")
    hdrs = [(n, v) for ln in lines[1:] if ":" in ln for n, _, v in [ln.partition(":")]]
    return version, hdrs, "\r\n" in text


def fingerprint(data: bytes, sequence=None):
    """Return the fingerprint string, or None if the input is not an HTTP request.

    sequence: the list of per-connection record numbers seen for this connection,
    when the caller tracks connections. Omit it for single-request analysis; the
    fingerprint is then emitted without the session section.
    """
    parsed = parse_head(data)
    if parsed is None:
        return None
    version, hdrs, crlf = parsed

    names = [n for n, _ in hdrs]
    low = [n.lower() for n in names]

    digits = version.split("/")[-1].replace(".", "")
    # Exactly two digits, so the readable prefix is always nine characters.
    ver = digits if len(digits) == 2 and digits.isdigit() and digits.isascii() else "00"
    eol = "c" if crlf else "l"
    dup = "d" if len(low) != len(set(low)) else "u"
    if "content-length" in low:
        body = "q"
    elif "transfer-encoding" in low:
        body = "k"
    else:
        body = "n"
    extra = min(sum(1 for n in low if n not in VOCAB), 9)

    bits = 0
    for i, name in enumerate(VOCAB):
        if name in low:
            bits |= 1 << i

    case = "".join("U" if n.isupper() else "l" if n.islower() else "C" for n in names)
    neg = [f"{n.lower()}={shape(v)}" for n, v in hdrs if n.lower() in NEGOTIATION]
    detail = hashlib.sha256(("|".join(neg) + "#" + case).encode()).hexdigest()[:8]

    fp = f"{SPEC_VERSION}{ver}{eol}{dup}{body}{min(len(names), 99):02d}{extra}_{bits:08x}_{detail}"
    if sequence is not None:
        fp += "_" + session_field(sequence)
    return fp


def session_field(sequence):
    """One character: 1 = single request, c = contiguous run, g = gapped run."""
    if len(sequence) <= 1:
        return "1"
    gaps = [b - a for a, b in zip(sequence, sequence[1:])]
    return "c" if all(g == 1 for g in gaps) else "g"


def distance(a: str, b: str) -> int:
    """Number of vocabulary headers two fingerprints differ by.

    This is the property the format exists for. JA4H cannot answer it: its
    middle section is a hash, so one added header changes the whole token.
    """
    return bin(int(a.split("_")[1], 16) ^ int(b.split("_")[1], 16)).count("1")

# Akin benchmarked against JA4H and p0f

Corpus: 60,000 connections over 21 days from the HoneyLabs sensor network, all
HTTP/1.x. Each scheme computed from the same stored request bytes.

| Scheme | Clusters | Max UAs in one cluster | Mean persistence | ARI vs JA4H |
|---|---|---|---|---|
| JA4H | 155 | 187 | 17.0d | 1.000 |
| p0f HTTP scheme | 337 | 68 | 15.0d | 0.997 |
| Akin, request only | 161 | 179 | 16.8d | 0.949 |
| Akin, with session | 179 | 177 | 15.9d | 0.951 |

Higher cluster counts are not better. p0f's 337 come from the User-Agent
entering the fingerprint, which splits single operators across many tokens.

## Known-ground-truth test

A botnet running one CVE-2026-4020 exploit, 870,253 events across 6,910 IPs and
3,383 distinct User-Agent strings. The correct answer is one fingerprint.

| Scheme | Fingerprints |
|---|---|
| JA4H | 1 |
| p0f HTTP scheme | 363 |
| Akin, request only | 1 |
| Akin, with session | 1 |

## Distance property

Cluster pairs in the corpus differing by exactly one header: 560. By exactly
two: 1,158. For those pairs, the Hamming distance between Akin bitmaps equals
the true header difference 95% of the time. JA4H and p0f both give unrelated
tokens and cannot answer the question at all.

## Stability control

Consistency of each feature within a single source IP, which is the test that
separates a client property from environmental noise. Measured across IPs with
five or more sessions.

| Feature | Consistency |
|---|---|
| Structural header features | 1.00 |
| Session contiguity field | 0.99 |
| Requests-per-connection bucket | 0.92 |
| User-Agent string | 0.77 |
| Request path shape | 0.71 |

The User-Agent and the path were excluded on these numbers. The
requests-per-connection bucket was excluded as well: 0.92 is below the bar the
retained features clear.

## Throughput

Single Raspberry Pi 5 core, Python reference implementation.

| Scheme | Per request |
|---|---|
| p0f HTTP scheme | 6.7 µs |
| Akin | 23.1 µs |

43,000 requests per second on one core. The difference is the value-shape
regexes in the detail hash. Go figures are in the Go implementation's own
benchmark.

## What the numbers do not show

Agreement with JA4H at 0.949 is high, and the controls show that is inherent to
the domain: p0f reaches 0.997, the User-Agent alone 0.992, sorted header names
0.944, header count 0.773. Any reasonable scheme lands near JA4H. The claim
worth making is the distance property, computability from a bare request head,
and an unencumbered licence, not a better clustering score.

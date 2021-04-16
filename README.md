<div align="center">
<h1>q</h1>

A tiny command line DNS client with support for UDP, DoT, DoH, and DoQ.

[![Go Report](https://goreportcard.com/badge/github.com/natesales/q?style=for-the-badge)](https://goreportcard.com/report/github.com/natesales/q)
[![License](https://img.shields.io/github/license/natesales/q?style=for-the-badge)](https://raw.githubusercontent.com/natesales/q/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/natesales/q?style=for-the-badge)](https://github.com/natesales/q/releases)

![q screenshot](screenshot.png)
</div>

### Usage
```
q command line DNS client (https://github.com/natesales/q) version dev

Usage:
  q [OPTIONS] @<protocol>://<server>:[port] <rr types> <qname>

Options:
  -c, --chaos    Use CHAOS QCLASS
  -d, --dnssec   Request DNSSEC
  -r, --raw      Output raw DNS string format
  -i, --insecure Skip verifying TLS certificate
  -h, --help     Display help menu
  -v, --verbose  Enable verbose logging
  -q, --quiet    Don't display DNS response

Protocols:
  dns    RFC 1034 UDP/TCP DNS
  tls    RFC 7858 DNS over TLS
  https  RFC 8484 DNS over HTTPS
  quic   draft-ietf-dprive-dnsoquic-02 DNS over QUIC
```

### Demo

[![asciicast](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ.svg)](https://asciinema.org/a/XdWPPvZgx4hEBFwGnGwL13bsZ)

### Protocol Support
- UDP DNS ([RFC 1034](https://tools.ietf.org/html/rfc1034))
- DNS over TLS ([RFC 7858](https://tools.ietf.org/html/rfc7858))
- DNS over HTTPS ([RFC 8484](https://tools.ietf.org/html/rfc8484))
- DNS over QUIC ([draft-ietf-dprive-dnsoquic-02](https://tools.ietf.org/html/draft-ietf-dprive-dnsoquic-02))

### Installation
`q` is available as a single binary under [releases](https://github.com/natesales/q/releases) and in my [public code repositories](https://github.com/natesales/repo).
